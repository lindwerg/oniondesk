"""Secret lifecycle and fixed mainnet workflow for the launcher's nonce API.

Only explicit operations expose addresses. Polling uses RAM records, presence
checks and a bounded vault filename listing; no RPC, storage probe or writes.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
import secrets
import threading
import time
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from feather_bundle import FeatherSession, FeatherState, ProgressCallback

import wallet_bundle
from wallet_engine import Network, WalletError, WalletRecord
from wallet_vault import default_vault_manager

_WALLET_ID = re.compile(r"wallet_[0-9a-f]{32}\Z")
_VAULT_ID = re.compile(r"vault_[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_WORD = re.compile(r"[a-z]+\Z")
_SECRET_SECONDS = 180


@dataclass(frozen=True)
class _Backup:
    wallet_id: str
    token: str = field(repr=False)
    positions: tuple[int, int, int]
    expected: tuple[str, str, str] = field(repr=False)


def _wallet_id(identifier):
    if not isinstance(identifier, str) or not _WALLET_ID.fullmatch(identifier):
        raise WalletError("Неизвестный локальный кошелёк.")
    return identifier


class WalletController:
    def __init__(self, *, vault_manager=None, _engine_factory=None):
        # Factory injection is for offline fixtures only; no network/path/binary
        # options exist in the browser-facing methods below.
        self._vault = vault_manager or default_vault_manager()
        self._factory = _engine_factory or wallet_bundle.prepare_engine
        self._lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._engine = None
        self._workspace_root: Path | None = None
        self._feather: FeatherSession | None = None
        self._records = ()
        self._pending = None
        self._backup = None
        self._timer = None
        self._deadline = 0.0
        self._generation = 0
        self._message = "Создайте кошелёк или откройте своё зашифрованное хранилище."

    @staticmethod
    def _emit(emit, message, percent):
        if emit:
            emit({"message": message, "percent": percent})

    @contextmanager
    def _operation(self):
        if not self._operation_lock.acquire(blocking=False):
            raise WalletError("Дождитесь завершения текущей операции с кошельком.")
        try:
            yield
        finally:
            self._operation_lock.release()

    def _clear_locked(self, *, invalidate=True):
        if invalidate:
            self._generation += 1
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._pending is not None:
            self._pending.clear_secret()
            self._pending = None
        self._backup = None
        self._deadline = 0.0

    def _expire_locked(self):
        if self._deadline and time.monotonic() >= self._deadline:
            self._clear_locked()

    def _arm_locked(self):
        if self._timer is not None:
            self._timer.cancel()
        self._deadline = time.monotonic() + _SECRET_SECONDS
        generation = self._generation

        def expire():
            with self._lock:
                if self._generation == generation:
                    self._expire_locked()

        self._timer = threading.Timer(_SECRET_SECONDS, expire)
        self._timer.daemon = True
        self._timer.start()

    def forget(self):
        with self._lock:
            self._clear_locked()

    def _snapshot(self):
        with self._lock:
            self._expire_locked()
            opened = self._workspace_root is not None or self._engine is not None
            return opened, self._pending is not None, self._records, self._message

    def state(self):
        opened, pending, records, message = self._snapshot()
        has_wallet = opened and len(records) == 1
        summary = {"has_wallet": has_wallet,
                   "backup_confirmed": records[0].backup_confirmed if has_wallet else None}
        presence = wallet_bundle.status()
        try:
            vaults = self._vault.list_vaults()
        except WalletError as error:
            return {**summary, "available": False, "workspace_open": opened, "pending_seed": pending,
                    "vaults": [], "message": str(error)}
        return {**summary, "available": presence["available"], "workspace_open": opened,
                "pending_seed": pending, "vaults": vaults,
                "message": message if presence["available"] else presence["message"]}

    def list_wallets(self):
        _, _, records, _ = self._snapshot()
        return {"wallets": [asdict(record) for record in records], "vaults": self._vault.list_vaults()}

    @staticmethod
    def _records_checked(records):
        if (not isinstance(records, (list, tuple)) or len(records) != 1
                or any(not isinstance(record, WalletRecord) or record.network != Network.MAINNET.value for record in records)):
            raise WalletError("Хранилище должно содержать ровно один кошелёк. Сохранённые файлы не удаляются.")
        return tuple(records)

    def _prepare(self, root):
        engine = self._factory(network=Network.MAINNET, wallet_root=root)
        if getattr(engine, "network", None) is not Network.MAINNET:
            raise WalletError("Интерфейс поддерживает только основную сеть Monero.")
        with self._lock:
            self._engine = engine
            self._records = ()
        return engine

    def _close_previous(self):
        if self._feather is not None:
            self._feather.close()  # A running Feather prevents detaching its store.
        self._check_cached_feather()
        self._vault.close()
        with self._lock:
            self._engine, self._records = None, ()
            self._workspace_root = None  # Retain until the native close succeeds.

    def _check_cached_feather(self) -> None:
        with self._lock:
            engine = self._engine
            root = self._workspace_root
        if root is None and engine is not None:
            root = engine.root
        if root is not None:
            from feather_bundle import assert_workspace_idle
            assert_workspace_idle(root)

    def feather_state(self) -> FeatherState:
        import feather_bundle
        with self._lock:
            result = self._feather.state() if self._feather is not None else feather_bundle.status()
            result["workspace_open"] = self._engine is not None
            return result

    def _feather_operation(self, action: Literal["prepare", "launch", "connect", "stop"],
                           emit: ProgressCallback | None = None) -> None:
        # Share the exact wallet operation lock: create/unlock/lock cannot race
        # an external wallet process or unmount its filesystem during launch.
        with self._operation():
            with self._lock:
                engine = self._engine
            if action == "stop":
                if self._feather is not None:
                    self._feather.stop()
                self._check_cached_feather()
                return
            if engine is None or self._vault.active_id is None:
                raise WalletError("Сначала откройте своё зашифрованное хранилище кошелька.")
            engine._require_encrypted_storage()
            if self._feather is None:
                from feather_bundle import FeatherSession
                self._feather = FeatherSession()
            getattr(self._feather, action)(engine.root, emit)

    def prepare_feather(self, emit: ProgressCallback | None = None) -> None:
        self._feather_operation("prepare", emit)

    def launch_feather(self, emit: ProgressCallback | None = None) -> None:
        self._feather_operation("launch", emit)

    def connect_feather(self, emit: ProgressCallback | None = None) -> None:
        self._feather_operation("connect", emit)

    def stop_feather(self) -> None:
        self._feather_operation("stop")

    @contextmanager
    def _opening(self):
        with self._lock:
            self._clear_locked()
            generation = self._generation
        previous_closed = False
        try:
            self._close_previous()
            previous_closed = True
            yield generation
        except BaseException:
            self.forget()
            if previous_closed:
                self._close_previous()  # Images/partial wallet files are never removed.
            raise

    def _publish_pending(self, pending, generation, records):
        with self._lock:
            self._records = records
            if generation != self._generation:
                pending.clear_secret()
                return False
            self._pending = pending
            self._backup = None
            self._arm_locked()
            return True

    def create(self, password, emit=None):
        with self._operation(), self._opening() as generation:
            self._emit(emit, "Готовлю зашифрованное хранилище…", 10)
            root = self._vault.create(password)
            with self._lock:
                self._workspace_root = root
            self._emit(emit, "Проверяю шифрование и официальный Monero RPC…", 45)
            engine = self._prepare(root)
            self._emit(emit, "Создаю кошелёк внутри зашифрованного хранилища…", 70)
            pending = engine.create_wallet(password)
            try:
                records = self._records_checked(engine.list_wallets())
                retained = self._publish_pending(pending, generation, records)
                with self._lock:
                    self._message = "Кошелёк создан. Отдельно сохраните 25 слов и подтвердите резервную копию."
                self._emit(emit, "Кошелёк создан. Можно открыть резервную фразу на 180 секунд.", 100)
                return {"wallet": asdict(pending.wallet), "vault_id": self._vault.active_id, "pending_seed": retained}
            except BaseException:
                pending.clear_secret()
                raise

    def unlock(self, vault_id, password, emit=None):
        if vault_id == "system":
            raise WalletError("Прежнее общее хранилище сохранено без изменений. Используйте отдельное хранилище выбранного кошелька.")
        if not isinstance(vault_id, str) or not _VAULT_ID.fullmatch(vault_id):
            raise WalletError("Неизвестное личное хранилище.")
        with self._operation(), self._opening():
            self._emit(emit, "Открываю выбранное зашифрованное хранилище…", 15)
            root = self._vault.unlock(vault_id, password)
            with self._lock:
                self._workspace_root = root
            self._emit(emit, "Проверяю шифрование и официальный Monero RPC…", 50)
            engine = self._prepare(root)
            records = self._records_checked(engine.list_wallets())
            # Every supported platform has exactly one wallet per vault ID.
            engine.open_wallet(records[0].wallet_id, password)
            with self._lock:
                self._records = records
                self._message = "Зашифрованное хранилище открыто. Резервная фраза скрыта."
            self._emit(emit, "Кошелёк открыт. Резервная фраза скрыта.", 100)
            return {"wallets": [asdict(record) for record in records], "vault_id": self._vault.active_id}

    def reveal(self, wallet_id, password, emit=None):
        _wallet_id(wallet_id)
        with self._operation():
            with self._lock:
                self._clear_locked()
                generation, engine, records = self._generation, self._engine, self._records
            if engine is None or not any(record.wallet_id == wallet_id for record in records):
                raise WalletError("Сначала откройте своё зашифрованное хранилище.")
            self._emit(emit, "Проверяю пароль выбранного кошелька…", 25)
            pending = engine.reveal_seed(wallet_id, password)
            retained = self._publish_pending(pending, generation, records)
            self._emit(emit, "Резервная фраза готова к отдельному показу на 180 секунд.", 100)
            return {"wallet_id": wallet_id, "pending_seed": retained}

    def take_seed(self):
        with self._lock:
            self._expire_locked()
            if self._pending is None:
                raise WalletError("Резервная фраза скрыта или истёк срок показа. Введите пароль снова.")
            words = self._pending.mnemonic.split()
            if len(words) != 25 or any(not _WORD.fullmatch(word) for word in words):
                self._clear_locked()
                raise WalletError("Неизвестный формат резервной фразы.")
            wallet_id = self._pending.wallet.wallet_id
            positions = tuple(sorted(secrets.SystemRandom().sample(range(1, 26), 3)))
            challenge = secrets.token_urlsafe(32)
            self._backup = _Backup(wallet_id, challenge, positions, tuple(words[index - 1] for index in positions))
            self._pending.clear_secret()
            self._pending = None
            self._arm_locked()
            return {"wallet_id": wallet_id, "words": words, "challenge": challenge, "positions": list(positions)}

    def confirm_backup(self, wallet_id, challenge, answers):
        _wallet_id(wallet_id)
        if (not isinstance(challenge, str) or not _CHALLENGE.fullmatch(challenge)
                or not isinstance(answers, list) or len(answers) != 3
                or any(not isinstance(word, str) or len(word) > 64 for word in answers)):
            raise WalletError("Введите три проверочных слова из своей резервной копии.")
        normalized = [word.strip().lower() for word in answers]
        with self._operation():
            with self._lock:
                self._expire_locked()
                backup, engine = self._backup, self._engine
                if backup is None or engine is None:
                    raise WalletError("Проверка резервной копии истекла. Откройте фразу после ввода пароля снова.")
                matches = [secrets.compare_digest(expected, supplied if supplied.isascii() else "\0")
                           for expected, supplied in zip(backup.expected, normalized)]
                same_token = secrets.compare_digest(backup.token, challenge)
                same_wallet = secrets.compare_digest(backup.wallet_id, wallet_id)
                if not all(matches) or not same_token or not same_wallet:
                    raise WalletError("Проверочные слова не совпали. Используйте отдельно сохранённую резервную копию.")
                self._clear_locked()
            record = engine.confirm_backup(wallet_id)
            with self._lock:
                self._records = tuple(record if old.wallet_id == wallet_id else old for old in self._records)
                self._message = "Резервная копия подтверждена. Храните её отдельно от приложения и пароля."
            return {"wallet": asdict(record)}

    def close(self):
        # Invalidate a late create/reveal before trying the operation lock.
        self.forget()
        with self._operation():
            self._close_previous()  # Failure keeps owned mount and workspace for recovery.
            with self._lock:
                self._message = "Сеанс кошелька закрыт. Резервная фраза скрыта."
