"""Owned macOS encrypted image lifecycle; no disk formatting or secret files.

Only generated sparsebundles in one private application directory are accepted.
Passwords go to hdiutil's stdin as UTF-8 plus NUL. No image password is retained,
logged, passed in argv or saved to Keychain. State/listing perform no commands.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import subprocess
import sys
import threading

from wallet_engine import WalletError, _private_directory, default_wallet_root

_VAULT_ID = re.compile(r"vault_[0-9a-f]{32}\Z")
_DEVICE = re.compile(r"/dev/disk[0-9]+(?:s[0-9]+)*\Z")
_MAX_PLIST = 2 * 1024**2
_EJECT = "Хранилище уже подключено вне этого запуска. Безопасно извлеките OnionDeskWallet в Дисковой утилите и откройте его снова здесь."


@dataclass(frozen=True)
class _Mounted:
    identifier: str
    image: Path = field(repr=False)
    mountpoint: Path = field(repr=False)
    device: str
    mount_device: int


def _password_bytes(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024 or "\0" in password:
        raise WalletError("Пароль хранилища должен содержать от 12 до 1024 символов.")
    try:
        return password.encode("utf-8") + b"\0"
    except UnicodeError:
        raise WalletError("Пароль содержит недопустимые символы.") from None


def _private_existing(path, *, missing=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return False
        raise WalletError("Локальное хранилище не найдено.") from None
    except OSError:
        raise WalletError("Не удалось проверить личную папку хранилищ.") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise WalletError("Папка хранилищ должна принадлежать вам и иметь права 0700.")
    return True


class MacVaultManager:
    def __init__(self, *, base=None):
        self.base = Path(base or Path.home() / "Library" / "Application Support" / "OnionDesk" / "vaults").expanduser().absolute()
        self._lock = threading.RLock()
        self._active = None
        self._uncertain = False

    @property
    def active_id(self):
        with self._lock:
            return self._active.identifier if self._active else None

    @property
    def workspace_open(self):
        with self._lock:
            return self._active is not None

    def list_vaults(self):
        if not _private_existing(self.base, missing=True):
            return []
        found = []
        try:
            with os.scandir(self.base) as entries:
                for index, entry in enumerate(entries):
                    if index >= 1024:
                        raise WalletError("Слишком много файлов в папке хранилищ.")
                    identifier = entry.name.removesuffix(".sparsebundle")
                    if (entry.name.endswith(".sparsebundle") and _VAULT_ID.fullmatch(identifier)
                            and entry.is_dir(follow_symlinks=False)):
                        found.append({"id": identifier, "label": "Кошелёк " + identifier[-6:]})
            return sorted(found, key=lambda value: value["id"])
        except OSError:
            raise WalletError("Не удалось прочитать список личных хранилищ.") from None

    @contextmanager
    def _serialized(self):
        import fcntl
        try:
            self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
            _private_existing(self.base)
            path = self.base / ".vault.lock"
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError:
            raise WalletError("Не удалось открыть личную папку хранилищ.") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise WalletError("Небезопасные права файла блокировки хранилищ.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WalletError("Другая операция с хранилищем ещё выполняется.") from None
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _command(arguments, *, password=None, timeout=30):
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()),
                       "LANG": "C", "LC_ALL": "C"}
        try:
            result = subprocess.run(["/usr/bin/hdiutil", *arguments],
                                    input=_password_bytes(password) if password is not None else None,
                                    stdin=subprocess.DEVNULL if password is None else None,
                                    capture_output=True, timeout=timeout, check=False, env=environment)
            if result.returncode or not isinstance(result.stdout, bytes) or len(result.stdout) > _MAX_PLIST:
                raise WalletError("Операция с зашифрованным хранилищем не завершилась. Проверьте пароль и свободное место.")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise WalletError("macOS не завершила операцию с хранилищем. Не удаляйте его; проверьте Дисковую утилиту.") from None

    @classmethod
    def _plist(cls, arguments, **kwargs):
        try:
            result = plistlib.loads(cls._command(arguments, **kwargs))
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, plistlib.InvalidFileException, TypeError):
            raise WalletError("macOS вернула неизвестные сведения о хранилище.") from None

    def _image(self, identifier):
        if not isinstance(identifier, str) or not _VAULT_ID.fullmatch(identifier):
            raise WalletError("Неизвестное личное хранилище.")
        image = self.base / (identifier + ".sparsebundle")
        _private_existing(image)
        return image

    def _matching_images(self, image):
        info = self._plist(["info", "-plist"])
        images = info.get("images", [])
        if not isinstance(images, list) or len(images) > 1024:
            raise WalletError("Не удалось проверить подключённые хранилища.")
        return [item for item in images if isinstance(item, dict) and item.get("image-path") == str(image)]

    def _validate_mount(self, identifier, image, mountpoint, attachment):
        rows = attachment.get("system-entities", [])
        if not isinstance(rows, list):
            raise WalletError("Неизвестное подключение хранилища.")
        mounted = [row for row in rows if isinstance(row, dict) and row.get("mount-point") == str(mountpoint)]
        if len(mounted) != 1 or not isinstance(mounted[0].get("dev-entry"), str) or not _DEVICE.fullmatch(mounted[0]["dev-entry"]):
            raise WalletError("Не удалось подтвердить отдельный диск хранилища.")
        images = self._matching_images(image)
        if (len(images) != 1 or images[0].get("image-encrypted") is not True
                or images[0].get("owner-uid") != os.getuid()):
            raise WalletError("macOS не подтвердила владельца и шифрование хранилища.")
        matches = [row for row in images[0].get("system-entities", []) if isinstance(row, dict)
                   and row.get("mount-point") == str(mountpoint)
                   and row.get("dev-entry") == mounted[0]["dev-entry"]]
        if len(matches) != 1 or mountpoint.is_symlink() or not mountpoint.is_dir():
            raise WalletError("Папка подключённого хранилища не совпала с ожидаемой.")
        mounted_device = mountpoint.stat().st_dev
        if mounted_device == self.base.stat().st_dev:
            raise WalletError("Хранилище не подключено как отдельная файловая система.")
        return _Mounted(identifier, image, mountpoint, mounted[0]["dev-entry"], mounted_device)

    def _attach(self, identifier, image, password):
        if self._matching_images(image):
            raise WalletError(_EJECT)
        encrypted = self._plist(["isencrypted", "-plist", str(image)])
        if encrypted.get("encrypted") is not True:
            raise WalletError("Файл хранилища не имеет подтверждённого шифрования.")
        mounts = self.base / ".mounts"
        mounts.mkdir(mode=0o700, exist_ok=True)
        _private_existing(mounts)
        mountpoint = mounts / identifier
        if mountpoint.exists() or mountpoint.is_symlink():
            _private_existing(mountpoint)
            if os.path.ismount(mountpoint):
                raise WalletError(_EJECT)
            try:
                mountpoint.rmdir()  # Empty stale directory after a safe external eject.
            except OSError:
                raise WalletError("Папка подключения занята. Безопасно извлеките хранилище и проверьте Дисковую утилиту.") from None
        mountpoint.mkdir(mode=0o700)
        with self._lock:
            self._uncertain = True
        try:
            attachment = self._plist(["attach", "-stdinpass", "-nobrowse", "-owners", "on",
                                      "-mountpoint", str(mountpoint), "-plist", str(image)],
                                     password=password, timeout=60)
            active = self._validate_mount(identifier, image, mountpoint, attachment)
            with self._lock:
                self._active, self._uncertain = active, False
            return mountpoint / "wallets"
        except BaseException:
            # A timeout may occur after mounting. Only a proven unmounted empty
            # directory can be removed; mounted contents are never traversed.
            try:
                if not self._matching_images(image) and not os.path.ismount(mountpoint):
                    mountpoint.rmdir()
                    with self._lock:
                        self._uncertain = False
            except (OSError, WalletError):
                pass
            raise

    def create(self, password):
        _password_bytes(password)
        with self._serialized():
            with self._lock:
                if self._active or self._uncertain:
                    raise WalletError("Сначала безопасно закройте открытое хранилище.")
            identifier = "vault_" + secrets.token_hex(16)
            target = self.base / (identifier + ".sparsebundle")
            if target.exists() or target.is_symlink():
                raise WalletError("Имя хранилища уже занято. Повторите операцию.")
            temporary = self.base / (".create-" + secrets.token_hex(16))
            temporary.mkdir(mode=0o700)
            image = temporary / (identifier + ".sparsebundle")
            self._command(["create", "-size", "2g", "-type", "SPARSEBUNDLE", "-fs", "APFS",
                           "-volname", "OnionDeskWallet", "-encryption", "AES-256", "-stdinpass", str(image)],
                          password=password, timeout=120)
            if not image.is_dir() or image.is_symlink():
                raise WalletError("macOS не создала ожидаемое зашифрованное хранилище.")
            os.chmod(image, 0o700)
            encrypted = self._plist(["isencrypted", "-plist", str(image)])
            if encrypted.get("encrypted") is not True or target.exists() or target.is_symlink():
                raise WalletError("Новое хранилище не прошло проверку; оно сохранено для восстановления.")
            image.rename(target)
            temporary.rmdir()
            return self._attach(identifier, target, password)

    def unlock(self, identifier, password):
        _password_bytes(password)
        with self._serialized():
            with self._lock:
                if self._active or self._uncertain:
                    raise WalletError("Сначала безопасно закройте открытое хранилище.")
            return self._attach(identifier, self._image(identifier), password)

    def close(self):
        with self._lock:
            active, uncertain = self._active, self._uncertain
        if uncertain:
            raise WalletError("Состояние подключения неизвестно. Безопасно извлеките OnionDeskWallet в Дисковой утилите; принудительное отключение не выполняется.")
        if active is None:
            return
        with self._serialized():
            images = self._matching_images(active.image)
            if not images:
                if os.path.ismount(active.mountpoint):
                    raise WalletError("Папка хранилища занята другим диском. Отключение остановлено.")
            else:
                current = self._validate_mount(active.identifier, active.image, active.mountpoint, images[0])
                if current.device != active.device or current.mount_device != active.mount_device:
                    raise WalletError("Подключение хранилища изменилось. Безопасно извлеките его в Дисковой утилите; отключение другого диска запрещено.")
                self._command(["detach", active.device], timeout=30)
                if self._matching_images(active.image) or os.path.ismount(active.mountpoint):
                    raise WalletError("Хранилище ещё подключено. Закройте использующие его окна и повторите безопасное отключение.")
            # Only remove the known empty mount directory after detach.
            try:
                active.mountpoint.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                raise WalletError("Диск отключён, но папка подключения занята. Проверьте её перед повторным открытием.") from None
            with self._lock:
                self._active = None


class SystemVaultManager:
    """One wallet per private generated directory on existing BitLocker/LUKS."""
    def __init__(self):
        self.base = Path(default_wallet_root()).expanduser().absolute()
        self._active_id = None

    @property
    def active_id(self):
        return self._active_id

    @property
    def workspace_open(self):
        return self._active_id is not None

    def list_vaults(self):
        if not self._existing(self.base, missing=True):
            return []
        self._reject_legacy()
        found = []
        try:
            with os.scandir(self.base) as entries:
                for index, entry in enumerate(entries):
                    if index >= 1024:
                        raise WalletError("Слишком много файлов в папке кошельков.")
                    if _VAULT_ID.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                        found.append({"id": entry.name, "label": "Кошелёк " + entry.name[-6:]})
            return sorted(found, key=lambda value: value["id"])
        except OSError:
            raise WalletError("Не удалось прочитать список личных кошельков.") from None

    @staticmethod
    def _existing(path, *, missing=False):
        try:
            info = path.lstat()
        except FileNotFoundError:
            if missing:
                return False
            raise WalletError("Личный кошелёк не найден.") from None
        except OSError:
            raise WalletError("Не удалось проверить папку кошелька.") from None
        if (not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or (os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
            raise WalletError("Папка кошелька имеет небезопасный тип или права доступа.")
        return True

    def _reject_legacy(self):
        message = "Обнаружены данные прежнего общего хранилища. Они сохранены без изменений; откройте их официальным Monero Wallet перед переносом в отдельные хранилища."
        try:
            for network in ("mainnet", "stagenet"):
                path = self.base / network
                if path.is_symlink():
                    raise WalletError(message)
                if path.exists():
                    if not path.is_dir():
                        raise WalletError(message)
                    with os.scandir(path) as entries:
                        if any(entry.name != ".engine.lock" for entry in entries):
                            raise WalletError(message)
            with os.scandir(self.base) as entries:
                for index, entry in enumerate(entries):
                    if index >= 1024 or entry.name.endswith((".keys", ".metadata.json")):
                        raise WalletError(message)
        except OSError:
            raise WalletError("Не удалось безопасно проверить прежние данные кошельков.") from None

    @staticmethod
    def _attest(root):
        try:
            from wallet_security import attest_encrypted_storage
            result = attest_encrypted_storage(root)
            if (not isinstance(result, dict) or result.get("ok") is not True
                    or result.get("kind") not in {"bitlocker", "luks"}):
                raise WalletError(result.get("message", "Для кошелька нужно полное шифрование системы.") if isinstance(result, dict)
                                  else "Не удалось подтвердить шифрование системы.")
        except WalletError:
            raise
        except Exception:
            raise WalletError("Не удалось подтвердить шифрование системы. Операция запрещена.") from None

    def _ready(self, password):
        _password_bytes(password)
        if self._active_id is not None:
            raise WalletError("Сначала закройте открытый кошелёк.")

    def create(self, password):
        self._ready(password)
        self._attest(self.base)
        _private_directory(self.base)
        self._reject_legacy()
        identifier = "vault_" + secrets.token_hex(16)
        root = self.base / identifier
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            raise WalletError("Имя кошелька уже занято. Сохранённые файлы не изменялись.") from None
        except OSError:
            raise WalletError("Не удалось создать личную папку кошелька.") from None
        _private_directory(root)
        self._active_id = identifier
        return root

    def unlock(self, identifier, password):
        if identifier == "system":
            raise WalletError("Общее хранилище больше не открывается автоматически. Прежние данные сохранены без изменений.")
        if not isinstance(identifier, str) or not _VAULT_ID.fullmatch(identifier):
            raise WalletError("Неизвестное личное хранилище.")
        self._ready(password)
        self._existing(self.base)
        self._reject_legacy()
        root = self.base / identifier
        self._existing(root)
        self._attest(root)
        _private_directory(self.base)
        _private_directory(root)
        self._active_id = identifier
        return root

    def close(self):
        self._active_id = None


def default_vault_manager():
    return MacVaultManager() if sys.platform == "darwin" else SystemVaultManager()
