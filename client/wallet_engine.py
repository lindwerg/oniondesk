"""Local, offline Monero creation through the separately verified official RPC.

This module has no daemon, synchronization, import or payment interface. The
caller supplies a binary path and SHA-256 from the authenticated release catalog,
never a path or a hash received from the browser. POSIX permissions and Windows
private ACL readback are enforced before wallet files or RPC secrets are used.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import requests
from requests.auth import HTTPDigestAuth
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool


class WalletError(RuntimeError):
    """Safe error for the UI; never includes RPC bodies or exception messages."""


class Network(str, Enum):
    MAINNET = "mainnet"
    STAGENET = "stagenet"


@dataclass(frozen=True)
class WalletRecord:
    wallet_id: str
    network: str
    address: str
    backup_confirmed: bool = False
    seed_format: str = "Monero CLI: 25 English words"


@dataclass
class PendingWallet:
    wallet: WalletRecord
    mnemonic: str = field(repr=False)

    def clear_secret(self):
        # Releases this reference. Python cannot guarantee wiping all copies/RAM.
        self.mnemonic = ""


_ID = re.compile(r"wallet_[0-9a-f]{32}\Z")
_ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]{95}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_METHODS = frozenset({"get_version", "create_wallet", "get_address", "query_key",
                      "open_wallet", "close_wallet"})


def _connection_owned(pid, server_port, client_port):
    """Check the connected server socket, not just the reusable listening port."""
    try:
        if os.name == "nt":
            return _windows_connection_owned(pid, server_port, client_port)
        if sys.platform == "darwin":
            result = subprocess.run(["/usr/sbin/lsof", "-n", "-P", "-a", "-p", str(pid),
                                     f"-iTCP@127.0.0.1:{server_port}", "-sTCP:ESTABLISHED", "-Fpn"],
                                    capture_output=True, timeout=2, check=False)
            fields = result.stdout.decode("ascii", "replace").splitlines()
            return (result.returncode == 0 and f"p{pid}" in fields
                    and f"n127.0.0.1:{server_port}->127.0.0.1:{client_port}" in fields)
        if sys.platform.startswith("linux"):
            address = f"{int.from_bytes(socket.inet_aton('127.0.0.1'), sys.byteorder):08X}"
            server, client = f"{address}:{server_port:04X}", f"{address}:{client_port:04X}"
            inodes = set()
            with (Path("/proc") / str(pid) / "net" / "tcp").open() as table:
                for index, line in enumerate(table):
                    if index > 65_536:
                        return False
                    row = line.split()
                    if len(row) >= 10 and row[1] == server and row[2] == client and row[3] == "01":
                        inodes.add(f"socket:[{row[9]}]")
            for fd in (Path("/proc") / str(pid) / "fd").iterdir():
                try:
                    if os.readlink(fd) in inodes:
                        return True
                except OSError:
                    continue
    except (OSError, subprocess.TimeoutExpired):
        return False
    return False


def _windows_connection_owned(pid, server_port, client_port):
    import ctypes
    from ctypes import wintypes as wt
    import struct
    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                                       wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG]
    api.GetExtendedTcpTable.restype = wt.DWORD
    size = wt.DWORD()
    # TCP_TABLE_OWNER_PID_ALL = 5; inspect the established server side tuple.
    if api.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 5, 0) != 122:
        return False
    for _ in range(3):
        if not 4 <= size.value <= 16 * 1024**2:
            return False
        table = ctypes.create_string_buffer(size.value)
        status = api.GetExtendedTcpTable(table, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if status == 122:
            continue
        if status:
            return False
        count = struct.unpack_from("<I", table)[0]
        if count > (size.value - 4) // 24:
            return False
        loopback = int.from_bytes(socket.inet_aton("127.0.0.1"), "little")
        for index in range(count):
            state, local, local_port, remote, remote_port, owner = struct.unpack_from("<6I", table, 4 + index * 24)
            if (state == 5 and owner == pid and local == remote == loopback
                    and socket.ntohs(local_port & 0xffff) == server_port
                    and socket.ntohs(remote_port & 0xffff) == client_port):
                return True
        return False
    return False


def _windows_user_sid():
    import ctypes
    from ctypes import wintypes as wt
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    kernel.GetCurrentProcess.restype = wt.HANDLE
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    api.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    api.OpenProcessToken.restype = wt.BOOL
    api.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, pointer, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    api.GetTokenInformation.restype = wt.BOOL
    api.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wt.LPWSTR)]
    api.ConvertSidToStringSidW.restype = wt.BOOL
    token, size = wt.HANDLE(), wt.DWORD()
    if not api.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        raise WalletError("Не удалось определить текущего пользователя Windows.")
    try:
        api.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        if not 8 <= size.value <= 65_536:
            raise WalletError("Не удалось прочитать текущего пользователя Windows.")
        value = ctypes.create_string_buffer(size.value)
        if not api.GetTokenInformation(token, 1, value, size, ctypes.byref(size)):
            raise WalletError("Не удалось прочитать текущего пользователя Windows.")
        sid = ctypes.cast(value, ctypes.POINTER(pointer))[0]
        text = wt.LPWSTR()
        if not api.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise WalletError("Не удалось проверить пользователя Windows.")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, pointer))
    finally:
        kernel.CloseHandle(token)


def _windows_private_acl(path, *, protected_directory=False):
    import ctypes
    from ctypes import wintypes as wt
    import usb_tails as usb
    try:
        for ancestor in (path, *path.parents):
            if usb._windows_attributes(ancestor) & 0x400:
                raise WalletError("Папка кошельков содержит перенаправление Windows.")
        user = _windows_user_sid()
        owner, aces = usb._windows_security(path)
        if not _windows_acl_private(owner, aces, user):
            raise WalletError("Windows не подтвердила личные права доступа к кошельку.")
        if protected_directory:
            api = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            pointer = ctypes.c_void_p
            api.GetNamedSecurityInfoW.argtypes = [wt.LPWSTR, ctypes.c_int, wt.DWORD,
                    pointer, pointer, pointer, pointer, ctypes.POINTER(pointer)]
            api.GetNamedSecurityInfoW.restype = wt.DWORD
            api.GetSecurityDescriptorControl.argtypes = [pointer, ctypes.POINTER(wt.WORD), ctypes.POINTER(wt.DWORD)]
            api.GetSecurityDescriptorControl.restype = wt.BOOL
            kernel.LocalFree.argtypes = [pointer]
            kernel.LocalFree.restype = pointer
            descriptor, control, revision = pointer(), wt.WORD(), wt.DWORD()
            result = api.GetNamedSecurityInfoW(str(path), 1, 0x4, None, None, None, None, ctypes.byref(descriptor))
            try:
                if (result or not descriptor or not api.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
                        or not control.value & 0x1000):
                    raise WalletError("Папка кошельков должна иметь отдельные защищённые права Windows.")
            finally:
                if descriptor:
                    kernel.LocalFree(descriptor)
    except (OSError, usb.USBError):
        raise WalletError("Windows не смогла проверить приватность папки кошельков.") from None


def _windows_acl_private(owner, aces, user):
    # CPython 3.13's 0700 DACL grants SYSTEM, Administrators and Owner Rights.
    # Read access matters too. Unfamiliar/callback or other inherited grants fail.
    trusted = {user, "S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
    return (owner == user and bool(aces) and not any(kind not in (0, 1) or
            (kind == 0 and mask and sid not in trusted) for kind, flags, mask, sid in aces))


def _assert_owned_socket(process, sock, server_port):
    """No HTTP bytes are sent until this exact connected peer is attributed."""
    try:
        peer, local = sock.getpeername(), sock.getsockname()
        if peer != ("127.0.0.1", server_port) or local[0] != "127.0.0.1":
            raise WalletError("Локальное соединение Monero перенаправлено.")
        deadline = time.monotonic() + 1
        while process.poll() is None:
            if _connection_owned(process.pid, server_port, local[1]):
                if process.poll() is None:
                    return
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.025)
    except OSError:
        pass
    raise WalletError("Не удалось подтвердить принадлежность локального соединения Monero.")


def _owned_adapter(process, server_port):
    # Adapter subclassing is a requests extension point. Each newly connected
    # socket (including Digest's 401 retry) is checked before headers/body.
    class OwnedConnection(HTTPConnection):
        def connect(self):
            super().connect()
            try:
                _assert_owned_socket(process, self.sock, server_port)
            except BaseException:
                self.close()
                raise

    class OwnedPool(HTTPConnectionPool):
        ConnectionCls = OwnedConnection

    class OwnedAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            super().init_poolmanager(*args, **kwargs)
            # Never mutate urllib3's global pool class table.
            self.poolmanager.pool_classes_by_scheme = dict(self.poolmanager.pool_classes_by_scheme)
            self.poolmanager.pool_classes_by_scheme["http"] = OwnedPool

    return OwnedAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)


def default_wallet_root() -> Path:
    if os.name == "nt":
        return _windows_local_appdata() / "OnionDesk" / "wallets"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "OnionDesk" / "wallets"
    base = os.environ.get("XDG_DATA_HOME", "")
    directory = Path(base) if base and Path(base).is_absolute() else Path.home() / ".local" / "share"
    return directory / "oniondesk" / "wallets"


def _windows_local_appdata():
    import ctypes
    from ctypes import wintypes as wt
    import uuid
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wt.DWORD, wt.HANDLE, ctypes.POINTER(wt.LPWSTR)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole.CoTaskMemFree.restype = None
    identifier = ctypes.create_string_buffer(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le, 16)
    value = wt.LPWSTR()
    result = shell.SHGetKnownFolderPath(identifier, 0, None, ctypes.byref(value))
    try:
        if result or not value.value or value.value.startswith("\\\\"):
            raise WalletError("Windows не нашла локальную личную папку приложения.")
        return Path(value.value)
    finally:
        if value:
            ole.CoTaskMemFree(ctypes.cast(value, ctypes.c_void_p))


def _private_directory(path: Path):
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            raise WalletError("Папка кошельков не может быть перенаправлением.")
        if os.name == "nt":
            _windows_private_acl(path, protected_directory=True)
        elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise WalletError("Папка кошельков должна принадлежать вам и иметь права 0700.")
    except OSError:
        raise WalletError("Не удалось открыть личную папку кошельков.") from None


def _private_file(path: Path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
            raise WalletError("Небезопасные права файла кошелька; операция остановлена.")
        if os.name == "nt":
            _windows_private_acl(path)
        elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise WalletError("Небезопасные права файла кошелька; операция остановлена.")
    except OSError:
        raise WalletError("Не удалось открыть локальный файл кошелька.") from None


def _validate_address(address, network: Network) -> str:
    prefix = "4" if network is Network.MAINNET else "5"
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address) or not address.startswith(prefix):
        raise WalletError("RPC вернул адрес другой сети или неверного формата.")
    return address


class OfflineWalletEngine:
    """The UI calls create/open/confirm/list; every RPC process is short lived."""

    def __init__(self, binary_path: Path, expected_sha256: str, *,
                 network: Network = Network.MAINNET, wallet_root: Path | None = None):
        if os.name == "nt" and sys.version_info < (3, 13):
            raise WalletError("Для защищённой папки кошельков требуется Python 3.13 или новее.")
        try:
            self.network = Network(network)
        except ValueError:
            raise WalletError("Разрешены только mainnet и stagenet.") from None
        if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
            raise WalletError("Нет проверенной контрольной суммы Monero RPC.")
        self.binary = Path(binary_path).expanduser().absolute()
        self.expected_sha256 = expected_sha256
        self.root = Path(wallet_root or default_wallet_root()).expanduser().absolute()
        self._require_encrypted_storage()
        _private_directory(self.root)
        self.directory = self.root / self.network.value
        _private_directory(self.directory)

    def _require_encrypted_storage(self):
        if self.network is Network.STAGENET:
            return  # Test-only, no value. Production UI must always use mainnet.
        try:
            from wallet_security import attest_encrypted_storage
            result = attest_encrypted_storage(self.root)
            if not isinstance(result, dict) or result.get("ok") is not True:
                message = result.get("message") if isinstance(result, dict) else None
                raise WalletError(message or "Для кошелька нужна подтверждённая шифрованная среда.")
        except WalletError:
            raise
        except Exception:
            raise WalletError("Не удалось подтвердить шифрование папки кошельков. Операция запрещена.") from None

    def _verify_binary(self):
        try:
            info = self.binary.lstat()
            if os.name == "nt":
                _private_file(self.binary)
            elif (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                  or info.st_uid not in {0, os.getuid()} or not os.access(self.binary, os.X_OK)):
                raise WalletError("Небезопасный или недоступный Monero RPC.")
            digest = hashlib.sha256()
            with self.binary.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if not secrets.compare_digest(digest.hexdigest(), self.expected_sha256):
                raise WalletError("Контрольная сумма Monero RPC не совпала. Запуск отменён.")
        except OSError:
            raise WalletError("Проверенный Monero RPC не найден.") from None

    @staticmethod
    def _password(password: str):
        if not isinstance(password, str) or not 12 <= len(password) <= 1024 or "\0" in password:
            raise WalletError("Пароль кошелька должен содержать от 12 до 1024 символов.")

    @staticmethod
    def _wallet_id(wallet_id: str) -> str:
        if not isinstance(wallet_id, str) or not _ID.fullmatch(wallet_id):
            raise WalletError("Неизвестный локальный кошелёк.")
        return wallet_id

    @contextmanager
    def _locked(self):
        self._require_encrypted_storage()
        _private_directory(self.root)
        _private_directory(self.directory)
        path = self.directory / ".engine.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            _private_file(path)
            try:
                if os.name == "nt":
                    import msvcrt
                    if not os.fstat(fd).st_size:
                        os.write(fd, b"\0")
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise WalletError("Другая операция с кошельком ещё выполняется.") from None
            yield
        finally:
            os.close(fd)

    def _files(self, wallet_id):
        return (self.directory / wallet_id, self.directory / (wallet_id + ".keys"))

    def _check_wallet_files(self, wallet_id):
        for path in self._files(wallet_id):
            _private_file(path)
        # Official Monero may also create a public address sidecar.
        sidecar = self.directory / (wallet_id + ".address.txt")
        if sidecar.exists() or sidecar.is_symlink():
            _private_file(sidecar)

    def _metadata_path(self, wallet_id):
        return self.directory / (self._wallet_id(wallet_id) + ".metadata.json")

    @staticmethod
    def _mnemonic(rpc):
        mnemonic = rpc.call("query_key", {"key_type": "mnemonic"}).get("key")
        if not isinstance(mnemonic, str) or not re.fullmatch(r"[a-z]+(?: [a-z]+){24}", mnemonic):
            raise WalletError("RPC вернул неизвестный формат резервной фразы.")
        return mnemonic

    def _read_record(self, wallet_id) -> WalletRecord:
        path = self._metadata_path(wallet_id)
        _private_file(path)
        try:
            if path.stat().st_size > 2048:
                raise ValueError
            value = json.loads(path.read_text(encoding="utf-8"))
            if (value["wallet_id"] != wallet_id or value["network"] != self.network.value
                    or type(value["backup_confirmed"]) is not bool):
                raise ValueError
            return WalletRecord(wallet_id, self.network.value,
                                _validate_address(value["address"], self.network), value["backup_confirmed"])
        except (OSError, ValueError, KeyError, TypeError):
            raise WalletError("Повреждена локальная карточка кошелька.") from None

    def _write_record(self, record: WalletRecord):
        path = self._metadata_path(record.wallet_id)
        temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(record.__dict__, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            raise WalletError("Не удалось сохранить карточку кошелька.") from None
        finally:
            temporary.unlink(missing_ok=True)

    def create_wallet(self, password: str) -> PendingWallet:
        self._password(password)
        with self._locked():
            wallet_id = "wallet_" + secrets.token_hex(16)
            # Collision or a planted file must never open/overwrite a wallet.
            if any(path.exists() or path.is_symlink() for path in self._files(wallet_id)):
                raise WalletError("Имя кошелька уже занято. Повторите операцию.")
            with _RpcProcess(self) as rpc:
                rpc.call("create_wallet", {"filename": wallet_id, "password": password, "language": "English"})
                address = _validate_address(rpc.call("get_address", {"account_index": 0, "address_index": [0]}).get("address"), self.network)
                mnemonic = self._mnemonic(rpc)
                rpc.close_wallet()
            self._check_wallet_files(wallet_id)
            record = WalletRecord(wallet_id, self.network.value, address)
            self._write_record(record)
            return PendingWallet(record, mnemonic)

    def open_wallet(self, wallet_id: str, password: str) -> WalletRecord:
        self._password(password)
        self._wallet_id(wallet_id)
        with self._locked():
            record = self._read_record(wallet_id)
            self._check_wallet_files(wallet_id)
            with _RpcProcess(self) as rpc:
                rpc.call("open_wallet", {"filename": wallet_id, "password": password})
                address = _validate_address(rpc.call("get_address", {"account_index": 0, "address_index": [0]}).get("address"), self.network)
                if address != record.address:
                    raise WalletError("Адрес не совпал с локальной карточкой кошелька.")
                rpc.close_wallet()
            self._check_wallet_files(wallet_id)
            return record

    def reveal_seed(self, wallet_id: str, password: str) -> PendingWallet:
        """Re-authenticate locally for an explicit backup screen after restart."""
        self._password(password)
        self._wallet_id(wallet_id)
        with self._locked():
            record = self._read_record(wallet_id)
            self._check_wallet_files(wallet_id)
            with _RpcProcess(self) as rpc:
                rpc.call("open_wallet", {"filename": wallet_id, "password": password})
                address = _validate_address(rpc.call("get_address", {"account_index": 0, "address_index": [0]}).get("address"), self.network)
                if address != record.address:
                    raise WalletError("Адрес не совпал с локальной карточкой кошелька.")
                mnemonic = self._mnemonic(rpc)
                rpc.close_wallet()
            self._check_wallet_files(wallet_id)
            return PendingWallet(record, mnemonic)

    def confirm_backup(self, wallet_id: str) -> WalletRecord:
        """Call only after the human explicitly confirms an independent backup."""
        with self._locked():
            current = self._read_record(self._wallet_id(wallet_id))
            self._check_wallet_files(wallet_id)
            record = WalletRecord(current.wallet_id, current.network, current.address, True)
            self._write_record(record)
            return record

    def list_wallets(self) -> list[WalletRecord]:
        with self._locked():
            return [self._read_record(path.name.removesuffix(".metadata.json"))
                    for path in sorted(self.directory.glob("wallet_*.metadata.json"))]


class _RpcProcess:
    """Owned process, authenticated loopback RPC, 90 second lifetime limit."""

    def __init__(self, engine):
        self.engine = engine
        self.process = None
        self.timer = None
        self.temporary = None
        self.session = None
        self.url = None
        self.wallet_open = False
        self.deadline = 0.0

    def __enter__(self):
        self.engine._verify_binary()
        try:
            self.temporary = Path(tempfile.mkdtemp(prefix=".rpc-", dir=self.engine.directory))
            os.chmod(self.temporary, 0o700)
            _private_directory(self.temporary)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            self.url = f"http://127.0.0.1:{port}/json_rpc"
            username, rpc_password = secrets.token_hex(16), secrets.token_hex(32)
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.auth = HTTPDigestAuth(username, rpc_password)
            config = self.temporary / "rpc.conf"
            fd = os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(f"rpc-login={username}:{rpc_password}\n")
            arguments = [str(self.engine.binary), "--config-file", str(config),
                         "--offline", "--no-initial-sync", "--rpc-bind-ip", "127.0.0.1",
                         "--rpc-bind-port", str(port), "--wallet-dir", str(self.engine.directory),
                         "--shared-ringdb-dir", str(self.temporary / "ringdb"), "--log-file", os.devnull,
                         "--log-level", "0", "--max-concurrency", "1"]
            if self.engine.network is Network.STAGENET:
                arguments.append("--stagenet")
            self.deadline = time.monotonic() + 90
            options = {"umask": 0o077, "start_new_session": True}
            environment = {"PATH": os.defpath, "HOME": str(Path.home()), "LANG": "C"}
            if os.name == "nt":
                options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
                system = os.environ.get("SystemRoot", r"C:\Windows")
                environment = {"SystemRoot": system, "PATH": str(Path(system) / "System32"),
                               "USERPROFILE": str(Path.home()), "TEMP": str(self.temporary), "TMP": str(self.temporary)}
            self.process = subprocess.Popen(arguments, cwd=self.temporary,
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL, close_fds=True,
                                            env=environment, **options)
            self.session.mount("http://", _owned_adapter(self.process, port))
            self.timer = threading.Timer(90, self._stop)
            self.timer.daemon = True
            self.timer.start()
            start_deadline = time.monotonic() + 15
            while True:
                try:
                    self.call("get_version", {}, timeout=0.5)
                    break
                except WalletError:
                    if self.process.poll() is not None or time.monotonic() >= start_deadline:
                        raise WalletError("Локальный Monero RPC не запустился.") from None
                    time.sleep(0.05)
            config.unlink()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def call(self, method, params, *, timeout=15):
        if method not in _METHODS or (method == "query_key" and params != {"key_type": "mnemonic"}):
            raise WalletError("Эта операция RPC запрещена.")
        if self.process is None or self.process.poll() is not None or time.monotonic() >= self.deadline:
            raise WalletError("Локальная сессия кошелька завершена.")
        body = json.dumps({"jsonrpc": "2.0", "id": "oniondesk", "method": method, "params": params}).encode()
        try:
            with self.session.post(self.url, data=body, headers={"Content-Type": "application/json"},
                                   timeout=min(timeout, self.deadline - time.monotonic()),
                                   allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise WalletError("Локальный Monero RPC отклонил подключение.")
                payload = response.raw.read(65_537)
                if len(payload) > 65_536:
                    raise ValueError
                result = json.loads(payload)
            if not isinstance(result, dict):
                raise ValueError
            if "error" in result:
                raise WalletError("Monero RPC отклонил операцию. Проверьте пароль и состояние кошелька.")
            if not isinstance(result.get("result"), dict):
                raise ValueError
            if method in {"create_wallet", "open_wallet"}:
                self.wallet_open = True
            return result["result"]
        except WalletError:
            raise
        except (OSError, requests.RequestException, ValueError, TypeError):
            raise WalletError("Нет корректного ответа от локального Monero RPC.") from None

    def close_wallet(self):
        if self.wallet_open:
            self.call("close_wallet", {"autosave_current": True})
            self.wallet_open = False

    def _stop(self):
        process = self.process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            except ProcessLookupError:
                pass

    def __exit__(self, *exception):
        try:
            if self.wallet_open:
                try:
                    self.close_wallet()
                except WalletError:
                    pass  # Original failure remains primary; the owned process is always stopped.
        finally:
            if self.timer is not None:
                self.timer.cancel()
            self._stop()
            if self.session is not None:
                self.session.close()
                self.session = None
            if self.temporary is not None:
                shutil.rmtree(self.temporary)
