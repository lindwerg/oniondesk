"""Publisher-verified, offline Feather inside the current encrypted workspace.

Feather 2.8.1 has no data-dir CLI flag. Its documented portable marker controls
wallets, settings, ringdb and Tor data. Never open a host profile, supply wallet
secrets, start a bundled Tor, or fetch software in the user's runtime.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Callable, Literal, TypedDict
import zipfile

import feather_catalog as catalog
import offline_bundle as offline
import usb_tails as usb
from wallet_engine import WalletError, _private_directory, _private_file


class FeatherError(WalletError):
    pass


_LOCK_NAME = "feather-oniondesk.lock"
_LOCK_LIMIT = 4096
_LOCK_MESSAGE = "Блокировку Feather нельзя безопасно связать с завершённым собственным запуском. Файл и хранилище сохранены."


def _lock_cleanup_supported() -> bool:
    # Qt 6.9 qlockfile_unix.cpp uses flock, except on Android. A retained
    # ordinary Python FD on Windows can itself prevent Qt's normal deletion.
    return os.name == "posix" and platform.system() in {"Darwin", "Linux"}


def _flock(fd: int, *, unlock: bool = False) -> None:
    import fcntl
    operation = fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB
    fcntl.flock(fd, operation)


def _private_lock_info(info: os.stat_result, device: int) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or info.st_mode & 0o077
            or info.st_dev != device or not 0 < info.st_size <= _LOCK_LIMIT):
        raise FeatherError(_LOCK_MESSAGE)


def _lock_present(directory: Path) -> bool:
    for path in (directory, *directory.parents):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise FeatherError(_LOCK_MESSAGE)
    try:
        (directory / _LOCK_NAME).lstat()
    except FileNotFoundError:
        return False
    return True


class _LaunchLock:
    """In-memory witness for one original Popen child, never a PID adoption.

    The nonce identifies this launch, and the retained descriptors prevent
    inode reuse. Qt's lock must be observed held while that child is still
    alive. Nothing is persisted that a fresh controller could later adopt.
    """

    def __init__(self, directory: Path, directory_fd: int,
                 process: subprocess.Popen[bytes], nonce: str) -> None:
        self.directory = directory
        self.directory_fd = directory_fd
        self.directory_info = os.fstat(directory_fd)
        self.process = process
        self.pid = process.pid
        self.nonce = nonce
        self.file_fd: int | None = None
        self.payload: bytes | None = None

    def _check_directory(self) -> None:
        for path in (self.directory, *self.directory.parents):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise FeatherError(_LOCK_MESSAGE)
        current = self.directory.lstat()
        held = os.fstat(self.directory_fd)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid()
                or current.st_mode & 0o077
                or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)
                or (held.st_dev, held.st_ino) !=
                (self.directory_info.st_dev, self.directory_info.st_ino)):
            raise FeatherError(_LOCK_MESSAGE)

    def _read(self, fd: int) -> bytes:
        before = os.fstat(fd)
        _private_lock_info(before, self.directory_info.st_dev)
        os.lseek(fd, 0, os.SEEK_SET)
        payload = os.read(fd, _LOCK_LIMIT + 1)
        after = os.fstat(fd)
        if (len(payload) != before.st_size or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise FeatherError(_LOCK_MESSAGE)
        return payload

    def _same_path(self, fd: int) -> None:
        current = os.stat(_LOCK_NAME, dir_fd=self.directory_fd, follow_symlinks=False)
        held = os.fstat(fd)
        _private_lock_info(current, self.directory_info.st_dev)
        _private_lock_info(held, self.directory_info.st_dev)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise FeatherError(_LOCK_MESSAGE)

    def capture(self) -> None:
        """One bounded read; a not-yet-created lock can be retried while alive."""
        if self.file_fd is not None or self.process.poll() is not None:
            return
        self._check_directory()
        try:
            fd = os.open(_LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=self.directory_fd)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(fd)
            # Qt creates, locks, then writes the file. An empty first snapshot
            # isn't ownership evidence; later polling may observe the full blob.
            if stat.S_ISREG(info.st_mode) and info.st_size == 0:
                return
            payload = self._read(fd)
            fields = payload.splitlines()
            if (len(fields) != 5 or not payload.endswith(b"\n") or b"\0" in payload
                    or fields[0] != str(self.pid).encode("ascii") or not fields[1]):
                raise FeatherError(_LOCK_MESSAGE)
            try:
                _flock(fd)
            except OSError as error:
                if error.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
            else:
                _flock(fd, unlock=True)
                raise FeatherError(_LOCK_MESSAGE)
            self._same_path(fd)
            if self.process.poll() is not None:
                return  # Never arm from a file first observed after child exit.
            self.file_fd, self.payload = fd, payload
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)

    def remove(self, process: subprocess.Popen[bytes], nonce: str) -> None:
        """Remove only our unchanged, natively unlocked, exit-code-zero lock."""
        fd = self.file_fd
        if (process is not self.process or nonce != self.nonce or process.pid != self.pid
                or process.poll() != 0 or fd is None or self.payload is None):
            raise FeatherError(_LOCK_MESSAGE)
        self._check_directory()
        _flock(fd)
        try:
            self._same_path(fd)
            if self._read(fd) != self.payload or process.poll() != 0:
                raise FeatherError(_LOCK_MESSAGE)
            self._check_directory()
            self._same_path(fd)
            # The private directory and Qt-compatible native lock serialize
            # cooperative users. POSIX has no unlink-if-inode syscall; this
            # does not claim protection against a hostile writer of our UID.
            os.unlink(_LOCK_NAME, dir_fd=self.directory_fd)
            try:
                os.stat(_LOCK_NAME, dir_fd=self.directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise FeatherError(_LOCK_MESSAGE)
        finally:
            _flock(fd, unlock=True)

    def close(self) -> None:
        try:
            if self.file_fd is not None:
                fd, self.file_fd = self.file_fd, None
                os.close(fd)
        finally:
            if self.directory_fd >= 0:
                fd, self.directory_fd = self.directory_fd, -1
                os.close(fd)


ProgressCallback = Callable[[dict[str, object]], None]


class FeatherState(TypedDict):
    available: bool
    version: str
    checked_on: str
    prepared: bool
    running: bool
    workspace_open: bool
    network_mode: Literal["offline", "tor"]
    message: str


def _platform_key():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "macos-arm64"
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        return "windows-x64"
    if system == "Linux" and machine in {"amd64", "x86_64"}:
        return "linux-x64"
    if system == "Linux" and machine in {"arm64", "aarch64"}:
        return "linux-arm64"
    raise FeatherError("В комплекте нет официальной сборки Feather для этой системы.")


def status() -> FeatherState:
    """Presence only. Polling never writes, verifies, probes encryption or runs GPG."""
    try:
        record = catalog.PLATFORMS[_platform_key()]
        root = offline._find_root()
        available = root is not None and all((root / row["path"]).is_file() for row in
                                             (record, record["signature"], catalog.KEY, catalog.HASHES))
        message = ("Официальный Feather есть в комплекте; версия проверена на дату сборки."
                   if available else "Файлы Feather отсутствуют. Распакуйте полный комплект заново.")
    except (OSError, FeatherError):
        available, message = False, "В комплекте нет официальной сборки Feather для этой системы."
    return {"available": available, "version": catalog.VERSION, "checked_on": catalog.CHECKED_ON,
            "prepared": False, "running": False, "workspace_open": False,
            "network_mode": "offline", "message": message}


def assert_workspace_idle(root: Path) -> None:
    """Read-only guard for cached sessions, including a fresh Python controller.

    A marker belongs to its encrypted workspace, not to this Python process.
    Inspect every cached version before a detach or successful stop ACK; never
    remove markers, adopt processes, or resolve redirected ancestors away.
    """
    message = "В хранилище найден незавершённый сеанс Feather. Закройте Feather штатно; блокировка, данные и чужие процессы сохранены."
    base = Path(root).absolute() / "feather"

    def present_directory(path: Path) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or (os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
            raise FeatherError(message)
        return True

    try:
        # Existing roots/ancestors must not redirect a read outside the vault.
        for ancestor in (base, *base.parents):
            try:
                info = ancestor.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise FeatherError(message)
        if not present_directory(base):
            return
        with os.scandir(base) as entries:
            for count, entry in enumerate(entries):
                if count >= 128:
                    raise FeatherError(message)
                folder = base / entry.name
                if not present_directory(folder):
                    raise FeatherError(message)
                temporary = folder / "tmp"
                if not present_directory(temporary):
                    continue
                # lstat also detects broken links and special files. No PID
                # read/lookup, deletion, or process signal is authorized here.
                try:
                    (temporary / "feather-oniondesk.lock").lstat()
                except FileNotFoundError:
                    continue
                raise FeatherError(message)
    except OSError:
        raise FeatherError("Не удалось проверить незавершённые сеансы Feather. Хранилище сохранено и не отключается.") from None


def _safe_directory(path):
    # Do not resolve first: that would erase evidence of redirected ancestors.
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise FeatherError("Папка Feather содержит перенаправление. Запуск остановлен.")
    _private_directory(path)
    return path


def _copy_asset(root, record, target):
    digest, copied = hashlib.sha256(), 0
    try:
        with offline._open_regular(root, record["path"], record["size_bytes"]) as source:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(chunk)
                    if copied > record["size_bytes"]:
                        raise FeatherError("Размер файла Feather изменился во время проверки.")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        if copied != record["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), record["sha256"]):
            raise FeatherError("Контрольная сумма Feather не совпала. Запуск запрещён.")
    except (OSError, offline.OfflineError):
        raise FeatherError("Файлы Feather повреждены или недоступны. Распакуйте полный комплект заново.") from None


def _valid_signature(output):
    rows = [line.split()[1:] for line in output.splitlines() if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"}
    valid = [row[1:] for row in rows if row and row[0] == "VALIDSIG"]
    return (not any(row and row[0] in rejected for row in rows)
            and any(row and row[0] == "GOODSIG" for row in rows)
            and len(valid) == 1 and len(valid[0]) >= 10
            and valid[0][9] == catalog.PUBLISHER_FINGERPRINT and valid[0][7] in {"8", "9", "10", "11"})


def _verify_publisher(binary, signature, key, hashes, record):
    # GnuPG opens a UNIX socket while importing even with --no-autostart.
    # Encrypted mount paths can exceed its limit; this short, private home
    # contains public publisher metadata only, never wallet/profile material.
    short = None if os.name == "nt" else ("/private/tmp" if platform.system() == "Darwin" else "/tmp")
    with tempfile.TemporaryDirectory(prefix="feather-gpg-", dir=short) as temporary:
        _verify_publisher_home(binary, signature, key, hashes, record, Path(temporary))


def _verify_publisher_home(binary, signature, key, hashes, record, home):
    gpg = usb._find_gpg()
    if not gpg:
        raise FeatherError("Нет GnuPG для проверки подписи Feather. Нужен полный комплект.")
    os.chmod(home, 0o700)
    command = [gpg, "--no-options", "--homedir", str(home), "--batch", "--no-tty", "--no-autostart",
               "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                   "TMPDIR": str(home), "TMP": str(home), "TEMP": str(home),
                   "LANG": "C", "LC_ALL": "C"}
    for name in ("SYSTEMROOT", "WINDIR"):
        if os.environ.get(name):
            environment[name] = os.environ[name]

    def execute(arguments):
        try:
            return subprocess.run(command + arguments, stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=45, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise FeatherError("Не удалось проверить подпись Feather. Запуск запрещён.") from None

    shown = execute(["--with-colons", "--import-options", "show-only", "--import", str(key)])
    primary, waiting = [], False
    for line in shown.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            waiting = True
        elif fields[0] == "fpr" and waiting and len(fields) > 9:
            primary.append(fields[9])
            waiting = False
    if shown.returncode or primary != [catalog.PUBLISHER_FINGERPRINT]:
        raise FeatherError("Ключ Feather не совпал с официальным закреплённым отпечатком.")
    if execute(["--import", str(key)]).returncode:
        raise FeatherError("Не удалось прочитать ключ Feather.")
    for arguments in (["--verify", str(signature), str(binary)], ["--verify", str(hashes)]):
        checked = execute(["--status-fd", "1", *arguments])
        if checked.returncode or not _valid_signature(checked.stdout.decode("utf-8", "replace")):
            raise FeatherError("Подпись Feather не прошла проверку. Запуск запрещён.")
    expected = f"{record['sha256']}  {PurePosixPath(record['path']).name}"
    if hashes.read_text(encoding="ascii").splitlines().count(expected) != 1:
        raise FeatherError("Подписанный список не содержит ожидаемый файл Feather.")


def _write_member(source, member, target):
    _safe_directory(target.parent)
    digest, copied = hashlib.sha256(), 0
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            copied += len(chunk)
            if copied > member["size_bytes"]:
                raise FeatherError("Размер программы Feather превышен.")
            digest.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if copied != member["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), member["sha256"]):
        raise FeatherError("Контрольная сумма программы Feather не совпала.")
    os.chmod(target, 0o700 if member["executable"] else 0o600)


def _extract(binary, record, target):
    """Materialize only compiled regular members, never archive links or paths."""
    if binary.suffix != ".zip":
        with binary.open("rb") as source:
            _write_member(source, record["members"][record["binary"]], target / record["binary"])
        return
    try:
        with zipfile.ZipFile(binary) as archive:
            items = archive.infolist()
            if len(items) > 64 or sum(item.file_size for item in items) > 256 * 1024**2:
                raise FeatherError("Архив Feather превышает разрешённые пределы.")
            files = [item for item in items if not item.is_dir()]
            if len(files) != len(record["members"]) or {item.filename for item in files} != set(record["members"]):
                raise FeatherError("Неожиданная структура архива Feather.")
            for item in files:
                path = offline._relative_path(item.filename)
                member = record["members"][item.filename]
                if stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG) or item.file_size != member["size_bytes"]:
                    raise FeatherError("Недопустимый тип или размер программы Feather.")
                with archive.open(item) as source:
                    _write_member(source, member, target.joinpath(*path.parts))
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, FeatherError):
            raise
        raise FeatherError("Не удалось безопасно прочитать архив Feather.") from None


def _verify_install(folder, record, key):
    try:
        return _verify_install_checked(folder, record, key)
    except (OSError, offline.OfflineError):
        raise FeatherError("Установленные файлы Feather повреждены или перенаправлены. Запуск запрещён.") from None


def _verify_install_checked(folder, record, key):
    _check_tree(folder)
    # Code directories are immutable even though the adjacent profile is not.
    allowed = set(record["members"]) | {".portable"}
    for entry in folder.rglob("*"):
        relative = entry.relative_to(folder)
        if relative.parts[0] in {"feather_data", "home", "tmp"}:
            continue
        if entry.is_file() and relative.as_posix() not in allowed:
            raise FeatherError("В папке программы Feather обнаружен посторонний файл.")
    for name, member in record["members"].items():
        path = folder.joinpath(*offline._relative_path(name).parts)
        _private_file(path)
        with offline._open_regular(folder, name, member["size_bytes"]) as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if not secrets.compare_digest(digest, member["sha256"]):
            raise FeatherError("Установленный Feather изменён. Запуск запрещён.")
    binary = folder / record["binary"]
    with binary.open("rb") as source:
        header = source.read(4096)
    if key == "macos-arm64":
        valid = header[:4] == b"\xcf\xfa\xed\xfe" and int.from_bytes(header[4:8], "little") == 0x100000c
    elif key == "windows-x64":
        offset = int.from_bytes(header[60:64], "little")
        valid = header[:2] == b"MZ" and header[offset:offset + 6] == b"PE\0\0\x64\x86"
    else:
        valid = (header[:6] == b"\x7fELF\x02\x01" and
                 int.from_bytes(header[18:20], "little") == (183 if key == "linux-arm64" else 62))
    if not valid:
        raise FeatherError("Архитектура Feather не соответствует этой системе.")
    return binary


def _check_tree(folder):
    count = 0
    for current, directories, files in os.walk(folder, followlinks=False):
        for name in directories + files:
            count += 1
            path = Path(current) / name
            info = path.lstat()
            if (count > 16384 or len(path.relative_to(folder).parts) > 24
                    or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise FeatherError("Папка Feather содержит небезопасные или неожиданные файлы.")


def _environment(home, temporary):
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                   "USER": "oniondesk", "LOGNAME": "oniondesk", "USERNAME": "oniondesk",
                   "TMPDIR": str(temporary), "TMP": str(temporary), "TEMP": str(temporary),
                   "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
                   "XDG_DATA_HOME": str(home / "data"), "XDG_RUNTIME_DIR": str(temporary),
                   "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}
    # GUI transport variables carry no wallet material and are needed on Linux.
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "SYSTEMROOT", "WINDIR"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    if os.name == "nt":
        environment.update({"USERPROFILE": str(home), "LOCALAPPDATA": str(home / "local"),
                            "APPDATA": str(home / "config")})
    return environment


class FeatherSession:
    """WalletController serializes this session with create/unlock/lock operations."""
    def __init__(self) -> None:
        self._folder: Path | None = None
        self._root: Path | None = None
        self._record: catalog.ReleaseRecord | None = None
        self._key: str | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._launch_nonce: str | None = None
        self._lock_watch: _LaunchLock | None = None
        self._lock_capture_failed = False
        self._witness_lock = threading.RLock()
        self._network_mode: Literal["offline", "tor"] = "offline"

    def state(self) -> FeatherState:
        self._capture_lock()
        result = status()
        result["prepared"] = self._folder is not None
        result["running"] = self._process is not None and self._process.poll() is None
        result["network_mode"] = self._network_mode
        if self._lock_capture_failed:
            result["message"] = _LOCK_MESSAGE
        return result

    def _capture_lock(self) -> None:
        with self._witness_lock:
            self._capture_lock_locked()

    def _capture_lock_locked(self) -> None:
        watch = self._lock_watch
        if watch is None or self._lock_capture_failed:
            return
        try:
            watch.capture()
        except (OSError, FeatherError):
            # Polling must remain usable, but an unsuccessful witness is never
            # reusable. Surface the failure in state and refuse later cleanup.
            watch.close()
            self._lock_watch = None
            self._lock_capture_failed = True

    def _release_lock_watch(self) -> None:
        with self._witness_lock:
            if self._lock_watch is not None:
                self._lock_watch.close()
                self._lock_watch = None
            self._launch_nonce = None
            self._lock_capture_failed = False

    @staticmethod
    def _emit(emit, message, percent):
        if emit:
            emit({"stage": "feather", "message": message, "percent": percent})

    def prepare(self, root: Path, emit: ProgressCallback | None = None) -> None:
        if self._process is not None:
            self.stop()  # Do not replace unresolved evidence with another root.
        key = _platform_key()
        record = catalog.PLATFORMS[key]
        source = offline._find_root()
        if source is None:
            raise FeatherError("Нет файлов Feather. Распакуйте полный комплект заново.")
        root = _safe_directory(root)
        base = _safe_directory(root / "feather")
        folder = base / (catalog.VERSION + "-" + key)
        self._emit(emit, "Проверяю официальный Feather из комплекта…", 10)
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=base) as temporary:
            work = Path(temporary)
            files = {}
            for name, item in (("binary", record), ("signature", record["signature"]),
                               ("key", catalog.KEY), ("hashes", catalog.HASHES)):
                files[name] = work / PurePosixPath(item["path"]).name
                _copy_asset(source, item, files[name])
            self._emit(emit, "Проверяю подпись издателя и закреплённый ключ Feather…", 40)
            _verify_publisher(files["binary"], files["signature"], files["key"], files["hashes"], record)
            if folder.exists() or folder.is_symlink():
                _safe_directory(folder)
            else:
                needed = sum(row["size_bytes"] for row in record["members"].values()) + 8 * 1024**2
                if shutil.disk_usage(base).free < needed:
                    raise FeatherError("В зашифрованном хранилище недостаточно места для Feather. Файлы сохранены.")
                prepared = _safe_directory(work / "program")
                _extract(files["binary"], record, prepared)
                _verify_install(prepared, record, key)
                os.rename(prepared, folder)
            _verify_install(folder, record, key)
        self._root, self._folder, self._record, self._key = root, folder, record, key
        self._emit(emit, "Подпись и файлы Feather проверены. Можно открыть автономное окно.", 100)

    def launch(self, root: Path, emit: ProgressCallback | None = None) -> None:
        self._launch(root, emit)

    def connect(self, root: Path, emit: ProgressCallback | None = None) -> None:
        if self._process is not None:
            self.stop()
        if self._folder is None or self._root != Path(root).absolute():
            raise FeatherError("Сначала подготовьте Feather в открытом зашифрованном хранилище.")
        # Reuse the launcher's TLS-verified Tor route check. Never accept a
        # proxy URL/port from the browser or inherit host proxy variables.
        import launcher
        self._emit(emit, "Проверяю подключение Tor Browser через защищённый маршрут…", 20)
        port = launcher.find_tor_proxy()
        if type(port) is not int or port not in {9050, 9150}:
            raise FeatherError("Маршрут Tor не прошёл проверку. Прямого подключения не будет.")
        self._launch(root, emit, verified_tor_port=port)

    def _launch(self, root: Path, emit: ProgressCallback | None = None, *,
                verified_tor_port: int | None = None) -> None:
        if self._process is not None:
            self.stop()
        if self._root != Path(root).absolute() or self._folder is None:
            raise FeatherError("Сначала подготовьте Feather в открытом зашифрованном хранилище.")
        folder = _safe_directory(self._folder)
        binary = _verify_install(folder, self._record, self._key)
        # Every mutable path stays on the attested encrypted filesystem.
        data = _safe_directory(folder / "feather_data")
        home = _safe_directory(folder / "home")
        temporary = _safe_directory(folder / "tmp")
        if _lock_present(temporary):
            raise FeatherError("В этом хранилище найден незавершённый сеанс Feather. Закройте его штатно; чужой процесс и файл блокировки не изменяются.")
        for path in (data / "wallets", home / "config", home / "cache", home / "data", home / "local"):
            _safe_directory(path)
        for path in (folder / ".portable", data / "settings.json"):
            if path.exists() or path.is_symlink():
                _private_file(path)
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
        settings = data / "settings.json"
        # Force a safe first/repeated launch even if a prior user changed the
        # profile. Preserve unrelated UI preferences, never host wallet paths.
        try:
            with offline._open_regular(data, settings.name, settings.stat().st_size) as source:
                raw = source.read(1024 * 1024 + 1)
            previous = json.loads(raw) if raw else {}
            if len(raw) > 1024 * 1024 or not isinstance(previous, dict):
                raise ValueError
        except (OSError, ValueError, offline.OfflineError):
            raise FeatherError("Не удалось безопасно прочитать настройки Feather.") from None
        previous.update({"firstRun": False, "offlineMode": verified_tor_port is None,
                         "proxy": 1, "torPrivacyLevel": 2,
                         "torOnlyAllowOnion": True, "socks5Host": "127.0.0.1", "socks5Port": str(verified_tor_port or 9150),
                         "useLocalTor": True, "enabledPlugins": [], "disableWebsocket": True,
                         "disableLogging": True, "writeStackTraceToDisk": False,
                         "writeRecentlyOpenedWallets": False, "recentlyOpenedWallets": [],
                         "autoOpenWalletPath": "",
                         "walletDirectory": str(data / "wallets"), "lastPath": str(data / "wallets"),
                         "minimizeToTray": False, "showTrayIcon": False})
        fd = os.open(settings, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(previous, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        self._emit(emit, "Открываю Feather внутри зашифрованного хранилища…", 80)
        directory_fd = -1
        try:
            if _lock_cleanup_supported():
                directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                # Check again at the spawn boundary, including broken links.
                try:
                    os.stat(_LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    present = False
                else:
                    present = True
                if present:
                    raise FeatherError(_LOCK_MESSAGE)
            options = {"umask": 0o077, "start_new_session": True} if os.name != "nt" else {
                "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
            self._process = subprocess.Popen([str(binary), "--quiet", "--use-local-tor"],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, cwd=folder,
                                             env=_environment(home, temporary), **options)
            with self._witness_lock:
                self._launch_nonce = secrets.token_hex(32)
                if directory_fd >= 0:
                    self._lock_watch = _LaunchLock(temporary, directory_fd, self._process, self._launch_nonce)
                    directory_fd = -1  # The launch witness owns this descriptor.
            self._capture_lock()
            try:
                self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._capture_lock()
            else:
                raise FeatherError("Feather не открыл окно. Проверьте поддержку системы; файлы кошельков сохранены.")
            if self._lock_capture_failed:
                raise FeatherError(_LOCK_MESSAGE)
        except OSError:
            raise FeatherError("Система не смогла открыть Feather. Файлы кошельков сохранены.") from None
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)
        self._network_mode = "tor" if verified_tor_port is not None else "offline"
        message = ("Feather открыт через проверенный Tor. Дождитесь синхронизации в его окне; готовность оплаты здесь не подтверждается."
                   if verified_tor_port is not None else "Feather открыт автономно. Восстановление 25 слов выполняется только в его окне.")
        self._emit(emit, message, 100)

    def stop(self) -> None:
        process = self._process
        self._capture_lock()  # A pending witness may only arm while still alive.
        if process is not None and process.poll() is None:
            # A GUI may hold unsaved wallet changes. Ask for a normal exit in
            # Feather; never kill it or any process found by name/PID scanning.
            raise FeatherError("Закройте окно Feather штатной командой File → Quit. Затем повторите закрытие сеанса или хранилища.")
        with self._witness_lock:
            try:
                if self._lock_watch is not None:
                    self._lock_watch._check_directory()
                if self._folder is not None and _lock_present(self._folder / "tmp"):
                    if process is None or self._lock_watch is None or self._launch_nonce is None:
                        raise FeatherError(_LOCK_MESSAGE)
                    self._lock_watch.remove(process, self._launch_nonce)
            except OSError:
                raise FeatherError(_LOCK_MESSAGE) from None
            self._release_lock_watch()
            self._process = None
            self._network_mode = "offline"

    def close(self) -> None:
        self.stop()  # A running/foreign process never permits a vault detach.
        self._root = self._folder = self._record = self._key = None
