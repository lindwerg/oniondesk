"""Bounded Android USB installer with a private, ephemeral ADB identity.

The launcher has no arbitrary ADB/shell interface. Only the compiled public
catalog is accepted. Real phones must be USB transports and explicitly selected
from a fresh scan. Private RSA keys and ADB state live on verified encrypted
storage; a separate MacVaultManager never sees a user's wallet directory.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
import zipfile

import offline_bundle as offline
import phone_catalog as catalog
from wallet_engine import (WalletError, _assert_owned_socket, _private_directory,
                           _private_file, default_wallet_root)
from wallet_vault import MacVaultManager
from wallet_security import attest_encrypted_storage


class PhoneError(RuntimeError):
    """Public error: raw command output, paths and serials never leave here."""


_GUIDANCE = [
    "Подключите разблокированный Android кабелем с передачей данных. Если телефон спрашивает режим USB, выберите «Передача файлов».",
    "На телефоне откройте «Настройки → О телефоне» и нажмите «Номер сборки» 7 раз. Затем в «Для разработчиков» включите только «Отладка по USB».",
    "Разрешите подключение USB в обычном запросе компьютера. На телефоне подтвердите RSA-запрос «Разрешить отладку по USB»; постоянное доверие включать не нужно.",
    "Нажмите «Найти телефон», выберите своё устройство и установите Tor Browser. Во время установки держите телефон разблокированным и подтвердите штатные запросы Android.",
    "В открывшемся Tor Browser нажмите «Подключиться». Если соединение блокируется, включите мосты в настройках подключения самого Tor Browser.",
    "После работы закройте USB-сеанс здесь, отключите кабель и выключите USB-отладку на телефоне. В «Для разработчиков» можно отозвать разрешения USB-отладки.",
]
_CLEANUP = "USB-сеанс ещё не закрыт безопасно. Закройте программы, использующие временный диск, и повторите «Закрыть USB-сеанс». Файлы сохранены; принудительное отключение не выполняется."
_ID = re.compile(r"phone_[0-9a-f]{32}\Z")
_SERIAL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_TRANSPORT = re.compile(r"[0-9]{1,12}\Z")
_MAX_OUTPUT = 2 * 1024**2



def _adb_environment(home, android, temporary):
    # Current AOSP CalculatePublicKey derives both keygen and wire comments
    # from LOGNAME/HOSTNAME (POSIX) or USERNAME/COMPUTERNAME (Windows).
    # Set both pairs for legacy/current publishers; never inherit OS identity.
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                   "HOSTNAME": "local", "LOGNAME": "oniondesk", "USER": "oniondesk",
                   "USERNAME": "oniondesk", "COMPUTERNAME": "local",
                   "ANDROID_USER_HOME": str(android), "ADB_VENDOR_KEYS": str(android / "adbkey"),
                   "ADB_MDNS": "0", "ADB_MDNS_AUTO_CONNECT": "", "ADB_MDNS_AUTO_CONNECT_ALL": "0",
                   "ADB_LOCAL_TRANSPORT_MAX_PORT": "0", "TMPDIR": str(temporary),
                   "TMP": str(temporary), "TEMP": str(temporary), "LANG": "C", "LC_ALL": "C"}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        environment["USERPROFILE"] = str(home)
        environment["LOCALAPPDATA"] = str(home)
        environment["APPDATA"] = str(home)
    return environment


def _validate_public_key(path):
    """Accept one bounded private Android RSA-2048 file with neutral metadata."""
    message = "Временный USB-ключ не прошёл проверку приватности. USB-сеанс не запущен."
    try:
        _private_file(path)
        size = path.lstat().st_size
        if not 1 <= size <= 1024:
            raise PhoneError(message)
        # Reuse the bounded no-follow/identity/regular-file checks, including
        # Windows reparse-point handle verification, before reading any bytes.
        with offline._open_regular(path.parent, path.name, size) as source:
            content = source.read(1025)
    except (OSError, WalletError, offline.OfflineError):
        raise PhoneError(message) from None
    matched = re.fullmatch(rb"([A-Za-z0-9+/]{699}=) oniondesk@local(?:\r?\n)?", content)
    if matched is None:
        raise PhoneError(message)
    try:
        decoded = base64.b64decode(matched[1], validate=True)
    except (ValueError, binascii.Error):
        raise PhoneError(message) from None
    if (len(decoded) != 524 or base64.b64encode(decoded) != matched[1]
            or int.from_bytes(decoded[:4], "little") != 64
            or int.from_bytes(decoded[-4:], "little") != 65537):
        raise PhoneError(message)


def _platform_key():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64", "x86_64"}:
        return "macos"
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        return "windows-x64"
    if system == "Linux" and machine in {"amd64", "x86_64"}:
        return "linux-x64"
    raise PhoneError("Для этой системы нет официального USB-инструмента Google в комплекте. Linux ARM64 не поддерживается этим USB-сценарием.")


def status():
    """Cheap discovery only: no commands, hashes, writes, key creation or ADB."""
    try:
        key = _platform_key()
        root = offline._find_root()
        records = [catalog.PLATFORMS[key], catalog.KEY, *catalog.APKS.values(), *catalog.SIGNATURES.values()]
        available = catalog.RELEASE_READY and root is not None and all((root / row["path"]).is_file() for row in records)
        message = "Файлы для установки Tor Browser по USB есть в комплекте." if available else "Для USB-установки нужен полный комплект Android."
    except (OSError, PhoneError):
        available, message = False, "Официальная USB-установка недоступна для этой системы. Linux ARM64 не поддерживается."
    return {"available": available, "version": catalog.TOR_VERSION,
            "message": message, "guidance": list(_GUIDANCE), "devices": [],
            "session_open": False, "cleanup_required": False, "tor_ready": False}



def _run_limited(arguments, *, environment, timeout):
    """Bound stdout/stderr while the fixed child command is still running."""
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0)
    except OSError:
        raise PhoneError("USB-инструмент не удалось запустить.") from None
    output = [bytearray(), bytearray()]
    overflow = threading.Event()

    def read_pipe(pipe, index):
        try:
            while block := pipe.read(65536):
                if len(output[index]) + len(block) > _MAX_OUTPUT:
                    overflow.set()
                    return
                output[index].extend(block)
        except OSError:
            overflow.set()
        finally:
            pipe.close()

    readers = [threading.Thread(target=read_pipe, args=(pipe, index), daemon=True)
               for index, pipe in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    failed = False
    while process.poll() is None:
        if overflow.is_set() or time.monotonic() >= deadline:
            failed = True
            process.kill()  # Exact owned short-lived client handle, never the ADB server.
            break
        time.sleep(0.02)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise PhoneError("USB-инструмент не завершился. Закройте USB-сеанс здесь.") from None
    for reader in readers:
        reader.join(timeout=2)
    if failed or overflow.is_set() or any(reader.is_alive() for reader in readers):
        raise PhoneError("Телефон не завершил операцию или вернул слишком большой ответ. Проверьте экран, кабель и повторите поиск устройства.")
    return subprocess.CompletedProcess(arguments, process.returncode, bytes(output[0]), bytes(output[1]))


def _port_listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except ConnectionRefusedError:
        return False
    except OSError:
        # Unknown network state cannot permit deletion of the key store.
        return True


def _copy_asset(root, record, target):
    if root is None:
        raise PhoneError("Файлы Android больше недоступны. Подключите носитель с полным комплектом.")
    digest, copied = hashlib.sha256(), 0
    try:
        with offline._open_regular(root, record["path"], record["size_bytes"]) as source:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as output:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(block)
                    if copied > record["size_bytes"]:
                        raise PhoneError("Размер файла Android изменился. Установка остановлена.")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        if copied != record["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), record["sha256"]):
            raise PhoneError("Проверка файла Android не пройдена. Распакуйте полный комплект заново.")
    except (OSError, offline.OfflineError):
        raise PhoneError("Файлы Android повреждены или недоступны. Нужен полный комплект.") from None


def _extract_tools(archive, destination):
    """Extract only Google's ADB and the original packaged runtime libraries."""
    names = {"platform-tools/adb", "platform-tools/adb.exe",
             "platform-tools/AdbWinApi.dll", "platform-tools/AdbWinUsbApi.dll",
             "platform-tools/libwinpthread-1.dll", "platform-tools/lib64/libc++.so",
             "platform-tools/lib64/libc++.dylib"}
    total = 0
    try:
        with zipfile.ZipFile(archive) as bundle:
            rows = bundle.infolist()
            if len(rows) > 256 or len({row.filename for row in rows}) != len(rows):
                raise PhoneError("Архив USB-инструмента содержит неожиданные записи.")
            for row in rows:
                path = PurePosixPath(row.filename)
                mode = row.external_attr >> 16
                if (path.is_absolute() or ".." in path.parts or "\\" in row.filename
                        or stat.S_ISLNK(mode) or row.flag_bits & 1):
                    raise PhoneError("Архив USB-инструмента имеет небезопасную структуру.")
                total += row.file_size
                if total > 100 * 1024**2:
                    raise PhoneError("Архив USB-инструмента слишком большой.")
                if row.filename not in names:
                    continue
                target = destination.joinpath(*path.parts[1:])
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with bundle.open(row) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                os.chmod(target, 0o700 if path.name in {"adb", "adb.exe"} else 0o600)
        binary = destination / ("adb.exe" if platform.system() == "Windows" else "adb")
        if not binary.is_file():
            raise PhoneError("В официальном архиве нет USB-инструмента для этой системы.")
        return binary
    except (OSError, zipfile.BadZipFile, RuntimeError):
        raise PhoneError("Официальный USB-инструмент не удалось распаковать.") from None


class _EncryptedSession:
    """A fresh phone-only store; never lists, unlocks or touches real wallets."""
    def __init__(self):
        self.base = default_wallet_root().parent / "phone-sessions" / ("session_" + secrets.token_hex(16))
        self.vault = None
        self.private = None
        self.opened = False
        self.created = False

    def open(self):
        try:
            if platform.system() != "Darwin":
                evidence = attest_encrypted_storage(self.base)
                if evidence.get("ok") is not True or evidence.get("kind") not in {"bitlocker", "luks"}:
                    raise PhoneError("Для USB-сеанса нужно подтверждённое шифрование диска и памяти подкачки: BitLocker в Windows или LUKS в Linux. Настройки системы не изменялись.")
            _private_directory(self.base.parent)
            self.base.mkdir(mode=0o700)  # Never reuse a path after a crash.
            self.created = True
            _private_directory(self.base)
            if platform.system() == "Darwin":
                self.vault = MacVaultManager(base=self.base / "private-store")
                # The random image password is kept only for this call, never persisted.
                self.private = self.vault.create(secrets.token_urlsafe(48))
                _private_directory(self.private)
                evidence = attest_encrypted_storage(self.private)
                if evidence.get("ok") is not True or evidence.get("kind") != "encrypted-image":
                    raise PhoneError("macOS не подтвердила шифрование временного диска и памяти подкачки. USB-сеанс остановлен.")
            else:
                self.private = self.base / "private-store"
                _private_directory(self.private)
            self.opened = True
            return self.private
        except (WalletError, OSError):
            raise PhoneError("Не удалось открыть отдельное зашифрованное хранилище USB-сеанса. Личные кошельки не изменялись.") from None

    def close(self):
        try:
            if self.vault:
                self.vault.close()  # No force detach, no deletion after failure.
                if self.vault.workspace_open:
                    raise PhoneError(_CLEANUP)
            if self.created:
                if self.base.is_symlink() or os.path.ismount(self.base):
                    raise PhoneError(_CLEANUP)
                shutil.rmtree(self.base)
            self.created, self.opened, self.private = False, False, None
        except (OSError, WalletError):
            raise PhoneError(_CLEANUP) from None


@dataclass(frozen=True)
class _Device:
    identifier: str
    serial: str = field(repr=False)
    transport: str
    state: str
    label: str
    scanned: float


def _parse_devices(raw, *, emulator_serial=None):
    if len(raw) > _MAX_OUTPUT:
        raise PhoneError("Ответ USB-устройств слишком большой.")
    devices = []
    lines = raw.decode("utf-8", "replace").splitlines()
    if not lines or lines[0].strip() != "List of devices attached":
        raise PhoneError("Не удалось получить список Android-устройств.")
    seen = set()
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2 or not _SERIAL.fullmatch(fields[0]) or fields[0] in seen:
            raise PhoneError("Получен неизвестный список Android-устройств.")
        seen.add(fields[0])
        properties = dict(word.split(":", 1) for word in fields[2:] if ":" in word)
        # TCP/Wi-Fi devices are not supported. The test hook permits only one
        # exact emulator owned by an isolated test harness; never UI input.
        if not properties.get("usb") and fields[0] != emulator_serial:
            continue
        transport = properties.get("transport_id", "")
        if not _TRANSPORT.fullmatch(transport):
            raise PhoneError("Не удалось подтвердить USB-подключение Android.")
        state = fields[1] if fields[1] in {"device", "unauthorized", "offline"} else "unavailable"
        # Model/serial supplied by the device never enter public logs or labels.
        devices.append(_Device("phone_" + secrets.token_hex(16), fields[0], transport,
                               state, "Android USB " + str(len(devices) + 1), time.monotonic()))
        if len(devices) > 32:
            raise PhoneError("Подключено слишком много устройств. Оставьте только нужный телефон.")
    return devices


class PhoneUSBController:
    def __init__(self, *, _store_factory=_EncryptedSession, _test_emulator_serial=None):
        if _test_emulator_serial is not None and not re.fullmatch(r"emulator-[0-9]{4,5}", _test_emulator_serial):
            raise PhoneError("Неизвестный тестовый эмулятор.")
        self._store_factory = _store_factory
        self._test_emulator_serial = _test_emulator_serial
        self._lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._store = self._process = self._guard = self._binary = None
        self._port = None
        self._environment = None
        self._devices = {}
        self._cleanup_required = False
        self._message = "Подключите Android и нажмите «Найти телефон»."
        self._installed = False
        self._installed_for = None

    @staticmethod
    def _emit(emit, message, percent):
        if emit:
            emit({"stage": "android-usb", "message": message, "percent": percent})

    @contextmanager
    def _operation(self):
        if not self._operation_lock.acquire(blocking=False):
            raise PhoneError("Операция с телефоном ещё выполняется.")
        try:
            if self._cleanup_required:
                raise PhoneError(_CLEANUP)
            yield
        finally:
            self._operation_lock.release()

    def status(self):
        result = status()
        with self._lock:
            evidence = self._installed_for
            # A confirmation belongs to one session and its exact frozen USB
            # record (including private serial/transport), never a later scan.
            installed = bool(self._installed and evidence
                             and self._store is not None
                             and evidence[0] is self._store
                             and self._devices.get(evidence[1].identifier) == evidence[1])
            result.update({"devices": [{"id": row.identifier, "state": row.state, "label": row.label}
                                       for row in self._devices.values()],
                           "session_open": self._store is not None,
                           "cleanup_required": self._cleanup_required,
                           "message": self._message, "installed": installed})
        return result

    state = status

    def _owned(self):
        if self._process is None or self._process.poll() is not None or self._guard is None:
            raise PhoneError("USB-сеанс прерван. Закройте его здесь и найдите телефон заново.")
        try:
            _assert_owned_socket(self._process, self._guard, self._port)
        except WalletError:
            raise PhoneError("Принадлежность локального USB-сеанса не подтверждена. Операция остановлена.") from None

    def _command(self, arguments, *, timeout=15):
        self._owned()
        # Numeric -H intentionally disables adb's implicit server start path.
        # The server is always our explicit foreground Popen, never host:5037.
        try:
            result = _run_limited([str(self._binary), "-H", "127.0.0.1", "-P", str(self._port), *arguments],
                                  timeout=timeout, environment=self._environment)
        except (OSError, subprocess.TimeoutExpired):
            raise PhoneError("Телефон не завершил операцию. Проверьте экран, кабель и повторите поиск устройства.") from None
        self._owned()
        if len(result.stdout) > _MAX_OUTPUT or len(result.stderr) > _MAX_OUTPUT:
            raise PhoneError("Телефон вернул слишком большой ответ. Операция остановлена.")
        return result

    def _start(self, emit):
        if self._store is not None:
            self._owned()
            return
        key = _platform_key()
        root = offline._find_root()
        if root is None:
            raise PhoneError("Файлы Android отсутствуют. Нужен полный комплект.")
        self._store = self._store_factory()  # Retain even a partial open for safe cleanup.
        try:
            self._emit(emit, "Открываю отдельное зашифрованное USB-хранилище…", 8)
            private = self._store.open()
            public = self._store.base / "public-tools"
            _private_directory(public)
            archive = public / "google-platform-tools.zip"
            _copy_asset(root, catalog.PLATFORMS[key], archive)
            self._binary = _extract_tools(archive, public)
            home = private / "home"
            android = home / ".android"
            temporary = private / "tmp"
            for path in (home, android, temporary):
                _private_directory(path)
            # Fixed, minimal environment excludes global HOME/ADB keys, serial,
            # server sockets, tracing, preload hooks and user shell settings.
            self._environment = _adb_environment(home, android, temporary)
            made = _run_limited([str(self._binary), "keygen", str(android / "adbkey")],
                                timeout=10, environment=self._environment)
            if made.returncode:
                raise PhoneError("Не удалось создать временный ключ USB-сеанса.")
            for path in (android / "adbkey", android / "adbkey.pub"):
                if os.name != "nt":
                    os.chmod(path, 0o600)
                _private_file(path)
            _validate_public_key(android / "adbkey.pub")
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self._port = reservation.getsockname()[1]
            self._process = subprocess.Popen([str(self._binary), "-L", f"tcp:localhost:{self._port}", "server", "nodaemon"],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, env=self._environment,
                                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0)
            deadline = time.monotonic() + 12
            while self._process.poll() is None and time.monotonic() < deadline:
                try:
                    guard = socket.create_connection(("127.0.0.1", self._port), timeout=1)
                    _assert_owned_socket(self._process, guard, self._port)
                    self._guard = guard
                    break
                except (OSError, WalletError):
                    if 'guard' in locals():
                        guard.close()
                    time.sleep(0.05)
            self._owned()
            check = self._command(["version"])
            if check.returncode or catalog.PLATFORM_TOOLS_VERSION.encode() not in check.stdout:
                raise PhoneError("Версия официального USB-инструмента не совпала с комплектом.")
        except BaseException as error:
            try:
                self._close()
            except (PhoneError, OSError):
                self._cleanup_required = True
            if isinstance(error, (WalletError, OSError)):
                raise PhoneError("Не удалось открыть защищённый USB-сеанс. Проверьте доступ к полному комплекту и повторите закрытие сеанса при необходимости.") from None
            raise

    def list_devices(self, emit=None):
        with self._operation():
            with self._lock:
                self._installed, self._installed_for = False, None
                self._devices = {}
                self._message = "Проверяю USB-подключение Android…"
            self._start(emit)
            self._emit(emit, "Проверяю USB-подключение. Подтвердите запрос на телефоне…", 65)
            result = self._command(["devices", "-l"])
            if result.returncode:
                raise PhoneError("Android не обнаружен. Проверьте USB-кабель, разрешение компьютера и USB-отладку на телефоне.")
            rows = _parse_devices(result.stdout, emulator_serial=self._test_emulator_serial)
            with self._lock:
                self._devices = {row.identifier: row for row in rows}
                self._message = ("Выберите свой Android. Для состояния «Ожидает разрешения» подтвердите запрос на телефоне и повторите поиск."
                                 if rows else "Телефон не найден. Проверьте кабель с передачей данных, разблокировку и USB-отладку; затем повторите поиск.")
            self._emit(emit, self._message, 100)
            return self.status()

    def _fresh_device(self, selected):
        if time.monotonic() - selected.scanned > 300:
            raise PhoneError("Список телефонов устарел. Нажмите «Найти телефон» и выберите устройство заново.")
        result = self._command(["devices", "-l"])
        if result.returncode:
            raise PhoneError("USB-подключение потеряно. Найдите телефон заново.")
        fresh = _parse_devices(result.stdout, emulator_serial=self._test_emulator_serial)
        matches = [row for row in fresh if row.serial == selected.serial and row.transport == selected.transport]
        if len(matches) != 1 or matches[0].state != "device":
            raise PhoneError("Выбранное USB-подключение изменилось или не разрешено. Найдите телефон заново и подтвердите запрос на его экране.")
        return ["-t", selected.transport]

    def install(self, device_id, emit=None):
        with self._operation():
            with self._lock:
                self._installed, self._installed_for = False, None
                self._message = "Проверяю выбранный Android…"
            if not isinstance(device_id, str) or not _ID.fullmatch(device_id) or device_id not in self._devices:
                raise PhoneError("Сначала найдите и выберите свой Android.")
            selected = self._devices[device_id]
            target = self._fresh_device(selected)
            self._emit(emit, "Определяю совместимую официальную сборку Tor Browser…", 15)
            answer = self._command(target + ["shell", "getprop", "ro.product.cpu.abilist"])
            abis = answer.stdout.decode("ascii", "replace").strip().split(",")
            if answer.returncode or len(abis) > 16 or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value) for value in abis):
                raise PhoneError("Архитектура Android не определена. Установка остановлена.")
            abi = next((name for name in abis if name in catalog.APKS), None)
            if abi is None:
                raise PhoneError("Для архитектуры этого телефона в комплекте нет официального Tor Browser.")
            root = offline._find_root()
            public = self._store.base / ("install_" + secrets.token_hex(16))
            _private_directory(public)
            apk, signature, key = public / "tor-browser.apk", public / "tor-browser.apk.asc", public / "tor-browser-developers.key"
            try:
                for record, path in ((catalog.APKS[abi], apk), (catalog.SIGNATURES[abi], signature), (catalog.KEY, key)):
                    _copy_asset(root, record, path)
                self._emit(emit, "Проверяю криптографическую подпись Tor Project…", 40)
                try:
                    offline._verify_tor_signature(apk, signature, key)
                except offline.OfflineError:
                    raise PhoneError("Подпись Tor Project не прошла проверку. Установка запрещена.") from None
                # Selection and ABI are rechecked after the lengthy hash/GPG work.
                target = self._fresh_device(selected)
                again = self._command(target + ["shell", "getprop", "ro.product.cpu.abilist"])
                if again.returncode or again.stdout != answer.stdout:
                    raise PhoneError("Выбранный Android изменился. Найдите телефон заново.")
                self._emit(emit, "Устанавливаю Tor Browser. Подтвердите обычные запросы на телефоне…", 65)
                installed = self._command(target + ["install", "-r", str(apk)], timeout=180)
                if installed.returncode or b"Success" not in installed.stdout.splitlines():
                    raise PhoneError("Android не разрешил установку. Если Tor Browser уже установлен с другой подписью или новее, он сохранён. Не удаляйте его данные; проверьте запросы на телефоне.")
                version = self._command(target + ["shell", "dumpsys", "package", catalog.PACKAGE])
                versions = re.findall(rb"\bversionName=([^\s]+)", version.stdout)
                if version.returncode or not versions or any(value != catalog.TOR_VERSION.encode() for value in versions):
                    raise PhoneError("Приложение установлено, но его версия не подтверждена. Проверьте Tor Browser на телефоне.")
                target = self._fresh_device(selected)
                with self._lock:
                    self._installed = True
                    self._installed_for = (self._store, selected)
                launched = self._command(target + ["shell", "am", "start", "-W", "-n", catalog.LAUNCH_ACTIVITY], timeout=30)
                if launched.returncode or b"Status: ok" not in launched.stdout or b"Error:" in launched.stdout:
                    raise PhoneError("Tor Browser установлен. Откройте его значком на телефоне и нажмите «Подключиться».")
                with self._lock:
                    self._message = "Tor Browser установлен и открыт на Android. На телефоне нажмите «Подключиться» и дождитесь соединения; при блокировке настройте мосты. Затем закройте USB-сеанс здесь."
                self._emit(emit, self._message, 100)
                return self.status()
            finally:
                # This directory contains only verified public publisher files.
                shutil.rmtree(public)

    def _close(self):
        with self._lock:
            self._installed, self._installed_for = False, None
            self._devices = {}
            self._message = "Закрываю USB-сеанс…"
        if self._process is not None:
            if self._process.poll() is None:
                # Exact process handle only; never adb kill-server/killall/taskkill.
                self._process.terminate()
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    raise PhoneError(_CLEANUP) from None
            if self._guard is not None:
                self._guard.close()
                self._guard = None
            self._process = None
        if self._port is not None and _port_listening(self._port):
            raise PhoneError(_CLEANUP)
        if self._store is not None:
            self._store.close()
            self._store = None
        self._binary = self._environment = self._port = None
        with self._lock:
            self._devices = {}
            self._cleanup_required = False
            self._message = "USB-сеанс закрыт, временный ключ удалён. Отключите кабель и выключите USB-отладку на телефоне."

    def close(self):
        if not self._operation_lock.acquire(blocking=False):
            raise PhoneError("Дождитесь завершения операции с телефоном, затем закройте USB-сеанс.")
        try:
            self._close()
            return self.status()
        except (PhoneError, OSError):
            self._cleanup_required = True
            raise PhoneError(_CLEANUP) from None
        finally:
            self._operation_lock.release()
