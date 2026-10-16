"""Prepare publisher-signed, pinned software from the shared offline folder.

No external network operation exists here. A bounded numeric-loopback TCP probe
only refuses occupied browser ports; it never authenticates a proxy as Tor.
Distribution files and their manifest
are untrusted until the compiled catalog's size/hash and publisher PGP checks pass.
Only fresh copies in a private user cache are mounted, extracted, or launched.
"""
from __future__ import annotations

import hashlib
import configparser
import errno
import json
import os
from pathlib import Path, PurePosixPath
import platform
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

import offline_catalog as catalog
import usb_tails as usb

MAX_MANIFEST_BYTES = 64 * 1024
MAX_EXTRACT_BYTES = 2 * 1024**3
MAX_ARCHIVE_MEMBERS = 20_000
_TOR_LOCK = threading.Lock()
_TOR_LAST_WORK = None
_SELECTED_EMBEDDED_ROOT = None
_NOSCRIPT_ID = "{73a6fe31-595d-460b-a920-fcc0f8843232}"
_BRIDGE_PREFS = (
    'user_pref("torbrowser.settings.bridges.enabled", true);\n'
    'user_pref("torbrowser.settings.bridges.source", 0);\n'
    'user_pref("torbrowser.settings.bridges.builtin_type", "obfs4");\n'
)


class OfflineError(usb.USBError):
    """The local package was absent, damaged, or could not safely be prepared."""


class _MountedVolumeError(OfflineError):
    """A private image mount may remain attached; its directory must be kept."""


class _BrowserLaunchError(OfflineError):
    """An OS launch was attempted; never delete a possibly active profile."""


def _windows_data_root():
    # The installer writes HKLM. Never accept HKCU/environment/current-directory
    # overrides for an installed application's shared distribution folder.
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\OnionDesk", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, kind = winreg.QueryValueEx(key, "DataRoot")
        if kind != winreg.REG_SZ or not isinstance(value, str) or not value or len(value) > 32760:
            raise OfflineError("Установленный комплект содержит некорректный путь к файлам. Установите его заново.")
        path = Path(value)
        if not path.is_absolute() or value.startswith("\\\\"):
            raise OfflineError("Папка файлов комплекта должна находиться на локальном диске.")
        return path
    except (ImportError, FileNotFoundError):
        return None
    except OSError as exc:
        raise OfflineError("Windows не смогла прочитать папку файлов комплекта. Установите его заново.") from exc


def _embedded_data_root():
    """Only the frozen macOS app's own fixed resource path is embedded data."""
    if not getattr(sys, "frozen", False) or platform.system() != "Darwin":
        return None
    executable = Path(sys.executable).absolute()
    contents = executable.parent.parent
    if executable.parent.name != "MacOS" or contents.name != "Contents" or contents.parent.suffix != ".app":
        return None
    return contents / "Resources/OnionDesk-Data"


def _data_roots():
    if not getattr(sys, "frozen", False):
        return [Path(__file__).resolve().parent.parent / "OnionDesk-Data"]
    if platform.system() == "Windows":
        installed = _windows_data_root()
        if installed is not None:
            return [installed]
    # A macOS bundle's executable is four directory levels below the kit root.
    # This also covers the two-directory Linux portable layout, without an
    # unbounded ancestor or home-directory search.
    start = Path(sys.executable).absolute().parent
    return [parent / "OnionDesk-Data" for parent in (start, *list(start.parents)[:4])]


def _find_root():
    global _SELECTED_EMBEDDED_ROOT
    embedded = _embedded_data_root()
    if embedded is not None and (embedded == _SELECTED_EMBEDDED_ROOT or embedded.exists() or embedded.is_symlink()):
        # A present but damaged embedded folder must fail closed, never fall
        # through to a different external release or protected user directory.
        # Keep this choice if files disappear later in the same app session.
        _SELECTED_EMBEDDED_ROOT = embedded
        return embedded
    for root in _data_roots():
        if root.exists() or root.is_symlink():
            return root.absolute()
    return None


def _relative_path(value):
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise OfflineError("Некорректный путь в файлах комплекта.")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts) or str(path) != value:
        raise OfflineError("Некорректный путь в файлах комплекта.")
    return path


def _open_regular(root, relative, size):
    """Open one bounded file, refusing links, junctions and redirected ancestors."""
    relative = _relative_path(relative)
    root = Path(root).absolute()
    path = root.joinpath(*relative.parts)
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.resolve() != parent:
            raise OfflineError("Файлы комплекта содержат перенаправление. Распакуйте исходный архив заново.")
    fd = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != size or \
                getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise OfflineError("Размер или тип файла комплекта изменён. Распакуйте исходный архив заново.")
        # A substituted FIFO must not block before fstat can reject its type.
        # Windows has no O_NONBLOCK for regular filesystem files; lstat rejects
        # non-files/reparse points before opening, and the handle check below
        # independently verifies the actual target.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size or \
                (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise OfflineError("Размер или тип файла комплекта изменён. Распакуйте исходный архив заново.")
        if os.name == "nt":
            # O_NOFOLLOW is absent on Windows: inspect the opened handle as well
            # as each ancestor to reject junction/reparse substitutions.
            import ctypes
            import msvcrt
            from ctypes import wintypes as wt
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetFinalPathNameByHandleW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD]
            kernel.GetFinalPathNameByHandleW.restype = wt.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            count = kernel.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
            if not count or count >= len(buffer) or os.path.normcase(buffer.value.removeprefix("\\\\?\\")) != os.path.normcase(str(path)):
                raise OfflineError("Файл комплекта перенаправлен на другой путь.")
        source = os.fdopen(fd, "rb")
        fd = None
        return source
    except OSError as exc:
        raise OfflineError("Файл комплекта не найден или недоступен. Распакуйте полный архив заново.") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _check_manifest(root):
    path = root / "manifest.json"
    try:
        size = path.lstat().st_size
        if not 0 < size <= MAX_MANIFEST_BYTES:
            raise OfflineError("Описание файлов комплекта повреждено.")
        with _open_regular(root, "manifest.json", size) as source:
            raw = source.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) != size:
            raise OfflineError("Описание файлов комплекта изменилось во время проверки.")
        manifest = json.loads(raw, object_pairs_hook=_unique_json)
        expected = {"format": 1, "release_id": catalog.RELEASE_ID, "assets": catalog.ASSETS}
        if manifest != expected or not catalog.ASSETS:
            raise OfflineError("Файлы относятся к другой версии или описание комплекта изменено. Распакуйте исходный архив заново.")
        # Paths always come from code; even an otherwise matching manifest is
        # never a source of executable names or trust roots.
        for record in catalog.ASSETS.values():
            _relative_path(record["path"])
    except (OSError, ValueError, TypeError) as exc:
        raise OfflineError("Описание файлов комплекта повреждено. Распакуйте полный архив заново.") from exc


def _tor_assets():
    system, machine = platform.system(), platform.machine().lower()
    x86 = machine in {"x86_64", "amd64"}
    if system == "Darwin" and machine in {"arm64", "aarch64", "x86_64", "amd64"}:
        return catalog.TOR[system]
    if system in {"Windows", "Linux"} and x86:
        return catalog.TOR[system]
    raise OfflineError("Для этой архитектуры официальный стабильный Tor Browser в комплекте не выпускается. Используйте компьютер Intel/AMD x86-64 или macOS с Intel/Apple Silicon.")


def _has_assets(root, assets):
    for name in assets.values():
        record = catalog.ASSETS[name]
        with _open_regular(root, record["path"], record["size_bytes"]):
            pass
    return True


def status():
    """A cheap presence/size check for UI polling; preparation verifies contents."""
    tails = tor = False
    message = "Офлайн-файлы не найдены. Распакуйте полный комплект вместе с папкой OnionDesk-Data."
    try:
        root = _find_root()
        if root is not None:
            _check_manifest(root)
            try:
                tails = _has_assets(root, catalog.TAILS)
            except OfflineError as exc:
                message = str(exc)
            try:
                tor = _has_assets(root, _tor_assets())
                if tails:
                    message = "Tails и Tor Browser находятся в комплекте. Перед подготовкой мастер проверит контрольные суммы и подписи издателей."
            except OfflineError as exc:
                message = str(exc)
    except (OfflineError, KeyError) as exc:
        message = str(exc) if isinstance(exc, OfflineError) else "Описание файлов комплекта повреждено."
    return {"available": tails or tor, "tails_available": tails, "tor_available": tor,
            "tails_version": catalog.TAILS_VERSION, "tor_version": catalog.TOR_VERSION, "message": message}


def _emit(callback, stage, message, percent=None):
    usb._emit(callback, stage, message, percent)


def _copy_asset(root, name, destination, callback=None, cancel_event=None):
    record = catalog.ASSETS[name]
    digest = hashlib.sha256()
    copied = 0
    with _open_regular(root, record["path"], record["size_bytes"]) as source:
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            while chunk := source.read(usb.CHUNK):
                usb._cancel(cancel_event)
                copied += len(chunk)
                if copied > record["size_bytes"]:
                    raise OfflineError("Файл комплекта изменился во время проверки.")
                digest.update(chunk)
                output.write(chunk)
                if callback:
                    _emit(callback, "offline", "Проверяю и копирую официальный файл из комплекта…", int(copied * 90 / record["size_bytes"]))
            output.flush()
            os.fsync(output.fileno())
    if copied != record["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), record["sha256"]):
        raise OfflineError("Контрольная сумма файла комплекта не совпала. Подготовка остановлена; распакуйте исходный архив заново.")
    return destination


def prepare_tails(cache, progress_cb=None, cancel_event=None):
    """Return a privately copied artifact, or None when no offline folder exists.

    A present but damaged bundle fails closed. The caller may use its existing
    Tor-only online flow only for a genuinely absent offline folder.
    """
    root = _find_root()
    if root is None:
        return None
    _check_manifest(root)
    size = catalog.ASSETS[catalog.TAILS["image"]]["size_bytes"]
    cache = usb._secure_directory(cache)
    record_path = cache / "latest-verified.json"
    if record_path.exists():
        try:
            with usb._open_regular(record_path)[0] as record:
                previous = json.load(record)
            if usb._version(catalog.TAILS_VERSION) < usb._version(previous["version"]):
                raise OfflineError("Образ в комплекте старее уже проверенного Tails. Используйте обновлённый полный комплект.")
        except (KeyError, ValueError, OSError) as exc:
            raise OfflineError("Сохранённые сведения о Tails повреждены. Подготовка остановлена.") from exc
    if shutil.disk_usage(cache).free < size + 100 * 1024**2:
        raise OfflineError("Для подготовки Tails освободите не меньше 2 ГБ на компьютере.")
    work = Path(tempfile.mkdtemp(prefix="offline-", dir=cache))
    try:
        _emit(progress_cb, "offline", "Tails уже в комплекте. Проверяю образ без подключения к Интернету…", 0)
        files = {}
        for kind, name in catalog.TAILS.items():
            target = work / PurePosixPath(catalog.ASSETS[name]["path"]).name
            files[kind] = _copy_asset(root, name, target, progress_cb if kind == "image" else None, cancel_event)
        usb._cancel(cancel_event)
        _emit(progress_cb, "signature", "Проверяю подпись издателя Tails…", 95)
        usb._verify_signature(files["image"], files["signature"], files["key"])
        usb._cancel(cancel_event)
        destination = cache / f"verified-{catalog.TAILS_VERSION}-offline-{secrets.token_hex(8)}"
        work.rename(destination)
        result = {"path": str(destination / files["image"].name), "signature": str(destination / files["signature"].name),
                  "key": str(destination / files["key"].name), "sha256": catalog.ASSETS[catalog.TAILS["image"]]["sha256"],
                  "size_bytes": size, "version": catalog.TAILS_VERSION, "verified": True}
        record = cache / f"record-{secrets.token_hex(8)}.tmp"
        with os.fdopen(os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            json.dump({"version": catalog.TAILS_VERSION}, output)
        os.replace(record, record_path)
        _emit(progress_cb, "verified", "Официальный образ Tails из комплекта проверен. Можно выбрать флешку для записи.", 100)
        return result
    except (OSError, KeyError) as exc:
        raise OfflineError("Не удалось подготовить Tails из комплекта. Проверьте свободное место и распакуйте полный архив заново.") from exc
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)


def _valid_tor_signature(status_output):
    rows = [line.split()[1:] for line in status_output.splitlines() if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"}
    signatures = [row[1:] for row in rows if row and row[0] == "VALIDSIG"]
    return not any(row and row[0] in rejected for row in rows) and any(row and row[0] == "GOODSIG" for row in rows) and \
        len(signatures) == 1 and len(signatures[0]) >= 10 and signatures[0][9] == catalog.TOR_FINGERPRINT and signatures[0][7] in {"8", "9", "10", "11"}


def _verify_tor_signature(binary, signature, key):
    gpg = usb._find_gpg()
    if not gpg:
        raise OfflineError("В комплекте недоступна GnuPG для проверки подписи. Распакуйте или установите полный комплект заново.")
    short_tmp = None if os.name == "nt" else ("/private/tmp" if platform.system() == "Darwin" else "/tmp")
    with tempfile.TemporaryDirectory(prefix="onion-gpg-", dir=short_tmp) as home:
        os.chmod(home, 0o700)
        base = [gpg, "--no-options", "--homedir", home, "--batch", "--no-tty", "--no-autostart",
                "--no-auto-key-retrieve", "--auto-key-locate", "clear"]

        def execute(args):
            try:
                return subprocess.run(base + args, capture_output=True, timeout=600, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise OfflineError("Не удалось проверить подпись Tor Browser. Запуск запрещён.") from exc

        shown = execute(["--with-colons", "--import-options", "show-only", "--import", str(key)])
        primary, want_fingerprint = [], False
        for line in shown.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                want_fingerprint = True
            elif fields[0] == "fpr" and want_fingerprint and len(fields) > 9:
                primary.append(fields[9])
                want_fingerprint = False
        if shown.returncode or primary != [catalog.TOR_FINGERPRINT]:
            raise OfflineError("Ключ Tor Browser не совпадает с закреплённым ключом издателя. Запуск запрещён.")
        if execute(["--import", str(key)]).returncode:
            raise OfflineError("Ключ Tor Browser повреждён. Запуск запрещён.")
        checked = execute(["--status-fd", "1", "--verify", str(signature), str(binary)])
        if checked.returncode or not _valid_tor_signature(checked.stdout.decode("utf-8", "replace")):
            raise OfflineError("Подпись Tor Browser не прошла проверку. Запуск запрещён.")


def _tor_cache():
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Caches" / "OnionDesk" / "tor-browser"
    if platform.system() == "Windows":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "OnionDesk" / "tor-browser"
    return Path.home() / ".cache" / "OnionDesk" / "tor-browser"


def _is_elevated():
    if os.name != "nt":
        return os.geteuid() == 0
    import ctypes
    try:
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.IsUserAnAdmin.argtypes = []
        shell.IsUserAnAdmin.restype = ctypes.c_int
        return bool(shell.IsUserAnAdmin())
    except OSError as exc:
        raise OfflineError("Не удалось проверить права запуска. Откройте мастер от обычного пользователя.") from exc


def _busy_tor_ports():
    busy = []
    for port in (9150, 9151):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.2)
                result = connection.connect_ex(("127.0.0.1", port))
            if result == 0:
                busy.append(port)
            elif result not in {errno.ECONNREFUSED, 10061}:  # WSAECONNREFUSED
                raise OfflineError("Не удалось проверить, свободно ли локальное подключение Tor Browser. Закройте другие окна Tor Browser и повторите.")
        except OSError as exc:
            raise OfflineError("Не удалось проверить локальное подключение Tor Browser. Закройте другие окна Tor Browser и повторите.") from exc
    return busy


def _assert_tor_ports_free():
    if _busy_tor_ports():
        raise OfflineError("Локальное подключение Tor Browser уже занято. Если Tor Browser открыт, используйте его и нажмите «Проверить Tor» в мастере. Чтобы подготовить новую копию, сначала закройте другие окна Tor Browser.")


def _extract_linux(binary, destination):
    """Bounded extraction of the pinned release, which contains no links."""
    count = total = 0
    seen = set()
    with tarfile.open(binary, "r:xz") as archive:
        for member in archive:
            count += 1
            relative = _relative_path(member.name.rstrip("/"))
            if relative.parts[0] != "tor-browser" or str(relative) in seen:
                raise OfflineError("Архив Tor Browser содержит неожиданные пути.")
            seen.add(str(relative))
            if count > MAX_ARCHIVE_MEMBERS or member.size < 0:
                raise OfflineError("Архив Tor Browser превышает допустимый размер.")
            path = destination.joinpath(*relative.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            elif member.isfile():
                total += member.size
                if total > MAX_EXTRACT_BYTES:
                    raise OfflineError("Архив Tor Browser превышает допустимый размер.")
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = archive.extractfile(member)
                if source is None:
                    raise OfflineError("Не удалось прочитать архив Tor Browser.")
                with source, os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if member.mode & 0o111 else 0o600), "wb") as output:
                    copied = 0
                    while chunk := source.read(usb.CHUNK):
                        copied += len(chunk)
                        if copied > member.size:
                            raise OfflineError("Архив Tor Browser повреждён.")
                        output.write(chunk)
                    if copied != member.size:
                        raise OfflineError("Архив Tor Browser неполный.")
            elif member.issym() or member.islnk():
                raise OfflineError("Архив Tor Browser содержит ссылку, которой нет в проверенной версии комплекта.")
            else:
                raise OfflineError("Архив Tor Browser содержит неподдерживаемый тип файла.")
    launcher = destination / "tor-browser" / "start-tor-browser.desktop"
    if not launcher.is_file() or launcher.is_symlink():
        raise OfflineError("В официальном архиве не найден запуск Tor Browser.")
    return launcher


def _detach_mac_mount(mount):
    """Detach only this preparation's exact mount, with one bounded retry."""
    for force in (False, True):
        args = ["/usr/bin/hdiutil", "detach", *(["-force"] if force else []), str(mount)]
        try:
            result = subprocess.run(args, capture_output=True, timeout=60, check=False)
            if result.returncode == 0 and not os.path.ismount(mount):
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    raise _MountedVolumeError("Не удалось отключить временный образ Tor Browser. Его приватная папка сохранена. Извлеките образ через Дисковую утилиту и повторите подготовку. Браузер не открыт.")


def _private_layout(work, system):
    work = Path(work).absolute()
    marker = catalog.RELEASE_ID.encode("ascii")
    with _open_regular(work, ".oniondesk-managed", len(marker)) as source:
        if source.read(len(marker) + 1) != marker:
            raise OfflineError("Папка Tor Browser не принадлежит этой подготовке. Используйте новую копию из комплекта.")
    if system == "Darwin":
        resources = work / "Tor Browser.app/Contents/Resources"
        data = work / "TorBrowser-Data"
    elif system in {"Linux", "Windows"}:
        resources = work / ("tor-browser/Browser" if system == "Linux" else "Tor Browser/Browser")
        data = resources / "TorBrowser/Data"
    else:
        raise OfflineError("Эта операционная система не поддерживается.")
    return resources, data / "Browser/profile.default", data / "Tor"


def _inside_private_work(path, work):
    path, work = Path(path).absolute(), Path(work).absolute()
    try:
        path.relative_to(work)
    except ValueError as exc:
        raise OfflineError("Профиль Tor Browser должен находиться в собственной папке мастера.") from exc
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.resolve() != parent:
            raise OfflineError("Профиль Tor Browser содержит перенаправление. Подготовьте новую копию.")
    return path


def _noscript_package(resources, work):
    extension = _inside_private_work(resources / "distribution/extensions" / (_NOSCRIPT_ID + ".xpi"), work)
    size = extension.stat().st_size
    if not 0 < size <= 2 * 1024**2:
        raise OfflineError("В официальной копии не найден штатный NoScript. Запуск остановлен.")
    relative = extension.relative_to(Path(work).absolute()).as_posix()
    try:
        with _open_regular(work, relative, size) as source, zipfile.ZipFile(source) as package:
            info = package.getinfo("manifest.json")
            if not 0 < info.file_size <= 256 * 1024:
                raise OfflineError("Описание штатного NoScript повреждено.")
            manifest = json.loads(package.read(info))
        if not isinstance(manifest, dict):
            raise ValueError("Invalid manifest")
        settings = manifest.get("browser_specific_settings", manifest.get("applications", {}))
        gecko = settings.get("gecko", {}) if isinstance(settings, dict) else {}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        raise OfflineError("Не удалось прочитать штатный NoScript. Запуск остановлен.") from exc
    if not isinstance(gecko, dict) or gecko.get("id") != _NOSCRIPT_ID or not isinstance(manifest.get("version"), str):
        raise OfflineError("Не удалось подтвердить штатный NoScript. Запуск остановлен.")
    return manifest["version"]


def _prepare_private_profile(work, system):
    """Set only the vendor's connection settings in our fresh writable profile.

    Verified 15.0.25 TorSettings.sys.mjs maps BuiltIn to 0 and obtains obfs4
    descriptors from the publisher's signed pt_config.json. No fingerprinting,
    rendering, quickstart, TLS, or signed application files are changed.
    """
    resources, profile, tor_data = _private_layout(work, system)
    _inside_private_work(profile, work)
    _inside_private_work(tor_data, work)
    if system != "Windows":
        _noscript_package(resources, work)
    if system == "Linux":
        ini = profile.parent / "profiles.ini"
        size = ini.stat().st_size
        if not 0 < size <= 64 * 1024:
            raise OfflineError("Штатный профиль Tor Browser имеет неожиданный формат.")
        try:
            with _open_regular(work, ini.relative_to(Path(work).absolute()).as_posix(), size) as source:
                config = configparser.ConfigParser(interpolation=None, strict=True)
                config.read_string(source.read(64 * 1024 + 1).decode("utf-8"))
        except (configparser.Error, UnicodeDecodeError) as exc:
            raise OfflineError("Штатный профиль Tor Browser повреждён. Запуск остановлен.") from exc
        if not config.has_section("Profile0") or config["Profile0"].get("IsRelative") != "1" or \
                config["Profile0"].get("Path") != "profile.default" or config["Profile0"].get("Default") != "1" or not profile.is_dir():
            raise OfflineError("В комплекте изменён штатный профиль Tor Browser. Запуск остановлен.")
    usb._secure_directory(profile)
    target = profile / "user.js"
    try:
        # Never overwrite an existing profile preference file, even in a cache.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(_BRIDGE_PREFS)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as exc:
        raise OfflineError("В новой папке уже есть настройки Tor Browser. Подготовьте отдельную новую копию.") from exc
    return profile


def check_private_tor_runtime(work=None, timeout=5, system=None):
    """Bounded local assertions; pending is normal before first OS opening.

    This does not test connectivity. The launcher's separate HTTPS IsTor check
    remains the authority for accepting a Tor proxy. No socket or HTTP request
    is made here, and no private path is returned to the application UI.
    """
    selected = (work, system or platform.system()) if work is not None else _TOR_LAST_WORK
    pending = {"state": "pending", "noscript_active": False, "private_tor_data": False,
               "message": "Ожидаю первое открытие Tor Browser и создание его защищённого профиля."}
    if not selected:
        return pending
    work, system = selected
    deadline = time.monotonic() + min(30, max(0, float(timeout)))
    while True:
        try:
            resources, profile, tor_data = _private_layout(work, system)
            _inside_private_work(profile, work)
            _inside_private_work(tor_data, work)
            noscript = resources / "distribution/extensions" / (_NOSCRIPT_ID + ".xpi")
            if not resources.is_dir() or not noscript.is_file():
                result = pending
            else:
                _noscript_package(resources, work)
                extensions = profile / "extensions.json"
                active = False
                if extensions.exists():
                    size = extensions.stat().st_size
                    if not 0 < size <= 8 * 1024**2:
                        raise OfflineError("Не удалось проверить защитные расширения Tor Browser.")
                    with _open_regular(work, extensions.relative_to(Path(work).absolute()).as_posix(), size) as source:
                        metadata = json.loads(source.read(8 * 1024**2 + 1))
                    addons = metadata.get("addons", []) if isinstance(metadata, dict) else None
                    if not isinstance(addons, list) or len(addons) > 512 or any(not isinstance(item, dict) for item in addons):
                        raise OfflineError("Описание защитных расширений Tor Browser повреждено.")
                    entries = [item for item in addons if item.get("id") == _NOSCRIPT_ID]
                    if len(entries) > 1 or any(item.get("userDisabled") or item.get("appDisabled") for item in entries):
                        raise OfflineError("Штатный NoScript отключён. Закройте эту копию Tor Browser и подготовьте новую из комплекта.")
                    active = len(entries) == 1 and entries[0].get("active") is True
                private = tor_data.is_dir() and (tor_data / "state").is_file() and (tor_data / "lock").is_file()
                for name in ("state", "lock"):
                    if (tor_data / name).exists():
                        _inside_private_work(tor_data / name, work)
                        details = (tor_data / name).lstat()
                        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                            raise OfflineError("Данные Tor содержат неподходящий файл. Используйте новую отдельную копию.")
                verified = active and private
                result = {"state": "verified" if verified else "pending", "noscript_active": active,
                          "private_tor_data": private, "message": "Штатный NoScript активен, данные Tor находятся в отдельной папке мастера. Подключение к Tor проверяется отдельно." if verified else pending["message"]}
            if result["state"] == "verified" or time.monotonic() >= deadline:
                return result
        except (OfflineError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
            return {"state": "rejected", "noscript_active": False, "private_tor_data": False,
                    "message": str(exc) if isinstance(exc, OfflineError) else "Не удалось проверить отдельный профиль Tor Browser. Закройте эту копию и подготовьте новую."}
        time.sleep(0.2)


def _install_and_launch(binary, work):
    system = platform.system()
    if system == "Linux":
        launcher = _extract_linux(binary, work)
        profile = _prepare_private_profile(work, system)
        # The vendor's launcher handles its own relative libraries/profile.
        _assert_tor_ports_free()
        try:
            subprocess.Popen([str(launcher), "--detach", "--profile", str(profile)], cwd=launcher.parent,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            raise _BrowserLaunchError("Запуск Tor Browser не подтверждён. Подготовленная отдельная копия сохранена; закройте лишние окна браузера и повторите.") from exc
        return "Tor Browser подготовлен из проверенного комплекта с официальными мостами obfs4. В его окне нажмите «Подключиться» и дождитесь соединения, затем вернитесь в мастер."
    if system == "Darwin":
        mount = work / "mounted"
        mount.mkdir(mode=0o700)
        attached = False
        try:
            subprocess.run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", str(mount), str(binary)],
                           capture_output=True, timeout=180, check=True)
            attached = True
            app = mount / "Tor Browser.app"
            if not app.is_dir() or app.is_symlink():
                raise OfflineError("В официальном образе не найден Tor Browser.")
            destination = work / "Tor Browser.app"
            subprocess.run(["/usr/bin/ditto", str(app), str(destination)], capture_output=True, timeout=180, check=True)
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(destination)],
                           capture_output=True, timeout=180, check=True)
        finally:
            # An unsuccessful attach may nevertheless leave a mounted volume.
            # Never recursively remove a directory while its image is attached.
            if attached or os.path.ismount(mount):
                _detach_mac_mount(mount)
        profile = _prepare_private_profile(work, system)
        _assert_tor_ports_free()
        try:
            subprocess.run(["/usr/bin/open", "-n", str(destination), "--args", "--profile", str(profile)], capture_output=True, timeout=30, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise _BrowserLaunchError("Первое открытие Tor Browser ещё не подтверждено. Подготовленная отдельная копия сохранена. Подтвердите системное окно macOS и повторите проверку подключения.") from exc
        return "Tor Browser подготовлен из проверенного комплекта с официальными мостами obfs4. Подтвердите первое открытие macOS и нажмите «Подключиться». Вернитесь в мастер после установления соединения."
    if system == "Windows":
        # Use the publisher's interactive portable installer with a fresh private
        # destination. No existing Tor installation/profile is overwritten.
        destination = work / "Tor Browser"
        _assert_tor_ports_free()
        # The pinned portable NSIS payload contains profiles.ini and NoScript,
        # but no user.js. Its File /r operation preserves this new preference
        # file; the directory page asks Yes/No before using a nonempty folder.
        # tbb-15.0.25-build2: projects/browser/windows-installer/browser-portable.nsi
        profile = _prepare_private_profile(work, system)
        if not profile.is_relative_to(destination):
            raise OfflineError("Папка профиля установщика Tor Browser имеет неожиданный путь.")
        # NSIS requires an unquoted, final /D= value even for paths with spaces.
        # This is a CreateProcess command line, never a shell command.
        # https://nsis.sourceforge.io/Docs/Chapter3.html#installerusage
        command = subprocess.list2cmdline([str(binary)]) + " /D=" + str(destination)
        try:
            subprocess.Popen(command, executable=str(binary), cwd=work,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            raise _BrowserLaunchError("Открытие установщика Tor Browser не подтверждено. Подготовленная отдельная папка сохранена; повторите запуск мастера.") from exc
        return "Открыт проверенный официальный установщик Tor Browser. Оставьте указанную отдельную папку: в ней подготовлены мосты obfs4. Если установщик сообщит, что папка уже существует, подтвердите её использование. Завершите установку, откройте Tor Browser и нажмите «Подключиться», затем вернитесь в мастер."
    raise OfflineError("Эта операционная система не поддерживается.")


def prepare_tor(progress_cb=None):
    """Verify, prepare and launch the current OS's bundled official Tor Browser."""
    global _TOR_LAST_WORK
    if not _TOR_LOCK.acquire(blocking=False):
        raise OfflineError("Tor Browser уже подготавливается. Дождитесь завершения.")
    work, keep = None, False
    try:
        if _is_elevated():
            raise OfflineError("Откройте мастер от обычного пользователя. Tor Browser нельзя запускать с правами администратора.")
        _assert_tor_ports_free()
        assets = _tor_assets()
        root = _find_root()
        if root is None:
            raise OfflineError("Tor Browser отсутствует в комплекте. Распакуйте полный архив вместе с папкой OnionDesk-Data.")
        _check_manifest(root)
        cache = usb._secure_directory(_tor_cache())
        if shutil.disk_usage(cache).free < MAX_EXTRACT_BYTES + 300 * 1024**2:
            raise OfflineError("Для подготовки Tor Browser освободите не меньше 2,5 ГБ на компьютере.")
        work = Path(tempfile.mkdtemp(prefix=f"tor-{catalog.TOR_VERSION}-", dir=cache))
        (work / ".oniondesk-managed").write_text(catalog.RELEASE_ID, encoding="ascii")
        files = {}
        _emit(progress_cb, "offline", "Tor Browser уже в комплекте. Проверяю официальный файл…", 0)
        for kind, name in assets.items():
            target = work / PurePosixPath(catalog.ASSETS[name]["path"]).name
            files[kind] = _copy_asset(root, name, target, progress_cb if kind == "binary" else None)
        _emit(progress_cb, "signature", "Проверяю подпись издателя Tor Browser…", 95)
        _verify_tor_signature(files["binary"], files["signature"], files["key"])
        _emit(progress_cb, "install", "Подготавливаю отдельную копию Tor Browser для этого пользователя…", 98)
        message = _install_and_launch(files["binary"], work)
        keep = True
        _TOR_LAST_WORK = (work, platform.system())
        _emit(progress_cb, "complete", message, 100)
        return {"message": message}
    except (_MountedVolumeError, _BrowserLaunchError):
        # Preserve a mounted image or a possibly active browser and its profile.
        keep = True
        raise
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as exc:
        raise OfflineError("Не удалось подготовить Tor Browser. Проверьте свободное место, распакуйте полный комплект и повторите.") from exc
    finally:
        if work is not None and not keep:
            shutil.rmtree(work, ignore_errors=True)
        _TOR_LOCK.release()
