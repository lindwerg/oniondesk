"""Verified Tails download and explicit USB selection. No writes on discovery.

The image signature, never an unsigned download checksum alone, is the trust
boundary. The privileged helper repeats validation before opening a USB device.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urljoin, urlsplit

CLIENT = Path(__file__).resolve().parent


def _default_cache():
    if not getattr(sys, "frozen", False):
        return CLIENT / "data" / "tails"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Caches" / "OnionDesk" / "tails"
    if platform.system() == "Windows":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "OnionDesk" / "tails"
    return Path.home() / ".cache" / "OnionDesk" / "tails"


CACHE = _default_cache()
LATEST_URL = "https://tails.net/install/v2/Tails/amd64/stable/latest.json"
KEY_URL = "https://tails.net/tails-signing.key"
PUBLISHER_FINGERPRINT = "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"
MIN_VERSION = (7, 15)
MIN_USB_BYTES = 8_000_000_000
MAX_IMAGE_BYTES = 8 * 1024**3
CHUNK = 1024 * 1024
_SELECTIONS: dict[str, dict] = {}
_ARTIFACT: dict | None = None
_STATE_LOCK = threading.Lock()
_DOWNLOAD_LOCK = threading.Lock()
_WRITE_LOCK = threading.Lock()
_ACTIVE_HELPER = None


class USBError(RuntimeError):
    """A user-readable error; an unsafe operation is always refused."""


class USBCancelled(USBError):
    pass


def _emit(callback, stage, message, percent=None, **extra):
    if callback:
        callback({"stage": stage, "message": message, "percent": percent, **extra})


def _cancel(event, writing=False):
    if event is not None and event.is_set():
        if writing:
            raise USBCancelled("Запись прервана. На флешке может быть неполный образ; перед загрузкой запишите её заново.")
        raise USBCancelled("Подготовка отменена. Флешка не изменена.")


def _run(args, timeout=30, max_output=16 * 1024**2):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise USBError("Системная проверка носителей не завершилась. Повторите попытку.") from exc
    if result.returncode or len(result.stdout) > max_output:
        raise USBError("Не удалось безопасно проверить USB-носители. Закройте программы, использующие флешку, и повторите.")
    return result.stdout


def _find_gpg():
    # In particular, never elevate an arbitrary gpg.exe found in the current
    # directory/PATH. Windows Gpg4win uses these installation directories.
    if platform.system() == "Windows":
        # Windows GPG runs elevated. Neither caller environment variables nor
        # a mutable application-adjacent tools folder is a trusted installation.
        return _find_windows_gpg()
    bundle = Path(getattr(sys, "_MEIPASS", CLIENT)).resolve()
    bundled = bundle / "tools" / "gpg" / "bin" / "gpg"
    configured = os.environ.get("ONIONDESK_GPG")
    for path in ([Path(configured)] if configured else []) + [bundled]:
        if path.is_file() and _inside(path, bundle) and _inside(path, bundle / "tools" / "gpg") and os.access(path, os.X_OK):
            return str(path.resolve())
    if platform.system() == "Darwin":
        candidates = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg"]
    else:
        candidates = ["/usr/bin/gpg", "/bin/gpg"]
    found = next((str(Path(p).resolve()) for p in candidates if Path(p).is_file()), None)
    if found:
        return found
    # Unix callers may use a package-managed installation outside usual roots.
    # The helper runs it with the invoking user's privileges, never as root.
    if platform.system() != "Windows":
        return shutil.which("gpg")
    return None


def _windows_known_folders():
    """Program Files locations from the OS, never caller-controlled env vars."""
    import ctypes
    from ctypes import wintypes as wt
    import uuid
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wt.DWORD, wt.HANDLE, ctypes.POINTER(wt.LPWSTR)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole.CoTaskMemFree.restype = None
    folders = []
    for guid in ("905e63b6-c1bf-494e-b29c-65b732d3d21a", "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e"):
        identifier = ctypes.create_string_buffer(uuid.UUID(guid).bytes_le, 16)
        result = wt.LPWSTR()
        status = shell.SHGetKnownFolderPath(identifier, 0, None, ctypes.byref(result))
        try:
            if status == 0 and result.value:
                folder = Path(result.value)
                if folder.is_absolute() and folder.drive and not str(folder).startswith("\\\\"):
                    folders.append(folder)
        finally:
            if result:
                ole.CoTaskMemFree(ctypes.cast(result, ctypes.c_void_p))
    return folders


def _windows_security(path):
    """Read owner and DACL; unfamiliar ACE formats are handled fail closed."""
    import ctypes
    from ctypes import wintypes as wt
    import struct
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    security.GetNamedSecurityInfoW.argtypes = [wt.LPWSTR, ctypes.c_int, wt.DWORD,
            ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
    security.GetNamedSecurityInfoW.restype = wt.DWORD
    security.GetAce.argtypes = [pointer, wt.DWORD, ctypes.POINTER(pointer)]
    security.GetAce.restype = wt.BOOL
    security.IsValidSid.argtypes = [pointer]
    security.IsValidSid.restype = wt.BOOL
    security.GetLengthSid.argtypes = [pointer]
    security.GetLengthSid.restype = wt.DWORD
    security.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wt.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wt.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    def sid_string(sid):
        if not sid or not security.IsValidSid(sid):
            raise USBError("Windows не смогла проверить владельца GnuPG.")
        value = wt.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise USBError("Windows не смогла проверить права GnuPG.")
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, pointer))
    owner, dacl, descriptor = pointer(), pointer(), pointer()
    status = security.GetNamedSecurityInfoW(str(path), 1, 0x5, ctypes.byref(owner), None,
                                            ctypes.byref(dacl), None, ctypes.byref(descriptor))
    try:
        if status or not descriptor or not owner or not dacl:
            raise USBError("Windows не смогла подтвердить защищённую установку GnuPG.")
        revision, _, acl_size, count, _ = struct.unpack("BBHHH", ctypes.string_at(dacl, 8))
        if revision not in (2, 4) or acl_size < 8 or count > 1024:
            raise USBError("Неизвестный формат прав доступа GnuPG.")
        aces = []
        for index in range(count):
            ace = pointer()
            if not security.GetAce(dacl, index, ctypes.byref(ace)) or not ace:
                raise USBError("Не удалось прочитать права доступа GnuPG.")
            kind, flags, size = struct.unpack("BBH", ctypes.string_at(ace, 4))
            if kind not in (0, 1):
                aces.append((kind, flags, 0, ""))
                continue
            if size < 16:
                raise USBError("Повреждены права доступа GnuPG.")
            mask = struct.unpack("I", ctypes.string_at(ace.value + 4, 4))[0]
            sid = pointer(ace.value + 8)
            if not security.IsValidSid(sid) or security.GetLengthSid(sid) > size - 8:
                raise USBError("Повреждены сведения о владельце GnuPG.")
            aces.append((kind, flags, mask, sid_string(sid)))
        return sid_string(owner), aces
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def _windows_trusted_sids():
    # Fixed security identities avoid account-name lookups that Windows could
    # forward to a domain controller. TrustedInstaller's SID is documented in
    # Microsoft's WindowsAppSDK ApplicationData specification.
    # https://github.com/microsoft/WindowsAppSDK/blob/main/specs/applicationdata/ApplicationData.md
    return {"S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}


def _windows_attributes(path):
    import ctypes
    from ctypes import wintypes as wt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wt.LPCWSTR]
    kernel.GetFileAttributesW.restype = wt.DWORD
    value = kernel.GetFileAttributesW(str(path))
    if value == 0xFFFFFFFF:
        raise USBError("Windows не смогла проверить путь GnuPG.")
    return value


def _windows_acl_trusted(owner, aces, trusted, volume_root=False):
    if owner not in trusted or aces is None:
        return False
    # Data/append/EA/attributes, delete-child/delete, DACL/owner, generic write/all.
    modifying = 0x2 | 0x4 | 0x10 | 0x100 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
    if volume_root:
        # Creating an unrelated subdirectory in C:\ cannot replace an existing
        # protected Program Files child. All other modification rights count.
        modifying &= ~0x4
    for kind, flags, mask, sid in aces:
        if kind not in (0, 1):
            return False  # Object/callback/conditional ACEs need a full evaluator.
        if flags & 0x8 or kind == 1:  # INHERIT_ONLY_ACE, ACCESS_DENIED_ACE.
            continue
        if mask & modifying and sid not in trusted:
            return False
    return True


def _windows_trusted_gpg(path, installation_root):
    path, root = Path(path).absolute(), Path(installation_root).absolute()
    if not _inside(path, root) or path.is_symlink():
        return False
    trusted = _windows_trusted_sids()
    for current in (path, *path.parents):
        attributes = _windows_attributes(current)
        if attributes & 0x400 or (current == path and attributes & 0x10):  # REPARSE_POINT, DIRECTORY.
            return False
        owner, aces = _windows_security(current)
        if not _windows_acl_trusted(owner, aces, trusted, volume_root=current == Path(current.anchor)):
            return False
    return True


def _find_windows_gpg():
    try:
        roots = _windows_known_folders()
        for root in roots:
            for folder in ("OnionDesk/tools/gpg", "GnuPG", "Gpg4win"):
                path = root / folder / "bin" / "gpg.exe"
                if path.is_file() and _windows_trusted_gpg(path, root):
                    return str(path.absolute())
    except (USBError, OSError, AttributeError, ValueError):
        pass  # Unknown Windows security state is unavailable, never a fallback.
    return None


def system_info():
    system, machine = platform.system(), platform.machine().lower()
    native_x86 = machine in {"x86_64", "amd64"}
    if system == "Darwin" and native_x86:
        try:
            native_x86 = _run(["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"]).strip() != b"1"
        except USBError:
            pass  # sysctl.proc_translated is absent on Intel Macs.
    message = ("Tails рассчитан на компьютеры с процессором Intel/AMD x86-64; совместимость конкретной модели проверяется при загрузке."
               if native_x86 else
               "Tails не загружается на Apple Silicon и других ARM-компьютерах. Здесь можно подготовить флешку для компьютера Intel/AMD x86-64.")
    verifier = _find_gpg()
    return {"platform": system, "architecture": machine,
            "supported": system in {"Windows", "Darwin", "Linux"},
            "tails_can_boot_here": native_x86, "boot_message": message,
            "verifier_available": bool(verifier),
            "verifier_message": "Проверка подписи доступна." if verifier else
            "Нужна установленная GnuPG: Gpg4win на Windows, GPG Suite или GnuPG на macOS, пакет gnupg на Linux. После установки откройте мастер заново.",
            "minimum_usb_bytes": MIN_USB_BYTES,
            "download_notice": "Сначала мастер проверит официальный образ Tails из комплекта без Интернета. Если офлайн-файлов нет, загрузка доступна только через подключённый Tor Browser. Прямого соединения и локального DNS не будет."}


def _secure_directory(path):
    path = Path(path).absolute()
    # Reject symlinks/junction-like redirection in every existing ancestor.
    for parent in reversed((path, *path.parents)):
        if parent.exists() and (parent.is_symlink() or parent.resolve() != parent):
            raise USBError("Папка загрузки содержит ссылку. Переместите комплект в обычную локальную папку.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def _inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def _protected_paths(extra=()):
    return [CLIENT, CACHE, Path(sys.executable).resolve(), *[Path(x).resolve() for x in extra]]


def _system_mount(mount):
    if not mount:
        return False
    mount = str(mount).rstrip("/") or "/"
    return mount == "/" or any(mount == p or mount.startswith(p + "/")
                               for p in ("/boot", "/usr", "/var", "/etc", "/home", "/opt", "/System", "/Library", "/private"))


def _guard_disk(disk, extra=()):
    if disk.get("bus") != "usb" or not disk.get("whole") or disk.get("internal") is not False:
        raise USBError("Разрешены только целые внешние USB-носители.")
    if any(disk.get(flag) for flag in ("system", "boot", "swap", "readonly", "complex")):
        raise USBError("Этот носитель используется системой или защищён от записи.")
    if disk.get("size_bytes", 0) < MIN_USB_BYTES:
        raise USBError("Нужна флешка объёмом не меньше 8 ГБ.")
    serial = str(disk.get("serial", "")).strip()
    if not serial or set(serial) <= {"0", " ", "-"} or not disk.get("hardware"):
        raise USBError("Флешка не сообщает надёжный серийный номер. Для безопасной записи используйте другой USB-носитель.")
    for mount in disk.get("mounts", []):
        if _system_mount(mount) or any(_inside(p, mount) for p in _protected_paths(extra)):
            raise USBError("На этом носителе находится система, программа или скачанный образ. Выберите другую флешку.")
    if disk.get("protected_device"):
        raise USBError("Носитель содержит программу или образ; запись на него запрещена.")
    return disk


def _identity(disk):
    material = [disk["platform"], disk["native_id"], disk["serial"], disk["hardware"],
                disk["size_bytes"], disk.get("device_number"), disk.get("sector_size")]
    return hashlib.sha256(json.dumps(material, ensure_ascii=True, sort_keys=True).encode()).hexdigest()


def _flatten(node):
    yield node
    for child in node.get("children", []):
        yield from _flatten(child)


def _linux_disks(extra=()):
    columns = "NAME,KNAME,PATH,MAJ:MIN,SIZE,TYPE,TRAN,SERIAL,WWN,MODEL,RM,RO,MOUNTPOINTS,FSTYPE,LOG-SEC"
    tree = json.loads(_run(["/usr/bin/lsblk", "--json", "--bytes", "--tree", "--output", columns]))
    protected_dev = {os.stat(p).st_dev for p in _protected_paths(extra) if p.exists()}
    swap_devices = set()
    for line in Path("/proc/swaps").read_text().splitlines()[1:]:
        filename = line.split()[0]
        filename = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), filename)
        info = os.stat(filename)
        swap_devices.add(info.st_rdev if stat.S_ISBLK(info.st_mode) else info.st_dev)
    disks = []
    for node in tree.get("blockdevices", []):
        if node.get("type") != "disk" or node.get("tran") != "usb":
            continue
        name = node.get("kname", "")
        if not re.fullmatch(r"sd[a-z]+", name):
            continue
        entries = list(_flatten(node))
        mounts = [m for entry in entries for m in (entry.get("mountpoints") or []) if m and m != "[SWAP]"]
        numbers = [x.get("maj:min", "") for x in entries]
        protected = any(re.fullmatch(r"\d+:\d+", num) and
                        os.makedev(*map(int, num.split(":"))) in protected_dev for num in numbers)
        active_swap = any(re.fullmatch(r"\d+:\d+", num) and
                          os.makedev(*map(int, num.split(":"))) in swap_devices for num in numbers)
        sysfs = Path("/sys/class/block") / name
        topology = str((sysfs / "device").resolve())
        holders = any(list((Path("/sys/class/block") / entry.get("kname", "") / "holders").glob("*"))
                      for entry in entries)
        disks.append({"platform": "Linux", "native_id": name, "path": f"/dev/{name}",
                      "name": (node.get("model") or "USB-носитель").strip(),
                      "size_bytes": int(node["size"]), "serial": (node.get("serial") or "").strip(),
                      "hardware": [topology, node.get("wwn") or ""], "device_number": node.get("maj:min"),
                      "sector_size": int(node.get("log-sec") or 512), "mounts": mounts,
                      "partitions": [x["path"] for x in entries[1:] if x.get("type") == "part"],
                      "mounted_devices": [x["path"] for x in entries if any(m and m != "[SWAP]" for m in (x.get("mountpoints") or []))],
                      "bus": "usb", "whole": True, "internal": False,
                      "readonly": bool(node.get("ro")), "protected_device": protected,
                      "complex": holders or any(x.get("type") not in {"disk", "part"} for x in entries),
                      "swap": active_swap or any(x.get("fstype") == "swap" or "[SWAP]" in (x.get("mountpoints") or []) for x in entries)})
    return disks


def _mac_hardware():
    roots = plistlib.loads(_run(["/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOUSBHostDevice"], max_output=64 * 1024**2))
    result = {}
    def visit(node, serial="", hardware=None):
        serial = str(node.get("USB Serial Number", serial)).strip()
        if "USB Serial Number" in node:
            hardware = [node.get("IORegistryEntryID"), node.get("locationID"), node.get("idVendor"), node.get("idProduct")]
        bsd = node.get("BSD Name")
        if bsd and serial and hardware:
            result[bsd] = (serial, hardware)
        for child in node.get("IORegistryEntryChildren", []):
            visit(child, serial, hardware)
    for root in roots:
        visit(root)
    return result


def _mac_disks(extra=()):
    listing = plistlib.loads(_run(["/usr/sbin/diskutil", "list", "-plist", "external", "physical"]))
    if not listing.get("AllDisksAndPartitions"):
        return []
    hardware = _mac_hardware()
    disks = []
    for node in listing.get("AllDisksAndPartitions", []):
        name = node.get("DeviceIdentifier", "")
        if not re.fullmatch(r"disk\d+", name):
            continue
        info = plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", name]))
        if info.get("BusProtocol") != "USB":
            continue
        partitions = node.get("Partitions", [])
        mounts = []
        for part in partitions:
            pid = part.get("DeviceIdentifier", "")
            if not re.fullmatch(r"disk\d+s\d+", pid):
                raise USBError("Не удалось распознать разделы USB-носителя.")
            details = plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", pid]))
            if details.get("MountPoint"):
                mounts.append(details["MountPoint"])
        serial, hw = hardware.get(name, ("", None))
        disks.append({"platform": "Darwin", "native_id": name, "path": f"/dev/r{name}",
                      "name": info.get("MediaName", "USB-носитель"), "size_bytes": int(info.get("TotalSize", 0)),
                      "serial": serial, "hardware": hw, "sector_size": int(info.get("DeviceBlockSize", 512)),
                      "mounts": mounts, "partitions": [p["DeviceIdentifier"] for p in partitions],
                      "bus": "usb", "whole": info.get("Whole") is True,
                      "internal": info.get("Internal"), "readonly": info.get("Writable") is not True,
                      "complex": any(p.get("Content") in {"Apple_APFS", "Apple_CoreStorage", "Apple_RAID", "Apple_RAID_Offline"} for p in partitions)})
    return disks


def _windows_disks(extra=()):
    # Fixed script: no names, paths, or untrusted values interpolated in PowerShell.
    script = r"""$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new();
    $pages=@(Get-CimInstance Win32_PageFileUsage | ForEach-Object {$_.Name});
    $out=@(Get-Disk | Where-Object {$_.BusType -eq 'USB'} | ForEach-Object {
      $d=$_; $p=@(Get-Partition -DiskNumber $d.Number -ErrorAction Stop);
      [pscustomobject]@{Number=$d.Number;Name=$d.FriendlyName;Size=$d.Size;Serial=$d.SerialNumber;
        UniqueId=$d.UniqueId;Location=$d.Location;Sector=$d.LogicalSectorSize;ReadOnly=$d.IsReadOnly;
        Boot=$d.IsBoot;System=$d.IsSystem;Offline=$d.IsOffline;Paths=@($p|ForEach-Object {$_.AccessPaths});Pages=$pages}
    }); ConvertTo-Json -InputObject $out -Depth 5 -Compress"""
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    rows = json.loads(_run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]))
    disks = []
    for row in rows:
        paths = row.get("Paths") or []
        mounts = [p for p in paths if re.fullmatch(r"[A-Za-z]:\\", p) or not p.startswith("\\\\?\\Volume{")]
        volumes = [p.rstrip("\\") for p in paths if re.fullmatch(r"\\\\\?\\Volume\{[A-Fa-f0-9-]+\}\\", p)]
        protected = any(str(p).lower().startswith(m.lower()) for p in _protected_paths(extra) for m in mounts)
        swap = any(page.lower().startswith(m.lower()) for page in row.get("Pages", []) for m in mounts)
        disks.append({"platform": "Windows", "native_id": str(int(row["Number"])),
                      "path": rf"\\.\PhysicalDrive{int(row['Number'])}", "name": str(row.get("Name") or "USB-носитель").strip(),
                      "size_bytes": int(row["Size"]), "serial": str(row.get("Serial") or "").strip(),
                      "hardware": [row.get("UniqueId"), row.get("Location")], "sector_size": int(row.get("Sector") or 512),
                      "mounts": mounts, "volumes": sorted(set(volumes)), "bus": "usb", "whole": True, "internal": False,
                      "boot": bool(row.get("Boot")), "system": bool(row.get("System")), "swap": swap,
                      "readonly": bool(row.get("ReadOnly")), "complex": bool(row.get("Offline")),
                      "protected_device": protected})
    return disks


def _scan_disks(extra=()):
    system = platform.system()
    try:
        if system == "Linux":
            return _linux_disks(extra)
        if system == "Darwin":
            return _mac_disks(extra)
        if system == "Windows":
            return _windows_disks(extra)
    except (KeyError, TypeError, ValueError, OSError, plistlib.InvalidFileException) as exc:
        raise USBError("Система вернула неполные сведения о дисках. Безопасная запись пока недоступна.") from exc
    raise USBError("Подготовка флешки поддерживается на Windows, macOS и Linux.")


def list_usb_disks():
    safe = []
    for disk in _scan_disks():
        try:
            _guard_disk(disk)
        except USBError:
            continue
        disk["identity"] = _identity(disk)
        with _STATE_LOCK:
            token = next((key for key, old in _SELECTIONS.items() if old["identity"] == disk["identity"]), None)
            if token is None:
                token = secrets.token_urlsafe(24)
            _SELECTIONS[token] = disk
        safe.append({"id": token, "name": disk["name"], "size_bytes": disk["size_bytes"],
                     "identity": disk["identity"], "platform": disk["platform"]})
    return safe


def _revalidate(selection, extra=()):
    for disk in _scan_disks(extra):
        if disk["platform"] == selection.get("platform") and disk["native_id"] == selection.get("native_id"):
            _guard_disk(disk, extra)
            if disk["size_bytes"] != selection.get("size_bytes") or _identity(disk) != selection.get("identity"):
                raise USBError("Флешка изменилась после выбора. Обновите список и выберите её заново.")
            return disk
    raise USBError("Выбранная флешка отключена. Подключите её, обновите список и выберите заново.")


def _validate_url(url, image=False):
    parsed = urlsplit(url)
    hosts = {"tails.net"} if not image else {"download.tails.net", "tails.net"}
    if parsed.scheme != "https" or parsed.hostname not in hosts or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
        raise USBError("Сайт Tails вернул неожиданный адрес. Загрузка остановлена.")
    return url


def _mirror_url(url, image_name):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or "." not in parsed.hostname or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment or not parsed.path.endswith("/" + image_name):
        raise USBError("Официальный сервер загрузки вернул неожиданный адрес зеркала.")
    return url


def _verified_tor_port():
    # Reuse the HTTPS IsTor check. It uses socks5h and trust_env=False, and
    # probes only numeric loopback endpoints; there is no direct fallback.
    try:
        from launcher import find_tor_proxy
        port = find_tor_proxy()
    except (ImportError, RuntimeError, OSError) as exc:
        raise USBError("Откройте Tor Browser и подключитесь к Tor, затем повторите загрузку. Прямого подключения не будет.") from exc
    if port not in (9150, 9050):
        raise USBError("Не удалось подтвердить локальный маршрут Tor. Откройте Tor Browser и подключитесь к Tor.")
    return port


def _receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise USBError("Tor вернул неполный ответ при проверке адреса загрузки. Подключитесь к Tor и повторите.")
        result.extend(chunk)
    return bytes(result)


def _public_ip(address):
    import ipaddress
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise USBError("Tor вернул некорректный IP-адрес загрузки.") from exc
    if not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, "ipv4_mapped", None):
        raise USBError("Адрес сервера загрузки не является публичным; загрузка запрещена.")
    return str(ip)


def _tor_resolve(hostname, tor_port):
    # Tor's SOCKS extension: RFC 1928 framing with RESOLVE command 0xF0.
    # https://spec.torproject.org/socks-extensions.html#name-lookup
    # Crucially, this socket connects only to a numeric loopback IP, never to
    # the destination hostname. DNS is performed by Tor's exit, not the OS.
    if tor_port not in (9150, 9050):
        raise USBError("Недопустимый локальный порт Tor; загрузка запрещена.")
    try:
        encoded = hostname.encode("idna")
    except (AttributeError, UnicodeError) as exc:
        raise USBError("Не удалось распознать имя официального сервера загрузки.") from exc
    if not 1 <= len(encoded) <= 253 or not re.fullmatch(rb"[A-Za-z0-9.-]+", encoded):
        raise USBError("Некорректное имя сервера загрузки.")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            connection.connect(("127.0.0.1", tor_port))
            connection.sendall(b"\x05\x01\x00")
            if _receive_exact(connection, 2) != b"\x05\x00":
                raise USBError("Локальный Tor не принял безопасный запрос SOCKS5. Перезапустите Tor Browser и подключитесь.")
            connection.sendall(b"\x05\xf0\x00\x03" + bytes([len(encoded)]) + encoded + b"\x00\x00")
            version, status, reserved, address_type = _receive_exact(connection, 4)
            if version != 5 or reserved != 0 or status != 0 or address_type not in (1, 4):
                raise USBError("Tor не смог безопасно определить адрес сервера загрузки. Повторите после подключения к Tor.")
            address = _receive_exact(connection, 4 if address_type == 1 else 16)
            _receive_exact(connection, 2)  # SOCKS5 bound port, unused for RESOLVE.
            import ipaddress
            return _public_ip(ipaddress.ip_address(address))
    except OSError as exc:
        raise USBError("Откройте Tor Browser и подключитесь к Tor, затем повторите загрузку. Прямого подключения не будет.") from exc


def _public_request(url, tor_port=None):
    import certifi
    import urllib3
    from urllib3.contrib.socks import SOCKSProxyManager
    parsed = urlsplit(url)
    port = _verified_tor_port() if tor_port is None else tor_port
    address = _tor_resolve(parsed.hostname, port)
    # The pool's destination is the exact remotely resolved public IP, so
    # PySocks cannot re-resolve the hostname. TLS and HTTP retain the original
    # hostname. All connections go through the fixed numeric loopback proxy.
    manager = SOCKSProxyManager(f"socks5h://127.0.0.1:{port}", server_hostname=parsed.hostname,
                assert_hostname=parsed.hostname, cert_reqs="CERT_REQUIRED", ca_certs=certifi.where(),
                timeout=urllib3.Timeout(connect=30, read=60))
    pool = manager.connection_from_host(address, port=443, scheme="https")
    try:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        response = pool.urlopen("GET", target, headers={"Host": parsed.hostname, "Accept-Encoding": "identity"},
                                preload_content=False, redirect=False, retries=False, assert_same_host=False)
        return response, pool
    except urllib3.exceptions.HTTPError as exc:
        pool.close()
        raise USBError("Загрузка через Tor не завершилась. Подключите Tor Browser и повторите; прямого подключения не будет.") from exc


def _fetch(url, destination, limit, callback=None, cancel_event=None, image=False, expected_size=None, tor_port=None):
    import urllib3
    response = pool = None
    image_name = urlsplit(url).path.rsplit("/", 1)[-1]
    mirror = False
    try:
        port = _verified_tor_port() if tor_port is None else tor_port
        for _ in range(6):
            _cancel(cancel_event)
            if mirror:
                _mirror_url(url, image_name)
            else:
                _validate_url(url, image)
            response, pool = _public_request(url, port)
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                origin = urlsplit(url).hostname
                response.close()
                pool.close()
                response = pool = None
                if not location or mirror:
                    raise USBError("Неожиданное перенаправление зеркала Tails. Повторите загрузку.")
                redirected = urljoin(url, location)
                if image and origin == "download.tails.net" and urlsplit(redirected).hostname not in {"tails.net", "download.tails.net"}:
                    _mirror_url(redirected, image_name)
                    mirror = True  # Only the official TLS redirector chooses it.
                else:
                    _validate_url(redirected, image)
                url = redirected
                continue
            if response.status != 200:
                raise USBError("Официальная загрузка Tails временно недоступна. Повторите позже.")
            break
        else:
            raise USBError("Слишком много перенаправлений сайта Tails.")
        declared = int(response.headers.get("Content-Length") or 0)
        if declared > limit or (expected_size and declared and declared != expected_size):
            raise USBError("Размер загрузки не соответствует официальному описанию.")
        total = expected_size or declared
        done = 0
        digest = hashlib.sha256()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(destination, flags, 0o600), "wb") as output:
            for chunk in response.stream(CHUNK, decode_content=False):
                _cancel(cancel_event)
                if not chunk:
                    continue
                done += len(chunk)
                if done > limit:
                    raise USBError("Загрузка превышает допустимый размер.")
                output.write(chunk)
                digest.update(chunk)
                _emit(callback, "download", "Скачиваю официальный образ Tails…", int(done * 100 / total) if total else None,
                      bytes_done=done, bytes_total=total or None)
            output.flush()
            os.fsync(output.fileno())
        if expected_size and done != expected_size:
            raise USBError("Образ скачался не полностью. Повторите загрузку.")
        return digest.hexdigest()
    except (urllib3.exceptions.HTTPError, OSError) as exc:
        raise USBError("Не удалось скачать Tails через Tor. Подключите Tor Browser и повторите; прямого подключения не будет, запись не началась.") from exc
    finally:
        if response is not None:
            response.close()
        if pool is not None:
            pool.close()


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value):
        raise USBError("Не удалось распознать текущую версию Tails.")
    return tuple(int(p) for p in value.split("."))


def _parse_release(metadata):
    if metadata.get("product-name") != "Tails" or metadata.get("build_target") != "amd64" or metadata.get("channel") != "stable":
        raise USBError("Официальное описание Tails имеет неожиданный формат.")
    installs = metadata.get("installations", [])
    if len(installs) != 1 or _version(installs[0].get("version")) < MIN_VERSION:
        raise USBError("Сайт предлагает устаревшую или неоднозначную версию Tails.")
    version = installs[0]["version"]
    files = [item for path in installs[0].get("installation-paths", []) if path.get("type") == "img"
             for item in path.get("target-files", [])]
    if len(files) != 1:
        raise USBError("Не удалось найти единственный официальный USB-образ Tails.")
    item = files[0]
    expected_url = f"https://download.tails.net/tails/stable/tails-amd64-{version}/tails-amd64-{version}.img"
    if item.get("url") != expected_url or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) or not isinstance(item.get("size"), int) or not 1024**3 < item["size"] < MAX_IMAGE_BYTES:
        raise USBError("Официальное описание USB-образа не прошло проверку.")
    return {"version": version, "url": expected_url, "size_bytes": item["size"], "sha256": item["sha256"]}


def _open_regular(path):
    path = Path(path).absolute()
    if not _inside(path, CACHE) or path.resolve() != path:
        raise USBError("Образ должен находиться в собственной папке загрузки мастера без ссылок.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        os.close(fd)
        raise USBError("Файл образа имеет неподходящий тип или дополнительные ссылки.")
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes as wt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetFinalPathNameByHandleW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD]
        kernel.GetFinalPathNameByHandleW.restype = wt.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        actual = buffer.value.removeprefix("\\\\?\\")
        if not length or length >= len(buffer) or os.path.normcase(actual) != os.path.normcase(str(path)):
            os.close(fd)
            raise USBError("Файл перенаправлен на другой путь; запись запрещена.")
    return os.fdopen(fd, "rb"), details


def _hash_file(path, cancel_event=None):
    digest = hashlib.sha256()
    with _open_regular(path)[0] as source:
        while chunk := source.read(CHUNK):
            _cancel(cancel_event)
            digest.update(chunk)
    return digest.hexdigest()


def _valid_signature(status_output):
    lines = [line.split()[1:] for line in status_output.splitlines() if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"}
    if any(line and line[0] in rejected for line in lines):
        return False
    good = any(line and line[0] == "GOODSIG" for line in lines)
    valid = [line[1:] for line in lines if line and line[0] == "VALIDSIG"]
    # VALIDSIG's final primary-key fingerprint binds an Ed25519 subkey to the
    # pinned primary publisher key. SHA-1/MD5 signature digests are rejected.
    return good and len(valid) == 1 and len(valid[0]) >= 10 and \
        valid[0][9] == PUBLISHER_FINGERPRINT and valid[0][7] in {"8", "9", "10", "11"}


def _verify_signature(image, signature, key, gpg=None, parent=None, run_as=None):
    gpg = gpg or _find_gpg()
    if not gpg:
        raise USBError(system_info()["verifier_message"])
    # GnuPG uses Unix sockets whose path length is bounded (~104 bytes on macOS).
    # An extracted application folder can be much longer, so keyrings use a
    # short private temporary directory; downloaded artifacts remain in CACHE.
    short_tmp = None if os.name == "nt" else ("/private/tmp" if platform.system() == "Darwin" else "/tmp")
    with tempfile.TemporaryDirectory(prefix="tails-gpg-", dir=parent or short_tmp) as home:
        os.chmod(home, 0o700)
        options = {}
        if run_as and os.name != "nt" and os.geteuid() == 0 and run_as[0] != 0:
            uid, gid = run_as
            os.chown(home, uid, gid)
            # Native subprocess credential changes avoid a Python callback after
            # fork, which can deadlock while the helper's IPC reader is running.
            options.update(user=uid, group=gid, extra_groups=[])
        base = [gpg, "--no-options", "--homedir", home, "--batch", "--no-tty", "--no-autostart", "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        def execute(args):
            try:
                return subprocess.run(base + args, capture_output=True, timeout=600, check=False, **options)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise USBError("GnuPG не смогла проверить подпись. Запись запрещена.") from exc
        shown = execute(["--with-colons", "--import-options", "show-only", "--import", str(key)])
        primary = []
        want_fingerprint = False
        for line in shown.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                want_fingerprint = True
            elif fields[0] == "fpr" and want_fingerprint:
                primary.append(fields[9])
                want_fingerprint = False
        if shown.returncode or primary != [PUBLISHER_FINGERPRINT]:
            raise USBError("Ключ издателя Tails не совпадает с закреплённым ключом. Запись запрещена.")
        imported = execute(["--import", str(key)])
        if imported.returncode:
            raise USBError("Ключ Tails не удалось прочитать. Запись запрещена.")
        checked = execute(["--status-fd", "1", "--verify", str(signature), str(image)])
        if checked.returncode or not _valid_signature(checked.stdout.decode("utf-8", "replace")):
            raise USBError("Подпись образа Tails не прошла проверку. Этот файл записывать нельзя; повторите загрузку.")


def download_verified_image(progress_cb=None, cancel_event=None):
    global _ARTIFACT
    if not _DOWNLOAD_LOCK.acquire(blocking=False):
        raise USBError("Загрузка уже выполняется.")
    work = None
    try:
        with _STATE_LOCK:
            _ARTIFACT = None
        _cancel(cancel_event)
        if not _find_gpg():
            raise USBError(system_info()["verifier_message"])
        from offline_bundle import prepare_tails
        bundled = prepare_tails(CACHE, progress_cb, cancel_event)
        if bundled is not None:
            with _STATE_LOCK:
                _ARTIFACT = bundled
            return {k: bundled[k] for k in ("path", "sha256", "size_bytes", "version", "verified")}
        _emit(progress_cb, "tor", "Офлайн-образ не найден. Проверяю подключение Tor Browser перед загрузкой Tails…")
        tor_port = _verified_tor_port()
        _cancel(cancel_event)
        cache = _secure_directory(CACHE)
        work = Path(tempfile.mkdtemp(prefix="download-", dir=cache))
        _emit(progress_cb, "metadata", "Проверяю текущую официальную версию Tails…")
        _fetch(LATEST_URL, work / "latest.json", 256 * 1024, cancel_event=cancel_event, tor_port=tor_port)
        release = _parse_release(json.loads((work / "latest.json").read_text()))
        if shutil.disk_usage(cache).free < release["size_bytes"] + 100 * 1024**2:
            raise USBError("Для загрузки Tails не хватает свободного места на компьютере. Освободите не меньше 2 ГБ и повторите.")
        record_path = cache / "latest-verified.json"
        if record_path.exists():
            try:
                with _open_regular(record_path)[0] as record:
                    previous = json.load(record)
                if _version(release["version"]) < _version(previous["version"]):
                    raise USBError("Предложенная версия Tails старее уже проверенной. Загрузка остановлена.")
            except (KeyError, ValueError, OSError) as exc:
                raise USBError("Сохранённые сведения о версии повреждены. Переместите комплект в новую папку и повторите.") from exc
        image = work / f"tails-amd64-{release['version']}.img"
        signature = work / (image.name + ".sig")
        key = work / "tails-signing.key"
        _fetch(KEY_URL, key, 2 * 1024**2, cancel_event=cancel_event, tor_port=tor_port)
        _fetch(f"https://tails.net/torrents/files/{image.name}.sig", signature, 256 * 1024, cancel_event=cancel_event, tor_port=tor_port)
        sha256 = _fetch(release["url"], image, MAX_IMAGE_BYTES, progress_cb, cancel_event,
                        image=True, expected_size=release["size_bytes"], tor_port=tor_port)
        if not secrets.compare_digest(sha256, release["sha256"]):
            raise USBError("Контрольная сумма образа не совпала. Повторите загрузку.")
        _cancel(cancel_event)
        _emit(progress_cb, "signature", "Проверяю подпись издателя Tails…")
        _verify_signature(image, signature, key)
        _cancel(cancel_event)
        destination = cache / f"verified-{release['version']}-{sha256[:16]}-{secrets.token_hex(4)}"
        work.rename(destination)
        work = None
        artifact = {"path": str(destination / image.name), "signature": str(destination / signature.name),
                    "key": str(destination / key.name), "sha256": sha256, "size_bytes": release["size_bytes"],
                    "version": release["version"], "verified": True}
        record = cache / f"record-{secrets.token_hex(8)}.tmp"
        with os.fdopen(os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
            json.dump({"version": release["version"]}, out)
        os.replace(record, record_path)
        with _STATE_LOCK:
            _ARTIFACT = artifact
        _emit(progress_cb, "verified", "Официальный образ Tails скачан и подпись проверена.", 100)
        return {k: artifact[k] for k in ("path", "sha256", "size_bytes", "version", "verified")}
    except (OSError, ValueError) as exc:
        raise USBError("Не удалось сохранить или прочитать образ. Проверьте свободное место и повторите.") from exc
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        _DOWNLOAD_LOCK.release()


def _launch_admin(job_path, selected_name):
    helper = CLIENT / "usb_privileged.py"
    executable = str(Path(sys.executable).resolve())
    args = ([executable, "--usb-privileged", str(job_path)] if getattr(sys, "frozen", False)
            else [executable, "-I", str(helper), str(job_path)])
    system = platform.system()
    if system == "Darwin":
        command = shlex.join(args)
        prompt = f"Записать Tails на USB-носитель {selected_name[:100]}? Его данные будут заменены."
        applescript = f"do shell script {json.dumps(command, ensure_ascii=False)} with administrator privileges with prompt {json.dumps(prompt, ensure_ascii=False)}"
        return subprocess.Popen(["/usr/bin/osascript", "-e", applescript], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if system == "Linux":
        if not Path("/usr/bin/pkexec").is_file():
            raise USBError("Для системного окна прав администратора нужен polkit (pkexec) и графический сеанс. Установите polkit средствами системы.")
        return subprocess.Popen(["/usr/bin/pkexec", *args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if system == "Windows":
        from usb_privileged import launch_windows_admin
        return launch_windows_admin(executable, args[1:])
    raise USBError("Эта система не поддерживается.")


def write_verified_image(selection, typed_confirmation, progress_cb=None, cancel_event=None):
    global _ACTIVE_HELPER
    if typed_confirmation != "СТЕРЕТЬ":
        raise USBError("Чтобы заменить все данные выбранной флешки, введите слово СТЕРЕТЬ.")
    token = selection.get("id") if isinstance(selection, dict) else selection
    if not isinstance(token, str):
        raise USBError("Сначала выберите флешку из списка.")
    with _STATE_LOCK:
        selected = dict(_SELECTIONS.get(token) or {})
        artifact = dict(_ARTIFACT or {})
    if not selected:
        raise USBError("Выбранный носитель неизвестен. Обновите список USB-флешек.")
    if not artifact.get("verified"):
        raise USBError("Сначала скачайте и проверьте официальный образ Tails.")
    if not _WRITE_LOCK.acquire(blocking=False):
        raise USBError("Запись флешки уже выполняется.")
    jobdir = None
    process = None
    connection = None
    stream = None
    wrote = False
    authenticated = False
    try:
        with _STATE_LOCK:
            if _ACTIVE_HELPER is not None:
                raise USBError("Предыдущий системный помощник ещё завершает запись. Дождитесь его завершения перед повторной попыткой.")
        _cancel(cancel_event)
        extra = [artifact["path"]]
        _revalidate(selected, extra)
        _emit(progress_cb, "source", "Проверяю образ перед записью…")
        if _hash_file(artifact["path"], cancel_event) != artifact["sha256"]:
            raise USBError("Скачанный образ изменился. Загрузите и проверьте его заново.")
        jobdir = Path(tempfile.mkdtemp(prefix="job-", dir=_secure_directory(CACHE / "jobs")))
        job_path = jobdir / "request.json"
        secret = secrets.token_hex(32)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            listener.settimeout(0.3)
            request = {"format": 1, "selection": {k: selected[k] for k in ("platform", "native_id", "identity", "size_bytes")},
                       "artifact": artifact, "confirmation": typed_confirmation,
                       "port": listener.getsockname()[1], "token": secret}
            with os.fdopen(os.open(job_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                json.dump(request, output, ensure_ascii=True)
            _emit(progress_cb, "admin", "Подтвердите системное окно прав администратора. Мастер не запрашивает и не сохраняет пароль ОС.")
            process = _launch_admin(job_path, selected["name"])
            with _STATE_LOCK:
                _ACTIVE_HELPER = process
            deadline = time.monotonic() + 300
            connection = None
            while connection is None:
                if process.poll() is not None:
                    raise USBError("Системное разрешение не получено или помощник записи не запустился. Флешка не изменена.")
                if time.monotonic() > deadline:
                    raise USBError("Окно прав администратора не подтверждено вовремя. Повторите запись.")
                _cancel(cancel_event)
                try:
                    candidate, _ = listener.accept()
                    candidate.settimeout(5)
                    stream = candidate.makefile("rwb", buffering=0)
                    line = stream.readline(4096)
                    hello = json.loads(line)
                    if not secrets.compare_digest(str(hello.get("token", "")), secret):
                        stream.close()
                        candidate.close()
                        continue
                    connection = candidate
                    authenticated = True
                except (socket.timeout, ValueError):
                    if stream is not None:
                        stream.close()
                    if "candidate" in locals():
                        candidate.close()
                    continue
            with connection:
                connection.settimeout(1)
                # A reader thread avoids partial-line loss when a socket timeout
                # occurs; commands use the same authenticated connection.
                import queue
                messages = queue.Queue()
                connection.settimeout(None)
                def read_events():
                    try:
                        while True:
                            raw = stream.readline(65537)
                            if not raw:
                                messages.put({"stage": "disconnected"})
                                return
                            if len(raw) > 65536:
                                raise ValueError("oversized event")
                            messages.put(json.loads(raw))
                    except (OSError, ValueError):
                        messages.put({"stage": "disconnected"})
                reader = threading.Thread(target=read_events, daemon=True)
                reader.start()
                sent_cancel = False
                cancel_deadline = None
                while True:
                    if cancel_event is not None and cancel_event.is_set() and not sent_cancel:
                        connection.sendall(b'{"command":"cancel"}\n')
                        sent_cancel = True
                        cancel_deadline = time.monotonic() + 45
                    if cancel_deadline and time.monotonic() > cancel_deadline:
                        raise USBCancelled("Запрошена остановка записи. Дождитесь завершения системного помощника; флешку нужно записать заново.")
                    try:
                        message = messages.get(timeout=0.25)
                    except queue.Empty:
                        if process.poll() is not None:
                            raise USBError("Помощник завершился без подтверждения. Флешку нужно записать заново.")
                        continue
                    stage = message.get("stage")
                    if stage in {"write", "flush", "readback"}:
                        wrote = True
                    if stage == "complete":
                        _emit(progress_cb, "complete", message["message"], 100)
                        return message["result"]
                    if stage in {"error", "cancelled", "disconnected"}:
                        error = message.get("message") or "Связь с помощником прервалась. Флешку нужно записать заново."
                        raise (USBCancelled if stage == "cancelled" else USBError)(error)
                    if progress_cb:
                        progress_cb(message)
                # The OS helper owns its disk handle; closing IPC makes it stop
                # between bounded chunks, including if this window disappears.
    except OSError as exc:
        raise USBError("Не удалось запустить запись." + (" Флешку нужно записать заново." if wrote else " Флешка не изменена.")) from exc
    finally:
        if connection is not None:
            # makefile() retains the socket descriptor even after socket.close();
            # shutdown is required to notify the helper reliably on cancellation.
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if stream is not None:
            stream.close()
        if process is not None:
            # IPC closure stops the elevated helper between chunks. Keep a live
            # process tracked until it actually exits, including stalled I/O;
            # a second write cannot race an incompletely cancelled first write.
            if not authenticated and process.poll() is None and hasattr(process, "terminate"):
                try:
                    process.terminate()
                except OSError:
                    pass
            def reap():
                global _ACTIVE_HELPER
                try:
                    while process.poll() is None:
                        time.sleep(0.25)
                finally:
                    with _STATE_LOCK:
                        if _ACTIVE_HELPER is process:
                            _ACTIVE_HELPER = None
                    if hasattr(process, "close"):
                        process.close()
                    if jobdir is not None:
                        shutil.rmtree(jobdir, ignore_errors=True)
            threading.Thread(target=reap, daemon=True).start()
        elif jobdir is not None:
            shutil.rmtree(jobdir, ignore_errors=True)
        _WRITE_LOCK.release()
