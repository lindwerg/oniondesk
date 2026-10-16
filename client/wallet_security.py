"""Read-only, fail-closed evidence for encrypted mainnet wallet storage.

Native tools describe the filesystem containing the destination, not a machine
wide marketing capability. No command here enables encryption, changes keys or
queries recovery material. Unknown native output never permits a wallet.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path, PureWindowsPath
import plistlib
import re
import stat
import subprocess
import sys


class _Unverified(RuntimeError):
    pass


_DEVICE = re.compile(r"/dev/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\Z")
_DRIVE = re.compile(r"[A-Za-z]:\Z")
_GUIDANCE = [
    "Используйте папку на полностью зашифрованном носителе.",
    "Проверка ничего не меняет в настройках шифрования системы.",
]


def _run(arguments: list[str], *, extra_env: dict[str, str] | None = None) -> bytes:
    # Frozen launchers can inject their bundled ELF libraries into system tools.
    # Start with a small environment, excluding LD_*, DYLD_* and shell profiles.
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    if os.environ.get("HOME"):
        environment["HOME"] = os.environ["HOME"]
    if extra_env:
        environment.update(extra_env)
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=6, check=False, env=environment,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0)
    except (OSError, subprocess.TimeoutExpired):
        raise _Unverified from None
    if result.returncode or not isinstance(result.stdout, bytes) or len(result.stdout) > 2 * 1024**2:
        raise _Unverified
    return result.stdout


def _safe_components(path: Path) -> None:
    """Reject redirected existing ancestors without resolving away symlinks."""
    if not path.is_absolute() or ".." in path.parts or str(path).startswith("\\\\"):
        raise _Unverified
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise _Unverified


def _nearest_directory(target: Path) -> Path:
    _safe_components(target)
    for candidate in (target, *target.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise _Unverified
        return candidate
    raise _Unverified


def _mount_matches(mount: object, target: Path, *, require_coverage: bool = True) -> bool:
    if not isinstance(mount, str):
        return False
    location = Path(mount)
    _safe_components(location)
    if require_coverage:
        try:
            target.relative_to(location)
        except ValueError:
            return False
    return stat.S_ISDIR(location.stat().st_mode) and location.stat().st_dev == target.stat().st_dev


def _mac_swap_safe() -> bool:
    raw = _run(["/usr/sbin/sysctl", "vm.swapusage"]).decode("ascii", "strict").strip()
    number = r"[0-9]+(?:\.[0-9]+)?[KMGT]"
    match = re.fullmatch(rf"vm\.swapusage:\s+total\s*=\s*(?P<total>{number})\s+used\s*=\s*"
                         rf"(?P<used>{number})\s+free\s*=\s*{number}\s*(?P<encrypted>\(encrypted\))?", raw)
    return bool(match and (match["encrypted"] == "(encrypted)" or
                          (float(match["total"][:-1]) == 0 and float(match["used"][:-1]) == 0)))


def _mac_image_backing_safe(path: Path) -> bool:
    _safe_components(path)
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        return False
    if not stat.S_ISREG(info.st_mode) and not (stat.S_ISDIR(info.st_mode) and path.name.endswith(".sparsebundle")):
        return False
    # A writable ancestor can let another account replace the image by name.
    return not any(parent.stat().st_mode & 0o002 for parent in path.parents)


def _mac_encrypted_image(device: str, mount: str, target: Path) -> bool:
    images = plistlib.loads(_run(["/usr/bin/hdiutil", "info", "-plist"])).get("images")
    if not isinstance(images, list) or len(images) > 128:
        return False
    for image in images:
        if not isinstance(image, dict) or image.get("image-encrypted") is not True:
            continue
        owner = image.get("owner-uid")
        if type(owner) is not int or owner != os.getuid():
            continue
        entities = image.get("system-entities")
        if not isinstance(entities, list) or len(entities) > 128:
            continue
        if not any(isinstance(entry, dict) and entry.get("dev-entry") == device
                   and entry.get("mount-point") == mount for entry in entities):
            continue
        image_path = image.get("image-path")
        if not isinstance(image_path, str) or not _mount_matches(mount, target, require_coverage=False):
            continue
        backing = Path(image_path)
        if not _mac_image_backing_safe(backing):
            continue
        # Native live attachment metadata is authoritative for the mounted
        # device. Reopening its busy backing with isencrypted can fail even
        # after successful authenticated AES decryption. The vault manager
        # verifies the image separately before attachment.
        return True
    return False


def _mac_context(target: Path) -> str:
    rows = _run(["/bin/df", "-P", str(target)]).decode("utf-8", "strict").splitlines()
    if len(rows) != 2 or not rows[1].split():
        raise _Unverified
    device = rows[1].split()[0]
    if not re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)+", device):
        raise _Unverified
    volume = plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", device]))
    if not isinstance(volume, dict) or volume.get("DeviceNode") != device:
        raise _Unverified
    mount = volume.get("MountPoint")
    # APFS firmlinks expose /System/Volumes/Data through /Users and /private.
    # df already attributed the target to this exact DeviceNode; st_dev handles
    # those native aliases without requiring a misleading lexical prefix.
    if not isinstance(mount, str) or not _mount_matches(mount, target, require_coverage=False):
        raise _Unverified
    if volume.get("FileVault") is True:
        kind = "filevault"
    elif _mac_encrypted_image(device, mount, target):
        kind = "encrypted-image"
    else:
        raise _Unverified
    if not _mac_swap_safe():
        raise _Unverified
    return kind


def _device_path(value: object) -> str:
    if not isinstance(value, str) or not _DEVICE.fullmatch(value) or ".." in value.split("/"):
        raise _Unverified
    return value


def _block_identity(device: str) -> int:
    info = Path(_device_path(device)).stat()
    if not stat.S_ISBLK(info.st_mode):
        raise _Unverified
    return info.st_rdev


def _linux_block_encrypted(source: str, *, require_luks: bool) -> bool:
    source = _device_path(source)
    parsed = json.loads(_run(["/usr/bin/lsblk", "--inverse", "--json", "--paths",
                              "--output", "NAME,TYPE,FSTYPE", source]))
    roots = parsed.get("blockdevices") if isinstance(parsed, dict) else None
    if not isinstance(roots, list) or len(roots) != 1 or not isinstance(roots[0], dict):
        return False
    if _block_identity(_device_path(roots[0].get("name"))) != _block_identity(source):
        return False
    remaining = [128]

    def encrypted(node: object, seen_crypt: bool, depth: int) -> bool:
        remaining[0] -= 1
        if not isinstance(node, dict) or depth > 32 or remaining[0] < 0:
            return False
        _device_path(node.get("name"))
        seen_crypt = seen_crypt or node.get("type") == "crypt"
        if seen_crypt and (not require_luks or node.get("fstype") == "crypto_LUKS"):
            return True
        children = node.get("children")
        return (isinstance(children, list) and bool(children)
                and all(encrypted(child, seen_crypt, depth + 1) for child in children))

    return encrypted(roots[0], False, 0)


def _linux_context(target: Path) -> bool:
    parsed = json.loads(_run(["/usr/bin/findmnt", "--json", "--target", str(target),
                             "--output", "SOURCE,TARGET,FSTYPE"]))
    filesystems = parsed.get("filesystems") if isinstance(parsed, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1 or not isinstance(filesystems[0], dict):
        return False
    filesystem = filesystems[0]
    if not _mount_matches(filesystem.get("target"), target):
        return False
    source = filesystem.get("source")
    if not isinstance(source, str):
        return False
    source = re.sub(r"\[[^\[\]\x00]*\]\Z", "", source)  # btrfs subvolume suffix
    return _linux_block_encrypted(source, require_luks=True)


def _read_swaps() -> str:
    with Path("/proc/swaps").open(encoding="utf-8") as stream:
        value = stream.read(131_073)
    if len(value) > 131_072:
        raise _Unverified
    return value


def _linux_swap_safe() -> bool:
    rows = _read_swaps().splitlines()
    if not rows or rows[0].split() != ["Filename", "Type", "Size", "Used", "Priority"] or len(rows) > 17:
        return False
    for row in rows[1:]:
        fields = row.split()
        if len(fields) != 5 or not all(re.fullmatch(r"-?[0-9]+", item) for item in fields[2:]):
            return False
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[0])
        if "\\" in path or "\0" in path:
            return False
        if fields[1] == "partition":
            if not _linux_block_encrypted(path, require_luks=False):
                return False
        elif fields[1] == "file":
            file_path = Path(path)
            _safe_components(file_path)
            if not stat.S_ISREG(file_path.stat().st_mode) or not _linux_context(file_path):
                return False
        else:
            return False
    return True


def _windows_directory() -> Path:
    import ctypes
    from ctypes import wintypes as wt
    kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    kernel.GetWindowsDirectoryW.argtypes = [wt.LPWSTR, wt.UINT]
    kernel.GetWindowsDirectoryW.restype = wt.UINT
    value = ctypes.create_unicode_buffer(32_768)
    length = kernel.GetWindowsDirectoryW(value, len(value))
    if not 0 < length < len(value):
        raise _Unverified
    location = PureWindowsPath(value.value)
    if not _DRIVE.fullmatch(location.drive) or location.root != "\\":
        raise _Unverified
    return Path(value.value)


_BITLOCKER_SCRIPT = """$ErrorActionPreference='Stop';
$pagefiles=@(Get-CimInstance -ClassName Win32_PageFileUsage -Property Name -ErrorAction Stop);
if($pagefiles.Count -gt 128) { exit 3 };
$names=@(); $drives=@($env:ONIONDESK_TARGET_DRIVE,$env:ONIONDESK_SYSTEM_DRIVE);
foreach($page in $pagefiles) {
 $name=[string]$page.Name;
 if($name.Length -gt 32760 -or $name -notmatch '^[A-Za-z]:\\\\') { exit 3 };
 $drive=[System.IO.Path]::GetPathRoot($name).TrimEnd('\\');
 if($drive -notmatch '^[A-Za-z]:$') { exit 3 };
 $names += [pscustomobject]@{name=$name}; $drives += $drive.ToUpperInvariant();
}; $drives=@($drives | Sort-Object -Unique);
$rows=@(); foreach($drive in $drives) {
 if($drive -notmatch '^[A-Za-z]:$') { exit 3 };
 $volume=@(Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop);
 if($volume.Count -ne 1) { exit 3 }; $v=$volume[0];
 $rows += [pscustomobject]@{MountPoint=[string]$v.MountPoint;VolumeStatus=[string]$v.VolumeStatus;
 ProtectionStatus=[string]$v.ProtectionStatus;LockStatus=[string]$v.LockStatus;
 EncryptionPercentage=[int]$v.EncryptionPercentage};
}; $evidence=[pscustomobject]@{format=1;pagefiles_queried=$true;pagefiles=@($names);volumes=@($rows)};
ConvertTo-Json -InputObject $evidence -Depth 4 -Compress
"""


def _bitlocker_rows_safe(evidence: object, target_drive: str, system_drive: str) -> bool:
    """Require protection of every active pagefile volume, even when unused."""
    if not _DRIVE.fullmatch(target_drive) or not _DRIVE.fullmatch(system_drive):
        return False
    if (not isinstance(evidence, dict) or type(evidence.get("format")) is not int or evidence["format"] != 1
            or evidence.get("pagefiles_queried") is not True):
        return False
    pagefiles, rows = evidence.get("pagefiles"), evidence.get("volumes")
    if not isinstance(pagefiles, list) or len(pagefiles) > 128 or not isinstance(rows, list):
        return False
    expected = {target_drive.upper(), system_drive.upper()}
    for pagefile in pagefiles:
        name = pagefile.get("name") if isinstance(pagefile, dict) else None
        if not isinstance(name, str) or not 4 <= len(name) <= 32760 or "\0" in name:
            return False
        path = PureWindowsPath(name)
        if (not path.is_absolute() or not _DRIVE.fullmatch(path.drive) or path.root != "\\"
                or len(path.parts) < 2 or any(part in {".", ".."} or ":" in part for part in path.parts[1:])):
            return False
        expected.add(path.drive.upper())
    if len(rows) != len(expected):
        return False
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("MountPoint"), str)
                or row["MountPoint"].upper() not in expected or row["MountPoint"].upper() in seen
                or row.get("VolumeStatus") != "FullyEncrypted"
                or row.get("ProtectionStatus") != "On" or row.get("LockStatus") != "Unlocked"
                or type(row.get("EncryptionPercentage")) is not int or row["EncryptionPercentage"] != 100):
            return False
        seen.add(row["MountPoint"].upper())
    return seen == expected


def _windows_context(target: Path) -> bool:
    windows = _windows_directory()
    target_drive, system_drive = PureWindowsPath(str(target)).drive, PureWindowsPath(str(windows)).drive
    if not _DRIVE.fullmatch(target_drive) or not _DRIVE.fullmatch(system_drive):
        return False
    executable = windows / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    _safe_components(executable)
    if not executable.is_file():
        return False
    encoded = base64.b64encode(_BITLOCKER_SCRIPT.encode("utf-16le")).decode("ascii")
    environment = {"SystemRoot": str(windows), "PATH": str(windows / "System32"),
                   "ONIONDESK_TARGET_DRIVE": target_drive, "ONIONDESK_SYSTEM_DRIVE": system_drive}
    raw = _run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
               extra_env=environment)
    return _bitlocker_rows_safe(json.loads(raw.decode("utf-8-sig")), target_drive, system_drive)


def attest_encrypted_storage(target: Path) -> dict[str, object]:
    """Return only public status; native paths, device IDs and stderr stay local."""
    try:
        location = Path(target).expanduser()
        closest = _nearest_directory(location)
        if sys.platform == "darwin":
            kind = _mac_context(closest)
        elif sys.platform.startswith("linux"):
            if not _linux_context(closest) or not _linux_swap_safe():
                raise _Unverified
            kind = "luks"
        elif sys.platform == "win32":
            if not _windows_context(closest):
                raise _Unverified
            kind = "bitlocker"
        else:
            raise _Unverified
        return {"ok": True, "kind": kind, "message": "Шифрование папки кошельков подтверждено.", "guidance": []}
    except Exception:
        # Unavailable permissions/tools, malformed output and races all deny.
        return {"ok": False, "kind": "unverified",
                "message": "Не удалось подтвердить шифрование папки и памяти подкачки. Создание и открытие кошелька запрещено.",
                "guidance": list(_GUIDANCE)}
