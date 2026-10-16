"""Narrow administrator helper: pinned signed Tails image -> guarded USB disk.

No shell/device path comes from the web UI, no format/erase command, no password
input. This module is also importable for mock-only tests of the copy/readback.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import usb_tails as usb


def _require_admin():
    if os.name == "nt":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise usb.USBError("Система не предоставила права администратора; запись запрещена.")
    elif os.geteuid() != 0:
        raise usb.USBError("Помощник требует системного подтверждения прав администратора.")


def _read_request(path):
    path = Path(path).absolute()
    if path.name != "request.json" or not re.fullmatch(r"job-[A-Za-z0-9_-]+", path.parent.name) or path.parent.parent.name != "jobs":
        raise usb.USBError("Некорректный запрос записи.")
    for item in (path, *path.parents):
        if item.is_symlink() or item.resolve() != item:
            raise usb.USBError("Запрос записи содержит ссылку; запись запрещена.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        details = os.fstat(source.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 16384:
            raise usb.USBError("Некорректный файл запроса записи.")
        if os.name != "nt":
            if details.st_mode & 0o077 or os.stat(path.parent).st_mode & 0o077:
                raise usb.USBError("Запрос записи доступен другим пользователям; запись запрещена.")
            invoking_uid = int(os.environ.get("PKEXEC_UID", details.st_uid))
            if invoking_uid != details.st_uid:
                raise usb.USBError("Владелец запроса не совпал с пользователем системного окна.")
        if getattr(sys, "frozen", False) and os.name != "nt":
            import pwd
            home = Path(pwd.getpwuid(details.st_uid).pw_dir)
            expected = (home / "Library/Caches/OnionDesk/tails" if platform.system() == "Darwin"
                        else home / ".cache/OnionDesk/tails")
        else:
            expected = usb.CACHE
        if path.parent.parent.parent != expected:
            raise usb.USBError("Запрос находится вне собственной папки мастера.")
        usb.CACHE = expected
        request = json.load(source)
    if request.get("format") != 1 or request.get("confirmation") != "СТЕРЕТЬ":
        raise usb.USBError("Нет явного подтверждения замены данных флешки.")
    if not isinstance(request.get("port"), int) or not 1024 <= request["port"] <= 65535 or not re.fullmatch(r"[a-f0-9]{64}", request.get("token", "")):
        raise usb.USBError("Некорректный канал связи с мастером.")
    selection, artifact = request.get("selection", {}), request.get("artifact", {})
    system = platform.system()
    pattern = {"Linux": r"sd[a-z]+", "Darwin": r"disk\d+", "Windows": r"\d{1,4}"}.get(system)
    if selection.get("platform") != system or not pattern or not re.fullmatch(pattern, selection.get("native_id", "")) or not re.fullmatch(r"[a-f0-9]{64}", selection.get("identity", "")):
        raise usb.USBError("Некорректный идентификатор USB-носителя.")
    if not isinstance(selection.get("size_bytes"), int) or selection["size_bytes"] < usb.MIN_USB_BYTES:
        raise usb.USBError("Недостаточный размер USB-носителя.")
    if not re.fullmatch(r"[a-f0-9]{64}", artifact.get("sha256", "")) or usb._version(artifact.get("version")) < usb.MIN_VERSION:
        raise usb.USBError("Некорректные сведения о проверенном образе.")
    if not isinstance(artifact.get("size_bytes"), int) or not 1024**3 < artifact["size_bytes"] < usb.MAX_IMAGE_BYTES:
        raise usb.USBError("Некорректный размер образа.")
    image = Path(artifact.get("path", "")).absolute()
    if image.parent.parent != usb.CACHE or not re.fullmatch(r"verified-" + re.escape(artifact["version"]) + "-" + artifact["sha256"][:16] + r"-[a-f0-9]{8}", image.parent.name) or image.name != f"tails-amd64-{artifact['version']}.img":
        raise usb.USBError("Запрос не указывает на проверенный образ мастера.")
    if artifact.get("signature") != str(image.parent / (image.name + ".sig")) or artifact.get("key") != str(image.parent / "tails-signing.key"):
        raise usb.USBError("Некорректные файлы подписи образа.")
    return request, (details.st_uid, details.st_gid) if os.name != "nt" else None


class _Channel:
    def __init__(self, request):
        self.cancel = threading.Event()
        self.connection = socket.create_connection(("127.0.0.1", request["port"]), timeout=15)
        self.connection.settimeout(10)
        self.connection.sendall((json.dumps({"token": request["token"]}) + "\n").encode())
        self.connection.settimeout(None)
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._receive, daemon=True)
        self.reader.start()

    def _receive(self):
        try:
            with self.connection.makefile("rb") as source:
                while True:
                    line = source.readline(4097)
                    if not line or len(line) > 4096:
                        self.cancel.set()
                        return
                    if json.loads(line).get("command") == "cancel":
                        self.cancel.set()
        except (OSError, ValueError):
            self.cancel.set()

    def emit(self, stage, message, percent=None, **extra):
        payload = {"stage": stage, "message": message, "percent": percent, **extra}
        try:
            with self.lock:
                self.connection.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode())
        except OSError as exc:
            self.cancel.set()
            raise usb.USBCancelled("Связь с мастером прервалась. Если запись уже началась, запишите флешку заново.") from exc

    def close(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()


def _snapshot(artifact, directory, event, owner=None):
    """Copy held descriptors to a root-owned snapshot before GPG and writing.

    This costs temporary storage but makes pathname/symlink swaps of user-cache
    files unable to replace the already verified write source.
    """
    directory = Path(directory)
    # Allow a dropped-privilege GPG process to read only the public Tails files.
    os.chmod(directory, 0o711)
    destinations = {}
    for kind, limit in (("path", usb.MAX_IMAGE_BYTES), ("signature", 256 * 1024), ("key", 2 * 1024**2)):
        usb._cancel(event)
        target = directory / {"path": "image.img", "signature": "image.img.sig", "key": "tails-signing.key"}[kind]
        source, info = usb._open_regular(artifact[kind])
        with source, open(target, "xb", buffering=0) as output:
            if owner is not None and info.st_uid != owner:
                raise usb.USBError("Владелец исходного файла изменился; запись запрещена.")
            if info.st_size > limit or (kind == "path" and info.st_size != artifact["size_bytes"]):
                raise usb.USBError("Размер исходного файла изменился; запись запрещена.")
            copied = 0
            digest = hashlib.sha256()
            while chunk := source.read(usb.CHUNK):
                usb._cancel(event)
                copied += len(chunk)
                if copied > limit:
                    raise usb.USBError("Исходный файл слишком велик; запись запрещена.")
                output.write(chunk)
                digest.update(chunk)
            after = os.fstat(source.fileno())
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise usb.USBError("Исходный файл изменился при проверке; запись запрещена.")
            if kind == "path" and (copied != artifact["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), artifact["sha256"])):
                raise usb.USBError("Образ изменился после скачивания; запись запрещена.")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(target, 0o444)
        destinations[kind] = target
    return destinations


def _posix_open(selection, image_path):
    import fcntl
    disk = usb._revalidate(selection, [image_path])
    if disk["platform"] == "Linux":
        for path in reversed(disk.get("mounted_devices", [])):
            if not re.fullmatch(r"/dev/sd[a-z]+\d*", path):
                raise usb.USBError("Неожиданный раздел носителя; запись запрещена.")
            usb._run(["/usr/bin/umount", "--", path])
    else:
        usb._run(["/usr/sbin/diskutil", "unmountDisk", disk["native_id"]])
    disk = usb._revalidate(selection, [image_path])
    if disk.get("mounts"):
        raise usb.USBError("Флешка используется системой и не была отключена от файловой системы.")
    details = os.lstat(disk["path"])
    expected_type = stat.S_ISBLK if disk["platform"] == "Linux" else stat.S_ISCHR
    if not expected_type(details.st_mode):
        raise usb.USBError("Путь носителя не является ожидаемым системным устройством.")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if disk["platform"] == "Linux":
        flags |= os.O_EXCL
    fd = os.open(disk["path"], flags)
    try:
        opened = os.fstat(fd)
        if not expected_type(opened.st_mode) or opened.st_rdev != details.st_rdev:
            raise usb.USBError("Системное устройство изменилось при открытии; запись запрещена.")
        if disk["platform"] == "Linux":
            size = struct.unpack("Q", fcntl.ioctl(fd, 0x80081272, b"\0" * 8))[0]  # BLKGETSIZE64
            readonly = struct.unpack("i", fcntl.ioctl(fd, 0x125E, b"\0" * 4))[0]  # BLKROGET
            if readonly:
                raise usb.USBError("Флешка защищена от записи.")
        else:
            block = struct.unpack("I", fcntl.ioctl(fd, 0x40046418, b"\0" * 4))[0]  # DKIOCGETBLOCKSIZE
            blocks = struct.unpack("Q", fcntl.ioctl(fd, 0x40086419, b"\0" * 8))[0]  # DKIOCGETBLOCKCOUNT
            size = block * blocks
            fcntl.fcntl(fd, 48, 1)  # F_NOCACHE on Darwin's raw device.
        if size != disk["size_bytes"]:
            raise usb.USBError("Размер устройства изменился; запись запрещена.")
        usb._revalidate(selection, [image_path])
        return _PosixDisk(fd, disk["platform"]), disk
    except BaseException:
        os.close(fd)
        raise


class _PosixDisk:
    def __init__(self, fd, system):
        self.fd, self.system = fd, system

    def write(self, data):
        return os.write(self.fd, data)

    def read(self, size):
        return os.read(self.fd, size)

    def seek(self, offset):
        return os.lseek(self.fd, offset, os.SEEK_SET)

    def flush(self):
        import fcntl
        os.fsync(self.fd)
        if self.system == "Linux":
            fcntl.ioctl(self.fd, 0x1261)  # BLKFLSBUF, invalidate block cache for readback.
        else:
            fcntl.ioctl(self.fd, 0x20006416)  # DKIOCSYNCHRONIZECACHE

    def close(self):
        os.close(self.fd)


def _win_kernel():
    from ctypes import wintypes as wt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel.CreateFileW.restype = wt.HANDLE
    kernel.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    kernel.DeviceIoControl.restype = wt.BOOL
    kernel.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    kernel.ReadFile.restype = wt.BOOL
    kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
    kernel.WriteFile.restype = wt.BOOL
    kernel.SetFilePointerEx.argtypes = [wt.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wt.DWORD]
    kernel.SetFilePointerEx.restype = wt.BOOL
    kernel.FlushFileBuffers.argtypes = [wt.HANDLE]
    kernel.FlushFileBuffers.restype = wt.BOOL
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    return kernel


def _win_ioctl(kernel, handle, code, size=0, data=b""):
    from ctypes import wintypes as wt
    output = ctypes.create_string_buffer(size) if size else None
    input_buffer = ctypes.create_string_buffer(data) if data else None
    done = wt.DWORD()
    if not kernel.DeviceIoControl(handle, code, input_buffer, len(data), output, size, ctypes.byref(done), None):
        raise usb.USBError("Windows не смогла заблокировать или проверить USB-устройство. Закройте файлы на флешке и повторите.")
    return output.raw[:done.value] if output else b""


def _win_open_handle(kernel, path):
    handle = kernel.CreateFileW(path, 0xC0000000, 3, None, 3, 0x80000000, None)  # OPEN_EXISTING, WRITE_THROUGH
    if handle == ctypes.c_void_p(-1).value:
        raise usb.USBError("Windows не разрешила открыть USB-устройство. Закройте программы, использующие флешку.")
    return handle


def _windows_open(selection, image_path):
    disk = usb._revalidate(selection, [image_path])
    kernel = _win_kernel()
    volumes = []
    handle = None
    try:
        for path in disk.get("volumes", []):
            if not re.fullmatch(r"\\\\\?\\Volume\{[A-Fa-f0-9-]+\}", path):
                raise usb.USBError("Неожиданный идентификатор тома Windows.")
            volume = _win_open_handle(kernel, path)
            volumes.append(volume)
            _win_ioctl(kernel, volume, 0x90018)  # FSCTL_LOCK_VOLUME: never force dismount without a lock.
            _win_ioctl(kernel, volume, 0x90020)  # FSCTL_DISMOUNT_VOLUME
        handle = _win_open_handle(kernel, disk["path"])
        number = struct.unpack("III", _win_ioctl(kernel, handle, 0x2D1080, 12))
        size = struct.unpack("q", _win_ioctl(kernel, handle, 0x7405C, 8))[0]
        descriptor = _win_ioctl(kernel, handle, 0x2D1400, 65536, struct.pack("III", 0, 0, 0))
        if len(descriptor) < 36:
            raise usb.USBError("Windows не сообщила аппаратный номер USB-носителя.")
        serial_offset, bus = struct.unpack_from("II", descriptor, 24)
        if serial_offset < 36 or serial_offset >= len(descriptor):
            raise usb.USBError("USB-носитель не сообщает аппаратный серийный номер.")
        serial = descriptor[serial_offset:].split(b"\0", 1)[0].decode("ascii", "strict").strip()
        if bus != 7 or serial != disk["serial"] or number[1] != int(disk["native_id"]) or number[2] != 0xFFFFFFFF or size != disk["size_bytes"]:
            raise usb.USBError("Открытое устройство не совпало с выбранной флешкой; запись запрещена.")
        usb._revalidate(selection, [image_path])
        return _WindowsDisk(kernel, handle, volumes), disk
    except BaseException:
        if handle is not None:
            kernel.CloseHandle(handle)
        for volume in volumes:
            kernel.CloseHandle(volume)
        raise


class _WindowsDisk:
    def __init__(self, kernel, handle, volumes):
        self.kernel, self.handle, self.volumes = kernel, handle, volumes

    def write(self, data):
        from ctypes import wintypes as wt
        done = wt.DWORD()
        buf = ctypes.create_string_buffer(bytes(data))
        if not self.kernel.WriteFile(self.handle, buf, len(data), ctypes.byref(done), None):
            raise usb.USBError("Windows сообщила об ошибке записи. Флешку нужно записать заново.")
        return done.value

    def read(self, size):
        from ctypes import wintypes as wt
        done = wt.DWORD()
        buf = ctypes.create_string_buffer(size)
        if not self.kernel.ReadFile(self.handle, buf, size, ctypes.byref(done), None):
            raise usb.USBError("Windows не смогла прочитать записанные данные. Флешку нужно записать заново.")
        return buf.raw[:done.value]

    def seek(self, offset):
        if not self.kernel.SetFilePointerEx(self.handle, offset, None, 0):
            raise usb.USBError("Windows не смогла выполнить проверку флешки.")

    def flush(self):
        if not self.kernel.FlushFileBuffers(self.handle):
            raise usb.USBError("Windows не подтвердила сохранение данных флешки.")

    def close(self):
        self.kernel.CloseHandle(self.handle)
        for volume in self.volumes:
            self.kernel.CloseHandle(volume)


def _write_and_verify(source, target, size, sha256, emit, event):
    """Works with streams only; tests pass ordinary temporary files here."""
    written = 0
    source.seek(0)
    target.seek(0)
    digest = hashlib.sha256()
    while written < size:
        usb._cancel(event, writing=written > 0)
        chunk = source.read(min(usb.CHUNK, size - written))
        if not chunk:
            raise usb.USBError("Исходный образ оборвался. Флешку нужно записать заново.")
        digest.update(chunk)
        emit("write", "Записываю Tails на выбранную флешку…", int(written * 100 / size), bytes_done=written, bytes_total=size)
        remaining = memoryview(chunk)
        while remaining:
            count = target.write(remaining)
            if not count or count > len(remaining):
                raise usb.USBError("Флешка не приняла данные. Запишите её заново.")
            remaining = remaining[count:]
            written += count
        usb._cancel(event, writing=True)
    if not secrets.compare_digest(digest.hexdigest(), sha256):
        raise usb.USBError("Исходный образ изменился во время записи. Флешку нужно записать заново.")
    emit("flush", "Сохраняю данные на устройстве…")
    target.flush()
    usb._cancel(event, writing=True)
    target.seek(0)
    verified = 0
    digest = hashlib.sha256()
    while verified < size:
        usb._cancel(event, writing=True)
        chunk = target.read(min(usb.CHUNK, size - verified))
        if not chunk:
            raise usb.USBError("Флешка не прочиталась полностью после записи. Запишите её заново.")
        verified += len(chunk)
        digest.update(chunk)
        emit("readback", "Проверяю записанные данные чтением с флешки…", int(verified * 100 / size), bytes_done=verified, bytes_total=size)
    if not secrets.compare_digest(digest.hexdigest(), sha256):
        raise usb.USBError("Записанные данные не совпали с образом. Попробуйте другую флешку.")
    return {"verified": True, "sha256": sha256, "bytes_written": written}


class _ElevatedWindowsProcess:
    def __init__(self, handle):
        from ctypes import wintypes as wt
        self.handle = handle
        self.kernel = _win_kernel()
        self.kernel.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wt.BOOL

    def poll(self):
        from ctypes import wintypes as wt
        result = wt.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(result)):
            return 1
        return None if result.value == 259 else result.value

    def close(self):
        self.kernel.CloseHandle(self.handle)


def launch_windows_admin(executable, args):
    from ctypes import wintypes as wt
    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("fMask", wt.ULONG), ("hwnd", wt.HWND),
                    ("lpVerb", wt.LPCWSTR), ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR),
                    ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wt.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
                    ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE)]
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = wt.BOOL
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = 0
    if not shell.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        raise usb.USBError("Системное разрешение администратора не получено. Флешка не изменена.")
    return _ElevatedWindowsProcess(info.hProcess)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    channel = None
    target = None
    writing = False
    try:
        _require_admin()
        request, run_as = _read_request(args[0])
        channel = _Channel(request)
        selection, artifact = request["selection"], request["artifact"]
        channel.emit("source", "Проверяю неизменность образа в системном помощнике…")
        usb._revalidate(selection, [artifact["path"]])
        private_tmp = None if os.name == "nt" else ("/private/tmp" if platform.system() == "Darwin" else "/tmp")
        with tempfile.TemporaryDirectory(prefix="tails-write-", dir=private_tmp) as directory:
            import shutil
            if shutil.disk_usage(directory).free < artifact["size_bytes"] + 100 * 1024**2:
                raise usb.USBError("Для безопасной проверки перед записью требуется ещё около 2 ГБ свободного места во временной папке компьютера.")
            files = _snapshot(artifact, directory, channel.cancel, run_as[0] if run_as else None)
            channel.emit("signature", "Повторно проверяю подпись издателя перед записью…")
            usb._verify_signature(files["path"], files["signature"], files["key"], parent=directory, run_as=run_as)
            usb._cancel(channel.cancel)
            # Guard cache/program disks again; the temporary snapshot is also a
            # protected path. Original cached image cannot be a write target.
            disk = usb._revalidate(selection, [artifact["path"], files["path"]])
            if artifact["size_bytes"] > disk["size_bytes"] or artifact["size_bytes"] % disk["sector_size"]:
                raise usb.USBError("Образ не помещается или не подходит размеру секторов флешки.")
            channel.emit("unmount", "Отключаю выбранную флешку от файловой системы…")
            target, disk = (_windows_open(selection, files["path"]) if os.name == "nt" else _posix_open(selection, files["path"]))
            usb._cancel(channel.cancel)
            writing = True
            with open(files["path"], "rb", buffering=0) as image:
                result = _write_and_verify(image, target, artifact["size_bytes"], artifact["sha256"], channel.emit, channel.cancel)
            target.close()
            target = None
            channel.emit("complete", "Tails записан, данные проверены чтением. Теперь можно безопасно извлечь флешку.", 100,
                         result={**result, "version": artifact["version"], "name": disk["name"]})
        return 0
    except Exception as exc:
        if channel:
            try:
                if isinstance(exc, usb.USBError):
                    message = str(exc)
                else:
                    message = "Системный помощник не смог завершить операцию." + (" Флешку нужно записать заново." if writing else " Запись не началась.")
                channel.emit("cancelled" if isinstance(exc, usb.USBCancelled) else "error", message)
            except Exception:
                pass
        return 1
    finally:
        if target:
            try:
                target.flush()
            except Exception:
                pass
            target.close()
        if channel:
            channel.close()


if __name__ == "__main__":
    raise SystemExit(main())
