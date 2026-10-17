"""Pinned native Windows engine tests before the unchanged GUI lifecycle."""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import urllib.request

STREAM_LIMIT = 24 * 1024
LINE_LIMIT = 8 * 1024
SUITE_TIMEOUT = 300
FAILURE_CODES = {"NativeEngineTestTimedOut", "NativeEngineTargetedFailed", "NativeEngineFullSuiteFailed", "NativeEngineTestOutputInvalid"}
PIN_KEYS = {"schema", "asset", "bytes", "sha256", "source_freeze_sha256", "expected_tests"}


def checked_test_pins(native):
    pins = native.PINS["distributions"]["windows-x64"].get("native_tests")
    if not isinstance(pins, dict) or set(pins) != PIN_KEYS or type(pins["schema"]) is not int or pins["schema"] != 1 or \
            pins["asset"] != "oniondesk-windows-r5-r2-native-ancestor-v4-tests-20261017.exe" or \
            type(pins["bytes"]) is not int or not 1024 * 1024 <= pins["bytes"] <= 16 * 1024 * 1024 or \
            not isinstance(pins["sha256"], str) or not native.SHA.fullmatch(pins["sha256"]) or \
            not isinstance(pins["source_freeze_sha256"], str) or not native.SHA.fullmatch(pins["source_freeze_sha256"]):
        raise ValueError("NativeEngineTestPinInvalid")
    names = pins["expected_tests"]
    if not isinstance(names, list) or not 5 <= len(names) <= 100 or any(
        not isinstance(name, str) or not re.fullmatch(r"Test[A-Za-z0-9_]{1,120}", name) for name in names
    ) or names != sorted(set(names)) or sum(name.startswith("TestR2Native") for name in names) != 5:
        raise ValueError("NativeEngineTestPinInvalid")
    return pins


class BoundedStream:
    """Consume all bytes while retaining only a fixed first/tail budget."""
    def __init__(self, limit=STREAM_LIMIT):
        self.limit = limit
        self.first = bytearray()
        self.tail = bytearray()
        self.total = 0

    def feed(self, data):
        self.total += len(data)
        first_budget = self.limit // 2
        take = min(len(data), first_budget - len(self.first))
        self.first.extend(data[:take])
        self.tail.extend(data[take:])
        del self.tail[:max(0, len(self.tail) - (self.limit - first_budget))]

    def value(self):
        if self.total <= self.limit:
            return bytes(self.first + self.tail)
        return bytes(self.first) + b"\n[bounded stream: middle omitted]\n" + bytes(self.tail)


class TestOutput:
    """Recognize only fixed Go test status lines; never export test text."""
    def __init__(self, expected):
        self.expected = set(expected)
        self.status = {}
        self.pending = bytearray()
        self.overlong = False
        self.invalid = False
        self.final_pass = False
        self.any_skip = False

    def line(self, line):
        line = line.removesuffix(b"\r")
        if line == b"PASS":
            self.final_pass = True
        if re.match(rb"\s*--- SKIP:", line):
            self.any_skip = True
        match = re.fullmatch(rb"--- (PASS|SKIP|FAIL): (Test[A-Za-z0-9_]{1,120}) \([0-9.]+s\)", line)
        if match:
            status, name = (item.decode("ascii") for item in match.groups())
            if name not in self.expected or name in self.status:
                self.invalid = True
            else:
                self.status[name] = status

    def feed(self, data):
        for segment in data.splitlines(keepends=True):
            ended = segment.endswith(b"\n")
            if not self.overlong:
                if len(self.pending) + len(segment) > LINE_LIMIT:
                    self.pending.clear()
                    self.overlong = self.invalid = True
                else:
                    self.pending.extend(segment.removesuffix(b"\n"))
            if ended:
                if not self.overlong:
                    self.line(bytes(self.pending))
                self.pending.clear()
                self.overlong = False

    def finish(self):
        if self.pending and not self.overlong:
            self.line(bytes(self.pending))
        self.pending.clear()

    def passed(self, targeted):
        return not self.invalid and self.final_pass and set(self.status) == self.expected and \
            all(value == "PASS" or not targeted and value == "SKIP" for value in self.status.values()) and \
            (not targeted or not self.any_skip)

    def counts(self):
        return sum(value == "PASS" for value in self.status.values()), sum(value == "SKIP" for value in self.status.values())


def temporary_identity(path, directory):
    info = path.lstat()
    if getattr(info, "st_file_attributes", 0) & 0x400 or \
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) or \
            not directory and info.st_nlink != 1 or not info.st_ino:
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    return [info.st_dev, info.st_ino]


def checked_temporary(native, harness, cleanup=False):
    record = harness.state.get("native_engine_temporary")
    identity_keys = {"parent_identity", "root_identity", "marker_identity", "temporary_identity"}
    keys = identity_keys | {"root", "stage"}
    if not isinstance(record, dict) or set(record) != keys or not re.fullmatch(r"[0-9a-f]{32}", harness.owner) or \
            not isinstance(record["root"], str) or record["stage"] not in {"creating", "ready", "cleanup", "finalizing"} or any(
                not isinstance(record[key], list) or len(record[key]) != 2 or
                any(type(value) is not int or value < 0 for value in record[key])
                for key in identity_keys if record[key] is not None
            ) or record["parent_identity"] is None or record["root_identity"] is None or \
            (record["stage"] in {"ready", "cleanup"} and any(record[key] is None for key in ("marker_identity", "temporary_identity"))) or \
            (not cleanup and record["stage"] != "ready"):
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    parent = native.local_app_data()
    root = parent / ("OnionDesk-Native-Tests-" + harness.owner)
    if not parent.is_absolute() or parent.resolve(strict=True) != parent or record["root"] != str(root) or \
            temporary_identity(parent, True) != record["parent_identity"]:
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")

    def matches(path, directory, expected, missing=False):
        try:
            identity = temporary_identity(path, directory)
        except FileNotFoundError:
            if missing:
                return False
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid") from None
        if expected is None or identity != expected:
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
        return True

    finalizing = record["stage"] == "finalizing"
    if not matches(root, True, record["root_identity"], missing=cleanup and finalizing):
        return root
    if record["stage"] != "creating":
        marker = matches(root / ".owner", False, record["marker_identity"], missing=cleanup and finalizing)
        if marker and (root / ".owner").read_text(encoding="utf-8") != harness.owner:
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
        matches(root / "temp", True, record["temporary_identity"], missing=cleanup and finalizing)
    return root


def windows_kernel():
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    return kernel


@contextlib.contextmanager
def windows_temporary_lease(path, directory, remove=False, expected=None):
    import ctypes
    kernel = windows_kernel()
    # No FILE_SHARE_DELETE: retained parents cannot be replaced while their
    # children are checked, created or removed. Never follow a reparse point.
    handle = kernel.CreateFileW(str(path), 0x80 | (0x10000 if remove else 0), 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    try:
        info = (ctypes.c_uint32 * 13)()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or info[0] & 0x400 or \
                bool(info[0] & 0x10) != directory or \
                expected is not None and temporary_identity(path, directory) != expected:
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
        yield kernel, handle
    finally:
        if not kernel.CloseHandle(handle):
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")


def create_temporary(native, harness):
    if "native_engine_temporary" in harness.state or not re.fullmatch(r"[0-9a-f]{32}", harness.owner):
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    parent = native.local_app_data()
    parent_identity = temporary_identity(parent, True)
    if not parent.is_absolute() or parent.resolve(strict=True) != parent:
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    root = parent / ("OnionDesk-Native-Tests-" + harness.owner)
    lease = windows_temporary_lease if os.name == "nt" else lambda *_args, **_kwargs: contextlib.nullcontext()
    with lease(parent, True, expected=parent_identity):
        # Persist the exclusive root identity before any child write. A failed
        # initialization can be removed by this identity without adopting a marker.
        root.mkdir(mode=0o700)
        record = {"root": str(root), "parent_identity": parent_identity,
                  "root_identity": temporary_identity(root, True), "marker_identity": None,
                  "temporary_identity": None, "stage": "creating"}
        harness.state["native_engine_temporary"] = record
        harness.save()
        with lease(root, True, expected=record["root_identity"]):
            with (root / ".owner").open("x", encoding="utf-8") as marker:
                record["marker_identity"] = temporary_identity(root / ".owner", False)
                harness.save()
                marker.write(harness.owner)
            (root / "temp").mkdir(mode=0o700)
            record["temporary_identity"] = temporary_identity(root / "temp", True)
            record["stage"] = "ready"
            harness.save()
            checked_temporary(native, harness)


def windows_remove_temporary(native, harness):
    import ctypes

    def remove_tree(path, directory, expected=None, children_only=False):
        with windows_temporary_lease(path, directory, remove=not children_only, expected=expected) as (kernel, handle):
            temporary_identity(path, directory)
            if directory:
                for child in path.iterdir():
                    info = child.lstat()
                    remove_tree(child, stat.S_ISDIR(info.st_mode))
            if not children_only:
                disposition = ctypes.c_int(1)
                if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                    raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")

    record = harness.state["native_engine_temporary"]
    with windows_temporary_lease(native.local_app_data(), True, expected=record["parent_identity"]):
        root = checked_temporary(native, harness, cleanup=True)
        if not root.exists():  # Only a persisted finalizing record permits this.
            return
        with windows_temporary_lease(root, True, remove=True, expected=record["root_identity"]) as (kernel, handle):
            checked_temporary(native, harness, cleanup=True)
            if record["stage"] != "finalizing":
                creating = record["stage"] == "creating"
                if not creating:
                    record["stage"] = "cleanup"
                    harness.save()
                # Preserve both authentication objects until every other owned
                # descendant is gone. A transient failure can retry this stage.
                for child in root.iterdir():
                    if not creating and child.name == ".owner":
                        continue
                    info = child.lstat()
                    remove_tree(child, stat.S_ISDIR(info.st_mode),
                                children_only=not creating and child.name == "temp")
                if creating:
                    record["marker_identity"] = record["temporary_identity"] = None
                record["stage"] = "finalizing"
                harness.save()
            checked_temporary(native, harness, cleanup=True)
            if any(child.name not in {".owner", "temp"} for child in root.iterdir()):
                raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
            for name, directory, key in (("temp", True, "temporary_identity"), (".owner", False, "marker_identity")):
                child = root / name
                if child.exists() or child.is_symlink():
                    if directory and any(child.iterdir()):
                        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
                    remove_tree(child, directory, expected=record[key])
            disposition = ctypes.c_int(1)
            if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")


def cleanup_temporary(native, harness):
    if "native_engine_temporary" not in harness.state:
        return
    root = checked_temporary(native, harness, cleanup=True)
    if os.name == "nt":
        windows_remove_temporary(native, harness)
    else:
        # Local boundary tests use Python's descriptor-anchored Unix remover.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
        shutil.rmtree(root)
    del harness.state["native_engine_temporary"]
    harness.save()


def test_environment(native, harness):
    root = harness.root.resolve(strict=True)
    if harness.root.is_symlink() or (harness.root / ".owner").is_symlink() or \
            (harness.root / ".owner").read_text(encoding="utf-8") != harness.owner:
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    environment = dict(harness.environment)
    if any(Path(environment.get(key, "")).resolve(strict=True) != root / "temp" for key in ("TEMP", "TMP", "TMPDIR")):
        raise RuntimeError("NativeEngineTemporaryOwnershipInvalid")
    temporary = checked_temporary(native, harness) / "temp"
    environment.update({key: str(temporary) for key in ("TEMP", "TMP", "TMPDIR")})
    environment["ONIONDESK_R2_NATIVE_REQUIRE_ADMIN_DEFAULT_OWNER"] = "1"
    return environment


def verify_executable(native, executable, pins):
    if executable.is_symlink() or not executable.is_file() or executable.stat().st_size != pins["bytes"] or \
            native.digest(executable) != pins["sha256"]:
        raise ValueError("NativeEngineTestPinMismatch")
    with executable.open("rb") as source:
        dos = source.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("NativeEngineTestPEInvalid")
        pe = struct.unpack_from("<I", dos, 60)[0]
        if pe > pins["bytes"] - 100:
            raise ValueError("NativeEngineTestPEInvalid")
        source.seek(pe)
        header = source.read(96)
    if len(header) != 96 or header[:4] != b"PE\x00\x00" or struct.unpack_from("<H", header, 4)[0] != 0x8664 or \
            struct.unpack_from("<H", header, 24)[0] != 0x20B or struct.unpack_from("<H", header, 92)[0] != 3:
        raise ValueError("NativeEngineTestPEInvalid")


def download_tests(native, harness, pins):
    directory = harness.root / "r2-native"
    directory.mkdir(mode=0o700)
    executable = directory / "OnionDesk-Engine-Tests.exe"
    url = "https://github.com/lindwerg/oniondesk/releases/download/" + native.PINS["release"] + "/" + pins["asset"]
    with urllib.request.urlopen(url, timeout=60) as response, executable.open("xb") as output:
        count = 0
        while data := response.read(1024 * 1024):
            count += len(data)
            if count > pins["bytes"]:
                raise ValueError("NativeEngineTestPinMismatch")
            output.write(data)
    verify_executable(native, executable, pins)
    harness.facts.update({"native_engine_test_asset_verified": True, "native_engine_test_sha256": pins["sha256"]})
    harness.save()
    return executable


def execute_suite(native, harness, executable, pins, targeted):
    import psutil
    verify_executable(native, executable, pins)
    environment = test_environment(native, harness)
    expected = [name for name in pins["expected_tests"] if not targeted or name.startswith("TestR2Native")]
    parser = TestOutput(expected)
    stdout, stderr = BoundedStream(), BoundedStream()
    read_failed = []
    process = None
    threads = []
    timed_out = False

    def read_pipe(pipe, capture, analyze=False):
        try:
            while data := pipe.read(4096):
                capture.feed(data)
                if analyze:
                    parser.feed(data)
        except Exception:
            read_failed.append(True)
        finally:
            pipe.close()

    arguments = [str(executable), "-test.v", "-test.timeout=5m"]
    if targeted:
        arguments.append("-test.run=^TestR2Native")
    try:
        process = subprocess.Popen(arguments, cwd=executable.parent, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        for pipe, capture, analyze in ((process.stdout, stdout, True), (process.stderr, stderr, False)):
            thread = threading.Thread(target=read_pipe, args=(pipe, capture, analyze), daemon=True)
            thread.start()
            threads.append(thread)
        # Persist the owned PID + creation-time pair before waiting or cleanup.
        try:
            harness.remember(psutil.Process(process.pid))
        except psutil.NoSuchProcess:
            if process.poll() is None:
                raise
        try:
            process.wait(timeout=SUITE_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()  # Popen owns the native Windows process HANDLE.
            process.wait(timeout=5)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
    parser.finish()
    passed, skipped = parser.counts()
    prefix = "native_engine_targeted" if targeted else "native_engine_full"
    harness.facts.update({prefix + "_passed_count": passed, prefix + "_skipped_count": skipped,
                          "native_engine_temp_owned": True})
    harness.save()
    diagnostic = ("suite=" + ("targeted" if targeted else "full") + "\nstdout:\n").encode("ascii") + \
        stdout.value() + b"\nstderr:\n" + stderr.value()
    if timed_out:
        return "NativeEngineTestTimedOut", diagnostic
    if process.returncode != 0:
        return "NativeEngineTargetedFailed" if targeted else "NativeEngineFullSuiteFailed", diagnostic
    if read_failed or any(thread.is_alive() for thread in threads) or not parser.passed(targeted):
        return "NativeEngineTestOutputInvalid", diagnostic
    harness.facts[prefix + "_passed"] = True
    harness.save()
    return None, diagnostic


def run_engine_tests(native, harness):
    if sys.platform != "win32" or harness.distribution != "windows-x64":
        raise RuntimeError("NativeEngineWindowsRunnerRequired")
    pins = checked_test_pins(native)
    harness.phase("windows_native_engine_download")
    diagnostic = b""
    try:
        create_temporary(native, harness)
        executable = download_tests(native, harness, pins)
        for targeted in (True, False):
            harness.phase("windows_native_engine_targeted" if targeted else "windows_native_engine_full")
            failure, diagnostic = execute_suite(native, harness, executable, pins, targeted)
            if failure:
                if failure not in FAILURE_CODES:
                    raise RuntimeError("NativeEngineTestOutputInvalid")
                raise RuntimeError(failure)
    except Exception as error:
        detail = str(error).encode("utf-8", errors="backslashreplace") + b"\n" + diagnostic
        try:
            native.encrypt_browser_diagnostic(RuntimeError(detail.decode("utf-8", errors="replace")), harness.facts["phase"])
            harness.facts["browser_diagnostic_encrypted"] = True
        except Exception as diagnostic_error:
            harness.facts["browser_diagnostic_encrypted"] = False
            harness.facts["diagnostic_error_class"] = type(diagnostic_error).__name__
            harness.facts.update({"diagnostic_error_code": code} if (code := native.trusted_error_facts(diagnostic_error).get("error_code")) else {})
        harness.save()
        raise
