"""R2 pin, process, output and encrypted-diagnostic boundaries."""
import contextlib
import copy
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
HOST_PATH = type(HERE)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = load("native_r5_r2_tests", "run.py")
R2 = load("windows_r2_tests", "windows_r2.py")


class FakeKernel32:
    """Model delete-on-close and injected faults without a Windows host."""
    def __init__(self):
        self.handles = {}
        self.next_handle = 1
        self.before_open = None
        self.fail_delete = None
        self.CreateFileW = mock.Mock(side_effect=self.open)
        self.GetFileInformationByHandle = mock.Mock(side_effect=self.information)
        self.SetFileInformationByHandle = mock.Mock(side_effect=self.disposition)
        self.CloseHandle = mock.Mock(side_effect=self.close)

    def open(self, name, access, sharing, _security, creation, flags, _template):
        path = HOST_PATH(name)
        if sharing != 3 or creation != 3 or flags != 0x02200000:
            raise AssertionError("Lease must exclude delete sharing and open the reparse point itself")
        if self.before_open:
            self.before_open(path)
        info = path.lstat()
        handle = self.next_handle
        self.next_handle += 1
        attributes = (0x400 if path.is_symlink() else 0) | (0x10 if path.is_dir() else 0)
        self.handles[handle] = {"path": path, "attributes": attributes, "delete": False, "access": access,
                                "identity": (info.st_dev, info.st_ino)}
        return handle

    def information(self, handle, output):
        ctypes.cast(output, ctypes.POINTER(ctypes.c_uint32))[0] = self.handles[handle]["attributes"]
        return 1

    def disposition(self, handle, kind, _value, size):
        entry = self.handles[handle]
        if kind != 4 or size != ctypes.sizeof(ctypes.c_int) or not entry["access"] & 0x10000:
            raise AssertionError("Delete must use the retained DELETE handle")
        path = entry["path"]
        if path == self.fail_delete or path.is_dir() and any(path.iterdir()):
            return 0
        entry["delete"] = True
        return 1

    def close(self, handle):
        entry = self.handles.pop(handle)
        if entry["delete"]:
            info = entry["path"].lstat()
            if (info.st_dev, info.st_ino) != entry["identity"]:
                raise AssertionError("Delete handle identity changed")
            if entry["attributes"] & 0x10:
                entry["path"].rmdir()
            else:
                entry["path"].unlink()
        return 1


@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        (root / "temp").mkdir()
        (root / ".owner").write_text("a" * 32, encoding="utf-8")
        harness = SimpleNamespace(root=root, owner="a" * 32, distribution="windows-x64", facts={},
                                  state={},
                                  environment={key: str(root / "temp") for key in ("TEMP", "TMP", "TMPDIR")},
                                  save=mock.Mock(), remember=mock.Mock())

        def phase(value):
            harness.facts["phase"] = value
        harness.phase = phase
        local = root / "current-local-app-data"
        local.mkdir()
        with mock.patch.object(NATIVE, "local_app_data", return_value=local):
            R2.create_temporary(NATIVE, harness)
            yield harness


class WindowsR2Tests(unittest.TestCase):
    def test_pins_are_immutable_asset_names_and_strict_schema(self):
        pins = R2.checked_test_pins(NATIVE)
        self.assertEqual(pins["sha256"], "0f70768c08f3d737c89b1c10a8af33c9ab07b3a241c4de7698948b588d7d436a")
        self.assertEqual(len(pins["expected_tests"]), 43)
        cases = [None, {**pins, "schema": True}, {**pins, "asset": "../private.exe"}, {**pins, "bytes": True},
                 {**pins, "sha256": "private/path"}, {**pins, "unknown": "raw"},
                 {**pins, "expected_tests": pins["expected_tests"] * 2}, {**pins, "expected_tests": ["TestOther"]}]
        for value in cases:
            config = copy.deepcopy(NATIVE.PINS)
            config["distributions"]["windows-x64"]["native_tests"] = value
            with self.subTest(value_type=type(value).__name__), mock.patch.object(NATIVE, "PINS", config):
                with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinInvalid$"):
                    R2.checked_test_pins(NATIVE)

    def test_executable_requires_exact_hash_size_console_pe_and_no_link(self):
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", data, 68, 0x8664)
        struct.pack_into("<H", data, 88, 0x20B)
        struct.pack_into("<H", data, 156, 3)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owned.exe"
            target.write_bytes(data)
            pins = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            R2.verify_executable(NATIVE, target, pins)
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinMismatch$"):
                R2.verify_executable(NATIVE, target, {**pins, "sha256": "0" * 64})
            data[156] = 2
            target.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPEInvalid$"):
                R2.verify_executable(NATIVE, target, {**pins, "sha256": hashlib.sha256(data).hexdigest()})
            target.unlink()
            try:
                target.symlink_to(Path(directory) / "missing.exe")
            except OSError:
                return
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinMismatch$"):
                R2.verify_executable(NATIVE, target, pins)

    def test_download_stops_at_exact_asset_budget_before_execution(self):
        with fixture() as harness, mock.patch.object(R2.urllib.request, "urlopen", return_value=io.BytesIO(b"extra")):
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinMismatch$"):
                R2.download_tests(NATIVE, harness, {"asset": "synthetic.exe", "bytes": 3})
        with fixture() as harness, mock.patch.object(R2.urllib.request, "urlopen", return_value=io.BytesIO(b"bad")):
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinMismatch$"):
                R2.download_tests(NATIVE, harness, {"asset": "synthetic.exe", "bytes": 3, "sha256": "0" * 64})
        self.assertNotIn("native_engine_test_asset_verified", harness.facts)

    def test_fixture_environment_is_owned_and_requires_admin_default_owner(self):
        with fixture() as harness:
            environment = R2.test_environment(NATIVE, harness)
            self.assertEqual(environment["ONIONDESK_R2_NATIVE_REQUIRE_ADMIN_DEFAULT_OWNER"], "1")
            for key in ("TEMP", "TMP", "TMPDIR"):
                self.assertEqual(Path(environment[key]).parent.parent, NATIVE.local_app_data())
                self.assertNotEqual(environment[key], harness.environment[key])
            harness.environment["TEMP"] = str(harness.root.parent)
            with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                R2.test_environment(NATIVE, harness)
            harness.environment["TEMP"] = str(harness.root / "temp")
            (harness.root / ".owner").write_text("b" * 32, encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                R2.test_environment(NATIVE, harness)

    def test_native_temporary_never_claims_existing_local_app_data_directory(self):
        with fixture() as harness:
            root = R2.checked_temporary(NATIVE, harness)
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"unowned unchanged")
            del harness.state["native_engine_temporary"]
            with self.assertRaises(FileExistsError):
                R2.create_temporary(NATIVE, harness)
            self.assertEqual(sentinel.read_bytes(), b"unowned unchanged")
            self.assertNotIn("native_engine_temporary", harness.state)

    def test_native_temporary_cleanup_validates_marker_identity_parent_and_path(self):
        cases = ("marker-content", "marker-missing", "marker-identity", "root-identity", "parent-identity", "external-path", "temporary-identity")
        for case in cases:
            with self.subTest(case=case), fixture() as harness:
                root = R2.checked_temporary(NATIVE, harness)
                sentinel = root / "sentinel"
                sentinel.write_bytes(b"preserve")
                record = harness.state["native_engine_temporary"]
                if case == "marker-content":
                    (root / ".owner").write_text("b" * 32, encoding="utf-8")
                elif case == "marker-missing":
                    (root / ".owner").unlink()
                elif case == "external-path":
                    record["root"] = str(harness.root)
                else:
                    key = {"marker-identity": "marker_identity", "root-identity": "root_identity",
                           "parent-identity": "parent_identity", "temporary-identity": "temporary_identity"}[case]
                    record[key] = [0, 0]
                with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                    R2.cleanup_temporary(NATIVE, harness)
                self.assertEqual(sentinel.read_bytes(), b"preserve")
                self.assertIn("native_engine_temporary", harness.state)

    def test_native_temporary_rejects_root_and_marker_links_without_external_changes(self):
        for linked in ("root", "marker"):
            with self.subTest(linked=linked), fixture() as harness:
                root = R2.checked_temporary(NATIVE, harness)
                outside = harness.root / "outside"
                outside.mkdir()
                (outside / ".owner").write_text(harness.owner, encoding="utf-8")
                (outside / "sentinel").write_bytes(b"outside unchanged")
                if linked == "root":
                    root.rename(root.with_name(root.name + "-held"))
                    root.symlink_to(outside, target_is_directory=True)
                else:
                    (root / ".owner").unlink()
                    (root / ".owner").symlink_to(outside / ".owner")
                with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                    R2.test_environment(NATIVE, harness)
                with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                    R2.cleanup_temporary(NATIVE, harness)
                self.assertEqual((outside / "sentinel").read_bytes(), b"outside unchanged")

    def test_native_temporary_cleanup_removes_only_owned_tree_and_clears_record(self):
        with fixture() as harness:
            root = R2.checked_temporary(NATIVE, harness)
            (root / "temp" / "nested").mkdir()
            (root / "temp" / "nested" / "owned").write_bytes(b"synthetic")
            unrelated = NATIVE.local_app_data() / "unrelated"
            unrelated.mkdir()
            (unrelated / "sentinel").write_bytes(b"outside unchanged")
            R2.cleanup_temporary(NATIVE, harness)
            self.assertFalse(root.exists())
            self.assertNotIn("native_engine_temporary", harness.state)
            self.assertEqual((unrelated / "sentinel").read_bytes(), b"outside unchanged")
            R2.cleanup_temporary(NATIVE, harness)

    def test_windows_cleanup_retry_keeps_authentication_until_descendants_are_gone(self):
        with fixture() as harness:
            root = R2.checked_temporary(NATIVE, harness)
            nested = root / "temp" / "nested"
            nested.mkdir()
            (nested / "owned").write_bytes(b"synthetic")
            kernel = FakeKernel32()
            kernel.fail_delete = nested
            with mock.patch.object(R2, "windows_kernel", return_value=kernel):
                with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                    R2.windows_remove_temporary(NATIVE, harness)
                self.assertEqual(harness.state["native_engine_temporary"]["stage"], "cleanup")
                self.assertEqual((root / ".owner").read_text(encoding="utf-8"), harness.owner)
                self.assertEqual(R2.checked_temporary(NATIVE, harness, cleanup=True), root)
                kernel.fail_delete = None
                with mock.patch.object(R2.os, "name", "nt"):
                    R2.cleanup_temporary(NATIVE, harness)
            self.assertFalse(root.exists())
            self.assertNotIn("native_engine_temporary", harness.state)
            self.assertFalse(kernel.handles)

    def test_windows_cleanup_finalizing_retry_requires_the_same_recorded_root(self):
        for failed_name, substituted in ((name, substituted) for name in ("temp", ".owner", "root") for substituted in (False, True)):
            with self.subTest(failed_name=failed_name, substituted=substituted), fixture() as harness:
                root = R2.checked_temporary(NATIVE, harness)
                kernel = FakeKernel32()
                kernel.fail_delete = root if failed_name == "root" else root / failed_name
                with mock.patch.object(R2, "windows_kernel", return_value=kernel):
                    with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                        R2.windows_remove_temporary(NATIVE, harness)
                    self.assertEqual(harness.state["native_engine_temporary"]["stage"], "finalizing")
                    self.assertEqual((root / ".owner").exists(), failed_name != "root")
                    self.assertEqual((root / "temp").exists(), failed_name == "temp")
                    kernel.fail_delete = None
                    if substituted:
                        root.rename(root.with_name(root.name + "-held"))
                        root.mkdir()
                        (root / "foreign").write_bytes(b"unchanged")
                    with mock.patch.object(R2.os, "name", "nt"):
                        if substituted:
                            with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                                R2.cleanup_temporary(NATIVE, harness)
                            self.assertEqual((root / "foreign").read_bytes(), b"unchanged")
                        else:
                            R2.cleanup_temporary(NATIVE, harness)
                            self.assertFalse(root.exists())

    def test_windows_create_rejects_substitution_before_any_child_write(self):
        with fixture() as harness:
            root = R2.checked_temporary(NATIVE, harness)
            R2.cleanup_temporary(NATIVE, harness)
            outside = NATIVE.local_app_data() / "outside"
            outside.mkdir()
            (outside / "sentinel").write_bytes(b"unchanged")
            kernel = FakeKernel32()

            def substitute(path):
                if path == root:
                    self.assertEqual(harness.state["native_engine_temporary"]["stage"], "creating")
                    harness.save.assert_called()
                    self.assertEqual(set(path.iterdir()), set())
                    path.rename(path.with_name(path.name + "-held"))
                    path.symlink_to(outside, target_is_directory=True)
            kernel.before_open = substitute
            with mock.patch.object(R2, "windows_kernel", return_value=kernel), mock.patch.object(R2.os, "name", "nt"):
                with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                    R2.create_temporary(NATIVE, harness)
            self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])
            self.assertEqual((outside / "sentinel").read_bytes(), b"unchanged")
            with self.assertRaisesRegex(RuntimeError, "^NativeEngineTemporaryOwnershipInvalid$"):
                R2.checked_temporary(NATIVE, harness, cleanup=True)

    def test_windows_failed_initialization_can_remove_only_its_persisted_root(self):
        with fixture() as harness:
            root = R2.checked_temporary(NATIVE, harness)
            R2.cleanup_temporary(NATIVE, harness)
            kernel = FakeKernel32()

            def fail_root_lease(path):
                if path == root:
                    self.assertEqual(harness.state["native_engine_temporary"]["stage"], "creating")
                    self.assertEqual(set(path.iterdir()), set())
                    raise RuntimeError("InjectedLeaseFailure")
            kernel.before_open = fail_root_lease
            with mock.patch.object(R2, "windows_kernel", return_value=kernel), mock.patch.object(R2.os, "name", "nt"):
                with self.assertRaisesRegex(RuntimeError, "^InjectedLeaseFailure$"):
                    R2.create_temporary(NATIVE, harness)
                self.assertEqual(harness.state["native_engine_temporary"]["root_identity"], R2.temporary_identity(root, True))
                kernel.before_open = None
                R2.cleanup_temporary(NATIVE, harness)
            self.assertFalse(root.exists())
            self.assertNotIn("native_engine_temporary", harness.state)
            self.assertFalse(kernel.handles)

    def test_parser_requires_every_expected_native_test_and_no_skips(self):
        good = b"--- PASS: TestR2NativeOne (0.01s)\r\n--- PASS: TestR2NativeTwo (0.00s)\r\nPASS\r\n"
        parser = R2.TestOutput(["TestR2NativeOne", "TestR2NativeTwo"])
        for byte in good:
            parser.feed(bytes([byte]))
        parser.finish()
        self.assertTrue(parser.passed(targeted=True))
        for bad in (good.replace(b"PASS: TestR2NativeOne", b"SKIP: TestR2NativeOne"), good.replace(b"TestR2NativeTwo", b"TestForeign"),
                    good + b"--- PASS: TestR2NativeOne (0.01s)\n", b"PASS\n", good.replace(b"PASS\r\n", b""),
                    b"X" * (R2.LINE_LIMIT + 1) + b"\n" + good):
            parser = R2.TestOutput(["TestR2NativeOne", "TestR2NativeTwo"])
            parser.feed(bad)
            parser.finish()
            self.assertFalse(parser.passed(targeted=True))
            self.assertLessEqual(len(parser.pending), R2.LINE_LIMIT)

    def test_stream_storage_is_bounded_and_retains_start_and_fatal_tail(self):
        capture = R2.BoundedStream()
        capture.feed(b"FIRST" + b"x" * 100000 + b"LAST")
        value = capture.value()
        self.assertLessEqual(len(value), R2.STREAM_LIMIT + 64)
        self.assertTrue(value.startswith(b"FIRST"))
        self.assertTrue(value.endswith(b"LAST"))
        self.assertIn(b"middle omitted", value)

    def execute_owned_helper(self, harness, body, timeout=None):
        helper = harness.root / "owned-process.py"
        helper.write_text(body, encoding="utf-8")
        actual_popen = subprocess.Popen
        seen = []

        def launch(arguments, **kwargs):
            seen.append(arguments)
            return actual_popen([sys.executable, str(helper), *arguments[1:]], **kwargs)

        psutil = SimpleNamespace(Process=lambda pid: SimpleNamespace(pid=pid), NoSuchProcess=ProcessLookupError)
        with mock.patch.object(R2, "verify_executable"), mock.patch.object(R2.subprocess, "Popen", side_effect=launch), \
             mock.patch.dict(sys.modules, {"psutil": psutil}), \
             mock.patch.object(R2, "SUITE_TIMEOUT", timeout if timeout is not None else 5):
            result = R2.execute_suite(NATIVE, harness, helper, {"expected_tests": ["TestR2NativeOwned"]}, True)
        return result, seen

    def test_real_owned_process_is_tracked_and_stdout_stderr_stay_private(self):
        body = ("import os,sys\n"
                "assert os.environ['ONIONDESK_R2_NATIVE_REQUIRE_ADMIN_DEFAULT_OWNER']=='1'\n"
                "print('private-path nonce-url diagnostics', file=sys.stderr)\n"
                "print('--- PASS: TestR2NativeOwned (0.00s)')\nprint('PASS')\n")
        with fixture() as harness:
            (failure, diagnostic), commands = self.execute_owned_helper(harness, body)
            self.assertIsNone(failure)
            self.assertIn(b"private-path nonce-url diagnostics", diagnostic)
            self.assertIn("-test.run=^TestR2Native", commands[0])
            harness.remember.assert_called_once()
            NATIVE.validate_public_json(harness.facts)
            self.assertNotIn("private-path", json.dumps(harness.facts))
            self.assertTrue(harness.facts["native_engine_targeted_passed"])
            self.assertEqual(harness.facts["native_engine_targeted_passed_count"], 1)

    def test_real_owned_process_timeout_and_failure_are_bounded(self):
        with fixture() as harness:
            (failure, diagnostic), _ = self.execute_owned_helper(harness, "import time\ntime.sleep(10)\n", timeout=0.05)
            self.assertEqual(failure, "NativeEngineTestTimedOut")
            self.assertLessEqual(len(diagnostic), 64 * 1024)
            self.assertNotIn("native_engine_targeted_passed", harness.facts)
        with fixture() as harness:
            (failure, _), _ = self.execute_owned_helper(harness, "import sys\nprint('private failure',file=sys.stderr)\nsys.exit(7)\n")
            self.assertEqual(failure, "NativeEngineTargetedFailed")
            self.assertNotIn("native_engine_targeted_passed", harness.facts)

    def test_failure_is_encrypted_and_full_suite_cannot_follow_failed_target(self):
        with fixture() as harness, mock.patch.object(R2.sys, "platform", "win32"), \
             mock.patch.object(R2, "create_temporary"), \
             mock.patch.object(R2, "download_tests", return_value=harness.root / "owned.exe"), \
             mock.patch.object(R2, "execute_suite", return_value=("NativeEngineTargetedFailed", b"private diagnostic path nonce")) as execute, \
             mock.patch.object(NATIVE, "encrypt_browser_diagnostic") as encrypt:
            with self.assertRaisesRegex(RuntimeError, "^NativeEngineTargetedFailed$"):
                R2.run_engine_tests(NATIVE, harness)
            execute.assert_called_once()
            self.assertIn("private diagnostic path nonce", str(encrypt.call_args.args[0]))
            self.assertTrue(harness.facts["browser_diagnostic_encrypted"])
            NATIVE.validate_public_json(harness.facts)
            self.assertNotIn("private diagnostic", json.dumps(harness.facts))

    def test_cms_failure_remains_failed_and_exports_only_fixed_code(self):
        with fixture() as harness, mock.patch.object(R2.sys, "platform", "win32"), \
             mock.patch.object(R2, "create_temporary"), \
             mock.patch.object(R2, "download_tests", side_effect=ValueError("NativeEngineTestPinMismatch")), \
             mock.patch.object(NATIVE, "encrypt_browser_diagnostic", side_effect=ValueError("DiagnosticRecipientPinMismatch")):
            with self.assertRaisesRegex(ValueError, "^NativeEngineTestPinMismatch$"):
                R2.run_engine_tests(NATIVE, harness)
            self.assertFalse(harness.facts["browser_diagnostic_encrypted"])
            self.assertEqual(harness.facts["diagnostic_error_code"], "DiagnosticRecipientPinMismatch")
            NATIVE.validate_public_json(harness.facts)

    def test_public_schema_rejects_raw_test_text_and_incorrect_fact_types(self):
        for value in ({"native_engine_stdout": "private"}, {"native_engine_test_sha256": "private/path"},
                      {"native_engine_targeted_passed": "true"}, {"native_engine_full_passed_count": -1}):
            with self.assertRaises(ValueError):
                NATIVE.validate_public_json(value)


if __name__ == "__main__":
    unittest.main()
