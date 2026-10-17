"""Boundary regression checks. Native success still requires the actual CI run."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("native_r5", Path(__file__).with_name("run.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)
DEBUG_SPEC = importlib.util.spec_from_file_location("windows_cache_debug", Path(__file__).with_name("windows_cache_debug.py"))
WINDOWS_DEBUG = importlib.util.module_from_spec(DEBUG_SPEC)
DEBUG_SPEC.loader.exec_module(WINDOWS_DEBUG)
R2_SPEC = importlib.util.spec_from_file_location("windows_r2", Path(__file__).with_name("windows_r2.py"))
WINDOWS_R2 = importlib.util.module_from_spec(R2_SPEC)
R2_SPEC.loader.exec_module(WINDOWS_R2)


class BoundaryTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Unix socket budget applies to Linux")
    def test_short_private_root_keeps_socket_budget_and_falls_back_from_long_parent(self):
        cases = [("/home/runner/work/_temp", Path("/home/runner/work/_temp")),
                 ("/runner/" + "long" * 40, Path("/tmp")), ("/runner/" + "Ж" * 80, Path("/tmp"))]
        for parent, expected in cases:
            result = expected / "od-12345678"
            with self.subTest(parent_bytes=len(os.fsencode(parent))), mock.patch.dict(os.environ, {"RUNNER_TEMP": parent}), \
                 mock.patch.object(HARNESS.tempfile, "mkdtemp", return_value=str(result)) as create:
                self.assertEqual(HARNESS.create_harness_root("a" * 32), result)
                create.assert_called_once_with(prefix="od-", dir=expected)
                self.assertLessEqual(HARNESS.browser_socket_path_max_bytes(result / "t"), 100)

    @unittest.skipIf(os.name == "nt", "Unix socket budget applies to Linux")
    def test_unexpected_long_temporary_name_fails_clearly_before_browser_tools(self):
        result = Path("/tmp") / ("od-" + "x" * 160)
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": "/tmp"}), \
             mock.patch.object(HARNESS.tempfile, "mkdtemp", return_value=str(result)), \
             mock.patch.object(Path, "rmdir") as remove, mock.patch.object(HARNESS.subprocess, "run") as tools:
            with self.assertRaisesRegex(RuntimeError, "^BrowserTemporaryPathTooLong$"):
                HARNESS.create_harness_root("a" * 32)
            remove.assert_called_once_with()
            tools.assert_not_called()

    def test_dispatch_suites_have_fixed_targets_and_independent_concurrency(self):
        workflow = (HARNESS.REPO / ".github/workflows/native-r5.yml").read_text(encoding="utf-8")
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("\n  workflow_dispatch:", workflow)
        self.assertIn("options: [all, linux, windows, windows-debug, windows-gui-component]", workflow)
        self.assertNotIn("\nconcurrency:", workflow)
        self.assertIn("group: native-r5-${{ github.ref }}-${{ matrix.distribution }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        expression = next(line for line in workflow.splitlines() if "include: ${{ fromJSON(" in line)
        matrices = [json.loads(value) for value in re.findall(r"'(\[.*?\])'", expression)]
        windows = {"distribution": "windows-x64", "runner": "windows-2022", "python_arch": "x64"}
        linux = [{"distribution": "linux-x64", "runner": "ubuntu-24.04", "python_arch": "x64"},
                 {"distribution": "linux-arm64", "runner": "ubuntu-24.04-arm", "python_arch": "arm64"}]
        self.assertEqual(matrices, [linux, [windows], [windows, *linux]])
        self.assertIn("inputs.suite == 'linux'", expression)
        self.assertIn("inputs.suite == 'windows'", expression)
        self.assertIn("inputs.suite == 'windows-debug'", expression)
        self.assertIn("inputs.suite == 'windows-gui-component'", expression)
        self.assertIn("if: runner.os == 'Windows' && inputs.suite != 'windows-debug' && inputs.suite != 'windows-gui-component'", workflow)
        self.assertIn("if: runner.os == 'Windows' && inputs.suite == 'windows-gui-component'", workflow)
        self.assertEqual(workflow.count("run: python -B tests/ci/native-r5/run.py run-windows-gui-component"), 1)
        self.assertIn("if: inputs.suite != 'windows-debug'\n        run: python -B tests/ci/native-r5/run.py provision", workflow)

    def test_normal_windows_route_requires_engine_before_gui_and_never_swallows_failure(self):
        for failure in (None, RuntimeError("NativeEngineTargetedFailed")):
            with self.subTest(engine_failed=failure is not None):
                instance = HARNESS.Harness.__new__(HARNESS.Harness)
                instance.distribution = "windows-x64"
                instance.facts = {"result": "RUNNING"}
                events = []
                instance.download = mock.Mock(side_effect=lambda: events.append("download"))
                instance.save = mock.Mock()
                instance._run_gui_lifecycle = mock.Mock(side_effect=lambda: events.append("gui"))

                def engine(_native, _harness):
                    events.append("engine")
                    if failure:
                        raise failure

                engine_call = mock.Mock(side_effect=engine)
                with mock.patch.object(HARNESS, "os", SimpleNamespace(name="nt")), \
                     mock.patch.dict(sys.modules, {HARNESS.__name__: HARNESS, "windows_r2": SimpleNamespace(run_engine_tests=engine_call)}):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError, "^NativeEngineTargetedFailed$"):
                            instance.run()
                    else:
                        instance.run()
                engine_call.assert_called_once_with(HARNESS, instance)
                self.assertEqual(events, ["download", "engine"] if failure else ["download", "engine", "gui"])
                self.assertIs(instance.facts["native_engine_suite_covered"], failure is None)
                self.assertEqual(instance.facts["result"], "RUNNING" if failure else "PASS")

    def test_windows_gui_component_reuses_full_sandboxed_gui_lifecycle_with_distinct_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for component in (False, True):
                with self.subTest(component=component):
                    instance = HARNESS.Harness.__new__(HARNESS.Harness)
                    instance.distribution = "windows-x64"
                    instance.root = root
                    instance.environment = {}
                    instance.facts = {"distribution": "windows-x64", "result": "RUNNING", "phase": "initialize"}
                    events = []
                    instance.download = mock.Mock(side_effect=lambda: events.append("frozen_download"))
                    instance.save = mock.Mock()
                    instance.phase = lambda phase: instance.facts.update({"phase": phase})
                    instance.discover = mock.Mock()
                    instance.wait_native_restore = mock.Mock(side_effect=lambda: events.append("cold_restore_and_install"))
                    instance.core_flow = mock.Mock(side_effect=lambda _context: events.append("first_action_next_quit"))
                    instance.spawn = mock.Mock(side_effect=lambda _executable: events.append("uninstaller"))
                    instance.drive_nsis = mock.Mock(side_effect=lambda **_kwargs: events.append("uninstall_complete"))
                    context = SimpleNamespace(browser=SimpleNamespace(version="130.0.1"), close=mock.Mock())
                    chromium = SimpleNamespace(executable_path=str(root / "chromium"),
                                               launch_persistent_context=mock.Mock(return_value=context))
                    manager = mock.MagicMock()
                    manager.__enter__.return_value = SimpleNamespace(chromium=chromium)
                    api = SimpleNamespace(sync_playwright=mock.Mock(return_value=manager))
                    engine = mock.Mock(side_effect=lambda *_args: events.append("engine"))
                    with mock.patch.object(HARNESS, "os", SimpleNamespace(name="nt")), \
                         mock.patch.object(HARNESS, "windows_claims", return_value=[root / "cache", root / "installation"]), \
                         mock.patch.dict(sys.modules, {HARNESS.__name__: HARNESS, "playwright.sync_api": api,
                                                      "windows_r2": SimpleNamespace(run_engine_tests=engine)}):
                        if component:
                            instance.run_windows_gui_component()
                        else:
                            instance.run()
                    expected = ["frozen_download", *([] if component else ["engine"]), "cold_restore_and_install",
                                "first_action_next_quit", "uninstaller", "uninstall_complete"]
                    self.assertEqual(events, expected)
                    self.assertEqual(engine.call_count, 0 if component else 1)
                    chromium.launch_persistent_context.assert_called_once_with(str(root / "browser-profile"), headless=False,
                        chromium_sandbox=True, viewport={"width": 1200, "height": 820}, env={}, accept_downloads=False)
                    instance.drive_nsis.assert_called_once_with(uninstall=True)
                    context.close.assert_called_once_with()
                    self.assertEqual(instance.facts["result"], "PASS_WINDOWS_GUI_COMPONENT" if component else "PASS")
                    self.assertIs(instance.facts["native_engine_suite_covered"], not component)
                    HARNESS.validate_public_json(instance.facts)

    def test_windows_gui_component_rejects_other_platforms_before_download(self):
        for platform, distribution in (("posix", "windows-x64"), ("nt", "linux-x64"), ("nt", "linux-arm64")):
            instance = HARNESS.Harness.__new__(HARNESS.Harness)
            instance.distribution = distribution
            instance.download = mock.Mock()
            with self.subTest(platform=platform, distribution=distribution), \
                 mock.patch.object(HARNESS, "os", SimpleNamespace(name=platform)):
                with self.assertRaisesRegex(RuntimeError, "^WindowsGUIComponentRunnerRequired$"):
                    instance.run_windows_gui_component()
                instance.download.assert_not_called()

    def test_component_cli_uses_same_fixed_windows_harness_and_owned_cleanup(self):
        instance = SimpleNamespace(run=mock.Mock(), run_windows_gui_component=mock.Mock())
        with mock.patch.object(HARNESS, "Harness", return_value=instance) as constructor, \
             mock.patch.object(HARNESS, "cleanup") as cleanup, \
             mock.patch.object(sys, "argv", ["run.py", "run-windows-gui-component"]):
            self.assertEqual(HARNESS.main(), 0)
        constructor.assert_called_once_with("windows-x64")
        instance.run_windows_gui_component.assert_called_once_with()
        instance.run.assert_not_called()
        cleanup.assert_called_once_with()

    def test_component_cli_rejects_distribution_arguments_and_invalid_modes(self):
        invalid = [["run-windows-gui-component", "windows-x64"], ["run-windows-gui-component", "linux-x64"],
                   ["run-windows-gui"], ["run", "windows-gui-component"], ["run", "windows-x64", "skip-engine"]]
        for arguments in invalid:
            with self.subTest(arguments=arguments), mock.patch.object(HARNESS, "Harness") as constructor, \
                 mock.patch.object(sys, "argv", ["run.py", *arguments]):
                with self.assertRaisesRegex(ValueError, "^ExpectedRunDistributionOrCleanup$"):
                    HARNESS.main()
                constructor.assert_not_called()

    def test_component_failure_or_cleanup_failure_cannot_leave_a_success_result(self):
        for stage, code in (("download", "ReleaseAssetPinMismatch"), ("gui", "OrdinaryNSISIncomplete"),
                            ("cleanup", "OwnedProcessCleanupIncomplete")):
            with self.subTest(stage=stage):
                instance = HARNESS.Harness.__new__(HARNESS.Harness)
                instance.distribution = "windows-x64"
                instance.facts = {"distribution": "windows-x64", "result": "RUNNING", "phase": "initialize"}
                instance.download = mock.Mock(side_effect=RuntimeError(code) if stage == "download" else None)
                instance._run_gui_lifecycle = mock.Mock(side_effect=RuntimeError(code) if stage == "gui" else None)
                instance.save = mock.Mock()
                with mock.patch.object(HARNESS, "os", SimpleNamespace(name="nt")), \
                     mock.patch.object(HARNESS, "Harness", return_value=instance), \
                     mock.patch.object(HARNESS, "cleanup", side_effect=RuntimeError(code) if stage == "cleanup" else None) as cleanup, \
                     mock.patch.object(sys, "argv", ["run.py", "run-windows-gui-component"]):
                    if stage == "cleanup":
                        with self.assertRaisesRegex(RuntimeError, "^" + code + "$"):
                            HARNESS.main()
                    else:
                        self.assertEqual(HARNESS.main(), 1)
                cleanup.assert_called_once_with()
                self.assertEqual(instance.facts["result"], "FAIL_OR_INCOMPLETE")
                self.assertEqual(instance.facts["error_code"], code)
                self.assertIs(instance.facts["native_engine_suite_covered"], False)
                HARNESS.validate_public_json(instance.facts)

    def test_component_success_schema_requires_windows_and_explicit_no_engine_coverage(self):
        facts = {"result": "PASS_WINDOWS_GUI_COMPONENT", "distribution": "windows-x64", "native_engine_suite_covered": False}
        HARNESS.validate_public_json(facts)
        invalid = [{"result": "PASS_WINDOWS_GUI_COMPONENT"}, {**facts, "native_engine_suite_covered": True},
                   {**facts, "native_engine_suite_covered": 0}, {**facts, "distribution": "linux-x64"},
                   {**facts, "result": "PASS_WINDOWS_GUI_COMPONENT_AND_ALL_PLATFORMS"}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                HARNESS.validate_public_json(value)

    def test_controlled_io_uses_utf8_even_with_cp1252_default(self):
        original_open = Path.open
        implicit = []

        def cp1252_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
            if "b" not in mode and encoding in {None, "locale"}:
                implicit.append(path.name)
                encoding = "cp1252"
            return original_open(path, mode, buffering, encoding, errors, newline)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(Path, "open", new=cp1252_open):
            for distribution in HARNESS.PINS["distributions"]:
                HARNESS.verify_contract(distribution)
            destination = Path(temporary) / "utf8.json"
            HARNESS.write_json(destination, {"message": "Подготовка OnionDesk"})
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8"))["message"], "Подготовка OnionDesk")
        self.assertEqual(implicit, [])

    def test_all_trusted_literal_errors_have_public_codes(self):
        trees = [ast.parse((HARNESS.HERE / name).read_text(encoding="utf-8")) for name in ("run.py", "windows_cache_debug.py", "windows_r2.py")]
        names = {"ValueError", "RuntimeError", "TimeoutError", "OSError", "InterruptedError"}
        literals = {node.exc.args[0].value for tree in trees for node in ast.walk(tree) if isinstance(node, ast.Raise)
                    and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name)
                    and node.exc.func.id in names and node.exc.args and isinstance(node.exc.args[0], ast.Constant)
                    and isinstance(node.exc.args[0].value, str)}
        self.assertEqual(literals | WINDOWS_R2.FAILURE_CODES, HARNESS.TRUSTED_ERROR_CODES)
        for code in literals:
            facts = HARNESS.trusted_error_facts(RuntimeError(code))
            self.assertEqual(facts, {"error_code": code})
            HARNESS.validate_public_json(facts)
        self.assertEqual(HARNESS.trusted_error_facts(RuntimeError("/private/path #nonce")), {})

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CMS tooling unavailable")
    def test_encrypted_diagnostic_is_bounded_and_passes_public_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = b"private-diagnostic-marker-never-published"
            with mock.patch.object(HARNESS, "EVIDENCE", root):
                HARNESS.encrypt_browser_diagnostic(RuntimeError(marker.decode("ascii") + "x" * 100000), "browser_launch")
                encrypted = (root / "browser-diagnostic.cms").read_bytes()
                self.assertLessEqual(len(encrypted), 128 * 1024)
                self.assertLessEqual(len(encrypted), 64 * 1024 + 4096)
                self.assertNotIn(marker, encrypted)
                HARNESS.seal_evidence()
                with mock.patch.object(HARNESS, "DIAGNOSTIC_CERT_SHA256", "0" * 64), self.assertRaises(ValueError):
                    HARNESS.encrypt_browser_diagnostic(RuntimeError("ignored"), "browser_launch")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CMS tooling unavailable")
    def test_public_boundary_rejects_plain_signed_foreign_and_trailing_cms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            marker = b"synthetic-private-plaintext-must-never-be-public"
            certificate = root / "synthetic-recipient.pem"
            key = root / "synthetic-fixture-key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(certificate), "-subj", "/CN=synthetic-CMS-boundary-fixture", "-days", "1"],
                           check=True, capture_output=True, timeout=30)
            commands = {
                "Data": ["-data_create"],
                "SignedData": ["-sign", "-nodetach", "-signer", str(certificate), "-inkey", str(key)],
                "ForeignRecipient": ["-encrypt", "-aes-256-cbc", str(certificate)],
                "AES128": ["-encrypt", "-aes-128-cbc", str(HARNESS.HERE / "diagnostic-recipient.pem")],
            }
            target = evidence / "browser-diagnostic.cms"
            with mock.patch.object(HARNESS, "EVIDENCE", evidence):
                for name, operation in commands.items():
                    result = subprocess.run(["openssl", "cms", "-binary", "-outform", "DER", *operation],
                                            input=marker, check=True, capture_output=True, timeout=20)
                    if name in {"Data", "SignedData"}:
                        self.assertIn(marker, result.stdout)
                    target.write_bytes(result.stdout)
                    with self.subTest(profile=name), self.assertRaises(ValueError):
                        HARNESS.seal_evidence()
                HARNESS.encrypt_browser_diagnostic(RuntimeError("synthetic valid encrypted diagnostic"), "browser_launch")
                HARNESS.seal_evidence()
                target.write_bytes(target.read_bytes() + marker)
                with self.assertRaises(ValueError):
                    HARNESS.seal_evidence()

    def test_system_browser_attestation_exports_only_fixed_boolean_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "chrome"
            facts = HARNESS.system_chrome_attestation(executable)
            self.assertFalse(facts["system_chrome_exists"])
            executable.write_bytes(b"synthetic")
            executable.chmod(0o777)
            facts = HARNESS.system_chrome_attestation(executable)
            self.assertTrue(facts["system_chrome_regular"])
            self.assertTrue(facts["system_chrome_group_writable"])
            self.assertTrue(facts["system_chrome_other_writable"])
            self.assertTrue(all(type(value) is bool for value in facts.values()))
            HARNESS.validate_public_json(facts)

    def test_known_root_owned_chrome_permissions_are_tightened_before_launch(self):
        executable = Path("/opt/google/chrome/chrome")
        parents = [Path("/opt"), Path("/opt/google"), executable.parent]
        modes = {path: (stat.S_IFREG if path == executable else stat.S_IFDIR) | 0o777 for path in [*parents, executable]}
        commands = []

        def file_stat(path):
            return SimpleNamespace(st_uid=0, st_mode=modes[path])

        def chmod(arguments, **_kwargs):
            self.assertEqual(arguments[:5], ["sudo", "--non-interactive", "chmod", "0755", "--"])
            commands.append(arguments)
            for name in arguments[5:]:
                path = Path(name)
                modes[path] = stat.S_IFMT(modes[path]) | 0o755
            return subprocess.CompletedProcess(arguments, 0)

        with mock.patch.object(Path, "lstat", new=file_stat), mock.patch.object(HARNESS.subprocess, "run", side_effect=chmod):
            HARNESS.harden_system_chrome_permissions()
        self.assertEqual([command[5:] for command in commands], [[str(path) for path in parents], [str(executable)]])
        self.assertTrue(all(stat.S_IMODE(mode) == 0o755 for mode in modes.values()))
        modes[executable] = stat.S_IFLNK | 0o777
        with mock.patch.object(Path, "lstat", new=file_stat), mock.patch.object(HARNESS.subprocess, "run") as command:
            with self.assertRaises(RuntimeError):
                HARNESS.harden_system_chrome_permissions()
            command.assert_not_called()

    def test_browser_elf_architecture_is_read_from_native_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-browser"
            header = bytearray(64)
            header[:7] = b"\x7fELF\x02\x01\x01"
            for machine in (62, 183):
                header[18:20] = machine.to_bytes(2, "little")
                target.write_bytes(header)
                self.assertEqual(HARNESS.browser_elf_machine(target), machine)
            header[5] = 2
            target.write_bytes(header)
            self.assertEqual(HARNESS.browser_elf_machine(target), 0)

    def test_bounded_browser_diagnostic_keeps_first_and_fatal_tail_as_utf8(self):
        payload = HARNESS.bounded_browser_diagnostic(RuntimeError("FIRST-MARKER" + "Ж" * 100000 + "LAST-FATAL-MARKER"), "browser_launch")
        self.assertLessEqual(len(payload), 64 * 1024)
        text = payload.decode("utf-8")
        self.assertIn("FIRST-MARKER", text)
        self.assertIn("middle omitted", text)
        self.assertTrue(text.endswith("LAST-FATAL-MARKER"))

    def test_cleanup_failure_records_exact_code_and_cannot_leave_pass_result(self):
        instance = SimpleNamespace(facts={"phase": "complete", "result": "PASS"}, save=mock.Mock(), run=mock.Mock())
        with mock.patch.object(HARNESS, "Harness", return_value=instance), \
             mock.patch.object(HARNESS, "cleanup", side_effect=RuntimeError("OwnedProcessCleanupIncomplete")), \
             mock.patch.object(sys, "argv", ["run.py", "run", "linux-x64"]), self.assertRaises(RuntimeError):
            HARNESS.main()
        self.assertEqual(instance.facts["result"], "FAIL_OR_INCOMPLETE")
        self.assertEqual(instance.facts["error_code"], "OwnedProcessCleanupIncomplete")

    def test_owned_native_terminal_error_stops_restore_without_blind_wait(self):
        instance = HARNESS.Harness.__new__(HARNESS.Harness)
        instance.environment = {}
        instance.entry = Path("synthetic-starter.exe")
        instance.facts = {}
        for name in ("phase", "save", "cache_progress", "discover"):
            setattr(instance, name, mock.Mock())
        instance.native_snapshot = mock.Mock(return_value=True)
        instance.payload = mock.Mock(return_value=None)
        instance.native_terminal_error = mock.Mock(return_value="unsafe_cache")
        instance.spawn = mock.Mock(return_value=SimpleNamespace(poll=lambda: None))
        env = {"USERPROFILE": "synthetic", "LOCALAPPDATA": "synthetic", "APPDATA": "synthetic"}
        with mock.patch.object(HARNESS.os, "name", "nt"), mock.patch.dict(os.environ, env), \
             mock.patch.object(HARNESS.time, "sleep") as wait:
            with self.assertRaisesRegex(RuntimeError, "^NativePreparationTerminalError$"):
                instance.wait_native_restore()
            wait.assert_not_called()
        self.assertEqual(instance.facts["native_error_code"], "unsafe_cache")
        self.assertEqual(HARNESS.classify_native_error(list(HARNESS.NATIVE_ERRORS)), "not_configured")
        self.assertIsNone(HARNESS.classify_native_error(["/private/arbitrary text"]))

    def test_windows_probe_public_output_contains_only_known_booleans_and_error_kind(self):
        snapshot = {"exists": True, "owner_is_user": False, "owner_is_admin": True, "dacl_protected": False,
                    "sddl": "O:private-owner-D:private", "descriptor_error": "private-path"}
        result = {"root_after": {**snapshot, "owner_is_user": True, "owner_is_admin": False}, "child_after": snapshot,
                  "token_owner_equals_user": False, "token_owner_is_admin": True, "token_elevated": True,
                  "go_version": "go1.26.2", "unsafe_error": True, "download_progress_seen": False,
                  "deadline_reached": False, "restore_lock_exists": False,
                  "restore_error": "unsafe cache: cache handle owner/DACL differs", "cache": "private-path",
                  "user_sid": "private-user-sid", "ancestors": [{"path": "private-ancestor-path", "security": snapshot}]}
        facts = WINDOWS_DEBUG.public_probe_facts(result)
        HARNESS.validate_public_json(facts)
        self.assertNotIn("private", json.dumps(facts))
        self.assertNotIn("user_sid", facts)
        self.assertNotIn("ancestors", facts)
        self.assertTrue(facts["manifest_child_owner_is_admin"])
        self.assertTrue(facts["cache_owner_is_user"])
        self.assertEqual(facts["probe_error_kind"], "owned_handle_owner_dacl")

    def test_contract_bytes_survive_git_autocrlf_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("tests/ci/native-r5/contracts/windows-x64.json")
            target = root / relative
            target.parent.mkdir(parents=True)
            original = (HARNESS.HERE / "contracts/windows-x64.json").read_bytes()
            target.write_bytes(original)
            (root / ".gitattributes").write_bytes((HARNESS.REPO / ".gitattributes").read_bytes())
            for arguments in (["init", "--quiet"], ["-c", "core.autocrlf=true", "add", "."]):
                subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
            target.unlink()
            subprocess.run(["git", "-c", "core.autocrlf=true", "checkout-index", "--all", "--force"],
                           cwd=root, check=True, capture_output=True)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),
                             HARNESS.PINS["distributions"]["windows-x64"]["manifest_sha256"])

    def test_empty_cleanup_does_not_import_optional_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            env = {"RUNNER_TEMP": temporary, "CI_STATE_FILE": str(root / "oniondesk-native-1-1-windows-x64.json"),
                   "PLAYWRIGHT_BROWSERS_PATH": str(root / "oniondesk-native-browsers-1-1")}
            original_import = __import__
            def guarded_import(name, *args, **kwargs):
                if name in {"psutil", "PIL", "playwright", "pywinauto"}:
                    raise ModuleNotFoundError(name)
                return original_import(name, *args, **kwargs)
            with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS, "EVIDENCE", evidence), \
                 mock.patch("builtins.__import__", side_effect=guarded_import):
                HARNESS.cleanup()

    def test_browser_launch_classifier_publishes_only_fixed_facts(self):
        cases = {
            "Missing X server or $DISPLAY": "display_unavailable",
            "Socket path too long: /private/synthetic/SingletonSocket": "socket_path_too_long",
            "The SUID sandbox helper binary was found, but is not configured correctly": "sandbox_helper_misconfigured",
            "No usable sandbox!": "sandbox_unavailable",
            "Failed to move to new namespace: Operation not permitted": "user_namespace_rejected",
            "error while loading shared libraries: private.so": "shared_library_missing",
            "Executable doesn't exist at /private/tool": "executable_missing",
            "unknown /private/path http://127.0.0.1/#nonce --secret-command": "unclassified_browser_launch_failure",
        }
        for literal, expected in cases.items():
            with self.subTest(reason=expected):
                facts = HARNESS.browser_failure_facts(RuntimeError(literal + "\nprocess did exit: signal=SIGTRAP"))
                self.assertEqual(facts, {"browser_failure_reason": expected, "browser_failure_signal": "SIGTRAP"})
                HARNESS.validate_public_json(facts)

    def test_sandbox_requires_positive_layer_one_namespaces_and_seccomp(self):
        rows = {"Layer 1 Sandbox": "Namespace", "PID namespaces": "Yes",
                "Network namespaces": "Yes", "Seccomp-BPF sandbox": "Yes"}
        self.assertEqual(HARNESS.positive_linux_sandbox_layer(rows), "Namespace")
        self.assertEqual(HARNESS.positive_linux_sandbox_layer({**rows, "Layer 1 Sandbox": "SUID"}), "SUID")
        for key in rows:
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                HARNESS.positive_linux_sandbox_layer({**rows, key: "No"})

    def test_sandbox_cleanup_rejects_unowned_system_path_before_sudo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tooling = root / "oniondesk-native-browsers-1-1"
            tooling.mkdir()
            (tooling / "sandbox-owner.json").write_text(json.dumps({"target": "/private/unowned", "sha256": "a" * 64}), encoding="utf-8")
            env = {"RUNNER_TEMP": temporary, "PLAYWRIGHT_BROWSERS_PATH": str(tooling),
                   "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
            with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    HARNESS.cleanup_browser_tooling()
                command.assert_not_called()

    def test_failed_helper_removal_preserves_ownership_and_cleanup_can_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            owner = "a" * 32
            root = parent / (("oniondesk-native-" + owner + "-test") if os.name == "nt" else "od-abcd1234")
            root.mkdir()
            (root / ".owner").write_text(owner, encoding="utf-8")
            state = parent / "oniondesk-native-1-1-linux-x64.json"
            state.write_text(json.dumps({"root": str(root), "owner": owner, "processes": [], "windows_claimed": False}), encoding="utf-8")
            tooling = parent / "oniondesk-native-browsers-1-1"
            tooling.mkdir()
            helper = parent / "owned-sandbox-helper"
            helper.write_bytes(b"owned helper")
            expected = hashlib.sha256(helper.read_bytes()).hexdigest()
            record = tooling / "sandbox-owner.json"
            record.write_text(json.dumps({"target": str(helper), "sha256": expected}), encoding="utf-8")
            evidence = parent / "evidence"
            env = {"RUNNER_TEMP": temporary, "CI_STATE_FILE": str(state), "PLAYWRIGHT_BROWSERS_PATH": str(tooling)}
            processes = SimpleNamespace(wait_procs=mock.Mock(return_value=([], [])), NoSuchProcess=ProcessLookupError)
            attempts = []

            def remove_helper(arguments, **_kwargs):
                self.assertEqual(arguments, ["sudo", "--non-interactive", "rm", "--", str(helper)])
                attempts.append(arguments)
                if len(attempts) == 1:
                    raise subprocess.CalledProcessError(1, "sudo")
                helper.unlink()
                return subprocess.CompletedProcess(arguments, 0)

            with mock.patch.dict(os.environ, env), mock.patch.dict(sys.modules, {"psutil": processes}), \
                 mock.patch.object(HARNESS, "EVIDENCE", evidence), \
                 mock.patch.object(HARNESS, "sandbox_helper_path", return_value=helper), \
                 mock.patch.object(HARNESS, "validate_sandbox_helper") as validate, \
                 mock.patch.object(HARNESS.subprocess, "run", side_effect=remove_helper):
                with self.assertRaises(subprocess.CalledProcessError):
                    HARNESS.cleanup()
                self.assertTrue(state.is_file())
                self.assertTrue((root / ".owner").is_file())
                self.assertTrue(record.is_file())
                self.assertTrue(helper.is_file())
                self.assertFalse((evidence / "cleanup.json").exists())
                HARNESS.cleanup()
                self.assertFalse(root.exists())
                self.assertFalse(state.exists())
                self.assertFalse(tooling.exists())
                self.assertFalse(helper.exists())
                self.assertTrue(json.loads((evidence / "cleanup.json").read_text(encoding="utf-8"))["private_cache_and_profile_removed"])
                self.assertEqual(validate.call_args_list, [mock.call(helper, expected), mock.call(helper, expected)])
                self.assertEqual(len(attempts), 2)

    def test_provision_rejects_non_public_runner_before_commands(self):
        with mock.patch.dict(os.environ, {"CI_DISTRIBUTION": "linux-x64", "CI_PUBLIC_REPOSITORY": "false"}), \
             mock.patch.object(HARNESS.subprocess, "run") as command:
            with self.assertRaises(RuntimeError):
                HARNESS.provision()
            command.assert_not_called()

    def test_all_frozen_contract_pins_and_counts(self):
        expected = {"windows-x64": (45, 47), "linux-x64": (627, 498), "linux-arm64": (627, 498)}
        for distribution, counts in expected.items():
            with self.subTest(distribution=distribution):
                pin, manifest, index = HARNESS.verify_contract(distribution)
                self.assertEqual((len(manifest["files"]), len(manifest["blobs"])), counts)
                self.assertRegex(pin["zip_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(len(index["parts"]), 2)
                self.assertEqual(manifest["entrypoint"], pin["entry"])

    def test_zip_names_reject_cross_platform_traversal_and_aliases(self):
        cases = ["../escape", "/abs", "a//b", "a/./b", "a/../b", "C:/test", "a\\b",
                 "nul.txt", "A/COM1", "a.", "a ", "a\x00b", "a\u200bb", "a\x7fb"]
        for value in cases:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                HARNESS.safe_member(value)

    def archive(self, root, names):
        target = root / "source.zip"
        with zipfile.ZipFile(target, "w") as archive:
            for name, mode, content in names:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, content)
        return target

    def test_zip_rejects_link_before_writing_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.archive(root, [("safe", stat.S_IFREG | 0o644, b"safe"),
                                         ("link", stat.S_IFLNK | 0o777, b"../outside")])
            destination = root / "out"
            destination.mkdir()
            with self.assertRaises(ValueError):
                HARNESS.extract_zip(source, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_zip_rejects_casefold_collision_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.archive(root, [("One", stat.S_IFREG | 0o644, b"1"), ("one", stat.S_IFREG | 0o644, b"2")])
            destination = root / "out"
            destination.mkdir()
            with self.assertRaises(ValueError):
                HARNESS.extract_zip(source, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_zip_preserves_native_executable_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.archive(root, [("OnionDesk", stat.S_IFREG | 0o755, b"native")])
            destination = root / "out"
            destination.mkdir()
            HARNESS.extract_zip(source, destination)
            self.assertEqual((destination / "OnionDesk").read_bytes(), b"native")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((destination / "OnionDesk").stat().st_mode), 0o755)

    def test_payload_rehash_detects_same_size_tamper_and_extra_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "Core"
            payload.write_bytes(b"good")
            payload.chmod(0o755)
            manifest = {"files": [{"path": "Core", "bytes": 4, "mode": 0o755,
                                    "sha256": hashlib.sha256(b"good").hexdigest()}],
                        "directories": [], "symlinks": []}
            HARNESS.verify_payload(root, manifest)
            payload.write_bytes(b"evil")
            with self.assertRaises(ValueError):
                HARNESS.verify_payload(root, manifest)
            payload.write_bytes(b"good")
            (root / "extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                HARNESS.verify_payload(root, manifest)

    def test_public_schema_rejects_raw_output_path_url_nonce_and_nested_data(self):
        cases = [{"raw_log": "secret"}, {"phase": "/private/path"}, {"source_commit": "https://invalid/"},
                 {"result": {"nonce": "secret"}}, {"error_class": "Error: secret/path"},
                 {"online_parts_verified": True}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                HARNESS.validate_public_json(value)

    def test_valid_public_schema(self):
        HARNESS.validate_public_json({"phase": "complete", "result": "PASS", "headed_ui": True,
            "distribution": "windows-x64", "source_commit": "a" * 40, "online_parts_verified": 2})

    def test_artifact_extra_file_and_size_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(HARNESS, "EVIDENCE", root):
                (root / "status.json").write_text(json.dumps({"result": "PASS"}), encoding="utf-8")
                HARNESS.seal_evidence()
                (root / "console.txt").write_text("private", encoding="utf-8")
                with self.assertRaises(ValueError):
                    HARNESS.seal_evidence()
                (root / "console.txt").unlink()
                with mock.patch.object(HARNESS, "MAX_EVIDENCE", 1), self.assertRaises(ValueError):
                    HARNESS.seal_evidence()

    def test_state_path_rejects_outside_runner_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"RUNNER_TEMP": temporary, "CI_STATE_FILE": "/tmp/oniondesk-native-1-1-linux-x64.json"}
            with mock.patch.dict(os.environ, env), self.assertRaises(ValueError):
                HARNESS.private_state_path()

    def test_browser_tooling_path_rejects_unowned_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"RUNNER_TEMP": temporary, "PLAYWRIGHT_BROWSERS_PATH": temporary + "/other"}
            with mock.patch.dict(os.environ, env), self.assertRaises(ValueError):
                HARNESS.browser_tooling_path()

    def test_quit_requires_connection_refusal_not_http_error_or_timeout(self):
        instance = HARNESS.Harness.__new__(HARNESS.Harness)
        instance.facts = {}
        instance.save = lambda: None
        with mock.patch.object(HARNESS.socket, "create_connection", side_effect=ConnectionRefusedError):
            instance.wait_core_listener_closed("http://127.0.0.1:12345/#" + "a" * 43)
        self.assertTrue(instance.facts["core_listener_closed"])
        instance.facts = {}
        with mock.patch.object(HARNESS.socket, "create_connection", side_effect=TimeoutError), \
             mock.patch.object(HARNESS.time, "monotonic", side_effect=[0, 1, 32]), \
             mock.patch.object(HARNESS.time, "sleep"), self.assertRaises(RuntimeError):
            instance.wait_core_listener_closed("http://127.0.0.1:12345/#" + "a" * 43)
        self.assertNotIn("core_listener_closed", instance.facts)


if __name__ == "__main__":
    unittest.main()
