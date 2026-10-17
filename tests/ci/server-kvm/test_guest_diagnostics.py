"""Static guest-command, fail-closed monitoring and private-console boundaries."""
import base64
from contextlib import ExitStack
import json
import multiprocessing
import os
from pathlib import Path
import runpy
import shlex
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, call, patch

import confidential
import guest_console
import guest_diagnostics as diagnostic
from test_harness import guest


def failed_state():
    return {"uptime_seconds": 180, "sysmaint_boot": True, "setup_complete": False,
            "telegram_executable": False, "proxy_environment_present": False, "unit_query_exit": 0,
            "unit": {"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed",
                     "Result": "exit-code", "Restart": "no", "ConditionResult": "yes"}}


class GuestDiagnosticTests(unittest.TestCase):
    def test_guest_command_key_cannot_select_arbitrary_command_or_gateway(self):
        with patch.object(diagnostic, "agent") as execute, self.assertRaises(KeyError):
            diagnostic.execute("arbitrary")
        execute.assert_not_called()
        self.assertEqual("oniondesk-workstation", diagnostic.DOMAIN)
        self.assertTrue(all(command[0].startswith("/usr/") for command in diagnostic.COMMANDS.values()))

    def test_qga_runs_only_fixed_command_and_decodes_bounded_output(self):
        output = b"synthetic private journal"
        responses = [{"pid": 42}, {"exited": True, "exitcode": 0, "out-data": base64.b64encode(output).decode()}]
        with patch.object(diagnostic, "agent", side_effect=responses) as execute:
            self.assertEqual((0, output, b""), diagnostic.execute("first_boot_journal"))
        arguments = execute.call_args_list[0].args[0]["arguments"]
        self.assertEqual("/usr/bin/journalctl", arguments["path"])
        self.assertIn("--unit=oniondesk-first-boot.service", arguments["arg"])
        self.assertEqual({"execute": "guest-exec-status", "arguments": {"pid": 42}}, execute.call_args_list[1].args[0])

    def test_qga_rejects_truncation_bad_base64_and_invalid_exit(self):
        failures = ({"exited": True, "exitcode": 0, "out-data": "%%%"},
                    {"exited": True, "exitcode": 0, "out-truncated": True},
                    {"exited": True, "exitcode": True},
                    {"exited": True, "exitcode": 0, "out-data": "A" * (128 * 1024)})
        for result in failures:
            with self.subTest(result=result.keys()), patch.object(diagnostic, "agent", side_effect=[{"pid": 42}, result]), self.assertRaises(ValueError):
                diagnostic.execute("state")

    def test_state_rejects_non_boolean_or_unknown_schema(self):
        report = failed_state()
        report["setup_complete"] = 0
        with patch.object(diagnostic, "execute", return_value=(0, json.dumps(report).encode(), b"")), self.assertRaises(ValueError):
            diagnostic.state()
        report = failed_state()
        report["private"] = "must not publish"
        with patch.object(diagnostic, "execute", return_value=(0, json.dumps(report).encode(), b"")), self.assertRaises(ValueError):
            diagnostic.state()

    def test_terminal_reason_requires_sysmaint_age_no_marker_and_no_restart(self):
        self.assertEqual("first_boot_unit_failed", diagnostic.terminal_reason(failed_state()))
        changes = (("sysmaint_boot", False), ("setup_complete", True), ("uptime_seconds", 119),
                   ("unit_query_exit", False), ("unit_query_exit", 1))
        for key, value in changes:
            report = failed_state()
            report[key] = value
            with self.subTest(key=key, value=value):
                self.assertIsNone(diagnostic.terminal_reason(report))
        report = failed_state()
        report["unit"]["Restart"] = "on-failure"
        self.assertIsNone(diagnostic.terminal_reason(report))

    def test_monitor_requires_stability_and_unknown_resets_candidate(self):
        monitor = diagnostic.Monitor()
        self.assertIsNone(monitor.observe(100, failed_state()))
        self.assertIsNone(monitor.observe(129, failed_state()))
        self.assertEqual("first_boot_unit_failed", monitor.observe(130, failed_state()))
        self.assertIsNone(monitor.observe(131, {}))
        self.assertIsNone(monitor.observe(200, failed_state()))
        self.assertIsNone(monitor.observe(229, failed_state()))

    def test_not_found_and_failed_condition_are_distinct_terminal_proofs(self):
        report = failed_state()
        report["unit"].update(LoadState="not-found", ActiveState="inactive", SubState="dead")
        self.assertEqual("first_boot_unit_not_found", diagnostic.terminal_reason(report))
        report["unit"].update(LoadState="loaded", ConditionResult="no")
        self.assertEqual("first_boot_unit_condition_failed", diagnostic.terminal_reason(report))
        report["unit"]["ConditionResult"] = "yes"
        self.assertIsNone(diagnostic.terminal_reason(report))

    def test_public_guest_state_does_not_copy_raw_unit_properties(self):
        report = failed_state()
        report["unit"]["private"] = "secret.onion /private/path"
        public = diagnostic.public_state(report)
        self.assertTrue(public["unit_failed"])
        self.assertNotIn("secret", json.dumps(public))
        self.assertNotIn("/private", json.dumps(public))

    def test_unavailable_qga_is_unknown_not_a_failed_service(self):
        private = confidential.PrivateDiagnostic()
        with patch.object(diagnostic, "execute", side_effect=subprocess.CalledProcessError(1, "private command")):
            report = diagnostic.collect(private)
        self.assertFalse(report["qga_available"])
        self.assertEqual(b"", private.data)
        self.assertNotIn("private command", json.dumps(report))

    def test_rfb_key_event_and_chord_use_documented_network_format(self):
        self.assertEqual(b"\x04\x01\0\0\0\0\0t", guest_console.key_event(ord("t"), True))
        connection = Mock()
        with patch.object(guest_console.time, "sleep"):
            guest_console.chord(connection, (1, 2))
        self.assertEqual([(4, 1, 0, 1), (4, 1, 0, 2), (4, 0, 0, 2), (4, 0, 0, 1)],
                         [struct.unpack("!BBHI", sent.args[0]) for sent in connection.sendall.call_args_list])

    def test_rfb_pauses_between_every_press_and_release_including_return(self):
        timeline = Mock()
        connection = Mock()
        timeline.attach_mock(connection.sendall, "send")
        with patch.object(guest_console.time, "sleep") as pause:
            timeline.attach_mock(pause, "pause")
            guest_console.chord(connection, (0xFFE1, ord("A")))
            guest_console.chord(connection, (0xFF0D,))
        expected = []
        for key, down in ((0xFFE1, True), (ord("A"), True), (ord("A"), False),
                          (0xFFE1, False), (0xFF0D, True), (0xFF0D, False)):
            expected.extend((call.send(guest_console.key_event(key, down)), call.pause(0.02)))
        self.assertEqual(expected, timeline.mock_calls)

    def test_failed_installer_tail_is_kept_only_in_private_buffer(self):
        process = Mock()
        process.poll.return_value = 1
        process.returncode = 1
        process.stdout.read.return_value = b"synthetic-private-installer-cause"
        private = confidential.PrivateDiagnostic()
        selector = Mock()
        with patch.object(guest.subprocess, "Popen", return_value=process), \
                patch.object(guest.selectors, "DefaultSelector", return_value=selector), \
                patch.object(guest.diagnostics, "static_error_sites", return_value=[]), \
                patch.object(guest.diagnostics, "output_summary", return_value={}), self.assertRaises(RuntimeError):
            guest.install("direct", {}, private)
        self.assertIn(b"synthetic-private-installer-cause", private.data)
        process.stdout.close.assert_called_once()


class ConsoleDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.markers = {role: self.root / (role + "-private") for role in guest_console.PROFILES}
        self.locks = {role: self.root / (role + ".lock") for role in guest_console.PROFILES}
        self.raw = {role: self.root / (role + ".ppm") for role in guest_console.PROFILES}
        self.outputs = {role: self.root / (role + "-console.cms") for role in guest_console.PROFILES}
        for name, value in (("SUPPRESSION_MARKERS", self.markers), ("LOCK_FILES", self.locks), ("RAW_IMAGES", self.raw), ("OUTPUTS", self.outputs)):
            self.stack.enter_context(patch.object(guest_console, name, value))
        self.stack.enter_context(patch.object(guest_console, "lock_owner_uid", return_value=os.geteuid()))
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.__exit__.return_value = False
        self.handshake()
        self.connect = self.stack.enter_context(patch.object(guest_console.socket, "create_connection", return_value=self.connection))
        self.stack.enter_context(patch.object(guest_console.time, "sleep"))

    def handshake(self):
        self.connection.recv.side_effect = [b"RFB 003.008\n", b"\x01", b"\x01", b"\0" * 4, b"\0" * 24]

    def image(self, arguments, **_kwargs):
        from PIL import Image
        Image.new("RGB", (640, 480), "white").save(arguments[-1], format="PPM")

    def test_only_two_fixed_roles_ports_domains_and_destinations_exist(self):
        self.assertEqual({"workstation": ("oniondesk-workstation", 5902),
                          "gateway": ("oniondesk-gateway", 5901)}, guest_console.PROFILES)
        self.assertEqual(set(guest_console.PROFILES), set(guest_console.READ_ONLY_COMMANDS))
        self.assertEqual(set(guest_console.PROFILES), set(guest_console.SUPPRESSION_MARKERS))
        self.assertEqual(set(guest_console.PROFILES), set(guest_console.RAW_IMAGES))
        self.assertEqual(set(guest_console.PROFILES), set(guest_console.OUTPUTS))

    def test_unknown_role_cannot_select_commands_network_or_files(self):
        for role in ("other", "../gateway", "127.0.0.1", "gateway; echo private", "", None, [], 1):
            with self.subTest(role=role), self.assertRaises(ValueError):
                guest_console.capture(role)
        self.connect.assert_not_called()
        self.assertEqual([], list(self.root.iterdir()))

    def test_literals_have_guest_timeout_and_safe_static_shell_syntax(self):
        for role in guest_console.PROFILES:
            with self.subTest(role=role):
                command = guest_console.command_for(role)
                parts = shlex.split(command)
                self.assertEqual(["timeout", "30", "sh", "-c"], parts[:4])
                self.assertEqual(5, len(parts))
                result = subprocess.run(["sh", "-n"], input=command.encode(), capture_output=True, timeout=5)
                self.assertEqual(0, result.returncode)
                for forbidden in ("sudo", "su ", "--insecure", " -k ", "--noproxy", "torsocks -i", "systemctl start", "systemctl restart", "apt-get ", " > ", "tee "):
                    self.assertNotIn(forbidden, command)

    def test_workstation_only_uses_fixed_tls_verified_tor_api(self):
        command = guest_console.command_for("workstation")
        self.assertIn("systemctl status oniondesk-first-boot.service --no-pager -l -n0", command)
        self.assertIn("journalctl -u oniondesk-first-boot.service -n6 --no-pager -o cat", command)
        self.assertIn("ps -eo pid,ppid,euid,comm,args", command)
        self.assertIn('[o]niondesk-workstation-setup|[c]url|[t]orsocks|[a]pt|[s]leep', command)
        self.assertIn("ip -o route", command)
        self.assertIn("timeout 8 getent ahostsv4 check.torproject.org", command)
        self.assertIn("curl --fail --silent --show-error --max-time 15 https://check.torproject.org/api/ip", command)
        self.assertEqual(1, command.count("https://"))
        self.assertIn("echo CURL_EXIT=$?", command)

    def test_gateway_uses_fixed_units_vendor_config_and_no_guessed_network_probe(self):
        command = guest_console.command_for("gateway")
        self.assertIn("systemctl status tor@default.service tor.service --no-pager -l -n0", command)
        self.assertIn("journalctl -u tor@default.service -u tor.service -n8 --no-pager -o cat", command)
        self.assertIn("/etc/tor/torrc /etc/torrc.d/95_whonix.conf /usr/local/etc/torrc.d/50_user.conf", command)
        self.assertIn("ss -lnt | head -n10; ip -o route", command)
        for forbidden in ("curl", "getent", "socks5", "9100", "9050", "9150"):
            self.assertNotIn(forbidden, command)

    def test_literal_and_event_budgets_cover_actual_paced_commands(self):
        self.assertLess(guest_console.MAX_CAPTURE_SECONDS, 120)
        self.assertEqual(0.02, guest_console.KEY_EVENT_INTERVAL)
        for role in guest_console.PROFILES:
            command = guest_console.command_for(role)
            self.assertLessEqual(len(command.encode("ascii")), guest_console.MAX_LITERAL_BYTES)
            events = 10 + sum(2 * len(guest_console.character_keys(char)) for char in command)
            self.assertLessEqual(events, guest_console.MAX_KEY_EVENTS)
            # Opening + typing + bounded guest shell + screenshot + CMS limits.
            self.assertLess(events * 0.02 + 4 + 31 + 15 + 20 + guest_console.LOCK_WAIT_SECONDS, guest_console.MAX_CAPTURE_SECONDS)

    def test_overlong_non_ascii_or_event_heavy_literals_fail_before_input(self):
        cases = (("a" * (guest_console.MAX_LITERAL_BYTES + 1), guest_console.MAX_KEY_EVENTS),
                 ("private \u2603", guest_console.MAX_KEY_EVENTS), ("A" * 700, guest_console.MAX_KEY_EVENTS))
        for command, event_limit in cases:
            with self.subTest(length=len(command)), patch.dict(guest_console.READ_ONLY_COMMANDS, workstation=command), \
                    patch.object(guest_console, "MAX_KEY_EVENTS", event_limit), self.assertRaises(ValueError):
                guest_console.capture("workstation")
        self.connect.assert_not_called()
        self.assertEqual([], list(self.root.iterdir()))

    def test_rfb_typing_preserves_property_capitals_and_shell_ampersands(self):
        with patch.dict(guest_console.READ_ONLY_COMMANDS, workstation="A&"):
            guest_console.type_read_only_command(self.connection, "workstation")
        keys = [struct.unpack("!BBHI", sent.args[0]) for sent in self.connection.sendall.call_args_list]
        self.assertEqual([(4, 1, 0, 0xFFE1), (4, 1, 0, ord("A")), (4, 0, 0, ord("A")), (4, 0, 0, 0xFFE1),
                          (4, 1, 0, 0xFFE1), (4, 1, 0, ord("&")), (4, 0, 0, ord("&")), (4, 0, 0, 0xFFE1)], keys)

    def test_every_role_marks_private_before_any_input_and_targets_only_own_console(self):
        for role, (domain, port) in guest_console.PROFILES.items():
            self.handshake()
            self.connection.sendall.reset_mock()
            self.connection.sendall.side_effect = lambda _data, role=role: self.assertTrue(self.markers[role].exists())
            with self.subTest(role=role), patch.object(guest_console.subprocess, "run", side_effect=RuntimeError("SyntheticScreenshotStop")) as screenshot:
                with self.assertRaisesRegex(RuntimeError, "SyntheticScreenshotStop"):
                    guest_console.capture(role)
            self.connect.assert_called_with(("127.0.0.1", port), timeout=5)
            screenshot.assert_called_once_with(["virsh", "--connect", "qemu:///system", "screenshot", domain, str(self.raw[role])],
                                               capture_output=True, check=True, timeout=15)
            self.assertTrue(self.markers[role].exists())
            self.assertFalse(self.raw[role].exists())
            keys = [struct.unpack("!BBHI", sent.args[0]) for sent in self.connection.sendall.call_args_list if len(sent.args[0]) == 8]
            self.assertEqual([(4, 1, 0, 0xFFE3), (4, 1, 0, 0xFFE9), (4, 1, 0, ord("t")),
                              (4, 0, 0, ord("t")), (4, 0, 0, 0xFFE9), (4, 0, 0, 0xFFE3),
                              (4, 1, 0, 0xFFC8), (4, 0, 0, 0xFFC8)], keys[:8])
            self.assertEqual(guest_console.READ_ONLY_COMMANDS[role],
                             "".join(chr(key) for _, down, _, key in keys[8:-2] if down and key != 0xFFE1))
            self.assertEqual([(4, 1, 0, 0xFF0D), (4, 0, 0, 0xFF0D)], keys[-2:])

    def test_failed_handshake_persistently_suppresses_both_public_roles(self):
        for role in guest_console.PROFILES:
            self.connection.recv.side_effect = None
            self.connection.recv.return_value = b"invalid vers"
            self.connection.sendall.reset_mock()
            with self.subTest(role=role), self.assertRaises(ValueError):
                guest_console.capture(role)
            self.connection.sendall.assert_not_called()
            self.assertTrue(guest_console.public_capture_suppressed(role))
            with patch.object(guest, "virsh") as screenshot, self.assertRaises(RuntimeError):
                guest.screenshot(role)
            screenshot.assert_not_called()

    def test_public_suppression_is_role_specific(self):
        for role in guest_console.PROFILES:
            self.assertFalse(guest_console.public_capture_suppressed(role))
        self.markers["gateway"].touch()
        self.assertTrue(guest_console.public_capture_suppressed("gateway"))
        self.assertFalse(guest_console.public_capture_suppressed("workstation"))

    def test_outer_snapshot_only_cannot_publish_either_private_console(self):
        for marker in self.markers.values():
            marker.touch()
        with patch.object(sys, "argv", ["container.py", "--snapshot-only"]), \
                patch.object(subprocess, "run") as command:
            runpy.run_path(str(Path(guest.__file__)), run_name="__main__")
        command.assert_not_called()

    def test_browser_capture_and_export_stop_before_credentials_when_role_private(self):
        for role in guest_console.PROFILES:
            self.markers[role].touch()
            with self.subTest(role=role), patch.object(guest, "Path") as path, \
                    patch.object(guest.subprocess, "run") as command:
                for capture in (guest.browser, lambda: guest.browser_session("private.onion", {})):
                    with self.assertRaisesRegex(RuntimeError, "PrivateConsolePublicCaptureSuppressed"):
                        capture()
            path.assert_not_called()
            command.assert_not_called()
            self.markers[role].unlink()

    def test_connection_failure_keeps_marker_and_deletes_any_private_raw_image(self):
        self.raw["gateway"].write_bytes(b"synthetic-private-raw")
        self.connect.side_effect = OSError("synthetic connection failure")
        with self.assertRaises(OSError):
            guest_console.capture("gateway")
        self.assertTrue(self.markers["gateway"].exists())
        self.assertFalse(self.raw["gateway"].exists())

    def test_each_console_encrypts_only_bounded_png_to_its_fixed_path(self):
        for role in guest_console.PROFILES:
            self.handshake()
            with self.subTest(role=role), patch.object(guest_console.subprocess, "run", side_effect=self.image), \
                    patch.object(guest_console.confidential, "encrypt_diagnostic", return_value=True) as encrypt:
                self.assertTrue(guest_console.capture(role))
            data, target = encrypt.call_args.args
            self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertLessEqual(len(data), 60 * 1024)
            self.assertEqual(self.outputs[role], target)
            self.assertFalse(self.raw[role].exists())
            self.assertTrue(self.markers[role].exists())

    def test_oversize_raw_image_is_removed_and_never_encrypted(self):
        def huge(arguments, **_kwargs):
            with Path(arguments[-1]).open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
        with patch.object(guest_console.subprocess, "run", side_effect=huge), \
                patch.object(guest_console.confidential, "encrypt_diagnostic") as encrypt, self.assertRaises(ValueError):
            guest_console.capture("workstation")
        encrypt.assert_not_called()
        self.assertFalse(self.raw["workstation"].exists())

    def test_oversize_encoded_png_is_removed_and_never_encrypted(self):
        def noisy(arguments, **_kwargs):
            from PIL import Image
            Image.frombytes("L", (1280, 1024), os.urandom(1280 * 1024)).save(arguments[-1], format="PPM")
        with patch.object(guest_console.subprocess, "run", side_effect=noisy), \
                patch.object(guest_console.confidential, "encrypt_diagnostic") as encrypt, self.assertRaises(ValueError):
            guest_console.capture("workstation")
        encrypt.assert_not_called()
        self.assertFalse(self.raw["workstation"].exists())

    def test_encryption_failure_keeps_marker_and_removes_raw(self):
        with patch.object(guest_console.subprocess, "run", side_effect=self.image), \
                patch.object(guest_console.confidential, "encrypt_diagnostic", side_effect=ValueError("SyntheticProfileFailure")), \
                self.assertRaises(ValueError):
            guest_console.capture("gateway")
        self.assertTrue(self.markers["gateway"].exists())
        self.assertFalse(self.raw["gateway"].exists())
        self.assertFalse(self.outputs["gateway"].exists())

    def test_deadline_restores_alarm_handler_and_disarms_on_success_and_failure(self):
        for failure in (False, True):
            with self.subTest(failure=failure), patch.object(guest_console.signal, "getitimer", return_value=(0.0, 0.0)), \
                    patch.object(guest_console.signal, "signal", return_value="previous") as handler, \
                    patch.object(guest_console.signal, "setitimer") as timer:
                try:
                    with guest_console.capture_deadline():
                        if failure:
                            raise ValueError("SyntheticFailure")
                except ValueError:
                    self.assertTrue(failure)
                self.assertEqual([call(guest_console.signal.ITIMER_REAL, guest_console.MAX_CAPTURE_SECONDS),
                                  call(guest_console.signal.ITIMER_REAL, 0)], timer.call_args_list)
                self.assertEqual(call(guest_console.signal.SIGALRM, "previous"), handler.call_args_list[-1])

    def test_deadline_raises_timeout_even_inside_blocking_processing(self):
        with patch.object(guest_console.signal, "getitimer", return_value=(0.0, 0.0)), \
                patch.object(guest_console.signal, "signal") as handler, patch.object(guest_console.signal, "setitimer"):
            with guest_console.capture_deadline():
                with self.assertRaises(TimeoutError):
                    handler.call_args_list[0].args[1](None, None)

    def test_existing_timer_is_not_overwritten_or_allowed_to_touch_guest(self):
        with patch.object(guest_console.signal, "getitimer", return_value=(1.0, 0.0)), \
                patch.object(guest_console.signal, "setitimer") as timer, self.assertRaises(RuntimeError):
            guest_console.capture("gateway")
        timer.assert_not_called()
        self.connect.assert_not_called()
        self.assertFalse(self.markers["gateway"].exists())


    def public_paths(self):
        def path(value):
            if str(value).startswith("/run/oniondesk-ci-"):
                return self.root / Path(value).name
            return Path(value)
        self.stack.enter_context(patch.object(guest, "Path", side_effect=path))
        self.stack.enter_context(patch.object(guest, "EVIDENCE", self.root))

    def test_direct_private_race_during_virsh_cannot_mark_or_input_before_publication(self):
        self.public_paths()
        for role in guest_console.PROFILES:
            def snapshot(*arguments, **_kwargs):
                with patch.object(guest_console, "LOCK_WAIT_SECONDS", 0), self.assertRaises(TimeoutError):
                    guest_console.activate_private(role)
                self.assertFalse(self.markers[role].exists())
                self.image(arguments)
            with self.subTest(role=role), patch.object(guest, "virsh", side_effect=snapshot):
                guest.screenshot(role)
            self.assertTrue((self.root / (role + ".png")).is_file())
            guest_console.activate_private(role)
            with patch.object(guest, "virsh") as screenshot, self.assertRaises(RuntimeError):
                guest.screenshot(role)
            screenshot.assert_not_called()

    def test_browser_canvas_capture_serializes_private_activation_for_each_role(self):
        canvas, driver, wait = Mock(), Mock(), Mock()
        wait.until.side_effect = [Mock(), Mock(), Mock(), canvas, Mock(), canvas, Mock()]
        webdriver = SimpleNamespace(ChromeOptions=Mock(), Chrome=Mock(return_value=driver))
        modules = {
            "selenium": SimpleNamespace(webdriver=webdriver),
            "selenium.webdriver": webdriver,
            "selenium.webdriver.common.by": SimpleNamespace(By=SimpleNamespace(ID="id", CSS_SELECTOR="css", TAG_NAME="tag")),
            "selenium.webdriver.chrome.service": SimpleNamespace(Service=Mock()),
            "selenium.webdriver.support.ui": SimpleNamespace(WebDriverWait=Mock(return_value=wait)),
        }
        roles = []
        def capture(path):
            role = "gateway" if str(path).endswith("browser-gateway.png") else "workstation"
            with patch.object(guest_console, "LOCK_WAIT_SECONDS", 0), self.assertRaises(TimeoutError):
                guest_console.activate_private(role)
            self.assertFalse(self.markers[role].exists())
            roles.append(role)
        canvas.screenshot.side_effect = capture
        with patch.dict(sys.modules, modules), patch.object(guest.os, "geteuid", return_value=12345), \
                patch.object(guest.Path, "home", return_value=self.root), patch.object(guest, "BROWSER_HOME", self.root), \
                patch.object(guest, "otp", return_value="123456"):
            result = guest.browser_session("a" * 56 + ".onion", {"login": "fixture", "password": "fixture", "totp_secret": "fixture"})
        self.assertEqual(["gateway", "workstation"], roles)
        self.assertTrue(result["gateway_real_noVNC_connected"])
        self.assertTrue(result["workstation_real_noVNC_connected"])
        driver.quit.assert_called_once()

    def test_browser_public_export_serializes_private_activation_for_each_role(self):
        from PIL import Image
        original_open = Image.open
        for role in guest_console.PROFILES:
            Image.new("RGB", (64, 48), "white").save(self.root / ("browser-" + role + ".png"))
        result = {key: True for key in ("real_onion_route_via_Tor", "password_TOTP_login", "non_root_browser",
                  "chromium_sandbox_confirmed", "gateway_real_noVNC_connected", "workstation_real_noVNC_connected")}
        roles = []
        def image(path):
            role = "gateway" if str(path).endswith("browser-gateway.png") else "workstation"
            with patch.object(guest_console, "LOCK_WAIT_SECONDS", 0), self.assertRaises(TimeoutError):
                guest_console.activate_private(role)
            self.assertFalse(self.markers[role].exists())
            roles.append(role)
            return original_open(path)
        def read(path, *_args, **_kwargs):
            return "a" * 56 + ".onion" if str(path).endswith("hostname") else json.dumps({"login": "fixture", "password": "fixture", "totp_secret": "fixture"})
        published = self.root / "published"
        published.mkdir()
        with patch.object(guest, "BROWSER_HOME", self.root), patch.object(guest, "EVIDENCE", published), \
                patch.object(guest.Path, "read_text", read), patch.object(Image, "open", side_effect=image), \
                patch.object(guest.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(result).encode())):
            self.assertEqual(result, guest.browser())
        self.assertEqual(["gateway", "workstation"], roles)
        self.assertEqual({"browser-gateway.png", "browser-workstation.png"}, {path.name for path in published.iterdir()})
        for role in roles:
            guest_console.activate_private(role)
            with self.assertRaises(RuntimeError):
                with guest_console.public_capture(role):
                    self.fail("PrivateExportAllowed")

    def test_real_process_public_capture_and_publish_precede_private_marker_and_input(self):
        self.public_paths()
        context = multiprocessing.get_context("fork")
        real_flock = guest_console.fcntl.flock
        for role in guest_console.PROFILES:
            capturing, release, blocked, private_input = [context.Event() for _ in range(4)]
            public_result, private_result = context.Queue(), context.Queue()

            def public_worker():
                def snapshot(*arguments, **_kwargs):
                    capturing.set()
                    if not release.wait(5):
                        raise RuntimeError("BarrierTimeout")
                    if private_input.is_set() or self.markers[role].exists():
                        raise RuntimeError("PrivateInterleavedCapture")
                    self.image(arguments)
                try:
                    with patch.object(guest, "virsh", side_effect=snapshot):
                        guest.screenshot(role)
                    public_result.put("published")
                except BaseException as error:
                    public_result.put(type(error).__name__)

            def private_worker():
                def acquire(*arguments):
                    try:
                        return real_flock(*arguments)
                    except BlockingIOError:
                        blocked.set()
                        raise
                def input_attempt(*_arguments, **_kwargs):
                    if not (self.root / (role + ".png")).is_file():
                        raise RuntimeError("PrivatePrecededPublication")
                    private_input.set()
                    raise OSError("SyntheticConnectionStop")
                try:
                    with patch.object(guest_console.fcntl, "flock", side_effect=acquire), \
                            patch.object(guest_console.socket, "create_connection", side_effect=input_attempt):
                        guest_console.capture(role)
                except OSError:
                    private_result.put("private_after_publication")
                except BaseException as error:
                    private_result.put(type(error).__name__)

            public, private = context.Process(target=public_worker), context.Process(target=private_worker)
            with self.subTest(role=role):
                try:
                    public.start()
                    self.assertTrue(capturing.wait(5))
                    private.start()
                    self.assertTrue(blocked.wait(5))
                    self.assertFalse(private_input.is_set())
                    self.assertFalse(self.markers[role].exists())
                    release.set()
                    self.assertEqual("published", public_result.get(timeout=5))
                    self.assertEqual("private_after_publication", private_result.get(timeout=5))
                    public.join(5)
                    private.join(5)
                    self.assertEqual((0, 0), (public.exitcode, private.exitcode))
                    self.assertTrue(private_input.is_set())
                    self.assertTrue(self.markers[role].exists())
                finally:
                    release.set()
                    for process in (public, private):
                        if process.pid is not None:
                            if process.is_alive():
                                process.kill()
                            process.join(5)
                    for queue in (public_result, private_result):
                        queue.close()
                        queue.join_thread()

    def test_real_process_private_marker_first_rejects_public_capture(self):
        self.public_paths()
        context = multiprocessing.get_context("fork")
        for role in guest_console.PROFILES:
            private_input, release = context.Event(), context.Event()
            result = context.Queue()
            def private_worker():
                def input_attempt(*_arguments, **_kwargs):
                    private_input.set()
                    if not release.wait(5):
                        raise RuntimeError("BarrierTimeout")
                    raise OSError("SyntheticConnectionStop")
                try:
                    with patch.object(guest_console.socket, "create_connection", side_effect=input_attempt):
                        guest_console.capture(role)
                except OSError:
                    pass
            def public_worker():
                try:
                    with patch.object(guest, "virsh") as screenshot:
                        try:
                            guest.screenshot(role)
                        except RuntimeError:
                            if screenshot.called:
                                raise AssertionError("PrivateFrameCaptureAttempted")
                            result.put("suppressed")
                except BaseException as error:
                    result.put(type(error).__name__)
            private, public = context.Process(target=private_worker), context.Process(target=public_worker)
            with self.subTest(role=role):
                try:
                    private.start()
                    self.assertTrue(private_input.wait(5))
                    public.start()
                    self.assertEqual("suppressed", result.get(timeout=5))
                    release.set()
                    public.join(5)
                    private.join(5)
                    self.assertEqual((0, 0), (public.exitcode, private.exitcode))
                    self.assertFalse((self.root / (role + ".png")).exists())
                finally:
                    release.set()
                    for process in (public, private):
                        if process.pid is not None:
                            if process.is_alive():
                                process.kill()
                            process.join(5)
                    result.close()
                    result.join_thread()

    def test_lock_wait_is_bounded_and_kernel_releases_lock_after_killed_process(self):
        context = multiprocessing.get_context("fork")
        locked = context.Event()
        release = context.Event()
        def worker():
            with guest_console.role_lock("workstation"):
                locked.set()
                release.wait(10)
        process = context.Process(target=worker)
        try:
            process.start()
            self.assertTrue(locked.wait(5))
            with patch.object(guest_console, "LOCK_WAIT_SECONDS", 0), self.assertRaises(TimeoutError):
                with guest_console.role_lock("workstation"):
                    self.fail("OverlappingLockAcquired")
            process.kill()
            process.join(5)
            with guest_console.role_lock("workstation"):
                self.assertEqual(0o600, self.locks["workstation"].stat().st_mode & 0o7777)
                self.assertEqual(1, self.locks["workstation"].stat().st_nlink)
        finally:
            if process.is_alive():
                process.kill()
            process.join(5)

    def test_lock_rejects_links_nonregular_wrong_permissions_and_wrong_owner(self):
        path = self.locks["workstation"]
        for kind in ("symlink", "hardlink", "fifo", "directory", "permissions", "owner"):
            other = self.root / "other"
            with self.subTest(kind=kind):
                if kind == "symlink":
                    path.symlink_to(other)
                elif kind == "hardlink":
                    other.touch(mode=0o600)
                    os.link(other, path)
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind == "directory":
                    path.mkdir(mode=0o700)
                else:
                    path.touch(mode=0o644 if kind == "permissions" else 0o600)
                owner = os.geteuid() + 1 if kind == "owner" else os.geteuid()
                with patch.object(guest_console, "lock_owner_uid", return_value=owner), \
                        self.assertRaises((OSError, ValueError)):
                    with guest_console.role_lock("workstation"):
                        self.fail("UnsafeLockAccepted")
                if kind == "directory":
                    path.rmdir()
                else:
                    path.unlink()
                other.unlink(missing_ok=True)

    def test_lock_releases_after_body_exception_without_deleting_shared_inode(self):
        with self.assertRaises(ValueError):
            with guest_console.role_lock("gateway"):
                raise ValueError("SyntheticFailure")
        inode = self.locks["gateway"].stat().st_ino
        with guest_console.role_lock("gateway"):
            self.assertEqual(inode, self.locks["gateway"].stat().st_ino)

    def test_private_marker_symlink_fails_closed_before_guest_input(self):
        self.markers["gateway"].symlink_to(self.root / "missing")
        with self.assertRaises(OSError):
            guest_console.capture("gateway")
        self.connect.assert_not_called()
        self.assertTrue(guest_console.public_capture_suppressed("gateway"))


if __name__ == "__main__":
    unittest.main()
