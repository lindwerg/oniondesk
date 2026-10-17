"""Static guest-command, fail-closed monitoring and private-console boundaries."""
import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch

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

    def test_rfb_typing_preserves_property_capitals_and_shell_ampersands(self):
        connection = Mock()
        with patch.object(guest_console, "READ_ONLY_COMMAND", "A&"), patch.object(guest_console.time, "sleep"):
            guest_console.type_read_only_command(connection)
        keys = [struct.unpack("!BBHI", sent.args[0]) for sent in connection.sendall.call_args_list]
        self.assertEqual([(4, 1, 0, 0xFFE1), (4, 1, 0, ord("A")), (4, 0, 0, ord("A")), (4, 0, 0, 0xFFE1),
                          (4, 1, 0, 0xFFE1), (4, 1, 0, ord("&")), (4, 0, 0, ord("&")), (4, 0, 0, 0xFFE1)], keys)

    def test_console_command_is_exact_fixed_read_only_literal(self):
        self.assertEqual(
            "clear; systemctl show oniondesk-first-boot.service "
            "-p LoadState,ActiveState,SubState,Result,Restart,ConditionResult,ExecMainStatus; "
            "sudo -n journalctl -u oniondesk-first-boot.service -n 16 --no-pager -o cat; "
            "systemctl --no-pager list-jobs; cat /proc/cmdline; "
            "dpkg-query -W telegram-desktop qemu-guest-agent; "
            "test -f /var/lib/oniondesk/setup.complete && echo SETUP_COMPLETE_PRESENT",
            guest_console.READ_ONLY_COMMAND,
        )

    def test_console_delivers_full_literal_then_return_before_private_screenshot(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [b"RFB 003.008\n", b"\x01", b"\x01", b"\0" * 4, b"\0" * 24]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "private-console"
            raw = Path(directory) / "private-console.ppm"
            target = Path(directory) / "console.cms"

            def send(data):
                self.assertTrue(marker.exists())

            connection.sendall.side_effect = send
            with patch.object(guest_console, "SUPPRESSION_MARKER", marker), \
                    patch.object(guest_console, "Path", return_value=raw), \
                    patch.object(guest_console.socket, "create_connection", return_value=connection), \
                    patch.object(guest_console.time, "sleep"), \
                    patch.object(guest_console.subprocess, "run", side_effect=RuntimeError("SyntheticScreenshotStop")) as screenshot, \
                    patch.object(guest_console.confidential, "encrypt_diagnostic") as encrypt:
                with self.assertRaisesRegex(RuntimeError, "SyntheticScreenshotStop"):
                    guest_console.capture(target)
            connection.setsockopt.assert_called_once_with(guest_console.socket.IPPROTO_TCP,
                                                         guest_console.socket.TCP_NODELAY, 1)
            keys = [struct.unpack("!BBHI", sent.args[0]) for sent in connection.sendall.call_args_list
                    if len(sent.args[0]) == 8]
            self.assertEqual([(4, 1, 0, 0xFFE3), (4, 1, 0, 0xFFE9), (4, 1, 0, ord("t")),
                              (4, 0, 0, ord("t")), (4, 0, 0, 0xFFE9), (4, 0, 0, 0xFFE3),
                              (4, 1, 0, 0xFFC8), (4, 0, 0, 0xFFC8)], keys[:8])
            self.assertEqual(guest_console.READ_ONLY_COMMAND,
                             "".join(chr(key) for _, down, _, key in keys[8:-2]
                                     if down and key != 0xFFE1))
            self.assertEqual([(4, 1, 0, 0xFF0D), (4, 0, 0, 0xFF0D)], keys[-2:])
            screenshot.assert_called_once_with(
                ["virsh", "--connect", "qemu:///system", "screenshot", guest_console.DOMAIN, str(raw)],
                capture_output=True, check=True, timeout=15,
            )
            encrypt.assert_not_called()
            self.assertTrue(marker.exists())
            self.assertFalse(raw.exists())

    def test_private_console_suppresses_every_later_public_snapshot_before_input(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.return_value = b"invalid vers"
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "private-console"
            with patch.object(guest_console, "SUPPRESSION_MARKER", marker), \
                    patch.object(guest_console.socket, "create_connection", return_value=connection):
                with self.assertRaises(ValueError):
                    guest_console.capture(Path(directory) / "console.cms")
                self.assertTrue(marker.exists())
                connection.sendall.assert_not_called()
                with self.assertRaises(RuntimeError):
                    guest.screenshot("workstation")

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


if __name__ == "__main__":
    unittest.main()
