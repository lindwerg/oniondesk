"""Static guest-command, fail-closed monitoring and private-console boundaries."""
import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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
        guest_console.chord(connection, (1, 2))
        events = connection.sendall.call_args.args[0]
        self.assertEqual([(4, 1, 0, 1), (4, 1, 0, 2), (4, 0, 0, 2), (4, 0, 0, 1)],
                         [struct.unpack("!BBHI", events[index:index + 8]) for index in range(0, len(events), 8)])

    def test_rfb_typing_preserves_property_capitals_and_shell_ampersands(self):
        with patch.object(guest_console, "READ_ONLY_COMMAND", "A&"):
            events = guest_console.typing_events()
        keys = [struct.unpack("!BBHI", events[index:index + 8]) for index in range(0, len(events), 8)]
        self.assertEqual([(4, 1, 0, 0xFFE1), (4, 1, 0, ord("a")), (4, 0, 0, ord("a")), (4, 0, 0, 0xFFE1),
                          (4, 1, 0, 0xFFE1), (4, 1, 0, ord("7")), (4, 0, 0, ord("7")), (4, 0, 0, 0xFFE1)], keys)

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
