"""Safe failure localization and sandbox boundaries; no Docker/VM/network I/O."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import diagnostics
from test_harness import guest, host


def retry_ready_fixture():
    return {"domains": {role: {"probe_completed": True, "defined": True, "shut_off": True,
                               "running": False, "paused": False, "qemu_pid_file_present": False}
                        for role in diagnostics.ROLES},
            "audits": {"pre_start": {"available": True, "ok": True, "exit_success": True}},
            "units": {"vms": {"probe_completed": True, "failed": True}}}


class DiagnosticTests(unittest.TestCase):
    def test_denial_maps_fixed_storage_ancestry_without_private_suffixes(self):
        private = b"error: Cannot access storage file '/var/lib/libvirt/images/oniondesk/gateway.qcow2' (as uid:64055, gid:64055): Permission denied secret.onion"
        report = diagnostics.denial_summary(private)
        self.assertIn("gateway_disk", report["resource_tokens"])
        self.assertIn("images_parent", report["resource_tokens"])
        self.assertEqual(["storage_access"], report["operation_tokens"])
        for secret in ("secret.onion", "64055", "/var/"):
            self.assertNotIn(secret, json.dumps(report))

    def test_denial_does_not_associate_other_line_or_similar_path_prefix(self):
        private = b"/var/lib/libvirt/images/oniondesk/gateway.qcow2\nPermission denied\nCannot access storage file '/var/lib/libvirt-private/secret': Permission denied"
        report = diagnostics.denial_summary(private)
        self.assertEqual(["var_lib"], report["resource_tokens"])
        self.assertEqual(["storage_access"], report["operation_tokens"])

    def test_denial_reports_mac_and_syscall_categories_as_static_tokens(self):
        report = diagnostics.denial_summary(b'apparmor="DENIED" operation="open" name="/sys/fs/cgroup/private-secret"\nUnable to create /run/libvirt/qemu/passt/private-socket: Permission denied')
        self.assertIn("apparmor", report["resource_tokens"])
        self.assertIn("cgroup", report["resource_tokens"])
        self.assertIn("passt_run", report["resource_tokens"])
        self.assertEqual(["create", "open"], report["operation_tokens"])
        self.assertNotIn("private", json.dumps(report))

    def test_qemu_access_probes_exact_default_identity_and_search_read_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            disk = parent / "fixture.qcow2"
            disk.write_bytes(b"")
            account = SimpleNamespace(pw_uid=os.getuid() + 1, pw_gid=os.getgid() + 1)
            denied = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"private")
            with patch.object(diagnostics, "ACCESS_PATHS", {"parent": (str(parent), True), "disk": (str(disk), False)}), \
                    patch.object(diagnostics.pwd, "getpwnam", return_value=account), \
                    patch.object(diagnostics, "run", return_value=denied) as execute:
                result = diagnostics.qemu_access_snapshot()
            self.assertEqual(0o700, result["paths"]["parent"]["mode"])
            self.assertFalse(result["paths"]["parent"]["owner_qemu"])
            self.assertFalse(result["paths"]["parent"]["qemu_search_access"])
            self.assertFalse(result["paths"]["disk"]["qemu_read_access"])
            self.assertTrue(result["paths"]["parent"]["access_probe_completed"])
            self.assertEqual(["runuser", "--user", "libvirt-qemu", "--", "test", "-x", str(parent)], execute.call_args_list[0].args[0])
            self.assertEqual("-r", execute.call_args_list[1].args[0][-2])
            self.assertNotIn("private", json.dumps(result))

    def test_qemu_access_tool_failure_is_not_reported_as_completed_denial(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(diagnostics, "ACCESS_PATHS", {"parent": (directory, True)}), \
                patch.object(diagnostics.pwd, "getpwnam", return_value=account), \
                patch.object(diagnostics, "run", return_value=subprocess.CompletedProcess([], 2, stdout=b"", stderr=b"private")):
            self.assertFalse(diagnostics.qemu_access_snapshot()["paths"]["parent"]["access_probe_completed"])

    def test_qemu_access_account_missing_is_explicitly_unavailable(self):
        with patch.object(diagnostics.pwd, "getpwnam", side_effect=KeyError("private")):
            self.assertEqual({"available": False}, diagnostics.qemu_access_snapshot())

    def test_single_retry_requires_both_defined_stopped_domains_and_passed_audit(self):
        fixture = retry_ready_fixture()
        denied = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"Cannot access storage file '/var/lib/libvirt/images/oniondesk/gateway.qcow2': Permission denied secret")
        with patch.object(diagnostics, "run", return_value=denied) as execute:
            result = diagnostics.gateway_start_retry(fixture)
        self.assertTrue(result["attempted"])
        self.assertFalse(result["exit_success"])
        self.assertIn("gateway_disk", result["denial"]["resource_tokens"])
        self.assertNotIn("secret", json.dumps(result))
        execute.assert_called_once_with(["virsh", "--connect", "qemu:///system", "start", "oniondesk-gateway"], timeout=60)
        fixture["domains"]["gateway"]["shut_off"] = False
        with patch.object(diagnostics, "run") as execute:
            self.assertEqual({"attempted": False}, diagnostics.gateway_start_retry(fixture))
            execute.assert_not_called()

    def test_retry_never_starts_after_failed_pre_start_audit(self):
        fixture = retry_ready_fixture()
        fixture["audits"]["pre_start"]["ok"] = False
        with patch.object(diagnostics, "run") as execute:
            self.assertEqual({"attempted": False}, diagnostics.gateway_start_retry(fixture))
            execute.assert_not_called()

    def test_retry_never_starts_with_unknown_or_non_boolean_pid_state(self):
        for role in diagnostics.ROLES:
            for value in (None, 0, "", "false", "missing"):
                fixture = retry_ready_fixture()
                if value == "missing":
                    fixture["domains"][role].pop("qemu_pid_file_present")
                else:
                    fixture["domains"][role]["qemu_pid_file_present"] = value
                with self.subTest(role=role, value=value), patch.object(diagnostics, "run") as execute:
                    self.assertEqual({"attempted": False}, diagnostics.gateway_start_retry(fixture))
                    execute.assert_not_called()

    def test_retry_never_starts_with_unavailable_or_unsuccessful_audit(self):
        for key in ("available", "ok", "exit_success"):
            for value in (False, None, 1, "missing"):
                fixture = retry_ready_fixture()
                if value == "missing":
                    fixture["audits"]["pre_start"].pop(key)
                else:
                    fixture["audits"]["pre_start"][key] = value
                with self.subTest(key=key, value=value), patch.object(diagnostics, "run") as execute:
                    self.assertEqual({"attempted": False}, diagnostics.gateway_start_retry(fixture))
                    execute.assert_not_called()

    def test_retry_never_starts_with_incomplete_probes_or_unconfirmed_stopped_state(self):
        targets = [("domains", role, key, value) for role in diagnostics.ROLES
                   for key, value in (("probe_completed", False), ("defined", False),
                                      ("shut_off", False), ("running", True), ("paused", True))]
        targets += [("units", "vms", "probe_completed", False), ("units", "vms", "failed", False)]
        for section, name, key, value in targets:
            fixture = retry_ready_fixture()
            fixture[section][name][key] = value
            with self.subTest(section=section, name=name, key=key), patch.object(diagnostics, "run") as execute:
                self.assertEqual({"attempted": False}, diagnostics.gateway_start_retry(fixture))
                execute.assert_not_called()

    def test_successful_sysmaint_staging_is_not_guest_failure(self):
        text = "Подготовлен workstation: официальный setup marker; одноразовый SYSMAINT."
        self.assertEqual("production_install_exit", guest.classify(text.encode()))

    def test_only_actual_timeout_message_classifies_guest_failure(self):
        for text in ("SYSMAINT не завершился вовремя. VM сохранена, готовность не подтверждена.",
                     "USER/Tor/Telegram не подтверждены вовремя: private endpoint"):
            self.assertEqual("guest_first_boot_or_readiness", guest.classify(text.encode()))
        self.assertEqual("production_install_exit", guest.classify(b"Host Tor configured"))

    def test_exact_err_trap_line_reduces_to_integer(self):
        line = diagnostics.STOP_PREFIX + "250" + diagnostics.STOP_SUFFIX
        report = diagnostics.output_summary(line.encode(), source=host.ROOT)
        self.assertEqual({"ERR_reported_lines": [250], "known_error_tokens": []}, report)

    def test_err_trap_ignores_arbitrary_suffix_prefix_and_out_of_range(self):
        lines = [diagnostics.STOP_PREFIX + number + diagnostics.STOP_SUFFIX for number in ("0", "9999", "private")]
        lines += ["private " + diagnostics.STOP_PREFIX + "250" + diagnostics.STOP_SUFFIX,
                  diagnostics.STOP_PREFIX + "250" + diagnostics.STOP_SUFFIX + " secret"]
        self.assertEqual([], diagnostics.output_summary("\n".join(lines).encode(), source=host.ROOT)["ERR_reported_lines"])

    def test_static_error_catalog_parses_without_executing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server").mkdir()
            for filename in ("runtime-audit.py", "validate-guest.py", "host_tor.py", "first_boot.py"):
                (root / "server" / filename).write_text("raise ValueError('known private literal')\n")
            sites = diagnostics.static_error_sites(root)
            self.assertEqual(4, len(sites))
            exported = json.dumps(diagnostics.error_tokens(b"known private literal plus secret", sites))
            self.assertIn("validate_guest_L1", exported)
            self.assertNotIn("private", exported)
            self.assertNotIn("secret", exported)

    def test_static_error_catalog_ignores_dynamic_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server").mkdir()
            for filename in ("runtime-audit.py", "validate-guest.py", "host_tor.py", "first_boot.py"):
                (root / "server" / filename).write_text("raise ValueError(private_value)\n")
            self.assertEqual([], diagnostics.static_error_sites(root))

    def test_real_validator_message_has_source_site_without_message(self):
        message = "Неверный тип NIC."
        sites = diagnostics.static_error_sites(host.ROOT)
        tokens = diagnostics.error_tokens(message.encode(), sites)
        self.assertTrue(any(token.startswith("validate_guest_L") for token in tokens))
        self.assertNotIn(message, json.dumps(tokens))

    def test_unknown_output_and_secrets_are_never_exported(self):
        raw = b"private-onion.onion password=arbitrary /private/files\nPermission denied"
        self.assertEqual(["permission"], diagnostics.error_tokens(raw))
        self.assertEqual([], diagnostics.error_tokens(b"unknown exception text private-onion.onion"))

    def test_audit_maps_private_identifiers_and_discards_all_details(self):
        report = {"ok": False, "checks": [
            {"id": "private./etc/oniondesk/credentials.json", "ok": False,
             "detail": "password=sentinel private-onion.onion /private/path"},
            {"id": "secret-new-check", "ok": False, "detail": "another secret"}]}
        response = subprocess.CompletedProcess([], 1, stdout=json.dumps(report).encode(), stderr=b"private")
        result = diagnostics.audit_summary(response)
        self.assertFalse(result["ok"])
        self.assertFalse(result["exit_success"])
        self.assertEqual(1, result["unknown_check_count"])
        self.assertEqual("credentials_permissions", result["checks"][0]["check"])
        for private in ("sentinel", "private-onion", "/etc/", "secret-new-check", "another secret"):
            self.assertNotIn(private, json.dumps(result))

    def test_audit_rejects_malformed_boolean_or_oversized_report(self):
        reports = ([], {"ok": True, "checks": []},
                   {"ok": True, "checks": [{"id": "audit.internal", "ok": "false"}]},
                   {"ok": False, "checks": [{"id": "audit.internal", "ok": False}] * 65})
        for report in reports:
            with self.subTest(report_type=type(report).__name__), self.assertRaises(ValueError):
                diagnostics.audit_summary(subprocess.CompletedProcess([], 1, stdout=json.dumps(report)))

    def test_private_log_reader_is_bounded_to_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "private.log"
            log.write_bytes(b"prefix-secret" + b"x" * diagnostics.MAX_PRIVATE_BYTES + b"known-end")
            data = diagnostics.private_tail(log)
            self.assertEqual(diagnostics.MAX_PRIVATE_BYTES, len(data))
            self.assertTrue(data.endswith(b"known-end"))
            self.assertNotIn(b"prefix-secret", data)

    def test_snapshot_continues_when_every_probe_fails(self):
        with patch.object(diagnostics, "run", side_effect=subprocess.TimeoutExpired("private command", 20)):
            report = diagnostics.snapshot()
        self.assertEqual({"pre_start", "topology", "full"}, set(report["audits"]))
        self.assertTrue(all(value == {"available": False} for value in report["audits"].values()))
        self.assertNotIn("private command", json.dumps(report))

    def test_snapshot_unit_and_domain_states_never_copy_output(self):
        def execute(arguments, **kwargs):
            if arguments[0] == "virsh":
                return subprocess.CompletedProcess(arguments, 1, stdout=b"private domain", stderr=b"private error")
            if arguments[0] == "systemctl":
                return subprocess.CompletedProcess(arguments, 0, stdout=b"LoadState=loaded\nActiveState=failed\nSubState=failed\nExecMainStatus=1\nprivate-field=secret", stderr=b"")
            if arguments[0] == "journalctl":
                return subprocess.CompletedProcess(arguments, 0, stdout=b"secret.onion Permission denied", stderr=b"")
            report = {"ok": False, "checks": [{"id": "audit.internal", "ok": False, "detail": "secret"}]}
            return subprocess.CompletedProcess(arguments, 1, stdout=json.dumps(report).encode(), stderr=b"")
        with patch.object(diagnostics, "run", side_effect=execute):
            result = diagnostics.snapshot()
        self.assertTrue(result["units"]["vms"]["failed"])
        self.assertEqual(1, result["units"]["vms"]["exit_status"])
        self.assertEqual(["permission"], result["units"]["vms"]["known_journal_error_tokens"])
        self.assertFalse(result["domains"]["gateway"]["defined"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("private domain", json.dumps(result))

    def test_browser_refuses_root_before_starting_selenium(self):
        with patch.object(guest.os, "geteuid", return_value=0), self.assertRaises(RuntimeError):
            guest.browser_session("a" * 56 + ".onion", {})

    def test_browser_passes_secrets_only_via_child_stdin(self):
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest("Pillow unavailable on this local host")
        def read(path, *args, **kwargs):
            return ("a" * 56 + ".onion" if str(path).endswith("hostname")
                    else json.dumps({"login": "fixture", "password": "password-sentinel", "totp_secret": "totp-sentinel"}))
        with patch.object(guest.Path, "read_text", read), \
                patch.object(guest.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "child")) as execute:
            with self.assertRaises(subprocess.CalledProcessError):
                guest.browser()
        args, kwargs = execute.call_args
        self.assertEqual(["runuser", "--user", "oniondesk-ci-browser", "--"], args[0][:4])
        self.assertNotIn("password-sentinel", json.dumps(args))
        self.assertNotIn("env", kwargs)
        self.assertIn(b"password-sentinel", kwargs["input"])

    def test_browser_code_requires_positive_sandbox_evaluation(self):
        source = Path(guest.__file__).read_text()
        browser = source[source.index("def browser_session("):source.index("def browser():")]
        self.assertNotIn("--no-sandbox", browser)
        self.assertNotIn("--disable-setuid-sandbox", browser)
        self.assertIn('driver.get("chrome://sandbox/")', browser)
        self.assertIn('== "You are adequately sandboxed."', browser)


if __name__ == "__main__":
    unittest.main()
