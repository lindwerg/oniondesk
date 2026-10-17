"""No Docker/VM operations: guard the public evidence and cleanup boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load("server_kvm_host", "run.py")
guest = load("server_kvm_container", "container.py")


class HarnessTests(unittest.TestCase):
    def test_manifest_is_exact_production_payload(self):
        manifest = host.payload(host.ROOT)
        self.assertEqual(29, len(manifest))
        self.assertIn("server/install.sh", manifest)
        self.assertTrue(all(len(value) == 64 for value in manifest.values()))

    def test_manifest_never_executes_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "client").mkdir()
            entries = tuple("server/file" + str(index) for index in range(29))
            (root / "server").mkdir()
            for entry in entries:
                (root / entry).write_text("payload")
            (root / "client/launcher.py").write_text("raise Exception('must not execute')\nRUNTIME_FILES=" + repr(entries))
            self.assertEqual(29, len(host.payload(root)))

    def test_manifest_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "client").mkdir()
            entries = tuple(["../secret"] + ["server/file" + str(index) for index in range(28)])
            (root / "client/launcher.py").write_text("RUNTIME_FILES=" + repr(entries))
            with self.assertRaises(ValueError):
                host.payload(root)

    def test_local_runner_refused_before_docker_access(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            host.require_public_runner()

    def test_log_classification_never_exports_secret_or_endpoint(self):
        secret = b"password=private-key-123 abcdefabcdef.onion\nPermission denied"
        self.assertEqual("permission", guest.classify(secret))
        self.assertEqual("production_install_exit", guest.classify(b"abcdefabcdef.onion unknown failure"))

    def test_successful_signature_line_is_not_a_failure_class(self):
        self.assertEqual("production_install_exit", guest.classify("Подпись и SHA-512 выпуска Whonix 18.2.1.9 проверены.".encode()))

    def test_signing_subkey_observation_accepts_primary_fingerprint(self):
        status = b"[GNUPG:] VALIDSIG SUBKEY 2026-10-17 123 0 4 0 1 10 00 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA\n"
        self.assertTrue(guest.signature_observed(status))
        self.assertFalse(guest.signature_observed(b"[GNUPG:] VALIDSIG OTHER\n"))

    def test_production_audit_private_path_identifiers_are_not_exported(self):
        report = {"ok": True, "checks": [{"id": "private./etc/oniondesk/credentials.json", "ok": True, "detail": "private"}]}
        response = subprocess.CompletedProcess([], 0, stdout=json.dumps(report).encode(), stderr=b"")
        with patch.object(guest, "command", return_value=response):
            self.assertEqual({"ok": True, "check_count": 1, "all_checks_passed": True}, guest.audit())

    def test_cleanup_rejects_foreign_ownership_before_remove(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            state = temporary / "oniondesk-server-kvm-123-1.json"
            state.write_text(json.dumps({"owner": "a" * 32, "container_id": "b" * 64}))
            inspected = subprocess.CompletedProcess([], 0, stdout="foreign\n", stderr="")
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "CI_STATE_FILE": str(state)}), \
                    patch.object(host.subprocess, "run", return_value=inspected) as execute:
                with self.assertRaises(RuntimeError):
                    host.cleanup()
                self.assertEqual(1, execute.call_count)
                self.assertIn("inspect", execute.call_args.args[0])

    def test_cleanup_uses_only_owned_immutable_id(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            state = temporary / "oniondesk-server-kvm-123-1.json"
            owner, identity = "a" * 32, "b" * 64
            state.write_text(json.dumps({"owner": owner, "container_id": identity}))
            inspected = subprocess.CompletedProcess([], 0, stdout=owner + "\n", stderr="")
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "CI_STATE_FILE": str(state)}), \
                    patch.object(host, "EVIDENCE", temporary / "evidence"), \
                    patch.object(host.subprocess, "run", return_value=inspected) as execute:
                host.cleanup()
                self.assertEqual(["docker", "container", "rm", "--force", identity], execute.call_args.args[0])
                self.assertFalse(state.exists())

    def test_cleanup_docker_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "oniondesk-server-kvm-123-1.json"
            state.write_text(json.dumps({"owner": "a" * 32, "container_id": "b" * 64}))
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="daemon down")
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "CI_STATE_FILE": str(state)}), \
                    patch.object(host.subprocess, "run", return_value=failed), \
                    patch.object(host, "invoke", side_effect=subprocess.CalledProcessError(1, "docker")):
                with self.assertRaises(subprocess.CalledProcessError):
                    host.cleanup()
                self.assertTrue(state.exists())

    def test_cleanup_recovers_create_id_before_start_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            state = temporary / "oniondesk-server-kvm-123-1.json"
            owner, identity = "a" * 32, "b" * 64
            state.write_text(json.dumps({"owner": owner}))
            cid = temporary / ("oniondesk-server-kvm-" + owner + ".cid")
            cid.write_text(identity)
            inspected = subprocess.CompletedProcess([], 0, stdout=owner + "\n", stderr="")
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "CI_STATE_FILE": str(state)}), \
                    patch.object(host, "EVIDENCE", temporary / "evidence"), \
                    patch.object(host.subprocess, "run", return_value=inspected) as execute:
                host.cleanup()
                self.assertEqual(["docker", "container", "rm", "--force", identity], execute.call_args.args[0])
                self.assertFalse(cid.exists())

    def test_evidence_rejects_unexpected_secret_file(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            def copied(_arguments, **_kwargs):
                (temporary / "export/credentials.json").write_text("must never publish")
            with patch.object(host, "invoke", side_effect=copied), self.assertRaises(ValueError):
                host.export_evidence("owned-container", temporary)

    def test_evidence_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            target = temporary / "private"
            target.write_text("must never publish")
            def copied(_arguments, **_kwargs):
                (temporary / "export/status.json").symlink_to(target)
            with patch.object(host, "invoke", side_effect=copied), self.assertRaises(ValueError):
                host.export_evidence("owned-container", temporary)

    def test_evidence_rejects_size_overrun_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            def copied(_arguments, **_kwargs):
                (temporary / "export/status.json").write_text("{}")
            with patch.object(host, "invoke", side_effect=copied), \
                    patch.object(host, "MAX_ARTIFACT_BYTES", 1), self.assertRaises(ValueError):
                host.export_evidence("owned-container", temporary)

    def test_evidence_copies_only_bounded_allowlisted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            evidence = temporary / "evidence"
            evidence.mkdir()
            def copied(_arguments, **_kwargs):
                (temporary / "export/status.json").write_text('{"result":"FAIL_OR_INCOMPLETE"}')
            with patch.object(host, "invoke", side_effect=copied), patch.object(host, "EVIDENCE", evidence):
                host.export_evidence("owned-container", temporary)
            self.assertEqual(["status.json"], [path.name for path in evidence.iterdir()])


if __name__ == "__main__":
    unittest.main()
