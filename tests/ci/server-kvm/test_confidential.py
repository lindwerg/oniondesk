"""Early real-probe shape and encrypted-only export boundary; no VM operations."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import confidential
from test_harness import guest, host


class ConfidentialTests(unittest.TestCase):
    def test_probe_variants_add_only_memory_then_passt(self):
        basic = ET.fromstring(guest.probe_xml("owned-probe"))
        memory = ET.fromstring(guest.probe_xml("owned-probe", "whonix_memory"))
        passt = ET.fromstring(guest.probe_xml("owned-probe", "whonix_memory_passt"))
        self.assertEqual("kvm", basic.get("type"))
        self.assertIsNone(basic.find("memoryBacking"))
        self.assertEqual("2", memory.findtext("memory"))
        self.assertEqual("ondemand", memory.find("memoryBacking/allocation").get("mode"))
        self.assertIsNotNone(memory.find("memoryBacking/discard"))
        self.assertIsNotNone(memory.find("memoryBacking/nosharepages"))
        self.assertIsNone(memory.find("devices/interface"))
        interface = passt.find("devices/interface")
        self.assertEqual("user", interface.get("type"))
        self.assertEqual("passt", interface.find("backend").get("type"))
        self.assertIsNone(interface.find("portForward"))
        self.assertIsNone(passt.find("devices/disk"))
        self.assertEqual(ET.tostring(memory.find("memoryBacking")), ET.tostring(passt.find("memoryBacking")))

    def test_unknown_probe_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            guest.probe_xml("owned-probe", "unknown")

    def test_failed_probe_encrypts_private_stderr_and_does_not_destroy_uncreated_domain(self):
        private = confidential.PrivateDiagnostic()
        with tempfile.TemporaryDirectory() as directory:
            real_path = Path
            def path(value):
                return real_path(directory) / "probe.xml"
            failure = subprocess.CalledProcessError(1, "virsh", output=b"", stderr=b"Unable to open /proc/sys/private-target: Permission denied")
            with patch.object(guest, "command"), patch.object(guest, "Path", side_effect=path), \
                    patch.object(guest, "virsh", side_effect=[b"version", failure]) as execute:
                with self.assertRaises(subprocess.CalledProcessError):
                    guest.probe_libvirt("whonix_memory_passt", private)
            self.assertIn(b"/proc/sys/private-target", private.data)
            self.assertFalse(any(call.args[0] == "destroy" for call in execute.call_args_list))

    def test_private_diagnostic_buffer_is_bounded_and_never_written_plain(self):
        private = confidential.PrivateDiagnostic()
        private.add("probe", b"old-secret" + b"x" * 100000)
        private.add("journal", b"new-secret")
        self.assertEqual(64 * 1024, len(private.data))
        self.assertNotIn(b"old-secret", private.data)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "server-diagnostic.cms"
            with patch.object(confidential, "encrypt_diagnostic", return_value=True) as encrypt:
                self.assertTrue(private.save(target))
                self.assertLessEqual(len(encrypt.call_args.args[0]), 64 * 1024)
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_real_envelope_is_pinned_bounded_and_has_no_plaintext_marker(self):
        marker = b"private-marker-never-published-in-plaintext"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "server-diagnostic.cms"
            self.assertTrue(confidential.encrypt_diagnostic(marker + b"x" * 100000, target))
            encrypted = target.read_bytes()
            confidential.validate_encrypted_diagnostic(encrypted)
            self.assertLessEqual(len(encrypted), 64 * 1024 + 4096)
            self.assertNotIn(marker, encrypted)
            with self.assertRaises(ValueError):
                confidential.validate_encrypted_diagnostic(encrypted + marker)
            with patch.object(confidential, "DIAGNOSTIC_CERT_SHA256", "0" * 64), self.assertRaises(ValueError):
                confidential.encrypt_diagnostic(marker, target)

    def test_rejects_plain_signed_foreign_recipient_and_wrong_cipher_profiles(self):
        marker = b"synthetic-private-plaintext-must-not-pass"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate, key = root / "fixture-cert.pem", root / "fixture-key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(certificate), "-subj", "/CN=synthetic-CMS-test", "-days", "1"],
                           check=True, capture_output=True, timeout=30)
            commands = {
                "Data": ["-data_create"],
                "SignedData": ["-sign", "-nodetach", "-signer", str(certificate), "-inkey", str(key)],
                "ForeignRecipient": ["-encrypt", "-aes-256-cbc", str(certificate)],
                "AES128": ["-encrypt", "-aes-128-cbc", str(confidential.HERE / "diagnostic-recipient.pem")],
            }
            for name, operation in commands.items():
                response = subprocess.run(["openssl", "cms", "-binary", "-outform", "DER", *operation],
                                          input=marker, check=True, capture_output=True, timeout=20)
                with self.subTest(profile=name), self.assertRaises(ValueError):
                    confidential.validate_encrypted_diagnostic(response.stdout)

    def test_host_rejects_plain_cms_before_copying_any_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            def copied(_arguments, **kwargs):
                (root / "export/status.json").write_text(json.dumps({"result": "FAIL_OR_INCOMPLETE"}))
                (root / "export/server-diagnostic.cms").write_bytes(b"private plaintext")
            with patch.object(host, "invoke", side_effect=copied), patch.object(host, "EVIDENCE", evidence):
                with self.assertRaises(ValueError):
                    host.export_evidence("owned-container", root)
            self.assertEqual([], list(evidence.iterdir()))

    def test_host_accepts_only_valid_encrypted_diagnostic_with_existing_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            def copied(_arguments, **kwargs):
                confidential.encrypt_diagnostic(b"synthetic-private-diagnostic", root / "export/server-diagnostic.cms")
            with patch.object(host, "invoke", side_effect=copied), patch.object(host, "EVIDENCE", evidence):
                host.export_evidence("owned-container", root)
            confidential.validate_encrypted_diagnostic((evidence / "server-diagnostic.cms").read_bytes())


if __name__ == "__main__":
    unittest.main()
