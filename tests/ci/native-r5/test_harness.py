"""Boundary regression checks. Native success still requires the actual CI run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("native_r5", Path(__file__).with_name("run.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class BoundaryTests(unittest.TestCase):
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
                (root / "status.json").write_text(json.dumps({"result": "PASS"}))
                HARNESS.seal_evidence()
                (root / "console.txt").write_text("private")
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
