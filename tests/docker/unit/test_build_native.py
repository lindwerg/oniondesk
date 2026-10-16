"""Native data staging uses tiny public fixtures and never launches an app."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

CLIENT = Path(__file__).resolve().parents[3] / "client"
sys.path.insert(0, str(CLIENT))
import offline_catalog
import phone_catalog
import wallet_catalog
import feather_catalog

spec = importlib.util.spec_from_file_location("build_native", CLIENT / "build-native.py")
build_native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_native)


class EmbeddedDataStaging(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.kit = self.base / "kit"
        self.root = self.kit / "OnionDesk-Data"
        self.root.mkdir(parents=True)
        self.destination = self.base / "OnionDesk.app/Contents/Resources/OnionDesk-Data"
        self.assets = {"tails-image": self.asset("tails/official.img", b"public tails"),
                       "tor-macos": self.asset("tor-browser/official.dmg", b"public tor")}
        self.hashes = self.asset("Monero/hashes.txt", b"public signed hashes")
        self.key = self.asset("Monero/publisher.asc", b"public publisher key")
        self.monero = {"macos-arm64": self.asset("Monero/official.tar.bz2", b"public monero")}
        self.phone = {"platform-tools": self.asset("Android/platform-tools.zip", b"public adb"),
                      "tor-apk": self.asset("Android/tor-browser.apk", b"public android tor"),
                      "tor-key": self.asset("Android/publisher.key", b"public android publisher key")}
        self.feather = {"binary": self.asset("Feather/official.zip", b"public feather"),
                        "signature": self.asset("Feather/official.zip.asc", b"public feather signature"),
                        "license": self.asset("licenses/Feather.txt", b"public feather license")}
        for target, name, value in ((build_native, "KIT", self.kit),
                                    (offline_catalog, "ASSETS", self.assets),
                                    (phone_catalog, "ASSETS", self.phone),
                                    (feather_catalog, "ASSETS", self.feather),
                                    (wallet_catalog, "HASHES", self.hashes),
                                    (wallet_catalog, "KEY", self.key),
                                    (wallet_catalog, "PLATFORMS", self.monero)):
            self.stack.enter_context(patch.object(target, name, value))
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"format": 1, "release_id": offline_catalog.RELEASE_ID, "assets": self.assets}))

    def asset(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {"path": relative, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}

    def test_only_full_official_allowlist_is_embedded_and_reported(self):
        (self.root / "private-wallet.keys").write_bytes(b"synthetic excluded data")
        (self.root / "user-profile").mkdir()
        (self.root / "user-profile/vault").write_bytes(b"synthetic excluded data")
        report = build_native.stage_embedded_data(self.destination)
        files = sorted(str(path.relative_to(self.destination)) for path in self.destination.rglob("*") if path.is_file())
        expected = sorted(["manifest.json", *(record["path"] for record in self.assets.values()),
                           self.hashes["path"], self.key["path"], self.monero["macos-arm64"]["path"],
                           *(record["path"] for record in self.phone.values()),
                           *(record["path"] for record in self.feather.values())])
        self.assertEqual(files, expected)
        self.assertEqual(report["file_count"], len(expected))
        self.assertTrue(report["source_reverified"])
        self.assertEqual([record["path"] for record in report["files"]], expected)
        for record in report["files"]:
            source, copied = self.root / record["path"], self.destination / record["path"]
            self.assertEqual(source.read_bytes(), copied.read_bytes())
            self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), record["sha256"])
            self.assertNotEqual(source.stat().st_ino, copied.stat().st_ino)
            self.assertEqual(copied.stat().st_nlink, 1)

    def test_same_size_tampering_and_missing_official_file_stop_staging(self):
        image = self.root / self.assets["tails-image"]["path"]
        image.write_bytes(b"x" * image.stat().st_size)
        with self.assertRaisesRegex(RuntimeError, "сумм"):
            build_native.stage_embedded_data(self.destination)
        self.assertFalse(self.destination.exists())
        image.unlink()
        with self.assertRaises(RuntimeError):
            build_native.stage_embedded_data(self.destination)

    def test_tampered_or_missing_android_file_stops_before_any_copy(self):
        apk = self.root / self.phone["tor-apk"]["path"]
        apk.write_bytes(b"x" * apk.stat().st_size)
        with patch.object(build_native, "clone_copy") as copied, self.assertRaisesRegex(RuntimeError, "сумм"):
            build_native.stage_embedded_data(self.destination)
        copied.assert_not_called()
        self.assertFalse(self.destination.exists())
        apk.unlink()
        with patch.object(build_native, "clone_copy") as copied, self.assertRaises(RuntimeError):
            build_native.stage_embedded_data(self.destination)
        copied.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_symlink_hardlink_and_fifo_are_rejected_without_blocking(self):
        image = self.root / self.assets["tails-image"]["path"]
        outside = self.base / "outside"
        image.rename(outside)
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    image.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, image)
                else:
                    os.mkfifo(image)
                try:
                    with self.assertRaises(RuntimeError):
                        build_native.stage_embedded_data(self.destination)
                    self.assertFalse(self.destination.exists())
                finally:
                    image.unlink()

    def test_wrong_manifest_and_redirected_source_root_stop_staging(self):
        self.manifest.write_text('{"format": 999}')
        with self.assertRaises(RuntimeError):
            build_native.stage_embedded_data(self.destination)
        outside = self.base / "outside"
        self.root.rename(outside)
        self.root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            build_native.stage_embedded_data(self.destination)

    def test_existing_or_redirected_destination_is_preserved(self):
        self.destination.mkdir(parents=True)
        keep = self.destination / "keep"
        keep.write_bytes(b"existing data")
        with self.assertRaises(RuntimeError):
            build_native.stage_embedded_data(self.destination)
        self.assertEqual(keep.read_bytes(), b"existing data")

    def test_source_change_after_copy_is_rejected(self):
        original_copy = build_native.clone_copy
        image = self.root / self.assets["tails-image"]["path"]

        def copy_then_change(source, target):
            result = original_copy(source, target)
            if source == image:
                image.write_bytes(b"x" * image.stat().st_size)
            return result

        with patch.object(build_native, "clone_copy", side_effect=copy_then_change), \
                self.assertRaisesRegex(RuntimeError, "сумм"):
            build_native.stage_embedded_data(self.destination)

    def test_corrupt_copy_is_rejected_before_build_can_sign(self):
        original_copy = build_native.clone_copy

        def damaged_copy(source, target):
            result = original_copy(source, target)
            if target.name == "official.img":
                target.write_bytes(b"x" * target.stat().st_size)
            return result

        with patch.object(build_native, "clone_copy", side_effect=damaged_copy), \
                self.assertRaisesRegex(RuntimeError, "сумм"):
            build_native.stage_embedded_data(self.destination)

    def test_build_embeds_before_signing_and_reports_independent_published_copy(self):
        work, tools = self.base / "build", self.base / "tools"
        work.mkdir()
        tools.mkdir()
        published = self.base / "Published.app"
        actual_run = build_native.run
        sign_calls = []
        client = self.kit / "client"
        client.mkdir()
        source_names = {"app.py", "launcher.py", "usb_tails.py", "usb_privileged.py", "offline_bundle.py",
                        "offline_catalog.py", "phone_usb.py", "phone_catalog.py", "wallet_engine.py",
                        "wallet_bundle.py", "wallet_catalog.py", "wallet_security.py", "wallet_vault.py",
                        "wallet_controller.py", "feather_bundle.py", "feather_catalog.py"}
        for name in source_names:
            (client / name).write_text(f"# Synthetic {name}; never executed.\n")

        def fake_external_commands(args, **kwargs):
            if str(args[0]) == "/bin/cp":
                return actual_run(args, **kwargs)
            if "PyInstaller" in args:
                self.assertEqual({entry.name for entry in (work / "resources/client-source").iterdir()}, source_names)
                self.assertIn(f"{work / 'resources/client-source'}:client-source", args)
                contents = work / "dist/OnionDesk.app/Contents"
                gpg = contents / "Frameworks/tools/gpg/bin/gpg"
                gpg.parent.mkdir(parents=True)
                gpg.write_bytes(b"Synthetic verifier; never executed")
                binary = contents / "MacOS/OnionDesk"
                binary.parent.mkdir()
                binary.write_bytes(b"Synthetic executable; never executed")
                (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "local.oniondesk.desktop"}))
            elif "--force" in args and str(args[0]) == "/usr/bin/codesign":
                sign_calls.append(args)
                self.assertTrue((work / "dist/OnionDesk.app/Contents/Resources/OnionDesk-Data/manifest.json").is_file())
            return SimpleNamespace(returncode=1 if "--usb-privileged" in args else 0, stdout="")

        with patch.object(build_native, "stage_resources", return_value=[]), \
                patch.object(build_native, "run", side_effect=fake_external_commands), \
                patch.object(build_native, "verify_gpg", return_value={}), \
                patch.object(build_native.importlib.metadata, "version", return_value="synthetic"):
            result = build_native.build(work, tools, {"binaries": [], "minimum_macos": "15.0"}, published)
        self.assertEqual(result, published)
        self.assertEqual(len(sign_calls), 1)
        evidence = json.loads((work / "evidence.json").read_text())
        self.assertEqual(evidence["embedded_data"]["file_count"], 12)
        self.assertTrue(evidence["embedded_data"]["source_reverified"])
        self.assertEqual({row["path"] for row in evidence["source_code"]}, {"client/" + name for name in source_names})
        for row in evidence["source_code"]:
            self.assertEqual(row["sha256"], hashlib.sha256((self.kit / row["path"]).read_bytes()).hexdigest())
        first = work / "dist/OnionDesk.app/Contents/Resources/OnionDesk-Data/manifest.json"
        second = published / "Contents/Resources/OnionDesk-Data/manifest.json"
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)
        self.assertEqual(second.stat().st_nlink, 1)

    def test_build_preserves_existing_app_before_running_any_build_command(self):
        existing = self.kit / "OnionDesk.app"
        existing.mkdir()
        keep = existing / "keep"
        keep.write_text("Synthetic running app")
        with patch.object(build_native, "run") as commands, self.assertRaisesRegex(RuntimeError, "сохранено"):
            build_native.build(self.base / "build", self.base / "tools", {})
        commands.assert_not_called()
        self.assertEqual(keep.read_text(), "Synthetic running app")


if __name__ == "__main__":
    unittest.main()
