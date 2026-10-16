"""Native image lifecycle boundaries. No physical device or real seed used."""
from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import wallet_vault as vault
from wallet_engine import WalletError

PASSWORD = "only fixture password"
IDENTIFIER = "vault_" + "a" * 32


@unittest.skipUnless(os.name == "posix", "macOS-style directory fixture")
class MacVault(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.manager = vault.MacVaultManager(base=self.folder / "vaults")
        self.mounted = False
        self.image = None
        self.mountpoint = None
        self.calls = []
        self.fail_detach = False
        self.fail_attach = False

    def images(self):
        return [{"image-path": str(self.image), "image-encrypted": True, "owner-uid": os.getuid(),
                 "system-entities": [{"dev-entry": "/dev/disk987s1", "mount-point": str(self.mountpoint)}]}] if self.mounted else []

    def command(self, arguments, *, password=None, timeout=30):
        self.calls.append((list(arguments), timeout))
        operation = arguments[0]
        if operation == "create":
            self.assertEqual(password, PASSWORD)
            path = Path(arguments[-1])
            path.mkdir(mode=0o700)
            (path / "Info.plist").write_bytes(b"encrypted image fixture")
            return b""
        if operation == "isencrypted":
            return plistlib.dumps({"encrypted": True})
        if operation == "info":
            return plistlib.dumps({"images": self.images()})
        if operation == "attach":
            self.assertEqual(password, PASSWORD)
            if self.fail_attach:
                raise WalletError("Fixture wrong password")
            self.image = Path(arguments[-1])
            self.mountpoint = Path(arguments[arguments.index("-mountpoint") + 1])
            self.mounted = True
            return plistlib.dumps({"system-entities": self.images()[0]["system-entities"]})
        if operation == "detach":
            if self.fail_detach:
                raise WalletError("Fixture busy mount")
            self.assertEqual(arguments, ["detach", "/dev/disk987s1"])
            self.mounted = False
            return b""
        raise AssertionError("Unexpected command")

    def mock_native(self):
        self.stack.enter_context(patch.object(vault.MacVaultManager, "_command", side_effect=self.command))
        def mounted(identifier, image, mountpoint, attachment):
            return vault._Mounted(identifier, image, mountpoint, "/dev/disk987s1", self.folder.stat().st_dev + 1)
        self.stack.enter_context(patch.object(vault.MacVaultManager, "_validate_mount", side_effect=mounted))

    def existing_image(self):
        self.manager.base.mkdir(mode=0o700)
        self.image = self.manager.base / (IDENTIFIER + ".sparsebundle")
        self.image.mkdir(mode=0o700)
        (self.image / "Info.plist").write_bytes(b"preserve this fixture")

    def test_constructor_and_listing_do_not_write_or_start_commands(self):
        with patch.object(vault.subprocess, "run") as run, patch.object(Path, "mkdir") as mkdir:
            manager = vault.MacVaultManager(base=self.folder / "not-created")
            self.assertEqual(manager.list_vaults(), [])
            self.assertIsNone(manager.active_id)
            run.assert_not_called()
            mkdir.assert_not_called()

    def test_create_encrypt_attach_and_nonforced_close_preserve_image(self):
        self.mock_native()
        root = self.manager.create(PASSWORD)
        self.assertEqual(root, self.mountpoint / "wallets")
        self.assertEqual(len(self.manager.list_vaults()), 1)
        self.assertEqual(self.manager.base.stat().st_mode & 0o777, 0o700)
        create = next(arguments for arguments, _ in self.calls if arguments[0] == "create")
        self.assertIn("2g", create)
        self.assertIn("AES-256", create)
        self.assertIn("APFS", create)
        self.assertIn("SPARSEBUNDLE", create)
        self.assertNotIn(PASSWORD, " ".join(create))
        image = self.image
        self.manager.close()
        self.assertIsNone(self.manager.active_id)
        self.assertTrue(image.is_dir())
        self.assertFalse(self.mountpoint.exists())
        self.assertFalse(any("-force" in args for args, _ in self.calls))

    def test_subprocess_password_only_stdin_no_keychain_or_command_interpolation(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"fixture", stderr=b"")
        with patch.object(vault.subprocess, "run", return_value=completed) as run, \
             patch.dict(vault.os.environ, {"DYLD_LIBRARY_PATH": "/untrusted-fixture", "LD_PRELOAD": "fixture"}):
            vault.MacVaultManager._command(["attach", "-stdinpass", "fixture.sparsebundle"], password=PASSWORD)
        args, options = run.call_args.args[0], run.call_args.kwargs
        self.assertEqual(args[0], "/usr/bin/hdiutil")
        self.assertNotIn(PASSWORD, " ".join(args))
        self.assertEqual(options["input"], PASSWORD.encode() + b"\0")
        self.assertFalse(options.get("shell", False))
        self.assertTrue(options["capture_output"])
        self.assertNotIn("DYLD_LIBRARY_PATH", options["env"])
        self.assertNotIn("LD_PRELOAD", options["env"])

    def test_detach_failure_keeps_owned_mount_and_image_for_retry(self):
        self.mock_native()
        self.manager.create(PASSWORD)
        active = self.manager._active
        self.fail_detach = True
        with self.assertRaises(WalletError):
            self.manager.close()
        self.assertIs(self.manager._active, active)
        self.assertTrue(self.image.is_dir())
        self.assertTrue(self.mountpoint.is_dir())
        self.fail_detach = False
        self.manager.close()
        self.assertIsNone(self.manager._active)

    def test_external_mounted_image_is_not_adopted_or_detached(self):
        self.existing_image()
        self.mountpoint = self.folder / "external mount"
        self.mounted = True
        self.mock_native()
        with self.assertRaises(WalletError):
            self.manager.unlock(IDENTIFIER, PASSWORD)
        self.manager.close()
        self.assertTrue(self.mounted)
        self.assertFalse(any(args[0] in {"attach", "detach"} for args, _ in self.calls))

    def test_replaced_device_or_mount_identity_is_never_detached(self):
        self.mock_native()
        self.manager.create(PASSWORD)
        active = self.manager._active
        for changed in (replace(active, device="/dev/disk988s1"), replace(active, mount_device=active.mount_device + 1)):
            with patch.object(vault.MacVaultManager, "_validate_mount", return_value=changed):
                with self.assertRaises(WalletError):
                    self.manager.close()
        self.assertIs(self.manager._active, active)
        self.assertFalse(any(args[0] == "detach" for args, _ in self.calls))

    def test_failed_attach_keeps_image_and_only_removes_proven_empty_unmounted_directory(self):
        self.existing_image()
        self.mock_native()
        self.fail_attach = True
        with patch.object(vault.os.path, "ismount", return_value=False):
            with self.assertRaises(WalletError):
                self.manager.unlock(IDENTIFIER, PASSWORD)
        self.assertTrue(self.image.is_dir())
        self.assertFalse((self.manager.base / ".mounts" / IDENTIFIER).exists())
        self.assertFalse(self.manager._uncertain)

    def test_unknown_mount_state_is_preserved_and_blocks_close_without_force(self):
        self.existing_image()
        self.mock_native()
        self.fail_attach = True
        with patch.object(vault.os.path, "ismount", return_value=True):
            with self.assertRaises(WalletError):
                self.manager.unlock(IDENTIFIER, PASSWORD)
        self.assertTrue((self.manager.base / ".mounts" / IDENTIFIER).exists())
        with self.assertRaises(WalletError):
            self.manager.close()
        self.assertFalse(any(args[0] == "detach" for args, _ in self.calls))

    def test_invalid_identifiers_and_symlink_images_are_rejected(self):
        self.existing_image()
        self.mock_native()
        for identifier in ("../foreign", "/dev/disk0", "vault_" + "а" * 32):
            with self.assertRaises(WalletError):
                self.manager.unlock(identifier, PASSWORD)
        target = self.image.with_name("vault_" + "c" * 32 + ".sparsebundle")
        target.symlink_to(self.image, target_is_directory=True)
        with self.assertRaises(WalletError):
            self.manager.unlock("vault_" + "c" * 32, PASSWORD)
        self.assertEqual(self.calls, [])

    def test_existing_image_is_never_overwritten_on_name_collision(self):
        self.existing_image()
        self.mock_native()
        with patch.object(vault.secrets, "token_hex", return_value="a" * 32):
            with self.assertRaises(WalletError):
                self.manager.create(PASSWORD)
        self.assertEqual((self.image / "Info.plist").read_bytes(), b"preserve this fixture")
        self.assertEqual(self.calls, [])


class SystemVault(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.root = self.folder / "wallets"
        self.security = types.SimpleNamespace(attest_encrypted_storage=Mock(return_value={"ok": False, "message": "Encryption required"}))
        self.stack.enter_context(patch.dict(sys.modules, {"wallet_security": self.security}))
        self.stack.enter_context(patch.object(vault, "default_wallet_root", return_value=self.root))
        self.manager = vault.SystemVaultManager()

    def test_no_system_encryption_changes_and_guard_is_fail_closed(self):
        with patch.object(vault.subprocess, "run") as run:
            self.assertEqual(self.manager.list_vaults(), [])
            with self.assertRaises(WalletError):
                self.manager.create(PASSWORD)
            self.assertFalse(self.root.exists())
            self.assertFalse(self.manager.workspace_open)
            self.security.attest_encrypted_storage.return_value = {"ok": True, "kind": "luks"}
            first = self.manager.create(PASSWORD)
            first_id = self.manager.active_id
            self.assertRegex(first_id, r"^vault_[0-9a-f]{32}$")
            self.assertEqual(first, self.root / first_id)
            self.manager.close()
            self.assertEqual(self.manager.unlock(first_id, PASSWORD), first)
            self.assertTrue(self.manager.workspace_open)
            self.manager.close()
            run.assert_not_called()

    def test_two_generated_vaults_keep_distinct_roots_and_cheap_readonly_listing(self):
        self.security.attest_encrypted_storage.return_value = {"ok": True, "kind": "luks"}
        first = self.manager.create(PASSWORD)
        self.manager.close()
        second = self.manager.create("second fixture password")
        second_id = self.manager.active_id
        self.manager.close()
        self.assertNotEqual(first, second)
        self.security.attest_encrypted_storage.reset_mock()
        with patch.object(Path, "mkdir") as mkdir:
            self.assertEqual(len(self.manager.list_vaults()), 2)
            mkdir.assert_not_called()
            self.security.attest_encrypted_storage.assert_not_called()
        self.assertEqual(self.manager.unlock(second_id, "second fixture password"), second)
        self.assertEqual(self.security.attest_encrypted_storage.call_args.args[0], second)

    def test_legacy_shared_data_are_reported_and_preserved(self):
        legacy = self.root / "mainnet"
        legacy.mkdir(mode=0o700, parents=True)
        self.root.chmod(0o700)
        old = legacy / "wallet_fixture.keys"
        old.write_bytes(b"preserve old encrypted fixture")
        self.security.attest_encrypted_storage.return_value = {"ok": True, "kind": "luks"}
        with self.assertRaises(WalletError):
            self.manager.list_vaults()
        with self.assertRaises(WalletError):
            self.manager.create(PASSWORD)
        with self.assertRaises(WalletError):
            self.manager.unlock("system", PASSWORD)
        self.assertEqual(old.read_bytes(), b"preserve old encrypted fixture")
        self.assertEqual(list(self.root.glob("vault_*")), [])

    def test_unsafe_ids_symlink_and_name_collision_never_overwrite_files(self):
        self.security.attest_encrypted_storage.return_value = {"ok": True, "kind": "luks"}
        with patch.object(vault.secrets, "token_hex", return_value="a" * 32):
            first = self.manager.create(PASSWORD)
            data = first / "fixture"
            data.write_bytes(b"preserve")
            self.manager.close()
            with self.assertRaises(WalletError):
                self.manager.create(PASSWORD)
        self.assertEqual(data.read_bytes(), b"preserve")
        alias = self.root / ("vault_" + "b" * 32)
        alias.symlink_to(first, target_is_directory=True)
        for identifier in ("../foreign", "/dev/disk0", "system", alias.name):
            with self.assertRaises(WalletError):
                self.manager.unlock(identifier, PASSWORD)


if __name__ == "__main__":
    unittest.main()
