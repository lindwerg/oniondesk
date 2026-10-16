"""Read-only storage attestation fixtures; never change host encryption settings."""
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import wallet_security as security


class StorageAttestation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.target = self.base / "new-wallets"
        self.calls = []

    def mac(self, *, filevault=False, image=False, swap="(encrypted)", wrong_device=False,
            image_verified=True, foreign_owner=False, wrong_image_device=False, wrong_image_mount=False):
        image_path = self.base / "vault.sparsebundle"
        image_path.mkdir(mode=0o700, exist_ok=True)
        def run(args, **kwargs):
            self.calls.append(args)
            if args[0] == "/bin/df":
                return b"Filesystem 512-blocks Used Available Capacity Mounted on\n/dev/disk9s1 100 1 99 1% /fixture\n"
            if args[:3] == ["/usr/sbin/diskutil", "info", "-plist"]:
                return plistlib.dumps({"DeviceNode": "/dev/disk8s1" if wrong_device else "/dev/disk9s1",
                                      "MountPoint": str(self.base), "Encryption": True, "FileVault": filevault})
            if args[:3] == ["/usr/bin/hdiutil", "info", "-plist"]:
                return plistlib.dumps({"images": [{"image-path": str(image_path),
                    "image-encrypted": image, "owner-uid": os.getuid() + int(foreign_owner),
                    "system-entities": [{"dev-entry": "/dev/disk7s1" if wrong_image_device else "/dev/disk9s1",
                                         "mount-point": str(self.base / "other") if wrong_image_mount else str(self.base)}]}]})
            if args[:3] == ["/usr/bin/hdiutil", "isencrypted", "-plist"]:
                if not image_verified:
                    raise security._Unverified("Busy backing fixture")
                return plistlib.dumps({"encrypted": True})
            if args == ["/usr/sbin/sysctl", "vm.swapusage"]:
                return f"vm.swapusage: total = 1024.00M  used = 2.00M  free = 1022.00M  {swap}\n".encode()
            raise AssertionError(args)
        return patch.object(security, "_run", side_effect=run)

    def linux(self, tree, swaps="Filename\tType\tSize\tUsed\tPriority\n", *, wrong_device=False):
        def run(args, **kwargs):
            self.calls.append(args)
            if args[0] == "/usr/bin/findmnt":
                return json.dumps({"filesystems": [{"source": "/dev/mapper/fixture[/@]", "target": str(self.base), "fstype": "btrfs"}]}).encode()
            if args[0] == "/usr/bin/lsblk":
                if args[-1] == "/dev/vdb2":
                    return json.dumps({"blockdevices": [{"name": "/dev/vdb2", "type": "part", "fstype": "swap"}]}).encode()
                return json.dumps({"blockdevices": tree}).encode()
            raise AssertionError(args)
        self.enterContext(patch.object(security, "_run", side_effect=run))
        self.enterContext(patch.object(security, "_read_swaps", return_value=swaps))
        self.enterContext(patch.object(security, "_block_identity", side_effect=lambda p: 1 if not wrong_device or p == "/dev/mapper/fixture" else 2))

    @staticmethod
    def luks():
        return [{"name": "/dev/mapper/fixture", "type": "lvm", "fstype": "btrfs", "children": [
            {"name": "/dev/dm-0", "type": "crypt", "fstype": "LVM2_member", "children": [
                {"name": "/dev/vda2", "type": "part", "fstype": "crypto_LUKS"}]}]}]

    def attest(self, platform):
        with patch.object(security.sys, "platform", platform):
            return security.attest_encrypted_storage(self.target)

    def test_mac_hardware_encryption_without_filevault_is_rejected(self):
        with self.mac():
            self.assertFalse(self.attest("darwin")["ok"])
        self.assertFalse(self.target.exists())

    def test_mac_filevault_and_encrypted_swap_are_accepted(self):
        with self.mac(filevault=True):
            self.assertEqual(self.attest("darwin")["kind"], "filevault")

    def test_mac_device_mismatch_and_clear_swap_fail_closed(self):
        for options in ({"filevault": True, "wrong_device": True}, {"filevault": True, "swap": ""}):
            with self.subTest(options=options), self.mac(**options):
                self.assertFalse(self.attest("darwin")["ok"])

    def test_mac_live_owned_encrypted_image_does_not_reopen_busy_backing(self):
        # This fixture isolates native image evidence; /tmp can be world-writable
        # on Linux. Backing path permissions have their own independent test.
        with self.mac(image=True, image_verified=False), patch.object(security, "_mac_image_backing_safe", return_value=True):
            result = self.attest("darwin")
            self.assertTrue(result["ok"])
            self.assertEqual(result["kind"], "encrypted-image")
        for options in ({"image": False}, {"image": True, "foreign_owner": True},
                        {"image": True, "wrong_image_device": True}, {"image": True, "wrong_image_mount": True},
                        {"image": True, "swap": ""}):
            with self.subTest(options=options), self.mac(**options), patch.object(security, "_mac_image_backing_safe", return_value=True):
                self.assertFalse(self.attest("darwin")["ok"])
        self.assertFalse(any("imageinfo" in call for call in self.calls))
        self.assertFalse(any("isencrypted" in call for call in self.calls))
        with self.mac(image=True), patch.object(security, "_mac_image_backing_safe", return_value=False):
            self.assertFalse(self.attest("darwin")["ok"])

    def test_mac_unknown_swap_is_rejected_and_zero_clear_swap_is_accepted(self):
        with self.mac(filevault=True), patch.object(security, "_mac_swap_safe", return_value=False):
            self.assertFalse(self.attest("darwin")["ok"])
        with patch.object(security, "_run", return_value=b"vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M\n"):
            self.assertTrue(security._mac_swap_safe())
        with patch.object(security, "_run", return_value=b"unrecognized output"):
            self.assertFalse(security._mac_swap_safe())
        for output in (b"vm.swapusage: total = 1024.00M used = 0.00M free = 1024.00M\n",
                       b"vm.swapusage: total = 0.00M used = 1.00M free = 0.00M\n"):
            with self.subTest(output=output), patch.object(security, "_run", return_value=output):
                self.assertFalse(security._mac_swap_safe())

    def test_linux_lvm_over_luks_and_no_swap_are_accepted(self):
        self.linux(self.luks())
        self.assertEqual(self.attest("linux")["kind"], "luks")

    def test_linux_mapper_name_without_crypto_is_rejected(self):
        self.linux([{"name": "/dev/mapper/fixture", "type": "lvm", "fstype": "ext4"}])
        self.assertFalse(self.attest("linux")["ok"])

    def test_linux_unencrypted_backing_branch_is_rejected(self):
        tree = self.luks()
        tree[0]["children"].append({"name": "/dev/vdb1", "type": "part", "fstype": "LVM2_member"})
        self.linux(tree)
        self.assertFalse(self.attest("linux")["ok"])

    def test_linux_wrong_source_identity_and_clear_swap_are_rejected(self):
        self.linux(self.luks(), swaps="Filename Type Size Used Priority\n/dev/vdb2 partition 4096 0 -2\n")
        self.assertFalse(self.attest("linux")["ok"])
        with patch.object(security, "_block_identity", side_effect=lambda p: 1 if p == "/dev/mapper/fixture" else 2), \
             patch.object(security, "_run", return_value=json.dumps({"blockdevices": [{"name": "/dev/wrong", "type": "crypt", "children": [{"name": "/dev/vda2", "fstype": "crypto_LUKS"}]}]}).encode()):
            self.assertFalse(security._linux_block_encrypted("/dev/mapper/fixture", require_luks=True))

    def test_linux_encrypted_swapfile_and_plain_crypt_swap_device(self):
        swapfile = self.base / "swapfile"
        swapfile.write_bytes(b"fixture")
        self.linux(self.luks(), swaps=f"Filename Type Size Used Priority\n{swapfile} file 4096 0 -2\n")
        self.assertTrue(self.attest("linux")["ok"])
        with patch.object(security, "_run", return_value=json.dumps({"blockdevices": [{"name": "/dev/mapper/swap", "type": "crypt"}]}).encode()):
            self.assertTrue(security._linux_block_encrypted("/dev/mapper/swap", require_luks=False))

    def test_target_symlink_and_unknown_system_are_rejected_without_commands(self):
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with patch.object(security, "_run") as run:
            self.assertFalse(security.attest_encrypted_storage(alias / "wallets")["ok"])
            with patch.object(security.sys, "platform", "unknown"):
                self.assertFalse(security.attest_encrypted_storage(self.target)["ok"])
            run.assert_not_called()

    def test_mount_must_cover_target_and_match_its_device(self):
        self.assertFalse(security._mount_matches(str(self.base / "unrelated"), self.base))
        alias_mount = self.base / "same-device-mount"
        alias_mount.mkdir()
        self.assertFalse(security._mount_matches(str(alias_mount), self.base))
        self.assertTrue(security._mount_matches(str(alias_mount), self.base, require_coverage=False))
        with patch.object(security, "_safe_components"), patch.object(Path, "stat", side_effect=[SimpleNamespace(st_mode=0o40700),
                    SimpleNamespace(st_dev=10), SimpleNamespace(st_dev=11)]):
            self.assertFalse(security._mount_matches(str(self.base), self.base))

    def test_image_backing_symlinks_and_world_writable_image_are_rejected(self):
        image = self.base / "vault.dmg"
        image.write_bytes(b"fixture")
        image.chmod(0o666)
        self.assertFalse(security._mac_image_backing_safe(image))
        link = self.base / "alias.dmg"
        link.symlink_to(image)
        with self.assertRaises(security._Unverified):
            security._mac_image_backing_safe(link)

    def test_windows_requires_fully_encrypted_protected_unlocked_target_and_system(self):
        good = {"MountPoint": "C:", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On", "LockStatus": "Unlocked", "EncryptionPercentage": 100}
        def evidence(rows, pagefiles=None):
            return {"format": 1, "pagefiles_queried": True,
                    "pagefiles": [] if pagefiles is None else pagefiles, "volumes": rows}
        self.assertTrue(security._bitlocker_rows_safe(evidence([good]), "C:", "C:"))
        for key, value in (("VolumeStatus", "EncryptionPaused"), ("ProtectionStatus", "Off"), ("LockStatus", "Locked"), ("EncryptionPercentage", 99), ("MountPoint", "D:")):
            with self.subTest(key=key):
                self.assertFalse(security._bitlocker_rows_safe(evidence([{**good, key: value}]), "C:", "C:"))
        self.assertFalse(security._bitlocker_rows_safe(evidence([]), "C:", "C:"))
        self.assertFalse(security._bitlocker_rows_safe(evidence([good]), "C:;exit", "C:"))

    def test_windows_every_active_pagefile_drive_must_be_protected(self):
        good = {"MountPoint": "C:", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On", "LockStatus": "Unlocked", "EncryptionPercentage": 100}
        pagefiles = [{"name": r"D:\pagefile.sys"}, {"name": r"C:\pagefile.sys"}]
        evidence = {"format": 1, "pagefiles_queried": True, "pagefiles": pagefiles,
                    "volumes": [good, {**good, "MountPoint": "D:"}]}
        self.assertTrue(security._bitlocker_rows_safe(evidence, "C:", "C:"))
        for change in ({"ProtectionStatus": "Off"}, {"VolumeStatus": "EncryptionPaused"},
                       {"EncryptionPercentage": 50}, {"LockStatus": "Unknown"}):
            bad = {**evidence, "volumes": [good, {**good, "MountPoint": "D:", **change}]}
            self.assertFalse(security._bitlocker_rows_safe(bad, "C:", "C:"))
        for missing in ({"format": 1, "volumes": [good]}, {**evidence, "pagefiles_queried": False},
                        {**evidence, "pagefiles": None}, {**evidence, "volumes": [good]}):
            self.assertFalse(security._bitlocker_rows_safe(missing, "C:", "C:"))
        for name in ("pagefile.sys", "D:pagefile.sys", r"\\server\share\pagefile.sys", r"\\?\D:\pagefile.sys",
                     r"D:\..\pagefile.sys", r"D:\pagefile.sys:stream", "", None):
            bad = {**evidence, "pagefiles": [{"name": name}]}
            self.assertFalse(security._bitlocker_rows_safe(bad, "C:", "C:"))
        self.assertIn("Get-CimInstance -ClassName Win32_PageFileUsage -Property Name -ErrorAction Stop", security._BITLOCKER_SCRIPT)

    def test_native_commands_are_bounded_and_ignore_frozen_loader_environment(self):
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/untrusted", "LD_PRELOAD": "payload", "DYLD_LIBRARY_PATH": "/untrusted"}), \
             patch.object(security.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"fixture")) as run:
            self.assertEqual(security._run(["/usr/bin/findmnt", "--json"]), b"fixture")
        options = run.call_args.kwargs
        self.assertEqual(options["timeout"], 6)
        self.assertEqual(options["stdin"], security.subprocess.DEVNULL)
        self.assertFalse(any(name.startswith(("LD_", "DYLD_")) for name in options["env"]))
        for result in (SimpleNamespace(returncode=1, stdout=b"{}"), SimpleNamespace(returncode=0, stdout=b"x" * (2 * 1024**2 + 1))):
            with patch.object(security.subprocess, "run", return_value=result), self.assertRaises(security._Unverified):
                security._run(["/usr/bin/findmnt", "--json"])

    def test_system_failure_returns_no_path_or_native_output(self):
        with patch.object(security, "_run", side_effect=OSError("private path and hardware ID")):
            result = self.attest("darwin")
        self.assertFalse(result["ok"])
        self.assertNotIn(str(self.base), json.dumps(result))
        self.assertNotIn("hardware ID", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
