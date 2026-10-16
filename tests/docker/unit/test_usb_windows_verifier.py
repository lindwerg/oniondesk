"""Windows verifier trust policy mocks. No executable is launched."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import usb_tails as usb

ADMIN = "S-1-5-32-544"
USER = "S-1-5-21-100-200-300-1001"
READ = 0x1200A9
WRITE = 0x120116


class WindowsVerifier(unittest.TestCase):
    def candidate(self, root):
        file = root / "GnuPG/bin/gpg.exe"
        file.parent.mkdir(parents=True)
        file.write_bytes(b"dummy verifier; never executable")
        return file

    def test_programfiles_env_and_path_spoof_cannot_select_verifier(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fake = self.candidate(root)
            with patch.object(usb.platform, "system", return_value="Windows"), \
                 patch.dict(os.environ, {"ProgramFiles": str(root), "ProgramFiles(x86)": str(root),
                                         "PATH": str(fake.parent), "ONIONDESK_GPG": str(fake)}), \
                 patch.object(usb, "_windows_known_folders", return_value=[]), \
                 patch.object(usb, "_windows_trusted_gpg") as check, patch.object(usb.subprocess, "run") as execute:
                self.assertIsNone(usb._find_gpg())
            check.assert_not_called()
            execute.assert_not_called()

    def test_protected_known_folder_installation_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            file = self.candidate(root)
            with patch.object(usb.platform, "system", return_value="Windows"), \
                 patch.object(usb, "_windows_known_folders", return_value=[root]), \
                 patch.object(usb, "_windows_attributes", side_effect=lambda path: 0x20 if path == file else 0x10), \
                 patch.object(usb, "_windows_security", return_value=(ADMIN, [(0, 0, 0x1F01FF, ADMIN), (0, 0, READ, USER)])):
                self.assertEqual(usb._find_gpg(), str(file))

    def test_user_owned_writable_and_reparse_exe_or_ancestor_denied(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            file = self.candidate(root)
            for unsafe in (file, file.parent, file.parent.parent, root):
                for problem in ("owner", "write", "reparse"):
                    def attributes(path):
                        normal = 0x20 if path == file else 0x10
                        return normal | (0x400 if path == unsafe and problem == "reparse" else 0)
                    def security(path):
                        owner = USER if path == unsafe and problem == "owner" else ADMIN
                        rights = WRITE if path == unsafe and problem == "write" else READ
                        return owner, [(0, 0, 0x1F01FF, ADMIN), (0, 0, rights, USER)]
                    with self.subTest(path=str(unsafe), problem=problem), \
                         patch.object(usb, "_windows_attributes", side_effect=attributes), \
                         patch.object(usb, "_windows_security", side_effect=security):
                        self.assertFalse(usb._windows_trusted_gpg(file, root))

    def test_oniondesk_installed_verifier_requires_same_protected_acl(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            file = root / 'OnionDesk/tools/gpg/bin/gpg.exe'
            file.parent.mkdir(parents=True)
            file.write_bytes(b'dummy verifier; not executed')
            with patch.object(usb.platform,'system',return_value='Windows'), patch.object(usb,'_windows_known_folders',return_value=[root]), patch.object(usb,'_windows_attributes',side_effect=lambda path: 0x20 if path==file else 0x10):
                with patch.object(usb,'_windows_security',return_value=(ADMIN,[(0,0,READ,USER)])):
                    self.assertEqual(usb._find_gpg(),str(file))
                with patch.object(usb,'_windows_security',return_value=(USER,[(0,0,WRITE,USER)])):
                    self.assertIsNone(usb._find_gpg())

    def test_unknown_security_or_known_folder_failure_has_no_fallback(self):
        with patch.object(usb.platform, "system", return_value="Windows"), \
             patch.object(usb, "_windows_known_folders", side_effect=OSError("WinAPI unavailable")), \
             patch.object(usb.shutil, "which") as path_search:
            self.assertIsNone(usb._find_gpg())
        path_search.assert_not_called()

    def test_null_dacl_unknown_ace_and_user_owner_denied(self):
        for owner, aces in ((ADMIN, None), (USER, []), (ADMIN, [(5, 0, READ, ADMIN)]),
                            (ADMIN, [(9, 8, READ, ADMIN)])):
            with self.subTest(owner=owner, aces=aces):
                self.assertFalse(usb._windows_acl_trusted(owner, aces, usb._windows_trusted_sids()))

    def test_all_public_modification_rights_denied(self):
        for mask in (0x2, 0x4, 0x10, 0x100, 0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000):
            with self.subTest(mask=mask):
                self.assertFalse(usb._windows_acl_trusted(ADMIN, [(0, 0, mask, USER)], usb._windows_trusted_sids()))

    def test_inherit_only_and_denied_aces_do_not_grant_write(self):
        self.assertTrue(usb._windows_acl_trusted(ADMIN, [(0, 8, WRITE, USER), (1, 0, WRITE, USER)], usb._windows_trusted_sids()))

    def test_volume_root_create_subdir_alone_allowed_but_delete_child_denied(self):
        trusted = usb._windows_trusted_sids()
        self.assertTrue(usb._windows_acl_trusted(ADMIN, [(0, 0, 0x4, USER)], trusted, volume_root=True))
        self.assertFalse(usb._windows_acl_trusted(ADMIN, [(0, 0, 0x40, USER)], trusted, volume_root=True))


if __name__ == "__main__":
    unittest.main()
