"""Small, offline fixtures: no installer is executed and no disk is opened."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
import zipfile
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import offline_bundle as offline
import offline_catalog as catalog
import usb_tails as usb


def valid_status(fingerprint=catalog.TOR_FINGERPRINT):
    return f"[GNUPG:] GOODSIG 01234 Publisher\n[GNUPG:] VALIDSIG {'A' * 40} 2026-10-12 1791849600 0 4 0 1 10 00 {fingerprint}\n"


class BundleFixture(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.root = self.folder / "OnionDesk-Data"
        self.root.mkdir()
        self.cache = self.folder / "private-cache"
        assets = {}
        for index, key in enumerate(("tails-image", "tails-signature", "tails-key", "tor-macos", "tor-macos-signature",
                                      "tor-windows", "tor-windows-signature", "tor-linux", "tor-linux-signature", "tor-key")):
            value = (key + str(index)).encode()
            path = "artifacts/" + key
            target = self.root / path
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(value)
            assets[key] = {"path": path, "size_bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        self.stack.enter_context(patch.object(catalog, "ASSETS", assets))
        self.stack.enter_context(patch.object(offline, "_data_roots", return_value=[self.root]))
        self.stack.enter_context(patch.object(offline, "_tor_cache", return_value=self.cache))
        self.stack.enter_context(patch.object(usb, "CACHE", self.cache))
        self.stack.enter_context(patch.object(offline, "_is_elevated", return_value=False))
        self.stack.enter_context(patch.object(offline, "_assert_tor_ports_free"))
        self.stack.enter_context(patch.object(offline.platform, "system", return_value="Linux"))
        self.stack.enter_context(patch.object(offline.platform, "machine", return_value="x86_64"))
        # Any accidentally introduced network access makes all fixture tests fail.
        self.stack.enter_context(patch("socket.socket", side_effect=AssertionError("No sockets in offline preparation")))
        self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("No local DNS in offline preparation")))
        self.manifest()

    def manifest(self, change=None):
        value = {"format": 1, "release_id": catalog.RELEASE_ID, "assets": catalog.ASSETS}
        value = json.loads(json.dumps(value))
        if change:
            change(value)
        (self.root / "manifest.json").write_text(json.dumps(value))

    def prepare(self):
        with patch.object(offline, "_verify_tor_signature") as verifier, \
             patch.object(offline, "_install_and_launch", return_value="Tor открыт") as launch:
            result = offline.prepare_tor()
        return result, verifier, launch


class Presence(BundleFixture):
    def test_status_is_safe_and_does_not_execute_or_hash_large_files(self):
        with patch.object(offline.subprocess, "run") as run, patch.object(offline, "_copy_asset") as copy:
            result = offline.status()
        self.assertEqual(set(result), {"available", "tails_available", "tor_available", "tails_version", "tor_version", "message"})
        self.assertTrue(result["available"] and result["tails_available"] and result["tor_available"])
        self.assertNotIn(str(self.folder), json.dumps(result))
        run.assert_not_called()
        copy.assert_not_called()

    def test_missing_folder_is_only_case_returning_none_for_tails(self):
        with patch.object(offline, "_data_roots", return_value=[self.folder / "absent"]):
            self.assertIsNone(offline.prepare_tails(self.cache))
            self.assertFalse(offline.status()["available"])
        (self.root / "manifest.json").unlink()
        with self.assertRaises(offline.OfflineError):
            offline.prepare_tails(self.cache)

    def test_missing_tails_does_not_hide_present_tor_installer(self):
        (self.root / "artifacts/tails-image").unlink()
        result = offline.status()
        self.assertFalse(result["tails_available"])
        self.assertTrue(result["tor_available"])

    def test_architectures_are_explicit_and_macos_arm_uses_universal(self):
        for system, machine in (("Darwin", "arm64"), ("Darwin", "x86_64"), ("Linux", "x86_64"), ("Windows", "AMD64")):
            with patch.object(offline.platform, "system", return_value=system), patch.object(offline.platform, "machine", return_value=machine):
                self.assertEqual(offline._tor_assets(), catalog.TOR[system])
        for system, machine in (("Linux", "aarch64"), ("Windows", "ARM64"), ("Linux", "i686")):
            with patch.object(offline.platform, "system", return_value=system), patch.object(offline.platform, "machine", return_value=machine), self.assertRaises(offline.OfflineError):
                offline._tor_assets()


class Integrity(BundleFixture):
    def test_copy_hash_and_publisher_check_happen_before_launch(self):
        result, verifier, launch = self.prepare()
        self.assertEqual(result, {"message": "Tor открыт"})
        verifier.assert_called_once()
        launch.assert_called_once()
        binary, signature, key = verifier.call_args.args
        self.assertTrue(binary.is_relative_to(self.cache))
        self.assertTrue(signature.is_relative_to(self.cache) and key.is_relative_to(self.cache))
        self.assertEqual(binary.read_bytes(), (self.root / "artifacts/tor-linux").read_bytes())
        self.assertEqual((binary.parent / ".oniondesk-managed").read_text(), catalog.RELEASE_ID)

    def test_same_size_tampering_stops_before_publisher_or_execute(self):
        binary = self.root / "artifacts/tor-linux"
        binary.write_bytes(b"x" * binary.stat().st_size)
        with patch.object(offline, "_verify_tor_signature") as verifier, patch.object(offline, "_install_and_launch") as launch, self.assertRaisesRegex(offline.OfflineError, "сумма"):
            offline.prepare_tor()
        verifier.assert_not_called()
        launch.assert_not_called()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_wrong_publisher_stops_before_execute(self):
        with patch.object(offline, "_verify_tor_signature", side_effect=offline.OfflineError("wrong publisher")), \
             patch.object(offline, "_install_and_launch") as launch, self.assertRaises(offline.OfflineError):
            offline.prepare_tor()
        launch.assert_not_called()

    def test_os_launch_uncertainty_never_deletes_possibly_active_profile(self):
        with patch.object(offline, "_verify_tor_signature"), patch.object(offline, "_install_and_launch", side_effect=offline._BrowserLaunchError("OS confirmation pending")), patch.object(offline.shutil, "rmtree") as cleanup, self.assertRaises(offline.OfflineError):
            offline.prepare_tor()
        cleanup.assert_not_called()
        self.assertEqual(len(list(self.cache.iterdir())), 1)

    def test_mutable_manifest_cannot_change_paths_hashes_version_or_size(self):
        changes = [lambda m: m.update(release_id="old-release"),
                   lambda m: m["assets"]["tor-linux"].update(path="../../outside"),
                   lambda m: m["assets"]["tor-linux"].update(sha256="a" * 64),
                   lambda m: m["assets"]["tor-linux"].update(size_bytes=1),
                   lambda m: m["assets"].update(extra={"path": "arbitrary.exe"})]
        for change in changes:
            self.manifest(change)
            with self.subTest(change=change), patch.object(offline, "_install_and_launch") as launch, self.assertRaises(offline.OfflineError):
                offline.prepare_tor()
            launch.assert_not_called()

    def test_symlinked_asset_and_parent_and_hardlink_rejected(self):
        source = self.root / "artifacts/tor-linux"
        outside = self.folder / "outside"
        source.rename(outside)
        source.symlink_to(outside)
        with self.assertRaises(offline.OfflineError):
            self.prepare()
        source.unlink()
        os.link(outside, source)
        with self.assertRaises(offline.OfflineError):
            self.prepare()
        source.unlink()
        outside.rename(source)
        actual = self.folder / "redirected"
        (self.root / "artifacts").rename(actual)
        (self.root / "artifacts").symlink_to(actual, target_is_directory=True)
        with self.assertRaises(offline.OfflineError):
            self.prepare()

    def test_oversize_file_manifest_and_duplicate_json_keys_rejected(self):
        target = self.root / "artifacts/tor-linux"
        target.write_bytes(target.read_bytes() + b"extra")
        with self.assertRaises(offline.OfflineError):
            self.prepare()
        (self.root / "manifest.json").write_bytes(b" " * (offline.MAX_MANIFEST_BYTES + 1))
        with self.assertRaises(offline.OfflineError):
            offline._check_manifest(self.root)
        (self.root / "manifest.json").write_text('{"format":1,"format":1}')
        with self.assertRaises(offline.OfflineError):
            offline._check_manifest(self.root)

    def test_elevated_browser_launch_rejected_before_copy(self):
        with patch.object(offline, "_is_elevated", return_value=True), patch.object(offline, "_copy_asset") as copy, self.assertRaisesRegex(offline.OfflineError, "обычного"):
            offline.prepare_tor()
        copy.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named FIFO files require POSIX")
    def test_fifo_asset_and_manifest_are_rejected_in_bounded_child_process(self):
        program = r'''
import json, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import offline_bundle as offline
import offline_catalog as catalog
catalog.ASSETS = json.loads(sys.argv[3])
offline._data_roots = lambda: [Path(sys.argv[2])]
offline._tor_cache = lambda: Path(sys.argv[4])
offline._is_elevated = lambda: False
offline._assert_tor_ports_free = lambda: None
offline.platform.system = lambda: "Linux"
offline.platform.machine = lambda: "x86_64"
def forbidden(*args, **kwargs):
    raise AssertionError("No network, signature subprocess, or launch on malformed file")
socket.socket = socket.getaddrinfo = forbidden
offline._verify_tor_signature = offline._install_and_launch = forbidden
assert offline.status()["tor_available"] is False
try:
    offline.prepare_tor()
except offline.OfflineError:
    pass
else:
    raise AssertionError("FIFO was accepted")
'''
        for relative in ("artifacts/tor-linux", "manifest.json"):
            target = self.root / relative
            previous = target.read_bytes()
            target.unlink()
            os.mkfifo(target)
            try:
                result = subprocess.run([sys.executable, "-c", program, str(Path(offline.__file__).resolve().parent),
                                         str(self.root), json.dumps(catalog.ASSETS), str(self.cache)],
                                        capture_output=True, timeout=3, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            finally:
                target.unlink()
                target.write_bytes(previous)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named FIFO files require POSIX")
    def test_file_replaced_with_fifo_between_lstat_and_open_is_nonblocking(self):
        target = self.root / "artifacts/tor-linux"
        real_open = os.open

        def raced_open(path, flags, *args, **kwargs):
            if Path(path) == target:
                self.assertTrue(flags & os.O_NONBLOCK)
                target.unlink()
                os.mkfifo(target)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(offline.os, "open", side_effect=raced_open), self.assertRaises(offline.OfflineError):
            offline._open_regular(self.root, "artifacts/tor-linux", catalog.ASSETS["tor-linux"]["size_bytes"])

    def test_failed_mac_detach_preserves_private_work_and_does_not_cleanup_or_open(self):
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            if args[:2] == ["/usr/bin/hdiutil", "attach"]:
                mount = Path(args[args.index("-mountpoint") + 1])
                (mount / "Tor Browser.app").mkdir()
            elif args[0] == "/usr/bin/ditto":
                Path(args[-1]).mkdir()
            code = 1 if args[:2] == ["/usr/bin/hdiutil", "detach"] else 0
            return subprocess.CompletedProcess(args, code, b"", b"")

        with patch.object(offline.platform, "system", return_value="Darwin"), patch.object(offline, "_verify_tor_signature"), \
             patch.object(offline.subprocess, "run", side_effect=run), patch.object(offline.shutil, "rmtree") as cleanup, \
             self.assertRaisesRegex(offline.OfflineError, "папка сохранена"):
            offline.prepare_tor()
        cleanup.assert_not_called()
        self.assertFalse(any(args[0] == "/usr/bin/open" for args in commands))
        works = list(self.cache.iterdir())
        self.assertEqual(len(works), 1)
        self.assertTrue((works[0] / ".oniondesk-managed").is_file())
        self.assertTrue((works[0] / "mounted").is_dir())
        self.assertTrue((works[0] / "tor-macos").is_file())


class TailsOffline(BundleFixture):
    def test_usb_prepares_bundle_without_tor_and_retains_private_signature(self):
        with patch.object(usb, "_find_gpg", return_value="/verified/gpg"), patch.object(usb, "_verify_signature") as verifier, \
             patch.object(usb, "_verified_tor_port", side_effect=AssertionError("Tor must not be consulted")), \
             patch.object(usb, "_fetch", side_effect=AssertionError("Offline must not download")):
            result = usb.download_verified_image()
        self.assertTrue(result["verified"])
        self.assertTrue(Path(result["path"]).is_relative_to(self.cache))
        verifier.assert_called_once()
        self.assertTrue(Path(usb._ARTIFACT["signature"]).is_file())
        self.assertTrue(Path(usb._ARTIFACT["key"]).is_file())
        self.assertEqual(json.loads((self.cache / "latest-verified.json").read_text()), {"version": catalog.TAILS_VERSION})

    def test_bad_bundle_never_falls_back_to_network(self):
        self.manifest(lambda m: m.update(release_id="old"))
        with patch.object(usb, "_find_gpg", return_value="/gpg"), patch.object(usb, "_verified_tor_port") as tor, \
             patch.object(usb, "_fetch") as fetch, self.assertRaises(offline.OfflineError):
            usb.download_verified_image()
        tor.assert_not_called()
        fetch.assert_not_called()
        self.assertIsNone(usb._ARTIFACT)

    def test_prior_newer_release_prevents_offline_downgrade(self):
        self.cache.mkdir()
        (self.cache / "latest-verified.json").write_text('{"version":"999.0"}')
        with patch.object(usb, "_verify_signature") as verifier, self.assertRaisesRegex(offline.OfflineError, "старее"):
            offline.prepare_tails(self.cache)
        verifier.assert_not_called()


class Publisher(unittest.TestCase):
    def test_tor_key_does_not_weaken_tails_pinned_key(self):
        self.assertTrue(offline._valid_tor_signature(valid_status()))
        self.assertFalse(offline._valid_tor_signature(valid_status(usb.PUBLISHER_FINGERPRINT)))
        self.assertFalse(usb._valid_signature(valid_status()))
        for error in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "FAILURE"):
            self.assertFalse(offline._valid_tor_signature(valid_status() + f"[GNUPG:] {error} x\n"))
        self.assertFalse(offline._valid_tor_signature(valid_status() + valid_status()))

    def test_wrong_primary_key_rejected_before_import_or_verification(self):
        shown = subprocess.CompletedProcess([], 0, stdout=f"pub::::::::::\nfpr:::::::::{'1' * 40}:\n".encode(), stderr=b"")
        with patch.object(usb, "_find_gpg", return_value="/gpg"), patch.object(offline.subprocess, "run", return_value=shown) as run, self.assertRaisesRegex(offline.OfflineError, "Ключ Tor Browser"):
            offline._verify_tor_signature(Path("b"), Path("s"), Path("k"))
        self.assertEqual(run.call_count, 1)
        self.assertIn("--no-auto-key-retrieve", run.call_args.args[0])


class PortGuard(unittest.TestCase):
    class Probe:
        def __init__(self, result):
            self.result = result
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect_ex(self, address):
            self.address = address
            if isinstance(self.result, BaseException):
                raise self.result
            return self.result

    def test_probe_is_bounded_numeric_loopback_only_and_sends_no_http(self):
        probes = [self.Probe(0), self.Probe(errno.ECONNREFUSED)]
        with patch.object(offline.socket, "socket", side_effect=probes), patch.object(offline.socket, "getaddrinfo", side_effect=AssertionError("No DNS")), patch.object(usb, "_public_request") as http, patch.object(usb, "_verified_tor_port") as verify:
            self.assertEqual(offline._busy_tor_ports(), [9150])
        self.assertEqual([p.address for p in probes], [("127.0.0.1", 9150), ("127.0.0.1", 9151)])
        self.assertTrue(all(p.timeout == 0.2 and p.closed for p in probes))
        http.assert_not_called()
        verify.assert_not_called()

    def test_connection_refused_means_free_and_unknown_errors_fail_closed(self):
        with patch.object(offline.socket, "socket", side_effect=[self.Probe(errno.ECONNREFUSED), self.Probe(10061)]):
            self.assertEqual(offline._busy_tor_ports(), [])
        for result in (errno.EACCES, errno.ETIMEDOUT, TimeoutError("bounded timeout")):
            probe = self.Probe(result)
            with self.subTest(result=result), patch.object(offline.socket, "socket", return_value=probe), self.assertRaises(offline.OfflineError):
                offline._busy_tor_ports()
            self.assertTrue(probe.closed)

    def test_busy_port_refuses_prepare_before_copy_signature_or_os_launch(self):
        with patch.object(offline, "_is_elevated", return_value=False), patch.object(offline, "_busy_tor_ports", return_value=[9151]), patch.object(offline, "_copy_asset") as copy, patch.object(offline, "_verify_tor_signature") as verify, patch.object(offline, "_install_and_launch") as launch, patch.object(offline.shutil, "rmtree") as cleanup, self.assertRaisesRegex(offline.OfflineError, "занято"):
            offline.prepare_tor()
        copy.assert_not_called()
        verify.assert_not_called()
        launch.assert_not_called()
        cleanup.assert_not_called()

    def test_windows_rechecks_before_preseed_and_interactive_installer(self):
        with patch.object(offline.platform, "system", return_value="Windows"), patch.object(offline, "_busy_tor_ports", return_value=[9150]), patch.object(offline, "_prepare_private_profile") as seed, patch.object(offline.subprocess, "Popen") as launch, self.assertRaisesRegex(offline.OfflineError, "Проверить Tor"):
            offline._install_and_launch(Path("official.exe"), Path("private-cache"))
        seed.assert_not_called()
        launch.assert_not_called()


class ArchiveSafety(unittest.TestCase):
    def archive(self, directory, entries):
        binary = directory / "tor.tar.xz"
        with tarfile.open(binary, "w:xz") as archive:
            for name, value, kind in entries:
                member = tarfile.TarInfo(name)
                if kind == "file":
                    member.size = len(value)
                    member.mode = 0o755
                    archive.addfile(member, io.BytesIO(value))
                else:
                    member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                    member.linkname = value
                    archive.addfile(member)
        return binary

    def test_safe_archive_without_links(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp).resolve()
            binary = self.archive(directory, [("tor-browser/start-tor-browser.desktop", b"#!/bin/sh\n", "file")])
            result = offline._extract_linux(binary, directory / "install")
            self.assertTrue(result.is_file())
            self.assertTrue(os.access(result, os.X_OK))

    def test_all_links_including_chained_internal_links_are_rejected_before_launch(self):
        entries = [("tor-browser/start-tor-browser.desktop", b"#!/bin/sh\n", "file"),
                   ("tor-browser/sub/a", "..", "symlink"),
                   ("tor-browser/b", "sub/a/..", "symlink")]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp).resolve()
            binary = self.archive(directory, entries)
            with patch.object(offline.platform, "system", return_value="Linux"), patch.object(offline.subprocess, "Popen") as launch, self.assertRaisesRegex(offline.OfflineError, "ссылку"):
                offline._install_and_launch(binary, directory / "install")
            launch.assert_not_called()

    def test_traversal_absolute_escape_symlinks_and_hardlinks_rejected(self):
        for entry in [("../outside", b"x", "file"), ("/outside", b"x", "file"), ("tor-browser/link", "../../outside", "symlink"),
                      ("tor-browser/link", "/outside", "symlink"), ("tor-browser/link", "other", "hardlink")]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp).resolve()
                binary = self.archive(directory, [entry])
                with self.assertRaises(offline.OfflineError):
                    offline._extract_linux(binary, directory / "install")

    def test_bounded_unpacked_bytes_and_member_count(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp).resolve()
            binary = self.archive(directory, [("tor-browser/start-tor-browser.desktop", b"12345", "file")])
            with patch.object(offline, "MAX_EXTRACT_BYTES", 4), self.assertRaises(offline.OfflineError):
                offline._extract_linux(binary, directory / "install")
            with patch.object(offline, "MAX_ARCHIVE_MEMBERS", 0), self.assertRaises(offline.OfflineError):
                offline._extract_linux(binary, directory / "install2")


class DataDiscovery(unittest.TestCase):
    def test_source_uses_only_sibling_data_folder(self):
        with patch.object(sys, "frozen", False, create=True):
            self.assertEqual(offline._data_roots(), [Path(offline.__file__).resolve().parent.parent / "OnionDesk-Data"])

    def test_frozen_macos_finds_kit_with_maximum_four_parent_hops(self):
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", "/kit/mac/OnionDesk.app/Contents/MacOS/OnionDesk"), patch.object(offline.platform, "system", return_value="Darwin"):
            roots = offline._data_roots()
        self.assertEqual(len(roots), 5)
        self.assertEqual(roots[-1], Path("/kit/OnionDesk-Data"))
        self.assertNotIn(Path("/OnionDesk-Data"), roots)

    def test_windows_installed_pointer_has_precedence_and_uses_hklm_64(self):
        key = Mock()
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
        registry = types.SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", KEY_READ=1, KEY_WOW64_64KEY=256,
                                         REG_SZ=1, OpenKey=Mock(return_value=key), QueryValueEx=Mock(return_value=("/installed/OnionDesk-Data", 1)))
        with patch.dict(sys.modules, {"winreg": registry}), patch.object(sys, "frozen", True, create=True), patch.object(offline.platform, "system", return_value="Windows"):
            roots = offline._data_roots()
        self.assertEqual(roots, [Path("/installed/OnionDesk-Data")])
        registry.OpenKey.assert_called_once_with("HKLM", r"Software\OnionDesk", 0, 257)

    def test_windows_registry_never_accepts_expandable_environment_pointer(self):
        key = Mock()
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
        registry = types.SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", KEY_READ=1, KEY_WOW64_64KEY=256,
                                         REG_SZ=1, OpenKey=Mock(return_value=key), QueryValueEx=Mock(return_value=("%USERPROFILE%/malicious", 2)))
        with patch.dict(sys.modules, {"winreg": registry}), self.assertRaises(offline.OfflineError):
            offline._windows_data_root()


class WindowsInstaller(unittest.TestCase):
    def setUp(self):
        guard = patch.object(offline, "_assert_tor_ports_free")
        guard.start()
        self.addCleanup(guard.stop)

    def test_nsis_destination_is_final_unquoted_private_path_without_shell(self):
        work = Path("/private cache/unique-oniondesk-folder")
        binary = work / "official-portable.exe"
        with patch.object(offline.platform, "system", return_value="Windows"), patch.object(offline.subprocess, "Popen") as popen, patch.object(offline, "_prepare_private_profile", return_value=work / "Tor Browser/Browser/TorBrowser/Data/Browser/profile.default"):
            message = offline._install_and_launch(binary, work)
        self.assertEqual(popen.call_args.args[0], '"/private cache/unique-oniondesk-folder/official-portable.exe" /D=/private cache/unique-oniondesk-folder/Tor Browser')
        self.assertEqual(popen.call_args.kwargs["executable"], str(binary))
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertIn("установщик", message)


class PrivateProfile(unittest.TestCase):
    def make_profile(self, work, system):
        (work / ".oniondesk-managed").write_text(catalog.RELEASE_ID)
        resources, profile, tor_data = offline._private_layout(work, system)
        extension = resources / "distribution/extensions" / (offline._NOSCRIPT_ID + ".xpi")
        extension.parent.mkdir(parents=True)
        with zipfile.ZipFile(extension, "w") as package:
            package.writestr("manifest.json", json.dumps({"version": "13.6.36.1984", "browser_specific_settings": {"gecko": {"id": offline._NOSCRIPT_ID}}}))
        if system in {"Linux", "Windows"}:
            profile.mkdir(parents=True)
            (profile.parent / "profiles.ini").write_text("[General]\nStartWithLastProfile=1\n[Profile0]\nName=default\nIsRelative=1\nPath=profile.default\nDefault=1\n")
            (profile / "vendor-stock-file").write_text("preserve me")
        return resources, profile, tor_data

    def test_only_three_vendor_connection_prefs_in_fresh_private_profile(self):
        for system in ("Darwin", "Linux", "Windows"):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as temp:
                work = Path(temp).resolve()
                resources, profile, tor_data = self.make_profile(work, system)
                result = offline._prepare_private_profile(work, system)
                self.assertEqual(result, profile)
                self.assertEqual((profile / "user.js").read_text(), offline._BRIDGE_PREFS)
                self.assertEqual((profile / "user.js").read_text().count("user_pref("), 3)
                self.assertNotIn("quickstart", (profile / "user.js").read_text())
                self.assertNotIn("network.proxy", (profile / "user.js").read_text())
                self.assertNotIn("fingerprint", (profile / "user.js").read_text())
                if system == "Darwin":
                    self.assertEqual(profile, work / "TorBrowser-Data/Browser/profile.default")
                    self.assertFalse(profile.is_relative_to(work / "Tor Browser.app"))
                else:
                    self.assertEqual((profile / "vendor-stock-file").read_text(), "preserve me")
                if os.name != "nt":
                    self.assertEqual((profile / "user.js").stat().st_mode & 0o777, 0o600)

    def test_never_overwrite_existing_user_js_or_follow_profile_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp).resolve()
            resources, profile, tor_data = self.make_profile(work, "Darwin")
            profile.mkdir(parents=True)
            (profile / "user.js").write_text("existing settings")
            with self.assertRaises(offline.OfflineError):
                offline._prepare_private_profile(work, "Darwin")
            self.assertEqual((profile / "user.js").read_text(), "existing settings")
            (profile / "user.js").unlink()
            profile.rmdir()
            outside = work / "outside-profile"
            outside.mkdir()
            profile.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(offline.OfflineError):
                offline._prepare_private_profile(work, "Darwin")
            self.assertFalse((outside / "user.js").exists())

    def test_stock_profile_escape_wrong_noscript_or_missing_marker_refuse_before_seed(self):
        for change in ("profile", "noscript", "marker"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                work = Path(temp).resolve()
                resources, profile, tor_data = self.make_profile(work, "Linux")
                if change == "profile":
                    (profile.parent / "profiles.ini").write_text("[Profile0]\nIsRelative=1\nPath=../../outside\nDefault=1\n")
                elif change == "noscript":
                    extension = resources / "distribution/extensions" / (offline._NOSCRIPT_ID + ".xpi")
                    with zipfile.ZipFile(extension, "w") as package:
                        package.writestr("manifest.json", '{"version":"1","browser_specific_settings":{"gecko":{"id":"wrong"}}}')
                else:
                    (work / ".oniondesk-managed").unlink()
                with self.assertRaises((offline.OfflineError, OSError)):
                    offline._prepare_private_profile(work, "Linux")
                self.assertFalse((profile / "user.js").exists())

    def test_runtime_pending_then_verified_without_network_or_private_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp).resolve()
            resources, profile, tor_data = self.make_profile(work, "Darwin")
            offline._prepare_private_profile(work, "Darwin")
            with patch("socket.socket", side_effect=AssertionError("No runtime network probe")), patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")):
                self.assertEqual(offline.check_private_tor_runtime(work, timeout=0, system="Darwin")["state"], "pending")
                (profile / "extensions.json").write_text(json.dumps({"addons": [{"id": offline._NOSCRIPT_ID, "active": True, "userDisabled": False, "appDisabled": False}]}))
                tor_data.mkdir(parents=True)
                (tor_data / "state").write_text("Tor state")
                (tor_data / "lock").write_bytes(b"")
                result = offline.check_private_tor_runtime(work, timeout=0, system="Darwin")
                self.assertEqual(result["state"], "verified")
                self.assertTrue(result["noscript_active"] and result["private_tor_data"])
                self.assertNotIn(str(work), json.dumps(result))

    def test_runtime_rejects_disabled_noscript_and_redirected_tor_data(self):
        for disabled in (False, True):
            with self.subTest(disabled=disabled), tempfile.TemporaryDirectory() as temp:
                work = Path(temp).resolve()
                resources, profile, tor_data = self.make_profile(work, "Darwin")
                offline._prepare_private_profile(work, "Darwin")
                (profile / "extensions.json").write_text(json.dumps({"addons": [{"id": offline._NOSCRIPT_ID, "active": not disabled, "userDisabled": disabled}]}))
                if not disabled:
                    outside = work / "outside-tor"
                    outside.mkdir()
                    tor_data.symlink_to(outside, target_is_directory=True)
                self.assertEqual(offline.check_private_tor_runtime(work, timeout=0, system="Darwin")["state"], "rejected")

    def test_windows_preseed_exists_before_portable_installer_can_autorun(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp).resolve()
            (work / ".oniondesk-managed").write_text(catalog.RELEASE_ID)
            expected = work / "Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/user.js"

            def start(*args, **kwargs):
                self.assertEqual(expected.read_text(), offline._BRIDGE_PREFS)
                return Mock()

            with patch.object(offline.platform, "system", return_value="Windows"), patch.object(offline.subprocess, "Popen", side_effect=start), patch.object(offline, "_assert_tor_ports_free"):
                message = offline._install_and_launch(work / "official.exe", work)
            self.assertIn("папка уже существует", message)
            self.assertIn("obfs4", message)

    def test_linux_launcher_receives_stock_profile_after_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp).resolve()
            resources, profile, tor_data = self.make_profile(work, "Linux")
            launcher = resources.parent / "start-tor-browser.desktop"
            with patch.object(offline.platform, "system", return_value="Linux"), patch.object(offline, "_extract_linux", return_value=launcher), patch.object(offline.subprocess, "Popen") as launch, patch.object(offline, "_assert_tor_ports_free"):
                message = offline._install_and_launch(work / "signed.tar.xz", work)
            self.assertEqual(launch.call_args.args[0], [str(launcher), "--detach", "--profile", str(profile)])
            self.assertEqual((profile / "user.js").read_text(), offline._BRIDGE_PREFS)
            self.assertIn("obfs4", message)


class MacSignature(unittest.TestCase):
    def setUp(self):
        guard = patch.object(offline, "_assert_tor_ports_free")
        guard.start()
        self.addCleanup(guard.stop)

    def test_codesign_runs_before_os_open_and_failure_prevents_open(self):
        for fail in (False, True):
            with self.subTest(codesign_fails=fail), tempfile.TemporaryDirectory() as temp:
                work = Path(temp).resolve()
                commands = []

                def run(args, **kwargs):
                    commands.append(args)
                    if args[:2] == ["/usr/bin/hdiutil", "attach"]:
                        (work / "mounted/Tor Browser.app").mkdir()
                    elif args[0] == "/usr/bin/ditto":
                        (work / "Tor Browser.app").mkdir()
                    elif args[0] == "/usr/bin/codesign" and fail:
                        raise subprocess.CalledProcessError(1, args)
                    return subprocess.CompletedProcess(args, 0, b"", b"")

                with patch.object(offline.platform, "system", return_value="Darwin"), patch.object(offline.subprocess, "run", side_effect=run), patch.object(offline, "_prepare_private_profile", return_value=work / "private-profile"):
                    if fail:
                        with self.assertRaises(subprocess.CalledProcessError):
                            offline._install_and_launch(work / "signed.dmg", work)
                    else:
                        offline._install_and_launch(work / "signed.dmg", work)
                sign = next(i for i, args in enumerate(commands) if args[0] == "/usr/bin/codesign")
                self.assertEqual(commands[sign][1:5], ["--verify", "--deep", "--strict", str(work / "Tor Browser.app")])
                opens = [i for i, args in enumerate(commands) if args[0] == "/usr/bin/open"]
                detach = next(i for i, args in enumerate(commands) if args[:2] == ["/usr/bin/hdiutil", "detach"])
                self.assertGreater(detach, sign)
                self.assertEqual(opens, [] if fail else [detach + 1])

    def test_busy_detach_retries_exact_private_mount_and_never_opens_after_failure(self):
        for fails_twice in (False, True):
            with self.subTest(detach_fails_twice=fails_twice), tempfile.TemporaryDirectory() as temp:
                work = Path(temp).resolve()
                commands = []
                detaches = []

                def run(args, **kwargs):
                    commands.append(args)
                    if args[:2] == ["/usr/bin/hdiutil", "attach"]:
                        (work / "mounted/Tor Browser.app").mkdir()
                    elif args[0] == "/usr/bin/ditto":
                        (work / "Tor Browser.app").mkdir()
                    elif args[:2] == ["/usr/bin/hdiutil", "detach"]:
                        detaches.append(args)
                        self.assertEqual(kwargs["timeout"], 60)
                        return subprocess.CompletedProcess(args, 1 if len(detaches) == 1 or fails_twice else 0, b"", b"")
                    return subprocess.CompletedProcess(args, 0, b"", b"")

                with patch.object(offline.platform, "system", return_value="Darwin"), patch.object(offline.subprocess, "run", side_effect=run), patch.object(offline, "_prepare_private_profile", return_value=work / "private-profile"):
                    if fails_twice:
                        with self.assertRaisesRegex(offline.OfflineError, "Браузер не открыт"):
                            offline._install_and_launch(work / "signed.dmg", work)
                    else:
                        offline._install_and_launch(work / "signed.dmg", work)
                self.assertEqual(detaches, [["/usr/bin/hdiutil", "detach", str(work / "mounted")],
                                            ["/usr/bin/hdiutil", "detach", "-force", str(work / "mounted")]])
                opens = [args for args in commands if args[0] == "/usr/bin/open"]
                self.assertEqual(len(opens), 0 if fails_twice else 1)


if __name__ == "__main__":
    unittest.main()
