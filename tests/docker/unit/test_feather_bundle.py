"""Offline, valueless Feather fixtures; no real wallet, process or network."""
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

if os.name == "posix":
    import fcntl

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import feather_bundle as bundle
import feather_catalog as catalog
import wallet_controller
from wallet_engine import WalletError


def signature(fingerprint=catalog.PUBLISHER_FINGERPRINT, digest="10"):
    return (f"[GNUPG:] GOODSIG 1F76E155CEFBA71C Fixture\n[GNUPG:] VALIDSIG {fingerprint} "
            f"2026-10-16 1792108800 0 4 0 1 {digest} 00 {fingerprint}\n")


class OpenedVaultFixture:
    def __init__(self, root):
        self.root = root
        self.active_id = None
        self.detach_attempts = 0
        self.busy = False

    def create(self, password):
        self.active_id = "vault_" + "a" * 32
        return self.root

    def unlock(self, identifier, password):
        self.active_id = identifier
        return self.root

    def close(self):
        if self.active_id is not None:
            self.detach_attempts += 1
            if self.busy:
                raise WalletError("Synthetic native detach busy; no force")
            self.active_id = None

    def list_vaults(self):
        return []


@unittest.skipUnless(os.name == "posix", "POSIX fixture permissions")
class FeatherBundle(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.source, self.vault = self.folder / "data", self.folder / "vault"
        (self.source / "Feather").mkdir(parents=True)
        self.vault.mkdir(mode=0o700)
        payload = bytearray(128)
        payload[:6] = b"\x7fELF\x02\x01"
        payload[18:20] = (62).to_bytes(2, "little")
        self.payload = bytes(payload)
        self.archive = self.source / "Feather/release.zip"
        self.zip()
        self.record = {**self.asset("Feather/release.zip"), "binary": "feather-fixture",
                       "members": {"feather-fixture": {"size_bytes": len(payload),
                           "sha256": hashlib.sha256(payload).hexdigest(), "executable": True}}}
        for name in ("signature.asc", "key.asc", "hashes.txt"):
            (self.source / "Feather" / name).write_text("fixture " + name)
        self.record["signature"] = self.asset("Feather/signature.asc")
        for name, value in (("KEY", self.asset("Feather/key.asc")),
                            ("HASHES", self.asset("Feather/hashes.txt")),
                            ("PLATFORMS", {"linux-x64": self.record})):
            self.stack.enter_context(patch.object(catalog, name, value))
        self.stack.enter_context(patch.object(bundle, "_platform_key", return_value="linux-x64"))
        self.stack.enter_context(patch.object(bundle.offline, "_find_root", return_value=self.source))
        self.session = bundle.FeatherSession()

    def asset(self, relative):
        path = self.source / relative
        return {"path": relative, "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def zip(self, *, link=False, duplicate=False, extra=False):
        with zipfile.ZipFile(self.archive, "w") as archive:
            item = zipfile.ZipInfo("feather-fixture")
            item.external_attr = (0o120777 if link else 0o100755) << 16
            archive.writestr(item, self.payload)
            if duplicate:
                archive.writestr(item, self.payload)
            if extra:
                archive.writestr("../../foreign", b"no")

    def prepare(self):
        with patch.object(bundle, "_verify_publisher") as verify:
            self.session.prepare(self.vault)
            self.assertEqual(verify.call_count, 1)

    def process(self):
        process = Mock()
        process.pid = 12345
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("fixture", 1)
        return process

    def launch_with_lock(self, *, payload=None, held=True):
        """The fixture holds a real Qt-compatible flock; no process is started."""
        self.prepare()
        process = self.process()
        holder = []

        def spawn(*args, **kwargs):
            lock = Path(kwargs["env"]["TMPDIR"]) / bundle._LOCK_NAME
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.addCleanup(os.close, fd)
            if held:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raw = payload if payload is not None else b"12345\nfixture-feather\nfixture-host\nfixture-machine\nfixture-boot\n"
            os.write(fd, raw)
            holder.append(fd)
            return process

        with patch.object(bundle.subprocess, "Popen", side_effect=spawn):
            self.session.launch(self.vault)
        self.addCleanup(self.session._release_lock_watch)
        return process, self.session._folder / "tmp" / bundle._LOCK_NAME, holder[0]

    def exited_owned_lock(self):
        process, lock, holder = self.launch_with_lock()
        fcntl.flock(holder, fcntl.LOCK_UN)
        process.poll.return_value = 0
        return process, lock, holder

    def test_exit_zero_removes_only_observed_own_lock_and_closes_descriptors(self):
        process, lock, _ = self.exited_owned_lock()
        sentinel = lock.parent / "sentinel"
        sentinel.write_bytes(b"preserve")
        watch = self.session._lock_watch
        descriptors = (watch.directory_fd, watch.file_fd)
        self.session.stop()
        self.session.stop()  # Idempotent, with no witness left to reuse.
        self.assertFalse(lock.exists())
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.assertIsNone(self.session._process)
        self.assertIsNone(self.session._launch_nonce)
        self.assertIsNone(self.session._lock_watch)
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_live_owned_lock_is_preserved_until_original_child_exits(self):
        process, lock, holder = self.launch_with_lock()
        original = lock.read_bytes()
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertEqual(lock.read_bytes(), original)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        fcntl.flock(holder, fcntl.LOCK_UN)
        process.poll.return_value = 0
        self.session.close()
        self.assertFalse(lock.exists())

    def test_controller_stop_ack_then_close_after_owned_normal_exit(self):
        _, lock, _ = self.exited_owned_lock()
        vault = OpenedVaultFixture(self.vault)
        vault.create("synthetic fixture password")
        controller = wallet_controller.WalletController(vault_manager=vault)
        controller._workspace_root = self.vault
        controller._engine = SimpleNamespace(root=self.vault)
        controller._feather = self.session
        controller.stop_feather()
        self.assertFalse(lock.exists())
        self.assertEqual(vault.detach_attempts, 0)
        self.assertIsNotNone(vault.active_id)
        controller.close()
        self.assertEqual(vault.detach_attempts, 1)
        self.assertIsNone(vault.active_id)

    def test_nonzero_exit_never_removes_even_attested_own_lock(self):
        process, lock, _ = self.exited_owned_lock()
        process.poll.return_value = -9
        before = lock.read_bytes()
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertEqual(lock.read_bytes(), before)
        self.assertIs(self.session._process, process)

    def test_lock_without_live_launch_attestation_cannot_be_adopted_after_exit(self):
        self.prepare()
        process = self.process()
        with patch.object(bundle.subprocess, "Popen", return_value=process):
            self.session.launch(self.vault)
        self.addCleanup(self.session._release_lock_watch)
        process.poll.return_value = 0
        lock = self.session._folder / "tmp" / bundle._LOCK_NAME
        lock.write_bytes(b"12345\nfixture-feather\nfixture-host\nfixture-machine\nfixture-boot\n")
        lock.chmod(0o600)
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertTrue(lock.exists())
        self.assertIsNone(self.session._lock_watch.file_fd)

    def test_wrong_pid_or_missing_native_lock_cannot_arm_ownership(self):
        for payload, held in ((b"99999\nforeign\nhost\nmachine\nboot\n", True), (None, False)):
            with self.subTest(payload=payload, held=held):
                with self.assertRaises(WalletError):
                    self.launch_with_lock(payload=payload, held=held)
                lock = self.session._folder / "tmp" / bundle._LOCK_NAME
                before = lock.read_bytes()
                self.session._process.poll.return_value = 0
                with self.assertRaises(WalletError):
                    self.session.stop()
                self.assertEqual(lock.read_bytes(), before)
                self.assertIsNone(self.session._lock_watch)
                lock.unlink()  # Fixture owner only, between the two subcases.
                self.session.stop()

    def test_replaced_process_object_or_nonce_cannot_remove_owned_lock(self):
        process, lock, _ = self.exited_owned_lock()
        before = lock.read_bytes()
        replacement = self.process()
        replacement.poll.return_value = 0
        self.session._process = replacement
        with self.assertRaises(WalletError):
            self.session.stop()
        self.session._process = process
        self.session._launch_nonce = "changed-nonce"
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertEqual(lock.read_bytes(), before)

    def test_changed_pid_blob_or_inode_is_preserved(self):
        for change in ("pid", "content", "inode"):
            with self.subTest(change=change):
                _, lock, _ = self.exited_owned_lock()
                original = lock.read_bytes()
                if change == "inode":
                    lock.unlink()
                    lock.write_bytes(original)
                    lock.chmod(0o600)
                else:
                    lock.write_bytes(original.replace(b"12345", b"54321") if change == "pid"
                                     else original.replace(b"fixture-host", b"changed-host"))
                changed = lock.read_bytes(), lock.stat().st_ino
                with self.assertRaises(WalletError):
                    self.session.stop()
                self.assertEqual((lock.read_bytes(), lock.stat().st_ino), changed)
                lock.unlink()
                self.session.stop()

    def test_link_replacements_and_redirected_parent_preserve_foreign_files(self):
        for kind in ("symlink", "hardlink", "parent"):
            with self.subTest(kind=kind):
                _, lock, _ = self.exited_owned_lock()
                other = self.folder / ("foreign-" + kind)
                other.write_bytes(b"foreign sentinel")
                other.chmod(0o600)
                original_directory = None
                if kind == "parent":
                    original_directory = lock.parent.with_name("original-tmp")
                    lock.parent.rename(original_directory)
                    lock.parent.symlink_to(self.folder, target_is_directory=True)
                else:
                    lock.unlink()
                    if kind == "symlink":
                        lock.symlink_to(other)
                    else:
                        os.link(other, lock)
                with self.assertRaises(WalletError):
                    self.session.stop()
                self.assertEqual(other.read_bytes(), b"foreign sentinel")
                if original_directory is not None:
                    lock.parent.unlink()
                    original_directory.rename(lock.parent)
                else:
                    lock.unlink()
                self.session.stop()

    def test_still_held_qt_flock_blocks_cleanup_then_allows_safe_retry(self):
        process, lock, holder = self.launch_with_lock()
        process.poll.return_value = 0
        before = lock.read_bytes()
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertEqual(lock.read_bytes(), before)
        fcntl.flock(holder, fcntl.LOCK_UN)
        self.session.stop()
        self.assertFalse(lock.exists())

    def test_read_error_preserves_lock_and_evidence_for_retry(self):
        _, lock, _ = self.exited_owned_lock()
        before = lock.read_bytes()
        with patch.object(bundle.os, "read", side_effect=OSError(errno.EIO, "fixture read error")):
            with self.assertRaises(WalletError):
                self.session.stop()
        self.assertEqual(lock.read_bytes(), before)
        self.session.stop()
        self.assertFalse(lock.exists())

    def test_pending_lock_is_captured_on_later_live_poll_only(self):
        self.prepare()
        process = self.process()
        with patch.object(bundle.subprocess, "Popen", return_value=process):
            self.session.launch(self.vault)
        self.addCleanup(self.session._release_lock_watch)
        self.assertIsNone(self.session._lock_watch.file_fd)
        lock = self.session._folder / "tmp" / bundle._LOCK_NAME
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, b"12345\nfixture-feather\nfixture-host\nfixture-machine\nfixture-boot\n")
        self.assertTrue(self.session.state()["running"])
        self.assertIsNotNone(self.session._lock_watch.file_fd)
        fcntl.flock(fd, fcntl.LOCK_UN)
        process.poll.return_value = 0
        self.session.stop()
        self.assertFalse(lock.exists())

    def test_capture_read_error_closes_fds_and_cannot_rearm(self):
        with patch.object(bundle.os, "read", side_effect=OSError(errno.EIO, "fixture read error")):
            with self.assertRaises(WalletError):
                self.launch_with_lock()
        process = self.session._process
        lock = self.session._folder / "tmp" / bundle._LOCK_NAME
        self.assertIsNone(self.session._lock_watch)
        self.assertTrue(self.session._lock_capture_failed)
        self.assertEqual(self.session.state()["message"], bundle._LOCK_MESSAGE)
        process.poll.return_value = 0
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertTrue(lock.exists())

    def test_unsafe_mode_and_excessive_payload_never_allow_cleanup(self):
        for change in ("mode", "size"):
            with self.subTest(change=change):
                _, lock, _ = self.exited_owned_lock()
                if change == "mode":
                    lock.chmod(0o640)
                else:
                    lock.write_bytes(b"x" * (bundle._LOCK_LIMIT + 1))
                before = lock.read_bytes(), lock.stat().st_mode
                with self.assertRaises(WalletError):
                    self.session.stop()
                self.assertEqual((lock.read_bytes(), lock.stat().st_mode), before)
                lock.unlink()
                self.session.stop()

    def test_new_prepare_cannot_discard_nonzero_exit_evidence(self):
        process, lock, _ = self.exited_owned_lock()
        process.poll.return_value = 7
        watch = self.session._lock_watch
        with patch.object(bundle, "_verify_publisher") as verify:
            with self.assertRaises(WalletError):
                self.session.prepare(self.vault)
        verify.assert_not_called()
        self.assertIs(self.session._lock_watch, watch)
        self.assertTrue(lock.exists())

    def test_normal_qt_unlink_releases_witness_without_second_deletion(self):
        _, lock, _ = self.exited_owned_lock()
        lock.unlink()  # Model Qt's ordinary successful unlock.
        with patch.object(bundle.os, "unlink") as unlink:
            self.session.stop()
        unlink.assert_not_called()
        self.assertIsNone(self.session._lock_watch)

    def test_unsupported_platform_retains_conservative_lock_refusal(self):
        with patch.object(bundle, "_lock_cleanup_supported", return_value=False):
            process, lock, holder = self.launch_with_lock()
        self.assertIsNone(self.session._lock_watch)
        process.poll.return_value = 0
        fcntl.flock(holder, fcntl.LOCK_UN)
        before = lock.read_bytes()
        with self.assertRaises(WalletError):
            self.session.stop()
        self.assertEqual(lock.read_bytes(), before)

    def test_prepare_checks_signature_and_cached_binary_without_launch(self):
        with patch.object(bundle.subprocess, "Popen") as popen:
            self.prepare()
            popen.assert_not_called()
        self.assertTrue(self.session.state()["prepared"])
        binary = self.session._folder / self.record["binary"]
        self.assertEqual(binary.read_bytes(), self.payload)
        binary.write_bytes(b"changed")
        with self.assertRaises(WalletError), patch.object(bundle.subprocess, "Popen") as popen:
            self.session.launch(self.vault)
        popen.assert_not_called()

    def test_bad_hash_signature_or_source_symlink_never_extracts(self):
        self.archive.write_bytes(b"changed")
        with patch.object(bundle, "_extract") as extract, self.assertRaises(WalletError):
            self.session.prepare(self.vault)
        extract.assert_not_called()
        self.zip()
        with patch.object(bundle, "_verify_publisher", side_effect=bundle.FeatherError("bad sig")), \
                patch.object(bundle, "_extract") as extract, self.assertRaises(WalletError):
            self.session.prepare(self.vault)
        extract.assert_not_called()
        moved = self.folder / "original.zip"
        self.archive.rename(moved)
        self.archive.symlink_to(moved)
        with self.assertRaises(WalletError):
            self.session.prepare(self.vault)

    def test_archive_links_duplicate_or_extra_paths_refused(self):
        for mode in ("link", "duplicate", "extra"):
            with self.subTest(mode=mode):
                self.zip(**{mode: True})
                with self.assertRaises(WalletError):
                    bundle._extract(self.archive, self.record, self.folder / mode)
        self.assertFalse((self.folder.parent / "foreign").exists())

    def test_wrong_architecture_and_redirected_profile_block_launch(self):
        self.prepare()
        record = dict(self.record)
        with self.assertRaises(WalletError):
            bundle._verify_install(self.session._folder, record, "linux-arm64")
        (self.session._folder / "feather_data").symlink_to(self.folder, target_is_directory=True)
        with patch.object(bundle.subprocess, "Popen") as popen, self.assertRaises(WalletError):
            self.session.launch(self.vault)
        popen.assert_not_called()

    def test_launch_forces_portable_offline_profile_and_no_secret_arguments(self):
        self.prepare()
        folder = self.session._folder
        data = folder / "feather_data"
        data.mkdir(mode=0o700)
        settings = data / "settings.json"
        settings.write_text(json.dumps({"offlineMode": False, "proxy": 0,
                                       "autoOpenWalletPath": "/foreign/private-wallet",
                                       "walletDirectory": "/foreign/wallets"}))
        settings.chmod(0o600)
        with patch.object(bundle.subprocess, "Popen", return_value=self.process()) as popen, \
                patch.dict(os.environ, {"HTTPS_PROXY": "foreign", "LD_PRELOAD": "foreign", "APPIMAGE": "foreign"}):
            self.session.launch(self.vault)
        command, options = popen.call_args.args[0], popen.call_args.kwargs
        self.assertEqual(command[1:], ["--quiet", "--use-local-tor"])
        self.assertFalse(any("password" in value or "seed" in value for value in command))
        self.assertEqual(options["cwd"], folder)
        self.assertEqual(options["env"]["HOME"], str(folder / "home"))
        self.assertEqual(options["env"]["TMPDIR"], str(folder / "tmp"))
        self.assertFalse({"HTTPS_PROXY", "LD_PRELOAD", "APPIMAGE"} & set(options["env"]))
        self.assertTrue((folder / ".portable").is_file())
        profile = json.loads(settings.read_text())
        self.assertTrue(profile["offlineMode"])
        self.assertFalse(profile["firstRun"])
        self.assertEqual(profile["proxy"], 1)
        self.assertEqual(profile["torPrivacyLevel"], 2)
        self.assertTrue(profile["torOnlyAllowOnion"])
        self.assertTrue(profile["useLocalTor"])
        self.assertEqual(profile["enabledPlugins"], [])
        self.assertEqual(profile["autoOpenWalletPath"], "")
        self.assertEqual(profile["walletDirectory"], str(data / "wallets"))

    def test_connect_requires_verified_tor_and_never_falls_back(self):
        self.prepare()
        fake_launcher = SimpleNamespace(find_tor_proxy=Mock(side_effect=RuntimeError("Tor unavailable")))
        with patch.dict(sys.modules, {"launcher": fake_launcher}), \
                patch.object(bundle.subprocess, "Popen") as popen, self.assertRaises(RuntimeError):
            self.session.connect(self.vault)
        popen.assert_not_called()
        fake_launcher.find_tor_proxy.side_effect = None
        fake_launcher.find_tor_proxy.return_value = 9050
        with patch.dict(sys.modules, {"launcher": fake_launcher}), \
                patch.object(bundle.subprocess, "Popen", return_value=self.process()):
            self.session.connect(self.vault)
        profile = json.loads((self.session._folder / "feather_data/settings.json").read_text())
        self.assertFalse(profile["offlineMode"])
        self.assertEqual(profile["socks5Port"], "9050")
        self.assertTrue(profile["torOnlyAllowOnion"])
        self.assertEqual(self.session.state()["network_mode"], "tor")

    def test_owned_or_foreign_running_process_never_killed_or_vault_detached(self):
        process = self.process()
        self.session._process = process
        with self.assertRaises(WalletError):
            self.session.close()
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        vault = SimpleNamespace(close=Mock())
        controller = wallet_controller.WalletController(vault_manager=vault)
        controller._feather = self.session
        with self.assertRaises(WalletError):
            controller.close()
        vault.close.assert_not_called()

    def test_closed_or_unattested_workspace_blocks_every_prepare_launch_connect(self):
        vault = SimpleNamespace(active_id=None)
        controller = wallet_controller.WalletController(vault_manager=vault)
        with patch.object(bundle, "FeatherSession") as session:
            for action in (controller.prepare_feather, controller.launch_feather, controller.connect_feather):
                with self.assertRaises(WalletError):
                    action()
            session.assert_not_called()
            vault.active_id = "vault_" + "a" * 32
            controller._engine = SimpleNamespace(_require_encrypted_storage=Mock(side_effect=WalletError("closed")))
            with self.assertRaises(WalletError):
                controller.prepare_feather()
            session.assert_not_called()

    def test_foreign_singleton_lock_is_preserved_and_blocks_launch_and_close(self):
        self.prepare()
        temporary = self.session._folder / "tmp"
        temporary.mkdir(mode=0o700)
        lock = temporary / "feather-oniondesk.lock"
        lock.write_text("foreign synthetic process")
        lock.chmod(0o600)
        with patch.object(bundle.subprocess, "Popen") as popen:
            with self.assertRaises(WalletError):
                self.session.launch(self.vault)
            with self.assertRaises(WalletError):
                self.session.close()
        popen.assert_not_called()
        self.assertEqual(lock.read_text(), "foreign synthetic process")

    def test_fresh_controller_cached_lock_blocks_close_switch_and_stop_ack(self):
        temporary = self.vault / "feather/older-cached-version/tmp"
        temporary.mkdir(parents=True, mode=0o700)
        for parent in (temporary.parent, temporary.parent.parent):
            parent.chmod(0o700)
        lock = temporary / "feather-oniondesk.lock"
        lock.write_text("foreign synthetic process; preserve")
        lock.chmod(0o600)
        sentinel = self.vault / "wallet-sentinel"
        sentinel.write_bytes(b"synthetic wallet data; preserve")
        before = {str(path.relative_to(self.vault)): path.read_bytes()
                  for path in self.vault.rglob("*") if path.is_file()}
        for action in ("close", "create", "unlock", "stop_feather"):
            with self.subTest(action=action):
                vault = Mock()
                vault.active_id = "vault_" + "a" * 32
                controller = wallet_controller.WalletController(vault_manager=vault)
                controller._engine = SimpleNamespace(root=self.vault)
                self.assertIsNone(controller._feather)
                with self.assertRaises(WalletError):
                    if action == "create":
                        controller.create("synthetic fixture password")
                    elif action == "unlock":
                        controller.unlock(vault.active_id, "synthetic fixture password")
                    else:
                        getattr(controller, action)()
                vault.close.assert_not_called()
                vault.create.assert_not_called()
                vault.unlock.assert_not_called()
        after = {str(path.relative_to(self.vault)): path.read_bytes()
                 for path in self.vault.rglob("*") if path.is_file()}
        self.assertEqual(after, before)
        lock.unlink()
        bundle.assert_workspace_idle(self.vault)  # No writes or cleanup required.

    def test_cached_lock_guard_rejects_redirected_directories_without_following(self):
        base = self.vault / "feather"
        base.mkdir(mode=0o700)
        (base / "old-cache").symlink_to(self.folder / "missing", target_is_directory=True)
        with self.assertRaises(WalletError):
            bundle.assert_workspace_idle(self.vault)
        self.assertTrue((base / "old-cache").is_symlink())

    def test_factory_failure_retains_returned_root_and_blocks_cleanup_with_cached_lock(self):
        temporary = self.vault / "feather/cached-version/tmp"
        temporary.mkdir(parents=True, mode=0o700)
        for parent in (temporary.parent, temporary.parent.parent):
            parent.chmod(0o700)
        lock = temporary / "feather-oniondesk.lock"
        lock.write_bytes(b"foreign synthetic lock; preserve")
        lock.chmod(0o600)
        sentinel = self.vault / "wallet-sentinel"
        sentinel.write_bytes(b"synthetic wallet; preserve")
        before = lock.read_bytes(), sentinel.read_bytes()
        for action in ("create", "unlock"):
            with self.subTest(action=action):
                vault = OpenedVaultFixture(self.vault)
                factory = Mock(side_effect=WalletError("Synthetic factory failed before engine assignment"))
                controller = wallet_controller.WalletController(vault_manager=vault, _engine_factory=factory)
                with self.assertRaises(WalletError):
                    if action == "create":
                        controller.create("synthetic fixture password")
                    else:
                        controller.unlock("vault_" + "a" * 32, "synthetic fixture password")
                factory.assert_called_once()
                self.assertIsNone(controller._engine)
                self.assertIsNone(controller._feather)
                self.assertEqual(controller._workspace_root, self.vault)
                self.assertIsNotNone(vault.active_id)
                self.assertEqual(vault.detach_attempts, 0)
                with self.assertRaises(WalletError):
                    controller.stop_feather()
                with self.assertRaises(WalletError):
                    controller.close()
                self.assertEqual(vault.detach_attempts, 0)
                self.assertEqual((lock.read_bytes(), sentinel.read_bytes()), before)

    def test_failed_native_cleanup_retains_root_for_later_stop_guard_and_retry(self):
        vault = OpenedVaultFixture(self.vault)
        vault.busy = True
        factory = Mock(side_effect=WalletError("Synthetic factory failed before engine assignment"))
        controller = wallet_controller.WalletController(vault_manager=vault, _engine_factory=factory)
        with self.assertRaises(WalletError):
            controller.unlock("vault_" + "a" * 32, "synthetic fixture password")
        self.assertEqual(vault.detach_attempts, 1)
        self.assertEqual(controller._workspace_root, self.vault)
        self.assertIsNone(controller._engine)
        self.assertTrue(controller.state()["workspace_open"])
        temporary = self.vault / "feather/cached-version/tmp"
        temporary.mkdir(parents=True, mode=0o700)
        for parent in (temporary.parent, temporary.parent.parent):
            parent.chmod(0o700)
        lock = temporary / "feather-oniondesk.lock"
        lock.write_bytes(b"foreign lock created while cleanup is busy")
        lock.chmod(0o600)
        with self.assertRaises(WalletError):
            controller.stop_feather()
        self.assertEqual(vault.detach_attempts, 1)
        self.assertEqual(lock.read_bytes(), b"foreign lock created while cleanup is busy")
        self.assertEqual(controller._workspace_root, self.vault)
        lock.unlink()  # Fixture owner ends its synthetic foreign session.
        vault.busy = False
        controller.close()
        self.assertIsNone(controller._workspace_root)
        self.assertIsNone(vault.active_id)

    def test_pinned_signer_strong_digest_and_failure_tags(self):
        self.assertTrue(bundle._valid_signature(signature()))
        self.assertFalse(bundle._valid_signature(signature("A" * 40)))
        self.assertFalse(bundle._valid_signature(signature(digest="2")))
        self.assertFalse(bundle._valid_signature(signature() * 2))
        for tag in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"):
            self.assertFalse(bundle._valid_signature(signature() + f"[GNUPG:] {tag}\n"))

    def test_wrong_primary_key_never_imported_or_verified(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"pub:::::::::\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n")
        with patch.object(bundle.usb, "_find_gpg", return_value="fixture-gpg"), \
                patch.object(bundle.subprocess, "run", return_value=result) as run, self.assertRaises(WalletError):
            bundle._verify_publisher(self.archive, self.archive, self.archive, self.archive, self.record)
        self.assertEqual(run.call_count, 1)
        self.assertIn("show-only", run.call_args.args[0])
        self.assertIn("--no-auto-key-retrieve", run.call_args.args[0])
        self.assertNotIn("LD_PRELOAD", run.call_args.kwargs["env"])

    def test_readonly_status_never_verifies_writes_or_runs_a_process(self):
        with patch.object(bundle.subprocess, "run") as run, patch.object(Path, "mkdir") as mkdir:
            self.assertTrue(bundle.status()["available"])
            run.assert_not_called()
            mkdir.assert_not_called()
        (self.source / "Feather/signature.asc").unlink()
        self.assertFalse(bundle.status()["available"])


class PlatformMetadata(unittest.TestCase):
    def test_only_exact_bundled_architectures_are_selected(self):
        for system, machine, expected in (("Darwin", "arm64", "macos-arm64"),
                ("Windows", "AMD64", "windows-x64"), ("Linux", "x86_64", "linux-x64"),
                ("Linux", "aarch64", "linux-arm64"), ("Windows", "arm64", None),
                ("Darwin", "x86_64", None), ("Linux", "armv7l", None)):
            with self.subTest(system=system, machine=machine), \
                    patch.object(bundle.platform, "system", return_value=system), \
                    patch.object(bundle.platform, "machine", return_value=machine):
                if expected:
                    self.assertEqual(bundle._platform_key(), expected)
                else:
                    with self.assertRaises(WalletError):
                        bundle._platform_key()


if __name__ == "__main__":
    unittest.main()
