"""Offline wallet boundary tests. No real keys, daemon or payment RPC calls."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import wallet_engine as wallet


@unittest.skipUnless(os.name == "posix", "Windows is intentionally unsupported pending private ACL support")
class WalletBoundaries(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.binary = self.folder / "official-rpc"
        self.binary.write_bytes(b"verified fixture; never executed")
        self.binary.chmod(0o700)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.engine = wallet.OfflineWalletEngine(self.binary, self.digest,
                                                network=wallet.Network.STAGENET,
                                                wallet_root=self.folder / "wallets")
        self.password = "this is a test password"
        self.address = "5" + "A" * 94
        self.seed = " ".join(["fixture"] * 25)

    def fake_rpc(self):
        rpc = Mock()
        def call(method, params):
            if method == "create_wallet":
                self.assertEqual(params["password"], self.password)
                self.assertRegex(params["filename"], r"^wallet_[0-9a-f]{32}$")
                for path in self.engine._files(params["filename"]):
                    path.write_bytes(b"encrypted fixture")
                    path.chmod(0o600)
                return {}
            if method == "get_address":
                return {"address": self.address}
            if method == "query_key":
                self.assertEqual(params, {"key_type": "mnemonic"})
                return {"key": self.seed}
            return {}
        rpc.call.side_effect = call
        process = Mock()
        process.__enter__ = Mock(return_value=rpc)
        process.__exit__ = Mock(return_value=False)
        self.stack.enter_context(patch.object(wallet, "_RpcProcess", return_value=process))
        return rpc

    def test_creates_private_wallet_and_explicit_backup_state_without_secret_metadata(self):
        self.fake_rpc()
        pending = self.engine.create_wallet(self.password)
        self.assertNotIn(self.seed, repr(pending))
        self.assertFalse(pending.wallet.backup_confirmed)
        metadata = self.engine._metadata_path(pending.wallet.wallet_id)
        text = metadata.read_text()
        self.assertNotIn(self.password, text)
        self.assertNotIn(self.seed, text)
        self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.engine.directory.stat().st_mode & 0o777, 0o700)
        confirmed = self.engine.confirm_backup(pending.wallet.wallet_id)
        self.assertTrue(confirmed.backup_confirmed)
        self.assertEqual(self.engine.list_wallets(), [confirmed])
        self.assertEqual(self.engine.open_wallet(confirmed.wallet_id, self.password), confirmed)
        revealed = self.engine.reveal_seed(confirmed.wallet_id, self.password)
        self.assertEqual(revealed.mnemonic, self.seed)
        self.assertNotIn(self.seed, repr(revealed))
        pending.clear_secret()
        self.assertEqual(pending.mnemonic, "")

    def test_secret_reveal_requires_password_and_checks_address(self):
        self.fake_rpc()
        record = self.engine.create_wallet(self.password).wallet
        with self.assertRaises(wallet.WalletError):
            self.engine.reveal_seed(record.wallet_id, "")
        self.address = "5" + "B" * 94
        with self.assertRaises(wallet.WalletError):
            self.engine.reveal_seed(record.wallet_id, self.password)

    def test_rejects_password_and_path_before_rpc(self):
        with patch.object(wallet, "_RpcProcess") as rpc:
            for password in ("", "short", "a" * 1025, "long password\0"):
                with self.assertRaises(wallet.WalletError):
                    self.engine.create_wallet(password)
            for identifier in ("../a", "/tmp/wallet", "wallet_" + "a" * 31, "wallet_" + "а" * 32):
                with self.assertRaises(wallet.WalletError):
                    self.engine.open_wallet(identifier, self.password)
            rpc.assert_not_called()

    def test_network_and_address_are_checked(self):
        with self.assertRaises(wallet.WalletError):
            wallet.OfflineWalletEngine(self.binary, self.digest, network="testnet", wallet_root=self.folder / "other")
        self.fake_rpc()
        self.address = "4" + "A" * 94
        with self.assertRaises(wallet.WalletError):
            self.engine.create_wallet(self.password)
        self.assertEqual(list(self.engine.directory.glob("*.metadata.json")), [])
        self.assertEqual(wallet._validate_address("4" + "A" * 94, wallet.Network.MAINNET), "4" + "A" * 94)

    def test_unknown_mnemonic_format_is_rejected(self):
        self.fake_rpc()
        self.seed = "fixture " * 16
        with self.assertRaises(wallet.WalletError):
            self.engine.create_wallet(self.password)

    def test_tampered_or_symlink_binary_never_executes(self):
        self.binary.write_bytes(b"tampered")
        with patch.object(wallet.subprocess, "Popen") as run:
            with self.assertRaises(wallet.WalletError):
                with wallet._RpcProcess(self.engine):
                    pass
            run.assert_not_called()
        target = self.folder / "target"
        target.write_bytes(b"anything")
        self.binary.unlink()
        self.binary.symlink_to(target)
        with self.assertRaises(wallet.WalletError):
            self.engine._verify_binary()

    def test_insecure_or_symlink_root_is_rejected(self):
        insecure = self.folder / "public"
        insecure.mkdir(mode=0o755)
        alias = self.folder / "alias"
        alias.symlink_to(self.engine.root, target_is_directory=True)
        for root in (insecure, alias):
            with self.assertRaises(wallet.WalletError):
                wallet.OfflineWalletEngine(self.binary, self.digest, wallet_root=root)

    def test_symlink_and_hardlink_wallet_files_are_rejected(self):
        self.fake_rpc()
        record = self.engine.create_wallet(self.password).wallet
        keys = self.engine._files(record.wallet_id)[1]
        target = self.folder / "foreign"
        target.write_bytes(b"foreign")
        target.chmod(0o600)
        keys.unlink()
        keys.symlink_to(target)
        with self.assertRaises(wallet.WalletError):
            self.engine.open_wallet(record.wallet_id, self.password)
        keys.unlink()
        os.link(target, keys)
        with self.assertRaises(wallet.WalletError):
            self.engine.open_wallet(record.wallet_id, self.password)

    def test_concurrent_operation_is_refused(self):
        with self.engine._locked():
            with self.assertRaises(wallet.WalletError):
                self.engine.list_wallets()

    def test_malformed_metadata_does_not_escape_private_directory(self):
        self.fake_rpc()
        record = self.engine.create_wallet(self.password).wallet
        metadata = self.engine._metadata_path(record.wallet_id)
        value = json.loads(metadata.read_text())
        value["network"] = "mainnet"
        metadata.write_text(json.dumps(value))
        with self.assertRaises(wallet.WalletError):
            self.engine.list_wallets()

    def test_rpc_allowlist_response_limits_and_redacted_errors(self):
        process = wallet._RpcProcess(self.engine)
        process.process = Mock()
        process.process.poll.return_value = None
        process.deadline = time.monotonic() + 60
        process.url = "http://127.0.0.1:12345/json_rpc"
        process.session = Mock()
        for method, params in (("transfer", {}), ("restore_deterministic_wallet", {}),
                               ("query_key", {"key_type": "spend_key"})):
            with self.assertRaises(wallet.WalletError):
                process.call(method, params)
        process.session.post.assert_not_called()
        for payload in (b"[]", b"null", b"x" * 65_537,
                        json.dumps({"error": {"message": self.password + self.seed}}).encode()):
            response = Mock()
            response.status_code = 200
            response.raw = io.BytesIO(payload)
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            process.session.post.return_value = response
            with self.assertRaises(wallet.WalletError) as raised:
                process.call("get_version", {})
            self.assertNotIn(self.password, str(raised.exception))
            self.assertNotIn(self.seed, str(raised.exception))

    def test_session_has_private_auth_no_proxy_and_owned_cleanup(self):
        process = wallet._RpcProcess(self.engine)
        child = Mock()
        child.poll.return_value = None
        with patch.object(wallet.subprocess, "Popen", return_value=child) as popen, \
             patch.object(wallet._RpcProcess, "call", return_value={}), \
             patch.object(wallet.requests, "Session", return_value=Mock()) as session:
            with process:
                args = popen.call_args.args[0]
                options = popen.call_args.kwargs
                self.assertIn("--offline", args)
                self.assertIn("--stagenet", args)
                self.assertEqual(args[args.index("--rpc-bind-ip") + 1], "127.0.0.1")
                self.assertNotIn("--disable-rpc-login", args)
                self.assertEqual(options["umask"], 0o077)
                self.assertNotIn(self.password, " ".join(args))
                self.assertFalse(session.return_value.trust_env)
                self.assertFalse((process.temporary / "rpc.conf").exists())
                runtime = process.temporary
            child.terminate.assert_called_once()
            session.return_value.close.assert_called_once()
            self.assertFalse(runtime.exists())

    def test_windows_older_python_rejects_before_creating_directories(self):
        with patch.object(wallet.os, "name", "nt"), patch.object(wallet.sys, "version_info", (3, 12)):
            with self.assertRaises(wallet.WalletError):
                wallet.OfflineWalletEngine(self.binary, self.digest)

    def test_windows_private_acl_rejects_other_readers_inheritance_and_unknown_aces(self):
        user = "S-1-5-21-111-222-333-1001"
        aces = [(0, 3, 0x1f01ff, sid) for sid in (user, "S-1-5-18", "S-1-5-32-544", "S-1-3-4")]
        self.assertTrue(wallet._windows_acl_private(user, aces, user))
        self.assertFalse(wallet._windows_acl_private("S-1-5-32-544", aces, user))
        self.assertFalse(wallet._windows_acl_private(user, [], user))
        for kind, flags, mask, sid in ((0, 0, 1, "S-1-1-0"), (0, 8, 1, "S-1-5-11"), (9, 0, 0, "")):
            self.assertFalse(wallet._windows_acl_private(user, aces + [(kind, flags, mask, sid)], user))

    def test_foreign_listener_never_receives_http_headers_or_secret_body(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(4)
        port = server.getsockname()[1]
        received = []

        def accept():
            connection, _ = server.accept()
            with connection:
                connection.settimeout(4)
                received.append(connection.recv(8192))

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        child = Mock(pid=999999)
        child.poll.return_value = None
        session = wallet.requests.Session()
        self.addCleanup(session.close)
        session.trust_env = False
        session.mount("http://", wallet._owned_adapter(child, port))
        with patch.object(wallet, "_connection_owned", return_value=False):
            with self.assertRaises(wallet.WalletError):
                session.post(f"http://127.0.0.1:{port}/json_rpc", data=self.password, timeout=3)
        thread.join(timeout=4)
        self.assertEqual(received, [b""])

    def test_socket_ownership_requires_exact_peer_and_live_owned_process(self):
        child, sock = Mock(pid=123), Mock()
        child.poll.return_value = None
        sock.getpeername.return_value = ("127.0.0.1", 23456)
        sock.getsockname.return_value = ("127.0.0.1", 34567)
        with patch.object(wallet, "_connection_owned", return_value=True) as owner:
            wallet._assert_owned_socket(child, sock, 23456)
            owner.assert_called_once_with(123, 23456, 34567)
            sock.getpeername.return_value = ("127.0.0.2", 23456)
            with self.assertRaises(wallet.WalletError):
                wallet._assert_owned_socket(child, sock, 23456)

    def test_mainnet_storage_guard_fails_closed_before_writes_and_rechecks_each_operation(self):
        security = types.SimpleNamespace(attest_encrypted_storage=Mock(return_value={"ok": False}))
        root = self.folder / "mainnet-wallets"
        with patch.dict(sys.modules, {"wallet_security": security}):
            with self.assertRaises(wallet.WalletError):
                wallet.OfflineWalletEngine(self.binary, self.digest, wallet_root=root)
            self.assertFalse(root.exists())
            security.attest_encrypted_storage.return_value = {"ok": True}
            mainnet = wallet.OfflineWalletEngine(self.binary, self.digest, wallet_root=root)
            security.attest_encrypted_storage.return_value = {"ok": False}
            with patch.object(wallet, "_RpcProcess") as process:
                for operation in (lambda: mainnet.create_wallet(self.password), mainnet.list_wallets,
                                  lambda: mainnet.open_wallet("wallet_" + "a" * 32, self.password),
                                  lambda: mainnet.reveal_seed("wallet_" + "a" * 32, self.password)):
                    with self.assertRaises(wallet.WalletError):
                        operation()
                process.assert_not_called()
            security.attest_encrypted_storage.side_effect = RuntimeError("unknown attestation failure")
            with self.assertRaises(wallet.WalletError):
                mainnet.list_wallets()


if __name__ == "__main__":
    unittest.main()
