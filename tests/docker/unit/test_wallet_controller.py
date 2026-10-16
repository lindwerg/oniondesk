"""RAM secret lifecycle and mainnet-only UI contracts; fixture words only."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import wallet_controller as controller
from wallet_engine import Network, PendingWallet, WalletError, WalletRecord
import wallet_vault

WORDS = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee".split()
PASSWORD = "only fixture password"
IDENTIFIER = "wallet_" + "a" * 32
VAULT = "vault_" + "b" * 32


class FakeVault:
    def __init__(self):
        self.active_id = None
        self.root = Path("/private/encrypted-fixture/wallets")
        self.images = []
        self.fail_close = False

    def list_vaults(self):
        return [{"id": value, "label": "Fixture vault"} for value in self.images]

    def create(self, password):
        if password != PASSWORD:
            raise WalletError("Fixture password rejected")
        self.images.append(VAULT)
        self.active_id = VAULT
        return self.root

    def unlock(self, identifier, password):
        if identifier != VAULT or password != PASSWORD:
            raise WalletError("Fixture password rejected")
        self.active_id = identifier
        return self.root

    def close(self):
        if self.fail_close:
            raise WalletError("Fixture detach failed; no force")
        self.active_id = None


class FakeEngine:
    network = Network.MAINNET

    def __init__(self):
        self.root = Path("/private/encrypted-fixture/wallets")
        self.records = []
        self.created = []
        self.block = None

    def create_wallet(self, password):
        if self.block:
            self.block[0].set()
            self.block[1].wait(timeout=4)
        if password != PASSWORD:
            raise WalletError("Fixture password rejected")
        record = WalletRecord(IDENTIFIER, "mainnet", "4" + "A" * 94)
        self.records = [record]
        pending = PendingWallet(record, " ".join(WORDS))
        self.created.append(pending)
        return pending

    def list_wallets(self):
        return list(self.records)

    def open_wallet(self, identifier, password):
        if identifier != IDENTIFIER or password != PASSWORD:
            raise WalletError("Fixture password rejected")
        return self.records[0]

    def reveal_seed(self, identifier, password):
        if self.block:
            self.block[0].set()
            self.block[1].wait(timeout=4)
        record = self.open_wallet(identifier, password)
        pending = PendingWallet(record, " ".join(WORDS))
        self.created.append(pending)
        return pending

    def confirm_backup(self, identifier):
        self.records = [replace(record, backup_confirmed=True) if record.wallet_id == identifier else record for record in self.records]
        return self.records[0]


class Controller(unittest.TestCase):
    def setUp(self):
        self.vault, self.engine = FakeVault(), FakeEngine()
        self.factory = Mock(return_value=self.engine)
        self.instance = controller.WalletController(vault_manager=self.vault, _engine_factory=self.factory)
        self.addCleanup(self.instance.forget)
        self.status = patch.object(controller.wallet_bundle, "status", return_value={"available": True, "message": "Fixture"})
        self.status.start()
        self.addCleanup(self.status.stop)

    def test_corner_summary_tracks_backup_and_reopening_without_secrets(self):
        initial = self.instance.state()
        self.assertFalse(initial['has_wallet'])
        self.assertIsNone(initial['backup_confirmed'])
        self.instance.create(PASSWORD, lambda _: None)
        created = self.instance.state()
        self.assertTrue(created['has_wallet'])
        self.assertFalse(created['backup_confirmed'])
        phrase = self.instance.take_seed()
        answers = [WORDS[position - 1] for position in phrase['positions']]
        self.instance.confirm_backup(IDENTIFIER, phrase['challenge'], answers)
        self.assertTrue(self.instance.state()['backup_confirmed'])
        self.instance.close()
        locked = self.instance.state()
        self.assertFalse(locked['has_wallet'])
        self.assertIsNone(locked['backup_confirmed'])
        self.assertEqual(len(locked['vaults']), 1)
        next_launch = controller.WalletController(vault_manager=self.vault, _engine_factory=self.factory)
        self.addCleanup(next_launch.forget)
        self.assertFalse(next_launch.state()['has_wallet'])
        next_launch.unlock(VAULT, PASSWORD, lambda _: None)
        reopened = next_launch.state()
        self.assertTrue(reopened['has_wallet'])
        self.assertTrue(reopened['backup_confirmed'])
        serialized = json.dumps(reopened)
        self.assertNotIn('4' + 'A' * 94, serialized)
        self.assertNotIn(IDENTIFIER, serialized)
        self.assertNotIn(PASSWORD, serialized)
        self.assertNotIn(' '.join(WORDS), serialized)

    def test_polling_is_readonly_cheap_and_does_not_expose_addresses_or_paths(self):
        before = self.instance.state()
        self.assertFalse(before["workspace_open"])
        self.assertEqual(self.instance.list_wallets()["wallets"], [])
        self.factory.assert_not_called()
        events = []
        self.instance.create(PASSWORD, events.append)
        self.factory.assert_called_once_with(network=Network.MAINNET, wallet_root=self.vault.root)
        serialized = json.dumps(self.instance.state())
        for secret in (PASSWORD, " ".join(WORDS), self.engine.records[0].address, str(self.vault.root)):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, json.dumps(events))
        with patch.object(self.engine, "list_wallets", side_effect=AssertionError("No RPC/attester during poll")):
            self.assertEqual(len(self.instance.list_wallets()["wallets"]), 1)
            self.assertTrue(self.instance.state()["pending_seed"])

    def test_take_seed_returns_once_and_keeps_only_three_expected_words(self):
        self.instance.create(PASSWORD)
        result = self.instance.take_seed()
        self.assertEqual(result["words"], WORDS)
        self.assertEqual(len(set(result["positions"])), 3)
        self.assertTrue(all(1 <= value <= 25 for value in result["positions"]))
        self.assertIsNone(self.instance._pending)
        self.assertEqual(len(self.instance._backup.expected), 3)
        self.assertEqual(self.engine.created[0].mnemonic, "")
        with self.assertRaises(WalletError):
            self.instance.take_seed()
        answers = [WORDS[position - 1] for position in result["positions"]]
        response = self.instance.confirm_backup(IDENTIFIER, result["challenge"], answers)
        self.assertTrue(response["wallet"]["backup_confirmed"])
        self.assertIsNone(self.instance._backup)
        self.assertTrue(self.instance.list_wallets()["wallets"][0]["backup_confirmed"])

    def test_confirmation_compares_all_words_token_and_wallet(self):
        self.instance.create(PASSWORD)
        result = self.instance.take_seed()
        original = controller.secrets.compare_digest
        with patch.object(controller.secrets, "compare_digest", wraps=original) as compare:
            with self.assertRaises(WalletError):
                self.instance.confirm_backup("wallet_" + "c" * 32, "X" * 43, ["wrong", "неверно", "wrong"])
            self.assertEqual(compare.call_count, 5)
        self.assertFalse(self.engine.records[0].backup_confirmed)
        self.assertIsNotNone(self.instance._backup)
        self.instance.forget()
        with self.assertRaises(WalletError):
            self.instance.confirm_backup(IDENTIFIER, result["challenge"], ["alpha"] * 3)

    def test_deadline_and_daemon_timer_clear_full_seed_and_challenge(self):
        self.instance.create(PASSWORD)
        self.assertTrue(self.instance._timer.daemon)
        with patch.object(controller.time, "monotonic", return_value=self.instance._deadline + 1):
            self.assertFalse(self.instance.state()["pending_seed"])
        self.assertEqual(self.engine.created[0].mnemonic, "")
        self.instance.reveal(IDENTIFIER, PASSWORD)
        self.instance.take_seed()
        with patch.object(controller.time, "monotonic", return_value=self.instance._deadline + 1):
            self.instance._timer.function()
        self.assertIsNone(self.instance._backup)

    def test_forget_during_long_create_prevents_late_seed_restore_and_never_blocks_polling(self):
        entered, release = threading.Event(), threading.Event()
        self.engine.block = (entered, release)
        result, errors = [], []
        def run():
            try:
                result.append(self.instance.create(PASSWORD))
            except Exception as error:
                errors.append(type(error).__name__)
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(timeout=2))
        started = time.monotonic()
        self.instance.forget()
        self.instance.state()
        self.instance.list_wallets()
        self.assertLess(time.monotonic() - started, 0.3)
        release.set()
        worker.join(timeout=3)
        self.assertEqual(errors, [])
        self.assertFalse(result[0]["pending_seed"])
        self.assertEqual(self.engine.created[0].mnemonic, "")
        self.assertIsNone(self.instance._pending)

    def test_forget_during_long_reveal_prevents_late_restore(self):
        self.instance.create(PASSWORD)
        entered, release = threading.Event(), threading.Event()
        self.engine.block = (entered, release)
        result = []
        worker = threading.Thread(target=lambda: result.append(self.instance.reveal(IDENTIFIER, PASSWORD)), daemon=True)
        worker.start()
        self.assertTrue(entered.wait(timeout=2))
        self.instance.forget()
        release.set()
        worker.join(timeout=3)
        self.assertFalse(result[0]["pending_seed"])
        self.assertIsNone(self.instance._pending)
        self.assertEqual(self.engine.created[-1].mnemonic, "")

    def test_close_failure_clears_secrets_keeps_workspace_and_can_retry(self):
        self.instance.create(PASSWORD)
        self.vault.fail_close = True
        with self.assertRaises(WalletError):
            self.instance.close()
        self.assertFalse(self.instance.state()["pending_seed"])
        self.assertTrue(self.instance.state()["workspace_open"])
        self.assertEqual(self.vault.active_id, VAULT)
        self.vault.fail_close = False
        self.instance.close()
        self.assertFalse(self.instance.state()["workspace_open"])
        self.instance.unlock(VAULT, PASSWORD)
        self.assertTrue(self.instance.state()["workspace_open"])

    def test_invalid_ids_password_and_test_network_never_reach_secret_operation(self):
        for identifier in ("../secret", "/tmp/secret", "system", "vault_" + "а" * 32):
            with self.assertRaises(WalletError):
                self.instance.unlock(identifier, PASSWORD)
        with self.assertRaises(WalletError):
            self.instance.create("wrong")
        self.factory.assert_not_called()
        self.engine.network = Network.STAGENET
        with self.assertRaises(WalletError):
            self.instance.create(PASSWORD)
        self.assertFalse(self.instance.state()["workspace_open"])
        self.assertEqual(self.engine.created, [])

    def test_each_vault_must_contain_exactly_one_wallet(self):
        self.instance.create(PASSWORD)
        self.instance.close()
        original = self.engine.records[0]
        for records in ([], [original, replace(original, wallet_id="wallet_" + "c" * 32)]):
            self.engine.records = records
            with patch.object(self.engine, "open_wallet") as opened:
                with self.assertRaises(WalletError):
                    self.instance.unlock(VAULT, PASSWORD)
                opened.assert_not_called()
            self.assertFalse(self.instance.state()["workspace_open"])

    def test_system_two_passwords_unlock_the_selected_vault_and_its_single_wallet(self):
        passwords = ["first fixture password", "second fixture password"]
        by_root = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "wallets"
            security = types.SimpleNamespace(attest_encrypted_storage=Mock(return_value={"ok": True, "kind": "luks"}))
            with patch.dict(sys.modules, {"wallet_security": security}), \
                 patch.object(wallet_vault, "default_wallet_root", return_value=root):
                manager = wallet_vault.SystemVaultManager()
                def factory(*, network, wallet_root):
                    self.assertEqual(network, Network.MAINNET)
                    if wallet_root not in by_root:
                        expected = passwords[len(by_root)]
                        engine = FakeEngine()
                        def create(password):
                            if password != expected:
                                raise WalletError("Fixture wrong password")
                            record = WalletRecord("wallet_" + wallet_root.name[6:], "mainnet", "4" + "A" * 94)
                            engine.records = [record]
                            return PendingWallet(record, " ".join(WORDS))
                        def opened(identifier, password):
                            if password != expected or identifier != engine.records[0].wallet_id:
                                raise WalletError("Fixture wrong selected wallet")
                            return engine.records[0]
                        engine.create_wallet = create
                        engine.open_wallet = Mock(side_effect=opened)
                        by_root[wallet_root] = engine
                    return by_root[wallet_root]
                instance = controller.WalletController(vault_manager=manager, _engine_factory=factory)
                self.addCleanup(instance.forget)
                first = instance.create(passwords[0])
                instance.close()
                second = instance.create(passwords[1])
                instance.close()
                self.assertNotEqual(first["vault_id"], second["vault_id"])
                result = instance.unlock(second["vault_id"], passwords[1])
                self.assertEqual(result["wallets"][0]["wallet_id"], second["wallet"]["wallet_id"])
                second_engine = by_root[root / second["vault_id"]]
                second_engine.open_wallet.assert_called_once_with(second["wallet"]["wallet_id"], passwords[1])
                instance.close()
                self.assertEqual(instance.unlock(first["vault_id"], passwords[0])["wallets"][0]["wallet_id"], first["wallet"]["wallet_id"])
                instance.close()


if __name__ == "__main__":
    unittest.main()
