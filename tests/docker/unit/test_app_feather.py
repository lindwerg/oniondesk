"""Feather API uses the existing nonce, job and fixed-input boundaries."""
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import app


class FeatherAPI(unittest.TestCase):
    def setUp(self):
        self.manager = Mock()
        self.desk = app.Desk(wallets=self.manager)

    def wait(self):
        deadline = time.monotonic() + 2
        while self.desk.job["state"] == "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.desk.job["state"], "done")

    def test_each_explicit_action_calls_only_its_fixed_controller_method(self):
        for action, method in (("prepare", "prepare_feather"), ("launch", "launch_feather"),
                               ("connect", "connect_feather"), ("stop", "stop_feather")):
            self.manager.reset_mock()
            result = self.desk.dispatch("/api/feather/" + action, {})
            self.assertTrue(result["started"])
            self.wait()
            self.assertEqual(self.desk.job["kind"], "feather-" + action)
            self.assertEqual([call[0] for call in self.manager.method_calls], [method])

    def test_no_seed_password_proxy_path_binary_or_extra_field_accepted(self):
        for name in ("seed", "password", "path", "binary", "proxy", "port", "wallet_id"):
            with self.assertRaises(ValueError):
                self.desk.dispatch("/api/feather/prepare", {name: "synthetic"})
        self.manager.prepare_feather.assert_not_called()
        with self.assertRaises(LookupError):
            self.desk.dispatch("/api/feather/pay", {})

    def test_busy_or_native_pending_rejects_before_job_or_launch(self):
        self.desk.native_access_pending = True
        with self.assertRaises(ValueError):
            self.desk.dispatch("/api/feather/launch", {})
        self.desk.native_access_pending = False
        self.desk.job = {"state": "running"}
        with self.assertRaises(ValueError):
            self.desk.dispatch("/api/feather/connect", {})
        self.manager.launch_feather.assert_not_called()
        self.manager.connect_feather.assert_not_called()


if __name__ == "__main__":
    unittest.main()
