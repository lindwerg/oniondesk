"""Concurrent passive requests must share one vault and secret lifecycle."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'client'))
import app


class WalletSingletonTests(unittest.TestCase):
    def test_cold_parallel_requests_construct_exactly_one_controller(self):
        desk = app.Desk()
        start = threading.Barrier(12)

        def construct():
            time.sleep(0.03)  # Reproduce an initial import/constructor delay.
            return object()

        def request(_):
            start.wait(timeout=5)
            return desk.wallet_manager()

        with patch('wallet_controller.WalletController', side_effect=construct) as constructor:
            with ThreadPoolExecutor(max_workers=12) as pool:
                controllers = list(pool.map(request, range(12)))
            self.assertEqual(constructor.call_count, 1)
            self.assertEqual(len({id(controller) for controller in controllers}), 1)

    def test_injected_controller_is_never_replaced(self):
        supplied = object()
        desk = app.Desk(wallets=supplied)
        with patch('wallet_controller.WalletController') as constructor:
            self.assertIs(desk.wallet_manager(), supplied)
            constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
