"""USB phone operations stay explicit, nonce-bound and safe to close; fixtures only."""
import threading
import unittest
import test_app as fixtures
from test_app import FakeUSB, FakeEngine, FakeOffline, FakeWallet, app


class FakePhone:
    def __init__(self):
        self.opened = False
        self.listed = self.installs = self.closed = 0
        self.fail_close = False

    def state(self):
        return {'available': True, 'session_open': self.opened,
                'cleanup_required': self.opened, 'tor_ready': False,
                'installed': bool(self.installs), 'devices': []}

    def list_devices(self, emit=None):
        self.listed += 1
        self.opened = True
        if emit:
            emit({'message': 'Тестовый телефон найден', 'percent': 100})

    def install(self, device_id, emit=None):
        if device_id != 'synthetic-device-only':
            raise ValueError('Выберите телефон из списка.')
        self.installs += 1

    def close(self):
        if self.fail_close:
            raise RuntimeError('Синтетический отказ закрытия')
        self.closed += 1
        self.opened = False


class PhoneAPI(unittest.TestCase):
    request = fixtures.LocalAPITest.request
    finished = fixtures.LocalAPITest.finished
    tearDown = fixtures.LocalAPITest.tearDown

    def setUp(self):
        self.phone = FakePhone()
        self.desk = app.Desk(FakeUSB(), FakeEngine(), FakeOffline(), FakeWallet(), phones=self.phone)
        self.server = app.LocalServer(self.desk)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(setattr, self.phone, 'fail_close', False)

    def test_polling_does_not_start_usb_or_reveal_pairing_keys(self):
        for _ in range(3):
            response = self.request('/api/state')[1]
            self.assertFalse(response['phone']['session_open'])
            self.assertFalse(response['phone']['tor_ready'])
        self.assertEqual((self.phone.listed, self.phone.installs, self.phone.closed), (0, 0, 0))

    def test_all_phone_mutations_require_nonce_origin_and_exact_fields(self):
        for endpoint in ('list', 'install', 'close'):
            fields = {'device_id': 'synthetic-device-only'} if endpoint == 'install' else {}
            path = '/api/phone/' + endpoint
            self.assertEqual(self.request(path, fields, nonce=False)[0], 403)
            self.assertEqual(self.request(path, fields, origin=False)[0], 403)
            self.assertEqual(self.request(path, {**fields, 'serial': 'forbidden'})[0], 400)
        self.assertEqual(self.phone.listed, 0)
        self.assertEqual(self.phone.installs, 0)
        self.assertEqual(self.request('/api/phone/install', {'device_id': '../unsafe'})[0], 400)

    def test_install_is_not_tor_readiness_and_closing_cleans_session(self):
        self.assertEqual(self.request('/api/phone/list', {})[0], 200)
        self.finished()
        self.assertEqual(self.phone.listed, 1)
        self.assertEqual(self.request('/api/phone/install', {'device_id': 'synthetic-device-only'})[0], 200)
        self.finished()
        state = self.request('/api/state')[1]['phone']
        self.assertTrue(state['installed'])
        self.assertFalse(state['tor_ready'])
        self.assertEqual(self.request('/api/phone/close', {})[0], 200)
        self.finished()
        self.assertFalse(self.request('/api/state')[1]['phone']['session_open'])

    def test_failed_phone_cleanup_blocks_quit_and_preserves_wallet(self):
        self.phone.opened = self.phone.fail_close = True
        self.desk.wallets.opened = True
        self.assertEqual(self.request('/api/quit', {})[0], 409)
        self.assertFalse(self.desk.closed)
        self.assertTrue(self.desk.wallets.opened)
        self.phone.fail_close = False

    def test_quitting_cannot_admit_a_new_usb_session_during_wallet_detach(self):
        entered, release = threading.Event(), threading.Event()
        original = self.desk.wallets.close
        def slow_wallet_close():
            entered.set()
            release.wait(3)
            original()
        self.desk.wallets.close = slow_wallet_close
        thread = threading.Thread(target=self.desk.close)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaises((ValueError, RuntimeError)):
                self.desk.dispatch('/api/phone/list', {})
            self.assertEqual(self.phone.listed, 0)
        finally:
            release.set()
            thread.join(3)
            self.desk.wallets.close = original
        self.assertTrue(self.desk.closed)
        self.assertFalse(self.phone.opened)
