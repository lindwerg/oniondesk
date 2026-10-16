"""Behavioral tests for the local authorization boundary and safe action contract."""
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

CLIENT = Path(__file__).resolve().parents[3] / 'client'
sys.path.insert(0, str(CLIENT))
import app


class FakeUSB:
    def __init__(self):
        self.writes = []
        self.downloads = 0
    def system_info(self):
        return {'platform':'Darwin','architecture':'arm64','tails_can_boot_here':False,'boot_message':'Tails на этом Mac не запускается','verifier_available':False}
    def list_usb_disks(self):
        return [{'id':'opaque-selection','name':'Test USB','size_bytes':16_000_000_000,'identity':'opaque-id','platform':'Darwin'}]
    def download_verified_image(self, emit, event):
        self.downloads += 1
        emit({'stage':'verify','message':'Подпись проверена','percent':100})
        return {'verified':True}
    def write_verified_image(self, selection, confirmation, emit, event):
        self.writes.append((selection, confirmation))
        emit({'message':'Записано','percent':100})


class FakeRemote:
    def close(self):
        pass


class FakeOffline:
    def __init__(self):
        self.launches = 0
    def status(self):
        return {'available': True, 'tails_available': True, 'tor_available': True,
                'tails_version': 'test', 'tor_version': 'test', 'message': 'Офлайн-файлы найдены'}
    def prepare_tor(self, emit):
        self.launches += 1
        emit('Официальный Tor Browser проверен')
        return {'message': 'Открыт официальный установщик. Завершите его шаги и подключитесь к Tor.'}


class FakeWallet:
    """Synthetic records only; never starts cryptographic software or a mount."""
    def __init__(self):
        self.opened = False
        self.pending = False
        self.fail_close = False
        self.creations = 0
        self.forgets = 0
        self.record = {'wallet_id': 'wallet_' + 'a' * 32, 'network': 'mainnet',
                       'address': '4' + 'A' * 94, 'backup_confirmed': False,
                       'seed_format': 'Monero CLI: 25 English words'}
    def state(self):
        return {'available': True, 'workspace_open': self.opened, 'pending_seed': self.pending,
                'has_wallet': self.opened,
                'backup_confirmed': self.record['backup_confirmed'] if self.opened else None,
                'vaults': [{'id': 'vault_' + 'b' * 32, 'label': 'Тестовое хранилище'}],
                'message': 'Синтетическая проверка без ключей и денег'}
    def list_wallets(self):
        return {'wallets': [dict(self.record)] if self.opened else [], 'vaults': self.state()['vaults']}
    def create(self, password, emit):
        self.creations += 1
        self.opened = self.pending = True
        emit({'message': 'Тестовый кошелёк подготовлен', 'percent': 100})
    def unlock(self, vault_id, password, emit):
        self.opened = True
    def reveal(self, wallet_id, password, emit):
        self.pending = True
    def take_seed(self):
        if not self.pending:
            raise RuntimeError('Фраза уже скрыта. Повторите авторизацию.')
        self.pending = False
        return {'wallet_id': self.record['wallet_id'], 'words': ['demo'] * 25,
                'challenge': 'c' * 43, 'positions': [2, 11, 23]}
    def confirm_backup(self, wallet_id, challenge, answers):
        if wallet_id != self.record['wallet_id'] or challenge != 'c' * 43 or answers != ['demo'] * 3:
            raise RuntimeError('Слова не совпали.')
        self.record['backup_confirmed'] = True
    def forget(self):
        self.forgets += 1
        self.pending = False
    def close(self):
        self.forget()
        if self.fail_close:
            raise RuntimeError('Хранилище используется')
        self.opened = False


class FakeEngine:
    def __init__(self):
        self.commands = []
    @staticmethod
    def validate_host(value):
        if value != '8.8.8.8':
            raise ValueError('Нужен публичный IP')
        return value
    @staticmethod
    def validate_fingerprint(value):
        if value != 'SHA256:' + 'A' * 43:
            raise ValueError('Нужен SHA256')
        return value
    def find_tor_proxy(self):
        return 9150
    def connect(self, *args):
        return FakeRemote()
    def run(self, remote, command, timeout=60):
        self.commands.append(command)
        if 'runtime-audit.py --json' in command:
            return json.dumps({'ok': True, 'checks': [{'id': 'test', 'ok': True, 'detail': 'Изоляция подтверждена'}]})
        if command.endswith(' status'):
            return 'Onion адрес: http://' + 'a'*56 + '.onion/\nНЕ ГОТОВО: Tor не подтверждён'
        return ''


class LocalAPITest(unittest.TestCase):
    def setUp(self):
        self.usb = FakeUSB()
        self.engine = FakeEngine()
        self.offline = FakeOffline()
        self.wallets = FakeWallet()
        self.desk = app.Desk(self.usb, self.engine, self.offline, self.wallets)
        self.server = app.LocalServer(self.desk)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
    def tearDown(self):
        self.desk.close()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)
    def request(self, path, body=None, *, nonce=True, origin=True, headers=None, raw=None):
        h = {'Host':self.server.host}
        if nonce: h['X-App-Nonce'] = self.desk.nonce
        if origin: h['Origin'] = self.server.origin
        h.update(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
        if data is not None: h.setdefault('Content-Type','application/json')
        request = Request(self.server.origin + path, data=data, headers=h)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response), dict(response.headers)
        except HTTPError as error:
            try:
                return error.code, json.load(error), dict(error.headers)
            finally:
                error.close()
    def finished(self):
        deadline = time.monotonic() + 3
        while self.desk.job['state'] == 'running' and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertNotEqual(self.desk.job['state'], 'running')

    def test_state_requires_nonce_and_has_no_secrets(self):
        status, _, _ = self.request('/api/state', nonce=False)
        self.assertEqual(status,403)
        self.assertEqual(self.request('/api/state', headers={'X-App-Nonce':'é'})[0],403)
        self.desk.credentials = {'password':'sentinel-secret'}
        status, result, headers = self.request('/api/state')
        self.assertEqual(status,200)
        self.assertNotIn('sentinel-secret',json.dumps(result))
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertNotIn('Access-Control-Allow-Origin',headers)

    def test_host_and_origin_reject_rebinding_and_external_site(self):
        self.assertEqual(self.request('/api/state',headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.request('/api/state',headers={'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('/api/state',headers={'Sec-Fetch-Site':'cross-site'})[0],403)

    def test_mutation_requires_exact_origin_and_nonce(self):
        self.assertEqual(self.request('/api/usb/download',{},origin=False)[0],403)
        self.assertEqual(self.request('/api/usb/download',{},nonce=False)[0],403)
        self.assertEqual(self.usb.downloads,0)

    def test_offline_tor_requires_authorization_and_does_not_claim_connection(self):
        self.assertEqual(self.request('/api/tor/start', {}, nonce=False)[0], 403)
        self.assertEqual(self.request('/api/tor/start', {}, origin=False)[0], 403)
        self.assertEqual(self.offline.launches, 0)
        self.desk.tor_verified = True
        self.assertEqual(self.request('/api/tor/start', {})[0], 200)
        self.finished()
        self.assertEqual(self.offline.launches, 1)
        self.assertFalse(self.desk.tor_verified)

    def test_wallet_creation_and_explicit_list_require_local_authorization(self):
        data = {'password': 'SENTINEL-PASSWORD'}
        self.assertEqual(self.request('/api/wallet/create', data, nonce=False)[0], 403)
        self.assertEqual(self.request('/api/wallet/create', data, origin=False)[0], 403)
        self.assertEqual(self.request('/api/wallet/list', nonce=False)[0], 403)
        self.assertEqual(self.wallets.creations, 0)
        self.assertEqual(self.request('/api/wallet/create', {**data, 'network': 'stagenet'})[0], 400)
        self.assertEqual(self.request('/api/wallet/create', {'password': 'short'})[0], 400)
        self.assertEqual(self.request('/api/wallet/create', data)[0], 200)
        self.finished()
        self.assertEqual(self.wallets.creations, 1)
        state = self.request('/api/state')[1]
        self.assertTrue(state['wallet']['pending_seed'])
        self.assertFalse(state['tor_verified'], 'Offline wallet creation is not a Tor check')
        serialized = json.dumps(state)
        self.assertNotIn(data['password'], serialized)
        self.assertNotIn(self.wallets.record['address'], serialized)
        self.assertNotIn('mnemonic', serialized)
        self.assertEqual(self.request('/api/wallet/list')[1]['wallets'][0]['address'], self.wallets.record['address'])

    def test_wallet_seed_is_explicit_single_use_and_backup_checked(self):
        self.wallets.opened = self.wallets.pending = True
        self.assertEqual(self.request('/api/wallet/seed')[0], 404)
        self.assertEqual(self.request('/api/wallet/seed', {}, nonce=False)[0], 403)
        status, payload, headers = self.request('/api/wallet/seed', {})
        self.assertEqual(status, 200)
        self.assertEqual(payload['words'], ['demo'] * 25)
        self.assertIn('no-store', headers.get('Cache-Control', ''))
        self.assertEqual(self.request('/api/wallet/seed', {})[0], 400)
        self.assertEqual(self.request('/api/wallet/confirm', {'wallet_id': payload['wallet_id'],
            'challenge': payload['challenge'], 'answers': ['wrong'] * 3})[0], 200)
        self.finished()
        self.assertFalse(self.wallets.record['backup_confirmed'])
        self.assertEqual(self.request('/api/wallet/confirm', {'wallet_id': payload['wallet_id'],
            'challenge': payload['challenge'], 'answers': ['demo'] * 3})[0], 200)
        self.finished()
        self.assertTrue(self.wallets.record['backup_confirmed'])

    def test_wallet_unexpected_errors_are_redacted_and_forget_is_available(self):
        secret = 'SENTINEL-password-and-private-words'
        def fail(_password, _emit):
            raise OSError(secret)
        self.wallets.create = fail
        self.request('/api/wallet/create', {'password': 'long-enough-password'})
        self.finished()
        self.assertNotIn(secret, json.dumps(self.request('/api/state')[1]))
        self.wallets.pending = True
        self.assertEqual(self.request('/api/wallet/forget', {})[0], 200)
        self.assertFalse(self.wallets.pending)

    def test_quit_keeps_app_available_when_wallet_cannot_be_detached(self):
        self.wallets.opened = self.wallets.pending = True
        self.wallets.fail_close = True
        self.assertEqual(self.request('/api/quit', {})[0], 409)
        self.assertFalse(self.desk.closed)
        self.assertFalse(self.wallets.pending)
        self.assertEqual(self.request('/api/state')[0], 200)
        self.wallets.fail_close = False

    def test_secrets_card_is_protected(self):
        self.desk.credentials = {'password':'sentinel-secret'}
        self.assertEqual(self.request('/api/secrets',nonce=False)[0],403)
        self.assertEqual(self.request('/api/secrets',headers={'Origin':'null'})[0],403)
        self.assertEqual(self.request('/api/secrets')[1]['credentials']['password'],'sentinel-secret')
        self.assertEqual(self.request('/api/secrets/clear',{})[0],200)
        self.assertIsNone(self.desk.credentials)

    def test_tails_handoff_requires_nonce_and_never_exports_credentials(self):
        self.assertEqual(self.request('/api/access-note')[0], 400)
        self.desk._set_credentials({'url': 'http://' + 'a' * 56 + '.onion/',
                                   'login': 'private-owner', 'password': 'private-password',
                                   'totp_secret': 'private-totp', 'otpauth_uri': 'private-uri'})
        self.assertEqual(self.request('/api/access-note', nonce=False)[0], 403)
        status, result, headers = self.request('/api/access-note')
        self.assertEqual(status, 200)
        self.assertIn('a' * 56 + '.onion', result['text'])
        for secret in ('private-owner', 'private-password', 'private-totp', 'private-uri'):
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('a' * 56, json.dumps(self.desk.state()))
        self.request('/api/secrets/clear', {})
        self.assertEqual(self.request('/api/access-note')[0], 400)

    def test_resume_observes_existing_job_and_does_not_call_install(self):
        self.desk.remote = FakeRemote()
        called = []
        def resume(remote, emit):
            called.append('resume')
            return {'url': 'http://' + 'b' * 56 + '.onion/', 'login': 'owner',
                    'password': 'password', 'totp_secret': 'totp', 'otpauth_uri': 'uri'}
        self.engine.resume_install = resume
        self.engine.install = lambda *args: self.fail('Cannot reinstall while resuming')
        self.assertEqual(self.request('/api/server/resume', {})[0], 200)
        self.finished()
        self.assertEqual(called, ['resume'])
        self.assertTrue(self.desk.server_installed)
        self.assertFalse(self.desk.guest_ready)

    def test_failed_or_malformed_audit_never_keeps_previous_green_state(self):
        self.desk.remote = FakeRemote()
        self.request('/api/server/action', {'action': 'audit'}); self.finished()
        self.assertTrue(self.desk.safety_checked)
        self.assertTrue(self.desk.safety_ok)
        for report in ({'ok': False, 'checks': [{'id': 'port', 'ok': False, 'detail': 'Открытый порт'}]},
                       {'ok': True, 'checks': []},
                       {'ok': True, 'checks': [{'id': 'port', 'ok': False, 'detail': 'Открытый порт'}]},
                       {'ok': 'true', 'checks': [{'id': 'port', 'ok': True, 'detail': 'test'}]}):
            self.desk.guest_ready = True
            self.engine.run = lambda *args, **kwargs: json.dumps(report)
            self.request('/api/server/action', {'action': 'audit'}); self.finished()
            self.assertFalse(self.desk.guest_ready)
            self.assertFalse(self.desk.safety_ok)

    def test_failing_audit_blocks_readiness_even_if_guest_claims_ready(self):
        self.desk.remote = FakeRemote()
        commands = []
        def respond(remote, command, **kwargs):
            commands.append(command)
            if 'runtime-audit.py --json' in command:
                return json.dumps({'ok': False, 'checks': [{'id': 'nic', 'ok': False, 'detail': 'Лишний сетевой адаптер'}]})
            return 'ГОТОВО: Telegram установлен'
        self.engine.run = respond
        self.request('/api/server/action', {'action': 'status'}); self.finished()
        self.assertFalse(self.desk.guest_ready)
        self.assertEqual(len(commands), 1)
        self.assertTrue(self.desk.safety_checked)
        self.assertIn('Лишний', self.desk.safety_report)

    def test_explicit_usb_erase_required_no_user_path(self):
        self.assertEqual(self.request('/api/usb/write',{'selection':'opaque-selection','confirmation':'yes','path':'/dev/disk0'})[0],400)
        self.assertEqual(self.usb.writes,[])
        self.assertEqual(self.request('/api/usb/write',{'selection':'opaque-selection','confirmation':'СТЕРЕТЬ'})[0],200)
        self.finished()
        self.assertEqual(self.usb.writes,[('opaque-selection','СТЕРЕТЬ')])

    def test_only_fixed_server_actions_and_no_arbitrary_command_api(self):
        self.desk.remote = FakeRemote()
        self.assertEqual(self.request('/api/server/action',{'action':'status; rm -rf /'})[0],400)
        self.assertEqual(self.request('/api/server/command',{'command':'whoami'})[0],404)
        self.assertEqual(self.engine.commands,[])
        self.assertEqual(self.request('/api/server/action',{'action':'status'})[0],200)
        self.finished()
        self.assertEqual(len(self.engine.commands), 2)
        self.assertIn('runtime-audit.py --json', self.engine.commands[0])
        self.assertEqual(self.engine.commands[1], 'sudo /opt/oniondesk/server/control.sh status')
        self.assertFalse(self.desk.guest_ready)
        self.assertNotIn('a'*56,self.desk.last_status)

    def test_install_requires_real_consent_and_connected_session(self):
        self.assertEqual(self.request('/api/server/install',{'licenses':True,'fresh_server':False})[0],400)
        self.assertEqual(self.request('/api/server/install',{'licenses':True,'fresh_server':True})[0],400)
        self.assertIsNone(self.desk.job)

    def test_oversized_duplicate_and_nonobject_json_fail(self):
        self.assertEqual(self.request('/api/usb/download',raw=b' '*(app.MAX_BODY+1))[0],413)
        self.assertEqual(self.request('/api/usb/download',raw=b'{"a":1,"a":2}')[0],400)
        self.assertEqual(self.request('/api/usb/download',raw=b'[]')[0],400)
        self.assertEqual(self.request('/api/usb/download',raw=b'{}',headers={'Content-Type':'text/plain'})[0],415)

    def test_static_paths_are_explicitly_whitelisted(self):
        self.assertEqual(self.request('/../launcher.py')[0],404)
        self.assertEqual(self.request('/client/launcher.py')[0],404)
        self.assertEqual(self.request('/api/state?nonce='+self.desk.nonce)[0],403)

    def test_terminal_fonts_are_local_and_explicitly_whitelisted(self):
        for filename in ('JetBrainsMono-Regular.ttf', 'JetBrainsMono-Bold.ttf'):
            with urlopen(self.server.origin + '/fonts/' + filename, timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(4), b'\x00\x01\x00\x00')
                self.assertIn("font-src 'self'", response.headers['Content-Security-Policy'])
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.request('/fonts/OFL.txt')[0], 404)
        self.assertEqual(self.request('/fonts/../app.py')[0], 404)

    def test_real_guide_frames_are_authorized_fixed_paths_and_not_success_claims(self):
        self.assertEqual(self.request('/api/guide-shots', nonce=False)[0], 403)
        status, body, _ = self.request('/api/guide-shots')
        self.assertEqual(status, 200)
        for item in body['shots'].values():
            self.assertTrue(item['url'].startswith('/screens/real/'))
            with urlopen(self.server.origin + item['url'], timeout=3) as response:
                self.assertEqual(response.read(8), b'\x89PNG\r\n\x1a\n')
        failure = body['shots'].get('tails-tor-failure')
        if failure is not None:
            self.assertIn('не подтверждён', failure['caption'])
        self.assertEqual(self.request('/screens/real/../../app.py')[0], 404)

    def test_concurrent_operation_and_quit_are_blocked(self):
        block = threading.Event()
        self.desk.start_job('slow',lambda event: block.wait(3))
        try:
            self.assertEqual(self.request('/api/usb/download',{})[0],400)
            self.assertEqual(self.request('/api/quit',{})[0],409)
        finally:
            block.set(); self.finished()

    def test_ready_requires_current_guest_report_not_vm_or_install(self):
        self.desk.remote = FakeRemote()
        self.desk.server_installed = True
        self.assertFalse(self.desk.state()['guest_ready'])
        original = self.engine.run
        def ready(remote, command, timeout=60):
            if 'runtime-audit.py --json' in command:
                return original(remote, command, timeout)
            return 'ГОТОВО: Telegram установлен; Tor в Workstation подтверждён сейчас.'
        self.engine.run = ready
        self.request('/api/server/action',{'action':'status'}); self.finished()
        self.assertTrue(self.desk.guest_ready)
        self.engine.run = original
        self.request('/api/server/action',{'action':'start'}); self.finished()
        self.assertFalse(self.desk.guest_ready)

    def test_connect_uses_engine_and_resets_previous_card(self):
        self.desk.credentials = {'password':'old'}
        status = self.request('/api/server/connect',{'host':'8.8.8.8','password':'only-in-job','fingerprint':'SHA256:'+'A'*43})[0]
        self.assertEqual(status,200); self.finished()
        self.assertTrue(self.desk.tor_verified)
        self.assertIsNotNone(self.desk.remote)
        self.assertIsNone(self.desk.credentials)
        self.assertNotIn('only-in-job',json.dumps(self.desk.state()))

    def test_usb_success_then_failure_never_retains_green_status(self):
        self.request('/api/usb/download',{}); self.finished()
        self.assertTrue(self.desk.usb_verified)
        self.request('/api/usb/write',{'selection':'opaque-selection','confirmation':'СТЕРЕТЬ'}); self.finished()
        self.assertTrue(self.desk.usb_written)
        def failed(*args):
            raise RuntimeError('Проверка не прошла')
        self.usb.write_verified_image = failed
        self.request('/api/usb/write',{'selection':'opaque-selection','confirmation':'СТЕРЕТЬ'}); self.finished()
        self.assertEqual(self.desk.job['state'],'error')
        self.assertFalse(self.desk.usb_written)
        self.usb.download_verified_image = failed
        self.request('/api/usb/download',{}); self.finished()
        self.assertEqual(self.desk.job['state'],'error')
        self.assertFalse(self.desk.usb_verified)

    def test_guest_success_then_timeout_is_not_ready(self):
        self.desk.remote = FakeRemote()
        original = self.engine.run
        self.engine.run = lambda remote, command, **kwargs: original(remote, command, **kwargs) if 'runtime-audit.py --json' in command else 'ГОТОВО: Telegram установлен; Tor подтверждён.'
        self.request('/api/server/action',{'action':'status'}); self.finished()
        self.assertTrue(self.desk.guest_ready)
        def failed(*args,**kwargs):
            raise TimeoutError('Соединение не ответило')
        self.engine.run = failed
        self.request('/api/server/action',{'action':'status'}); self.finished()
        self.assertEqual(self.desk.job['state'],'error')
        self.assertFalse(self.desk.guest_ready)

    def test_step_backgrounds_are_local_png_assets(self):
        for name in ('01-device','02-usb','03-purchase','04-setup','05-access','06-daily'):
            request = Request(self.server.origin+'/assets/steps/'+name+'.png')
            with urlopen(request,timeout=3) as response:
                self.assertEqual(response.status,200)
                self.assertEqual(response.headers.get_content_type(),'image/png')
                self.assertTrue(response.read().startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(self.request('/assets/steps/../app.py')[0],404)

    def test_failed_server_switch_cannot_install_on_previous_machine(self):
        closed = []
        old = FakeRemote()
        old.close = lambda: closed.append(True)
        self.desk.remote = old
        self.desk.credentials = {'password':'old-card'}
        self.desk.server_installed = True
        self.desk.guest_ready = True
        def failed(*args):
            raise RuntimeError('New machine did not authenticate')
        self.engine.connect = failed
        self.assertEqual(self.request('/api/server/connect',{
            'host':'8.8.8.8', 'password':'test-only',
            'fingerprint':'SHA256:' + 'A' * 43})[0],200)
        self.finished()
        self.assertEqual(self.desk.job['state'],'error')
        self.assertEqual(closed,[True])
        self.assertIsNone(self.desk.remote)
        self.assertIsNone(self.desk.credentials)
        self.assertFalse(self.desk.server_installed)
        self.assertFalse(self.desk.guest_ready)
        self.assertFalse(self.request('/api/state')[1]['server_connected'])
        self.assertEqual(self.request('/api/server/install',{
            'licenses':True,'fresh_server':True})[0],400)
        self.assertEqual(self.engine.commands,[])

    def test_rejected_concurrent_job_does_not_reset_existing_evidence(self):
        self.desk.usb_verified = True
        block = threading.Event()
        self.desk.start_job('slow',lambda event: block.wait(3))
        try:
            self.assertEqual(self.request('/api/usb/download',{})[0],400)
            self.assertTrue(self.desk.usb_verified)
        finally:
            block.set(); self.finished()

if __name__ == '__main__':
    unittest.main()
