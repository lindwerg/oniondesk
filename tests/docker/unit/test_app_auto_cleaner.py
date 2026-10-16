"""The launcher shows actual automatic-cleaner health, never a stale success."""
import copy
import json
import threading
import unittest
import test_app as fixtures
from test_app_phone import FakePhone


def report(watch_error=False):
    return {'installed': True, 'enabled': True, 'running': True, 'user_session': True,
            'auto_cleaner': not watch_error,
            'report': {'pending': 1, 'processing': 0, 'cleaned': 2, 'failed': 0,
                       'unsupported': 0, 'downloading': 0, 'watch_error': watch_error,
                       'scan_limited': False, 'capacity_reached': False,
                       'last_result': 'waiting', 'updated_at': '2026-10-15T17:00:00+00:00'}}


class AutomaticCleanerAPI(unittest.TestCase):
    request = fixtures.LocalAPITest.request
    finished = fixtures.LocalAPITest.finished
    tearDown = fixtures.LocalAPITest.tearDown

    def setUp(self):
        self.engine = fixtures.FakeEngine()
        self.desk = fixtures.app.Desk(fixtures.FakeUSB(), self.engine, fixtures.FakeOffline(),
                                     fixtures.FakeWallet(), phones=FakePhone())
        self.desk.remote = fixtures.FakeRemote()
        self.server = fixtures.app.LocalServer(self.desk)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def test_valid_unhealthy_report_keeps_counters_without_green_health(self):
        self.desk._set_auto_cleaner(json.dumps(report(True)))
        self.assertFalse(self.desk.auto_cleaner['auto_cleaner'])
        self.assertTrue(self.desk.auto_cleaner['report']['watch_error'])
        self.assertEqual(self.desk.auto_cleaner['report']['cleaned'], 2)

    def test_malformed_or_private_fields_clear_prior_confirmation(self):
        for mutate in (lambda value: value.update(auto_cleaner=False),
                       lambda value: value['report'].update(filename='private-sentinel.png'),
                       lambda value: value['report'].update(cleaned=True),
                       lambda value: value['report'].update(pending=-1)):
            value = copy.deepcopy(report())
            mutate(value)
            self.desk.auto_cleaner = report()
            with self.assertRaises(RuntimeError):
                self.desk._set_auto_cleaner(json.dumps(value))
            self.assertIsNone(self.desk.auto_cleaner)
            self.assertNotIn('private-sentinel', json.dumps(self.desk.state()))

    def test_nonce_origin_and_fixed_command(self):
        path, fields = '/api/server/action', {'action': 'auto-cleaner'}
        self.assertEqual(self.request(path, fields, nonce=False)[0], 403)
        self.assertEqual(self.request(path, fields, origin=False)[0], 403)
        commands = []
        def run(remote, command, timeout=0):
            commands.append(command)
            return json.dumps(report())
        self.engine.run = run
        self.assertEqual(self.request(path, fields)[0], 200)
        self.finished()
        self.assertEqual(commands, ['sudo /opt/oniondesk/server/control.sh auto-cleaner'])
        self.assertTrue(self.desk.auto_cleaner['auto_cleaner'])
        self.engine.run = lambda *args, **kwargs: 'not a report'
        self.assertEqual(self.request(path, fields)[0], 200)
        self.finished()
        self.assertEqual(self.desk.job['state'], 'error')
        self.assertIsNone(self.desk.auto_cleaner)
