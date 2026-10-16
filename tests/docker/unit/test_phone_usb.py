import base64
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'client'))
import phone_usb as phone


USB = b'List of devices attached\nPRIVATE_SERIAL device usb:1-2 product:test model:SECRET_MODEL device:test transport_id:4\n'


class PhoneUSBTests(unittest.TestCase):
    def test_scan_is_opaque_and_usb_only(self):
        rows = phone._parse_devices(USB + b'192.0.2.1:5555 device product:test transport_id:5\nemulator-5570 device product:test transport_id:6\n')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].serial, 'PRIVATE_SERIAL')
        self.assertNotIn('PRIVATE_SERIAL', repr(rows))
        self.assertNotIn('SECRET_MODEL', repr(rows))
        self.assertTrue(phone._ID.fullmatch(rows[0].identifier))

    def test_emulator_hook_is_exact(self):
        raw = b'List of devices attached\nemulator-5570 device transport_id:6\nemulator-5572 device transport_id:7\n'
        self.assertEqual([row.serial for row in phone._parse_devices(raw, emulator_serial='emulator-5570')], ['emulator-5570'])
        with self.assertRaises(phone.PhoneError):
            phone.PhoneUSBController(_test_emulator_serial='192.0.2.1:5555')

    def test_malformed_or_duplicate_transport_fails(self):
        for raw in (USB + USB.split(b'\n')[1] + b'\n', USB.replace(b'transport_id:4', b'transport_id:;bad'), b'unknown\n'):
            with self.subTest(raw=raw), self.assertRaises(phone.PhoneError):
                phone._parse_devices(raw)

    def test_status_has_no_commands_or_workspace_creation(self):
        with patch.object(phone.subprocess, 'run', side_effect=AssertionError), patch.object(phone.subprocess, 'Popen', side_effect=AssertionError), patch.object(phone._EncryptedSession, 'open', side_effect=AssertionError):
            result = phone.PhoneUSBController().status()
        self.assertFalse(result['session_open'])
        self.assertFalse(result['tor_ready'])
        self.assertIn('guidance', result)

    @staticmethod
    def _fixture_public_key(comment=b'oniondesk@local'):
        # Synthetic Android public-key structure: no actual RSA key material.
        raw = (64).to_bytes(4, 'little') + b'\0' * 516 + (65537).to_bytes(4, 'little')
        return base64.b64encode(raw) + b' ' + comment

    def test_adb_identity_environment_ignores_host_account_names(self):
        home = Path('/fixture/encrypted/home')
        android, temporary = home / '.android', home / 'tmp'
        identity = {'HOSTNAME': 'local', 'LOGNAME': 'oniondesk', 'USER': 'oniondesk',
                    'USERNAME': 'oniondesk', 'COMPUTERNAME': 'local'}
        inherited = {key: 'SYNTHETIC_HOST_IDENTITY' for key in identity}
        for name in ('posix', 'nt'):
            with self.subTest(system=name), patch.dict(phone.os.environ, inherited), patch.object(phone.os, 'name', name):
                environment = phone._adb_environment(home, android, temporary)
                self.assertEqual({key: environment[key] for key in identity}, identity)
                self.assertEqual(environment['HOME'], str(home))
                self.assertEqual(environment['ADB_VENDOR_KEYS'], str(android / 'adbkey'))
                self.assertNotIn('SYNTHETIC_HOST_IDENTITY', environment.values())

    def test_public_key_requires_exact_neutral_comment_and_android_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'adbkey.pub'
            path.write_bytes(self._fixture_public_key())
            path.chmod(0o600)
            self.assertIsNone(phone._validate_public_key(path))
            invalid = [self._fixture_public_key(b'SYNTHETIC_USER@SYNTHETIC_HOST'),
                       self._fixture_public_key(b'oniondesk@local extra'),
                       self._fixture_public_key() + b'\0',
                       self._fixture_public_key() + b'\nextra',
                       b'!' * 700 + b' oniondesk@local',
                       base64.b64encode(b'\0' * 524) + b' oniondesk@local',
                       b'x' * 1025]
            for index, content in enumerate(invalid):
                with self.subTest(case=index):
                    path.write_bytes(content)
                    with self.assertRaises(phone.PhoneError) as caught:
                        phone._validate_public_key(path)
                    self.assertNotIn('SYNTHETIC_', str(caught.exception))

    def test_public_key_rejects_nonprivate_file_links(self):
        if os.name == 'nt':
            self.skipTest('POSIX permissions/link fixture; Windows uses the existing private ACL verifier')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'adbkey.pub'
            path.write_bytes(self._fixture_public_key())
            path.chmod(0o644)
            with self.assertRaises(phone.PhoneError):
                phone._validate_public_key(path)
            path.chmod(0o600)
            linked = path.with_name('linked.pub')
            linked.symlink_to(path)
            with self.assertRaises(phone.PhoneError):
                phone._validate_public_key(linked)
            linked.unlink()
            os.link(path, linked)
            with self.assertRaises(phone.PhoneError):
                phone._validate_public_key(path)

    def _identity_start_fixture(self, root, comment):
        base = root / 'session'
        base.mkdir(mode=0o700)
        private = base / 'private'
        private.mkdir(mode=0o700)
        store = Mock(base=base)
        store.open.return_value = private
        controller = phone.PhoneUSBController(_store_factory=lambda: store)
        environments = []
        def keygen(arguments, *, environment, timeout):
            self.assertIn('keygen', arguments)
            environments.append(environment)
            key = Path(arguments[-1])
            key.write_bytes(b'fixture-private-key-not-an-actual-RSA-key')
            key.chmod(0o600)
            key.with_suffix('.pub').write_bytes(self._fixture_public_key(comment))
            key.with_suffix('.pub').chmod(0o600)
            return subprocess.CompletedProcess(arguments, 0, b'', b'')
        return controller, store, environments, keygen

    def test_non_neutral_key_comment_blocks_daemon_before_any_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, store, environments, keygen = self._identity_start_fixture(Path(directory).resolve(), b'SYNTHETIC_USER@SYNTHETIC_HOST')
            with patch.object(phone.offline, '_find_root', return_value=Path(directory)), patch.object(phone, '_platform_key', return_value='macos'), patch.object(phone, '_copy_asset'), patch.object(phone, '_extract_tools', return_value=Path('/fixture/adb')), patch.object(phone, '_run_limited', side_effect=keygen), patch.object(phone.subprocess, 'Popen') as daemon, patch.object(phone.socket, 'socket') as reservation:
                with self.assertRaises(phone.PhoneError):
                    controller._start(None)
            daemon.assert_not_called()
            reservation.assert_not_called()
            store.close.assert_called_once()
            self.assertEqual(environments[0]['HOSTNAME'], 'local')
            self.assertEqual(environments[0]['LOGNAME'], 'oniondesk')

    def test_keygen_and_daemon_share_neutral_identity_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, store, environments, keygen = self._identity_start_fixture(Path(directory).resolve(), b'oniondesk@local')
            controller._owned = Mock()
            controller._command = Mock(return_value=subprocess.CompletedProcess([], 0, b'Version 37.0.1', b''))
            process = Mock()
            process.poll.return_value = 0
            with patch.object(phone.offline, '_find_root', return_value=Path(directory)), patch.object(phone, '_platform_key', return_value='macos'), patch.object(phone, '_copy_asset'), patch.object(phone, '_extract_tools', return_value=Path('/fixture/adb')), patch.object(phone, '_run_limited', side_effect=keygen), patch.object(phone.subprocess, 'Popen', return_value=process) as daemon:
                controller._start(None)
            self.assertEqual(daemon.call_args.args[0][-2:], ['server', 'nodaemon'])
            self.assertIs(daemon.call_args.kwargs['env'], environments[0])
            self.assertEqual(daemon.call_args.kwargs['env']['COMPUTERNAME'], 'local')
            self.assertEqual(daemon.call_args.kwargs['env']['USERNAME'], 'oniondesk')
            with patch.object(phone, '_port_listening', return_value=False):
                controller.close()
            store.close.assert_called_once()

    def test_linux_arm64_fails_honestly(self):
        with patch.object(phone.platform, 'system', return_value='Linux'), patch.object(phone.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(phone.PhoneError, 'ARM64'):
                phone._platform_key()

    def test_copy_verifies_compiled_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root/'public').write_bytes(b'public-data')
            record = {'path':'public','size_bytes':11,'sha256':hashlib.sha256(b'public-data').hexdigest()}
            phone._copy_asset(root, record, root/'copy')
            record['sha256'] = '0'*64
            with self.assertRaises(phone.PhoneError):
                phone._copy_asset(root, record, root/'changed')

    def test_zip_traversal_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for index,name in enumerate(('../adb','/adb','platform-tools/adb')):
                archive=root/f'{index}.zip'
                with zipfile.ZipFile(archive,'w') as bundle:
                    row=zipfile.ZipInfo(name)
                    if index==2: row.external_attr = (0o120777 << 16)
                    bundle.writestr(row,b'unsafe')
                with self.subTest(name=name), self.assertRaises(phone.PhoneError):
                    phone._extract_tools(archive,root)

    def test_only_pinned_adb_runtime_paths_are_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'tools.zip';destination=root/'runtime';destination.mkdir()
            with zipfile.ZipFile(archive,'w') as bundle:
                bundle.writestr('platform-tools/adb',b'fixture-adb')
                bundle.writestr('platform-tools/lib64/libc++.so',b'fixture-runtime')
                bundle.writestr('platform-tools/fastboot',b'not-used')
            with patch.object(phone.platform,'system',return_value='Linux'):
                self.assertEqual(phone._extract_tools(archive,destination),destination/'adb')
            self.assertEqual((destination/'lib64/libc++.so').read_bytes(),b'fixture-runtime')
            self.assertFalse((destination/'fastboot').exists())

    def test_foreign_server_prevents_client_command(self):
        controller=phone.PhoneUSBController()
        controller._owned=Mock(side_effect=phone.PhoneError('ownership failed'))
        with patch.object(phone.subprocess,'run') as run, self.assertRaises(phone.PhoneError):
            controller._command(['devices','-l'])
        run.assert_not_called()

    def test_client_has_explicit_numeric_host_private_port(self):
        controller=phone.PhoneUSBController();controller._owned=Mock();controller._binary=Path('/private/adb');controller._port=59123;controller._environment={'HOME':'/private/encrypted'}
        with patch.object(phone,'_run_limited',return_value=subprocess.CompletedProcess([],0,b'ok',b'')) as run:
            controller._command(['devices','-l'])
        args=run.call_args.args[0]
        self.assertEqual(args[1:5],['-H','127.0.0.1','-P','59123'])
        self.assertNotIn('start-server',args)
        self.assertNotIn('kill-server',args)
        self.assertEqual(controller._owned.call_count,2)

    def test_install_requires_fresh_same_usb_transport(self):
        selected=phone._parse_devices(USB)[0];controller=phone.PhoneUSBController()
        controller._command=Mock(return_value=subprocess.CompletedProcess([],0,USB.replace(b'transport_id:4',b'transport_id:5'),b''))
        with self.assertRaises(phone.PhoneError): controller._fresh_device(selected)
        controller._command.assert_called_once_with(['devices','-l'])

    def test_install_rejects_unauthorized_and_stale(self):
        selected=phone._parse_devices(USB)[0];controller=phone.PhoneUSBController()
        controller._command=Mock(return_value=subprocess.CompletedProcess([],0,USB.replace(b'device usb:',b'unauthorized usb:'),b''))
        with self.assertRaises(phone.PhoneError): controller._fresh_device(selected)
        stale=phone._Device(selected.identifier,selected.serial,selected.transport,selected.state,selected.label,time.monotonic()-301)
        controller._command.reset_mock()
        with self.assertRaises(phone.PhoneError): controller._fresh_device(stale)
        controller._command.assert_not_called()

    def test_opaque_public_state(self):
        controller=phone.PhoneUSBController();row=phone._parse_devices(USB)[0];controller._devices={row.identifier:row}
        result=str(controller.status())
        self.assertNotIn('PRIVATE_SERIAL',result);self.assertNotIn('SECRET_MODEL',result)

    def test_close_failure_retains_store_and_blocks_next_job(self):
        controller=phone.PhoneUSBController();store=Mock();store.close.side_effect=phone.PhoneError('busy');controller._store=store
        with self.assertRaises(phone.PhoneError):controller.close()
        self.assertIs(controller._store,store);self.assertTrue(controller.status()['cleanup_required'])
        with self.assertRaises(phone.PhoneError):controller.list_devices()

    def test_exact_process_close_no_global_kill(self):
        controller=phone.PhoneUSBController();process=Mock();process.poll.return_value=None;controller._process=process;controller._guard=Mock();controller._store=Mock()
        with patch.object(phone.subprocess,'run') as run: controller.close()
        process.terminate.assert_called_once();process.wait.assert_called_once_with(timeout=10);run.assert_not_called()

    def test_non_mac_attestation_failure_creates_no_keys_or_store(self):
        store=phone._EncryptedSession()
        with patch.object(phone.platform,'system',return_value='Linux'),patch.object(phone,'attest_encrypted_storage',return_value={'ok':False}),patch.object(phone,'_private_directory') as mkdir:
            with self.assertRaises(phone.PhoneError):store.open()
        mkdir.assert_not_called();self.assertFalse(store.created)

    def test_busy_close_never_stops_running_install(self):
        controller=phone.PhoneUSBController();controller._operation_lock.acquire()
        try:
            with self.assertRaises(phone.PhoneError):controller.close()
        finally:controller._operation_lock.release()


    def _installer_fixture(self, root):
        controller=phone.PhoneUSBController();row=phone._parse_devices(USB)[0]
        controller._devices={row.identifier:row};controller._store=Mock(base=root)
        controller._fresh_device=Mock(return_value=['-t','4'])
        return controller,row

    def test_install_verified_apk_preserves_profile_and_does_not_claim_tor_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            controller,row=self._installer_fixture(Path(directory))
            commands=[]
            def command(args,**kwargs):
                commands.append(args)
                if args[2:]==['shell','getprop','ro.product.cpu.abilist']: data=b'arm64-v8a,armeabi-v7a\n'
                elif args[2:4]==['install','-r']: data=b'Success\n'
                elif args[2:4]==['shell','dumpsys']: data=b'    versionName=15.0.25\n'
                else: data=b'Status: ok\n'
                return subprocess.CompletedProcess(args,0,data,b'')
            controller._command=command
            with patch.dict(phone.catalog.APKS,{'arm64-v8a':{'path':'a'}},clear=True),patch.dict(phone.catalog.SIGNATURES,{'arm64-v8a':{'path':'b'}},clear=True),patch.object(phone,'_copy_asset'),patch.object(phone.offline,'_verify_tor_signature') as gpg:
                result=controller.install(row.identifier)
            gpg.assert_called_once()
            installs=[args for args in commands if 'install' in args]
            self.assertEqual(len(installs),1);self.assertEqual(installs[0][:4],['-t','4','install','-r'])
            self.assertFalse(any(flag in installs[0] for flag in ('-d','--downgrade','uninstall')))
            self.assertTrue(result['installed']);self.assertFalse(result['tor_ready'])
            self.assertEqual(controller._fresh_device.call_count,3)

    def test_bad_signature_never_installs(self):
        with tempfile.TemporaryDirectory() as directory:
            controller,row=self._installer_fixture(Path(directory))
            controller._command=Mock(return_value=subprocess.CompletedProcess([],0,b'arm64-v8a\n',b''))
            with patch.dict(phone.catalog.APKS,{'arm64-v8a':{}},clear=True),patch.dict(phone.catalog.SIGNATURES,{'arm64-v8a':{}},clear=True),patch.object(phone,'_copy_asset'),patch.object(phone.offline,'_verify_tor_signature',side_effect=phone.offline.OfflineError('bad')):
                with self.assertRaises(phone.PhoneError):controller.install(row.identifier)
            self.assertEqual(controller._command.call_count,1)
            self.assertFalse(controller.status()['installed'])

    @staticmethod
    def _successful_command(args, **kwargs):
        if 'getprop' in args:
            data = b'arm64-v8a\n'
        elif 'install' in args:
            data = b'Success\n'
        elif 'dumpsys' in args:
            data = b'    versionName=15.0.25\n'
        else:
            data = b'Status: ok\n'
        return subprocess.CompletedProcess(args, 0, data, b'')

    def _install_successfully(self, controller, row):
        controller._command = Mock(side_effect=self._successful_command)
        with patch.dict(phone.catalog.APKS, {'arm64-v8a': {'path': 'fixture.apk'}}, clear=True), patch.dict(phone.catalog.SIGNATURES, {'arm64-v8a': {'path': 'fixture.apk.asc'}}, clear=True), patch.object(phone, '_copy_asset'), patch.object(phone.offline, '_verify_tor_signature'):
            return controller.install(row.identifier)

    def test_close_and_scan_second_phone_cannot_reuse_first_installation(self):
        second = USB.replace(b'PRIVATE_SERIAL', b'SECOND_PRIVATE_SERIAL').replace(b'transport_id:4', b'transport_id:7')
        with tempfile.TemporaryDirectory() as directory:
            controller, first = self._installer_fixture(Path(directory))
            self.assertTrue(self._install_successfully(controller, first)['installed'])
            controller.close()
            self.assertFalse(controller.status()['installed'])
            controller._start = Mock()
            controller._command = Mock(return_value=subprocess.CompletedProcess([], 0, second, b''))
            result = controller.list_devices()
            self.assertEqual(len(result['devices']), 1)
            self.assertNotEqual(result['devices'][0]['id'], first.identifier)
            self.assertFalse(result['installed'])
            self.assertNotIn('PRIVATE_SERIAL', str(result))
            with self.assertRaises(phone.PhoneError):
                controller.install(first.identifier)
            self.assertFalse(controller.status()['installed'])

    def test_failed_rescan_clears_installation_before_refresh_or_command(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, first = self._installer_fixture(Path(directory))
            self.assertTrue(self._install_successfully(controller, first)['installed'])
            controller._start = Mock(side_effect=phone.PhoneError('new scan unavailable'))
            with self.assertRaises(phone.PhoneError):
                controller.list_devices()
            result = controller.status()
            self.assertFalse(result['installed'])
            self.assertEqual(result['devices'], [])
            self.assertNotIn('установлен и открыт', result['message'])

    def test_launch_failure_retains_only_current_device_version_confirmation(self):
        second = phone._parse_devices(USB.replace(b'PRIVATE_SERIAL', b'SECOND_PRIVATE_SERIAL').replace(b'transport_id:4', b'transport_id:7'))[0]
        with tempfile.TemporaryDirectory() as directory:
            controller, first = self._installer_fixture(Path(directory))
            def command(args, **kwargs):
                if 'am' in args:
                    return subprocess.CompletedProcess(args, 1, b'Error: launch rejected', b'')
                return self._successful_command(args, **kwargs)
            controller._command = Mock(side_effect=command)
            with patch.dict(phone.catalog.APKS, {'arm64-v8a': {'path': 'fixture.apk'}}, clear=True), patch.dict(phone.catalog.SIGNATURES, {'arm64-v8a': {'path': 'fixture.apk.asc'}}, clear=True), patch.object(phone, '_copy_asset'), patch.object(phone.offline, '_verify_tor_signature'):
                with self.assertRaises(phone.PhoneError):
                    controller.install(first.identifier)
            self.assertTrue(controller.status()['installed'])
            controller._devices = {second.identifier: second}
            self.assertFalse(controller.status()['installed'])
            self.assertNotIn('PRIVATE_SERIAL', str(controller.status()))

    def test_disconnected_target_after_version_proof_has_no_installation_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, first = self._installer_fixture(Path(directory))
            controller._fresh_device = Mock(side_effect=[['-t', '4'], ['-t', '4'], phone.PhoneError('target disconnected')])
            with self.assertRaises(phone.PhoneError):
                self._install_successfully(controller, first)
            self.assertFalse(controller.status()['installed'])
            self.assertFalse(any('am' in call.args[0] for call in controller._command.call_args_list))

    def test_confirmation_is_bound_to_private_transport_and_session(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, first = self._installer_fixture(Path(directory))
            self.assertTrue(self._install_successfully(controller, first)['installed'])
            for serial, transport in [('SECOND_PRIVATE_SERIAL', first.transport), (first.serial, '7')]:
                changed = phone._Device(first.identifier, serial, transport, first.state, first.label, first.scanned)
                controller._devices = {changed.identifier: changed}
                with self.subTest(transport=transport):
                    self.assertFalse(controller.status()['installed'])
            controller._devices = {first.identifier: first}
            previous_session = controller._store
            controller._store = Mock(base=Path(directory))
            self.assertFalse(controller.status()['installed'])
            controller._store = previous_session
            snapshot = controller.status()
            self.assertTrue(snapshot['installed'])
            snapshot['installed'] = False
            snapshot['devices'][0]['id'] = 'changed-public-copy'
            current = controller.status()
            self.assertTrue(current['installed'])
            self.assertEqual(current['devices'][0]['id'], first.identifier)
            self.assertNotIn('PRIVATE_SERIAL', str(current))

    def test_still_listening_port_blocks_store_deletion(self):
        controller=phone.PhoneUSBController();controller._port=59123;controller._store=Mock()
        with patch.object(phone,'_port_listening',return_value=True),self.assertRaises(phone.PhoneError):controller.close()
        controller._store.close.assert_not_called()
        self.assertTrue(controller.status()['cleanup_required'])

    def test_mac_detach_failure_never_deletes_store(self):
        store=phone._EncryptedSession();store.created=True;store.vault=Mock();store.vault.close.side_effect=phone.WalletError('busy')
        with patch.object(phone.shutil,'rmtree') as delete,self.assertRaises(phone.PhoneError):store.close()
        delete.assert_not_called();self.assertTrue(store.created)

    def test_child_output_limit_is_enforced(self):
        with self.assertRaises(phone.PhoneError):
            phone._run_limited([sys.executable,'-c','import sys; sys.stdout.buffer.write(b"x" * (3*1024*1024))'],environment={},timeout=5)


if __name__ == '__main__': unittest.main()
