import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[3] / 'client/launcher.py'
spec = importlib.util.spec_from_file_location('launcher', PATH)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def install_document():
    return {"version": 1, "unit": "oniondesk-install-0123abcd",
            "staging": "/var/tmp/oniondesk-input.A1b2C3d4", "sha256": "a" * 64}


class FakeSFTP:
    def __init__(self, files=None, directories=None, overrides=None):
        self.files = files or {}
        self.directories = directories or {}
        self.overrides = overrides or {}
        self.closed = False

    def lstat(self, path):
        if path in self.overrides:
            return self.overrides[path]
        if path in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR | self.directories[path], st_uid=0, st_size=0)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=len(self.files[path]))
        raise FileNotFoundError(path)

    def file(self, path, mode):
        return io.BytesIO(self.files[path])

    def close(self):
        self.closed = True


def credentials_sftp():
    return FakeSFTP({
        launcher.INSTALL_MARKER: b"2026-10-15T00:00:00+00:00\n",
        "/etc/oniondesk/credentials.json": json.dumps({
            "login": "owner", "password": "sample-password", "totp_secret": "A" * 32,
            "otpauth_uri": "otpauth://totp/OnionDesk?secret=" + "A" * 32,
        }).encode(),
        "/var/lib/tor/oniondesk/hostname": b"a" * 56 + b".onion\n",
    }, {"/etc/oniondesk": 0o700, "/var/lib/oniondesk": 0o711})


class ClientPrivacyTests(unittest.TestCase):
    def test_unknown_tor_mode_cannot_start_any_remote_work(self):
        with patch.object(launcher, 'run') as remote:
            with self.assertRaises(ValueError):
                launcher.install(Mock(), Mock(), tor_mode='direct;id')
        remote.assert_not_called()

    def test_rejects_non_public_addresses_and_shell_input(self):
        for value in ('127.0.0.1', '10.0.0.1', '169.254.169.254', 'http://example.org', '1.1.1.1;id', '::1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.validate_host(value)
        self.assertEqual(launcher.validate_host(' 1.1.1.1 '), '1.1.1.1')

    def test_fingerprint_required_not_auto_added(self):
        key = Mock()
        key.asbytes.return_value = b'test-public-key'
        expected = launcher.fingerprint(key)
        launcher.validate_fingerprint(expected)
        client = Mock()
        launcher.PinnedHostKey(expected).missing_host_key(client, 'host', key)
        client.get_host_keys().add.assert_called_once()
        wrong = launcher.PinnedHostKey('SHA256:' + 'A' * 43)
        with self.assertRaises(launcher.paramiko.SSHException):
            wrong.missing_host_key(client, 'host', key)

    def test_tor_check_cannot_fall_back_to_direct(self):
        session = Mock()
        session.get.side_effect = launcher.requests.ConnectionError('proxy unavailable')
        with patch.object(launcher.requests, 'Session', return_value=session):
            with self.assertRaises(RuntimeError):
                launcher.find_tor_proxy()
        self.assertEqual(session.get.call_count, 2)
        for call in session.get.call_args_list:
            self.assertEqual(call.args[0], 'https://check.torproject.org/api/ip')
            self.assertTrue(all(value.startswith('socks5h://127.0.0.1:') for value in call.kwargs['proxies'].values()))
        self.assertFalse(session.trust_env)

    def test_non_tor_response_is_rejected(self):
        session = Mock()
        session.get.return_value.json.return_value = {'IsTor': False}
        with patch.object(launcher.requests, 'Session', return_value=session):
            with self.assertRaises(RuntimeError):
                launcher.find_tor_proxy()

    def test_slow_tor_circuit_is_not_mistaken_for_an_absent_proxy(self):
        session = Mock()
        response = Mock()
        response.json.return_value = {'IsTor': True}
        def slow_circuit(_url, **kwargs):
            # Observed live SOCKS/TLS setup took 17 seconds. No wall-clock sleep.
            connect_timeout, read_timeout = kwargs['timeout']
            if connect_timeout < 17:
                raise launcher.requests.ConnectTimeout('Circuit is still building')
            self.assertLessEqual(connect_timeout, 60)
            self.assertLessEqual(read_timeout, 60)
            self.assertIsNot(kwargs.get('verify'), False)
            self.assertTrue(all(value.startswith('socks5h://127.0.0.1:')
                                for value in kwargs['proxies'].values()))
            return response
        session.get.side_effect = slow_circuit
        with patch.object(launcher.requests, 'Session', return_value=session):
            self.assertEqual(launcher.find_tor_proxy(), 9150)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.get.call_count, 1)

    def test_ssh_requires_the_verified_socks_socket(self):
        client, tunnel = Mock(), Mock()
        with patch.object(launcher.paramiko, 'SSHClient', return_value=client), patch.object(launcher.socks, 'socksocket', return_value=tunnel):
            launcher.connect('1.1.1.1', 'test-password', 'SHA256:' + 'A' * 43, 9150)
        tunnel.set_proxy.assert_called_once_with(launcher.socks.SOCKS5, '127.0.0.1', 9150, rdns=True)
        self.assertIs(client.connect.call_args.kwargs['sock'], tunnel)
        self.assertFalse(client.connect.call_args.kwargs['look_for_keys'])
        self.assertFalse(client.connect.call_args.kwargs['allow_agent'])

    def test_payload_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'server').mkdir()
            (root / 'frontend').mkdir()
            (root / 'server/external').symlink_to('/etc/passwd')
            with patch.object(launcher, 'KIT', root), self.assertRaises(RuntimeError):
                launcher.package_payload()

    def test_ssh_failure_closes_both_socket_and_client(self):
        client, tunnel = Mock(), Mock()
        client.connect.side_effect = launcher.paramiko.SSHException('key mismatch')
        with patch.object(launcher.paramiko, 'SSHClient', return_value=client), patch.object(launcher.socks, 'socksocket', return_value=tunnel):
            with self.assertRaises(launcher.paramiko.SSHException):
                launcher.connect('1.1.1.1', 'test-password', 'SHA256:' + 'A' * 43, 9150)
        client.close.assert_called_once()
        tunnel.close.assert_called_once()


class InstallerRecoveryTests(unittest.TestCase):
    def test_payload_contains_only_required_runtime_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in launcher.RUNTIME_FILES:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text("runtime file\n")
            (root / "server/credentials.json").write_text("private sentinel")
            (root / "server/.env").write_text("private sentinel")
            (root / "frontend/__pycache__").mkdir()
            (root / "frontend/__pycache__/private.pyc").write_bytes(b"private sentinel")
            with patch.object(launcher, "KIT", root):
                payload = launcher.package_payload()
            with launcher.tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                self.assertEqual(set(archive.getnames()), set(launcher.RUNTIME_FILES))
                self.assertTrue(all(member.isfile() for member in archive))
                for name in launcher.RUNTIME_FILES:
                    self.assertNotIn(b"private sentinel", archive.extractfile(name).read())

    def test_payload_rejects_missing_oversized_and_symlinked_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in launcher.RUNTIME_FILES:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b"runtime")
            first = root / launcher.RUNTIME_FILES[0]
            with patch.object(launcher, "KIT", root), patch.object(launcher, "MAX_RUNTIME_FILE", 3):
                with self.assertRaises(RuntimeError):
                    launcher.package_payload()
            first.unlink()
            with patch.object(launcher, "KIT", root), self.assertRaises(RuntimeError):
                launcher.package_payload()
            first.symlink_to(root / launcher.RUNTIME_FILES[1])
            with patch.object(launcher, "KIT", root), self.assertRaises(RuntimeError):
                launcher.package_payload()

    def test_sftp_timeout_precedes_subsystem_and_constructor(self):
        client, channel = Mock(), Mock()
        client.get_transport.return_value.open_session.return_value = channel
        order = []
        channel.settimeout.side_effect = lambda value: order.append(("timeout", value))
        channel.invoke_subsystem.side_effect = lambda value: order.append(("subsystem", value))
        with patch.object(launcher.paramiko, "SFTPClient", side_effect=lambda value: order.append(("client", value))):
            launcher.open_sftp(client)
        self.assertEqual(order, [("timeout", 60), ("subsystem", "sftp"), ("client", channel)])
        client.get_transport.return_value.open_session.assert_called_once_with(timeout=30)

    def test_unanswered_real_paramiko_subsystem_request_times_out(self):
        # A real Paramiko Channel waits forever for subsystem acknowledgement
        # despite settimeout(); the transport deliberately never acknowledges.
        channel = launcher.paramiko.Channel(7)
        transport = Mock()
        transport.get_log_channel.return_value = 'oniondesk.test.subsystem'
        channel._set_transport(transport)
        channel.remote_chanid = 8
        channel.active = True
        client = Mock()
        client.get_transport.return_value.open_session.return_value = channel
        with patch.object(launcher, 'CHANNEL_REQUEST_TIMEOUT', 0.03), \
                patch.object(launcher.paramiko, 'SFTPClient') as constructor:
            with self.assertRaises(TimeoutError):
                launcher.open_sftp(client)
        self.assertTrue(channel.closed)
        constructor.assert_not_called()

    def test_unanswered_real_paramiko_exec_request_times_out(self):
        channel = launcher.paramiko.Channel(9)
        transport = Mock()
        transport.get_log_channel.return_value = 'oniondesk.test.exec'
        channel._set_transport(transport)
        channel.remote_chanid = 10
        channel.active = True
        client = Mock()
        client.get_transport.return_value.open_session.return_value = channel
        with patch.object(launcher, 'CHANNEL_REQUEST_TIMEOUT', 0.03):
            with self.assertRaises(TimeoutError):
                launcher.run(client, 'true', timeout=1)
        self.assertTrue(channel.closed)

    def test_install_state_rejects_tampering_and_unexpected_fields(self):
        mutations = ({"unit": "other.service"}, {"unit": "oniondesk-install-deadbeef;id"},
                     {"staging": "/etc"}, {"staging": "/var/tmp/oniondesk-input.A1b2C3d4/../other"},
                     {"sha256": "wrong"}, {"version": True}, {"password": "private"})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = {**install_document(), **mutation}
                sftp = FakeSFTP({launcher.INSTALL_STATE_FILE: json.dumps(document).encode()},
                                {launcher.INSTALL_STATE_DIR: 0o700})
                with patch.object(launcher, "open_sftp", return_value=sftp), self.assertRaises(RuntimeError):
                    launcher._load_install_state(Mock())
                self.assertTrue(sftp.closed)

    def test_install_state_rejects_unsafe_permissions_links_and_duplicate_json(self):
        record = json.dumps(install_document()).encode()
        bad_metadata = (
            (launcher.INSTALL_STATE_DIR, stat.S_IFLNK | 0o700, 0),
            (launcher.INSTALL_STATE_DIR, stat.S_IFDIR | 0o755, 0),
            (launcher.INSTALL_STATE_FILE, stat.S_IFLNK | 0o600, 0),
            (launcher.INSTALL_STATE_FILE, stat.S_IFREG | 0o644, 0),
            (launcher.INSTALL_STATE_FILE, stat.S_IFREG | 0o600, 1000),
        )
        for path, mode, owner in bad_metadata:
            with self.subTest(path=path, mode=mode, owner=owner):
                sftp = FakeSFTP({launcher.INSTALL_STATE_FILE: record}, {launcher.INSTALL_STATE_DIR: 0o700},
                                {path: SimpleNamespace(st_mode=mode, st_uid=owner, st_size=len(record))})
                with patch.object(launcher, "open_sftp", return_value=sftp), self.assertRaises(RuntimeError):
                    launcher._load_install_state(Mock())
        duplicate = record[:-1] + b', "version": 1}'
        sftp = FakeSFTP({launcher.INSTALL_STATE_FILE: duplicate}, {launcher.INSTALL_STATE_DIR: 0o700})
        with patch.object(launcher, "open_sftp", return_value=sftp), self.assertRaises(RuntimeError):
            launcher._load_install_state(Mock())

    def test_incomplete_reservation_is_not_a_fresh_server(self):
        sftp = FakeSFTP(directories={launcher.INSTALL_STATE_DIR: 0o700})
        with patch.object(launcher, "open_sftp", return_value=sftp), self.assertRaises(RuntimeError):
            launcher._load_install_state(Mock())

    def test_existing_record_prevents_second_upload_and_installer(self):
        with patch.object(launcher, "_load_install_state", return_value=install_document()), \
                patch.object(launcher, "package_payload") as package, \
                patch.object(launcher, "_reserve_and_start_install") as start, \
                patch.object(launcher, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "второй установщик"):
                launcher.install(Mock(), Mock())
        package.assert_not_called()
        start.assert_not_called()
        run.assert_not_called()

    def test_remote_guard_rejects_legacy_unit_and_partial_install(self):
        for existing, units in ((True, ""), (False, "oniondesk-install-deadbeef.service loaded activating start")):
            with self.subTest(existing=existing, units=units), \
                    patch.object(os.path, "lexists", return_value=existing), \
                    patch.object(subprocess, "run", return_value=SimpleNamespace(stdout=units)), \
                    self.assertRaises(SystemExit):
                exec(launcher.INSTALL_GUARD, {})

    def test_reservation_is_exclusive_and_durable_before_systemd_starts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            staging = root / "staging"
            staging.mkdir(mode=0o700)
            archive = staging / "kit.tar.gz"
            archive.write_bytes(b"verified archive")
            archive.chmod(0o600)
            document = install_document()
            document["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(launcher, "run") as run:
                launcher._reserve_and_start_install(Mock(), document, "wizard")
            command = shlex.split(run.call_args.args[1])
            source = command[2].replace(launcher.INSTALL_GUARD, "import os, subprocess\n")
            state_dir = root / "state"
            source = source.replace('"/var/lib/oniondesk-client"', repr(str(state_dir)))
            snapshot = {**document, "staging": str(staging)}
            original_lstat = os.lstat

            def root_lstat(path, *args, **kwargs):
                metadata = original_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

            def systemd_start(arguments, **kwargs):
                saved = state_dir / "install-state.json"
                self.assertEqual(json.loads(saved.read_text()), snapshot)
                self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)
                self.assertEqual(arguments[0], "systemd-run")
                return SimpleNamespace(returncode=0)

            with patch("sys.argv", ["installer", json.dumps(snapshot), "wizard"]), \
                    patch.object(os, "lstat", side_effect=root_lstat), \
                    patch.object(os, "fsync") as sync, \
                    patch.object(subprocess, "run", side_effect=systemd_start) as start:
                exec(source, {})
                self.assertEqual(sync.call_count, 2)
                with self.assertRaises(SystemExit):
                    exec(source, {})
                self.assertEqual(start.call_count, 1)
            self.assertEqual(json.loads((state_dir / "install-state.json").read_text()), snapshot)

    def test_resume_observes_same_running_job_without_installing(self):
        running = "LoadState=loaded\nActiveState=activating\nSubState=start\nResult=success\nExecMainStatus=0\n"
        finished = "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n"
        commands = []

        def run(_client, command):
            commands.append(command)
            if command.startswith("/usr/bin/python3 -c") and '"systemctl", "show"' in command:
                return running if sum('"systemctl", "show"' in item for item in commands) == 1 else finished
            if command.startswith("journalctl"):
                return "Установка продолжается"
            self.fail("Resume attempted a mutation: " + command)

        with patch.object(launcher, "_load_install_state", return_value=install_document()), \
                patch.object(launcher, "run", side_effect=run), patch.object(launcher.time, "sleep"), \
                patch.object(launcher, "read_credentials", return_value={"url": "verified"}) as credentials:
            self.assertEqual(launcher.resume_install(Mock(), Mock()), {"url": "verified"})
        self.assertEqual(len(commands), 4)
        self.assertTrue(all("oniondesk-install-0123abcd" in command for command in commands))
        credentials.assert_called_once()

    def test_missing_job_after_reboot_never_redeploys(self):
        with patch.object(launcher, "_load_install_state", return_value=install_document()), \
                patch.object(launcher, "run", return_value="LoadState=not-found\nActiveState=inactive\n"), \
                patch.object(launcher, "read_credentials", side_effect=RuntimeError("No completion marker")), \
                patch.object(launcher, "_reserve_and_start_install") as start:
            with self.assertRaisesRegex(RuntimeError, "задача отсутствует"):
                launcher.resume_install(Mock(), Mock())
            with self.assertRaisesRegex(RuntimeError, "второй установщик"):
                launcher.install(Mock(), Mock())
        start.assert_not_called()

    def test_missing_finished_job_requires_valid_completion_marker(self):
        with patch.object(launcher, "_load_install_state", return_value=install_document()), \
                patch.object(launcher, "run", return_value="LoadState=not-found\n"), \
                patch.object(launcher, "open_sftp", return_value=credentials_sftp()):
            self.assertEqual(launcher.resume_install(Mock(), Mock())["login"], "owner")

    def test_failed_job_cannot_return_credentials(self):
        failed = "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\n"
        with patch.object(launcher, "_load_install_state", return_value=install_document()), \
                patch.object(launcher, "run", side_effect=[failed, "Installation failed"]), \
                patch.object(launcher, "read_credentials") as credentials:
            with self.assertRaisesRegex(RuntimeError, "завершилась ошибкой"):
                launcher.resume_install(Mock(), Mock())
        credentials.assert_not_called()

    def test_credentials_require_private_complete_marker(self):
        with patch.object(launcher, "open_sftp", return_value=credentials_sftp()):
            self.assertEqual(launcher.read_credentials(Mock())["url"], "http://" + "a" * 56 + ".onion/")
        for failure in ("missing", "permissions", "owner", "symlink", "invalid-date"):
            with self.subTest(failure=failure):
                sftp = credentials_sftp()
                if failure == "missing":
                    del sftp.files[launcher.INSTALL_MARKER]
                elif failure == "invalid-date":
                    sftp.files[launcher.INSTALL_MARKER] = b"2026-99-15T00:00:00+00:00\n"
                else:
                    mode = stat.S_IFREG | (0o644 if failure == "permissions" else 0o600)
                    if failure == "symlink":
                        mode = stat.S_IFLNK | 0o600
                    sftp.overrides[launcher.INSTALL_MARKER] = SimpleNamespace(
                        st_mode=mode, st_uid=1000 if failure == "owner" else 0,
                        st_size=len(sftp.files[launcher.INSTALL_MARKER]))
                with patch.object(launcher, "open_sftp", return_value=sftp), self.assertRaises(RuntimeError):
                    launcher.read_credentials(Mock())
                self.assertTrue(sftp.closed)


if __name__ == '__main__':
    unittest.main()
