import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

KIT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('automatic_metadata_cleaner', KIT / 'server/guest-auto-cleaner.py')
auto = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auto)


class AutomaticMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.clock = 100.0
        self.engine = mock.Mock()
        self.engine.TYPES = {'.jpg': None, '.jpeg': None, '.png': None, '.pdf': None, '.docx': None}
        self.engine.MAX_INPUT = 50 * 1024 * 1024
        self.watcher = auto.Watcher(self.home, self.engine, clock=lambda: self.clock)
        self.addCleanup(self.watcher.close)
        self.addCleanup(self.temp.cleanup)
        self.source = self.home / 'Downloads/private-name.png'
        self.source.write_bytes(b'not-yet-finished')

    def scan(self, seconds=0):
        self.clock += seconds
        self.watcher.scan()

    def cleaned(self, *_args, **_kwargs):
        output = self.home / 'OnionDesk-Clean/file-0123456789abcdef01234567.png'
        output.parent.mkdir(mode=0o700, exist_ok=True)
        output.write_bytes(b'clean-copy')
        output.chmod(0o600)
        return output

    def test_stable_debounce_duplicate_and_private_mapping(self):
        self.engine.clean_file.side_effect = self.cleaned
        original = self.source.stat()
        self.scan()
        self.assertEqual(self.watcher.report()['pending'], 1)
        self.scan(5)
        self.engine.clean_file.assert_not_called()
        self.scan(1)
        self.engine.clean_file.assert_called_once()
        self.scan(30)
        self.engine.clean_file.assert_called_once()
        self.assertEqual(self.watcher.report()['cleaned'], 1)
        after = self.source.stat()
        self.assertEqual((original.st_mtime_ns, original.st_ctime_ns), (after.st_mtime_ns, after.st_ctime_ns))
        public = (self.watcher.state_dir / 'report.json').read_text()
        self.assertNotIn('private-name', public)
        self.assertNotIn(str(self.home), public)
        history = json.loads((self.watcher.state_dir / 'history.json').read_text())
        self.assertEqual(history['entries']['Downloads/private-name.png']['output'], 'file-0123456789abcdef01234567.png')
        mapping = self.home / '.local/state/oniondesk/auto-clean/Соответствия файлов.txt'
        self.assertIn('Downloads/private-name.png', mapping.read_text())
        self.assertIn('file-0123456789abcdef01234567.png', mapping.read_text())
        self.assertEqual(stat.S_IMODE(mapping.stat().st_mode), 0o600)
        output_names = [item.name for item in (self.home / 'OnionDesk-Clean').iterdir()]
        self.assertEqual(output_names, ['file-0123456789abcdef01234567.png'])
        self.assertNotIn('private-name', json.dumps(output_names))
        self.assertNotIn('Соответствия', json.dumps(output_names, ensure_ascii=False))
        for name in ('report.json', 'history.json'):
            self.assertEqual(stat.S_IMODE((self.watcher.state_dir / name).stat().st_mode), 0o600)

    def test_partial_writes_reset_debounce_and_temporary_downloads_wait(self):
        self.engine.clean_file.side_effect = self.cleaned
        partial = self.home / 'Downloads/document.pdf.part'
        partial.write_bytes(b'partial')
        self.scan()
        self.scan(5)
        self.source.write_bytes(b'now-finished')
        self.scan(1)
        self.scan(5)
        self.engine.clean_file.assert_not_called()
        self.scan(1)
        self.engine.clean_file.assert_called_once()
        self.assertEqual(self.watcher.report()['downloading'], 1)

    def test_failure_is_not_clean_and_does_not_retry_until_change(self):
        self.engine.clean_file.side_effect = RuntimeError('private-sensitive-exception')
        self.scan()
        self.scan(6)
        self.scan(100)
        self.engine.clean_file.assert_called_once()
        self.assertEqual(self.watcher.report()['failed'], 1)
        self.assertEqual(self.watcher.report()['cleaned'], 0)
        self.assertNotIn('private-sensitive', (self.watcher.state_dir / 'history.json').read_text())
        self.source.write_bytes(b'changed-source')
        self.scan()
        self.scan(6)
        self.assertEqual(self.engine.clean_file.call_count, 2)

    def test_symlink_fifo_hardlink_unsupported_oversize_are_not_cleaned(self):
        self.source.unlink()
        external = self.home / 'outside.png'
        external.write_bytes(b'outside')
        downloads = self.home / 'Downloads'
        (downloads / 'link.png').symlink_to(external)
        os.mkfifo(downloads / 'pipe.png')
        os.link(external, downloads / 'hard.png')
        (downloads / 'archive.zip').write_bytes(b'zip')
        with (downloads / 'large.png').open('wb') as stream:
            stream.truncate(self.engine.MAX_INPUT + 1)
        self.scan()
        self.scan(6)
        self.engine.clean_file.assert_not_called()
        self.assertEqual(self.watcher.report()['failed'], 4)
        self.assertEqual(self.watcher.report()['unsupported'], 1)

    def test_nested_folders_and_symlink_watch_directory_are_not_followed(self):
        self.source.unlink()
        other = self.home / 'Downloads/nested'
        other.mkdir()
        (other / 'private.png').write_bytes(b'nested')
        telegram = self.home / 'Downloads/Telegram Desktop'
        telegram.rmdir()
        telegram.symlink_to(other, target_is_directory=True)
        self.scan()
        self.scan(6)
        self.engine.clean_file.assert_not_called()
        self.assertTrue(self.watcher.report()['watch_error'])

    def test_mutation_during_cleaning_removes_output_and_waits_again(self):
        def mutate(*args, **kwargs):
            output = self.cleaned(*args, **kwargs)
            self.source.write_bytes(b'mutation-during-worker')
            return output
        self.engine.clean_file.side_effect = mutate
        self.scan()
        self.scan(6)
        self.assertEqual(self.watcher.report()['cleaned'], 0)
        self.assertEqual(self.watcher.report()['pending'], 1)
        self.assertFalse(list((self.home / 'OnionDesk-Clean').glob('file-*')))
        self.scan(1)
        self.assertEqual(self.engine.clean_file.call_count, 1)

    def test_restart_does_not_publish_duplicate_and_state_symlink_is_rejected(self):
        self.engine.clean_file.side_effect = self.cleaned
        self.scan()
        self.scan(6)
        self.watcher.close()
        self.watcher = auto.Watcher(self.home, self.engine, clock=lambda: self.clock)
        self.scan(10)
        self.engine.clean_file.assert_called_once()
        self.watcher.close()
        report = self.watcher.state_dir / 'report.json'
        report.unlink()
        report.symlink_to(self.home / 'untouched')
        with self.assertRaises(auto.SafetyError):
            auto.Watcher(self.home, self.engine, clock=lambda: self.clock)
        self.assertFalse((self.home / 'untouched').exists())

    def test_removed_pending_download_does_not_remain_pending_forever(self):
        self.scan()
        self.source.unlink()
        self.scan(6)
        self.engine.clean_file.assert_not_called()
        self.assertEqual(self.watcher.report()['pending'], 0)
        self.assertEqual(self.watcher.report()['failed'], 1)

    def test_transient_processing_report_failure_restores_failed_checkpoint_and_health(self):
        self.engine.clean_file.side_effect = self.cleaned
        self.scan()
        original_write = auto.atomic_private_write
        failures = 0

        def fail_first_processing_report(path, encoded):
            nonlocal failures
            if path.name == 'report.json' and json.loads(encoded)['processing'] == 1 and failures == 0:
                failures += 1
                raise OSError(errno.ENOSPC, 'simulated transient report failure')
            return original_write(path, encoded)

        with mock.patch.object(auto, 'atomic_private_write', side_effect=fail_first_processing_report):
            for _ in range(3):
                self.scan(6)
                report = self.watcher.report()
                self.assertEqual(report['processing'], 0)
                self.assertEqual(report['pending'], 0)
                self.assertEqual(report['cleaned'], 0)
                self.assertEqual(report['failed'], 1)
                self.assertTrue(report['watch_error'])
                public = json.loads((self.watcher.state_dir / 'report.json').read_text())
                self.assertEqual(public['processing'], 0)
                self.assertEqual(public['failed'], 1)
                self.assertTrue(public['watch_error'])
        self.assertEqual(failures, 1)
        self.engine.clean_file.assert_not_called()
        saved = json.loads((self.watcher.state_dir / 'history.json').read_text())
        self.assertEqual(saved['copies'], {})
        self.assertEqual(saved['entries']['Downloads/private-name.png']['status'], 'failed')
        self.assertEqual(self.source.read_bytes(), b'not-yet-finished')
        self.assertFalse(list((self.home / 'OnionDesk-Clean').glob('file-*')))

    def test_success_commit_io_failure_rolls_back_only_own_copy_and_restart_is_idempotent(self):
        self.engine.clean_file.side_effect = self.cleaned
        previous = self.home / 'OnionDesk-Clean/file-aaaaaaaaaaaaaaaaaaaaaaaa.png'
        previous.parent.mkdir(mode=0o700)
        previous.write_bytes(b'previous-independent-copy')
        previous.chmod(0o600)
        self.scan()
        original_write = auto.atomic_private_write
        failed = False

        def fail_success_commit(path, encoded):
            nonlocal failed
            if path.name == 'history.json':
                saved = json.loads(encoded)
                if saved['entries']['Downloads/private-name.png']['status'] == 'cleaned':
                    failed = True
                    raise OSError(errno.ENOSPC, 'simulated full disk')
            return original_write(path, encoded)

        with mock.patch.object(auto, 'atomic_private_write', side_effect=fail_success_commit):
            self.scan(6)
        self.assertTrue(failed)
        self.assertEqual(self.watcher.report()['cleaned'], 0)
        self.assertEqual(self.watcher.report()['failed'], 1)
        self.assertEqual(list(previous.parent.iterdir()), [previous])
        self.assertEqual(previous.read_bytes(), b'previous-independent-copy')
        saved = json.loads((self.watcher.state_dir / 'history.json').read_text())
        self.assertEqual(saved['copies'], {})
        self.assertEqual(saved['entries']['Downloads/private-name.png']['status'], 'failed')
        for _ in range(3):
            self.watcher.close()
            self.watcher = auto.Watcher(self.home, self.engine, clock=lambda: self.clock)
            self.scan(6)
            self.assertEqual(self.watcher.report()['failed'], 1)
            self.assertEqual(self.watcher.report()['cleaned'], 0)
        self.engine.clean_file.assert_called_once()
        self.assertEqual(list(previous.parent.iterdir()), [previous])

    def test_persistent_commit_io_failure_still_has_restart_checkpoint(self):
        self.engine.clean_file.side_effect = self.cleaned
        self.scan()
        original_write = auto.atomic_private_write
        failed = False

        def disk_becomes_full(path, encoded):
            nonlocal failed
            if path.name == 'history.json':
                saved = json.loads(encoded)
                failed = failed or saved['entries']['Downloads/private-name.png']['status'] == 'cleaned'
                if failed:
                    raise OSError(errno.ENOSPC, 'simulated persistent full disk')
            return original_write(path, encoded)

        with mock.patch.object(auto, 'atomic_private_write', side_effect=disk_becomes_full):
            with self.assertRaises(OSError):
                self.scan(6)
            self.assertFalse(list((self.home / 'OnionDesk-Clean').glob('file-*')))
            for _ in range(3):
                self.watcher.close()
                self.watcher = auto.Watcher(self.home, self.engine, clock=lambda: self.clock)
                self.scan(6)
                self.assertEqual(self.watcher.report()['failed'], 1)
                self.assertEqual(self.watcher.report()['cleaned'], 0)
        self.engine.clean_file.assert_called_once()
        saved = json.loads((self.watcher.state_dir / 'history.json').read_text())
        self.assertEqual(saved['copies'], {})
        self.assertEqual(saved['entries']['Downloads/private-name.png']['status'], 'failed')

    def test_bounded_capacity_and_read_only_public_schema(self):
        with mock.patch.object(auto, 'MAX_ENTRIES', 1):
            self.scan()
            (self.home / 'Downloads/second.png').write_bytes(b'other')
            self.scan()
        self.assertTrue(self.watcher.report()['capacity_reached'])
        self.assertLess(len(json.dumps(self.watcher.report())), 4096)


class ActualStateByteCapacityTests(unittest.TestCase):
    def test_real_two_mib_history_capacity_stops_before_worker_across_three_restarts(self):
        # MAX_STATE and every history write are real, without persistence mocks.
        # Legal Linux control-character names consume six JSON bytes per byte.
        self.assertEqual(auto.MAX_STATE, 2 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / 'Downloads').mkdir(mode=0o700)
            (home / 'Downloads/Telegram Desktop').mkdir(mode=0o700)
            state = auto.state_directory(home)
            entries, copies = {}, {}
            for index in range(auto.MAX_ENTRIES):
                key = 'Downloads/' + '\x01' * 239 + str(index).zfill(4) + '.png'
                source = home / key
                source.write_bytes(b'fixture')
                entries[key] = {'signature': auto.signature(source.stat()), 'status': 'pending'}

            def payload():
                return {'version': 1, 'entries': entries, 'copies': copies}

            for index, key in enumerate(entries):
                name = 'file-' + str(index).zfill(24) + '.png'
                entries[key].update(status='cleaned', output=name)
                copies[name] = key
                if len(auto.encoded_json(payload())) > auto.MAX_STATE:
                    del copies[name]
                    entries[key] = {'signature': entries[key]['signature'], 'status': 'pending'}
                    break
            baseline = auto.encoded_json(payload())
            self.assertLessEqual(len(baseline), auto.MAX_STATE)
            self.assertGreater(len(baseline), auto.MAX_STATE - 2048)
            self.assertLess(len(copies), auto.MAX_COPIES)
            auto.atomic_private_json(state / 'history.json', payload())
            engine = mock.Mock(TYPES={'.png': None}, MAX_INPUT=50 * 1024 * 1024)
            clock = [0.0]
            for _ in range(3):
                watcher = auto.Watcher(home, engine, clock=lambda: clock[0])
                try:
                    clock[0] += auto.STABLE_SECONDS
                    watcher.scan()
                    report = watcher.report()
                    self.assertTrue(report['capacity_reached'])
                    self.assertFalse(report['watch_error'])
                    self.assertEqual(report['cleaned'], len(copies))
                    self.assertEqual(report['pending'], len(entries) - len(copies))
                    self.assertEqual(report['failed'], 0)
                    self.assertEqual(report['processing'], 0)
                    self.assertFalse(list((home / 'OnionDesk-Clean').glob('file-*')))
                    self.assertEqual((state / 'history.json').read_bytes(), baseline)
                finally:
                    watcher.close()
            engine.clean_file.assert_not_called()


class HealthAndIntegrationTests(unittest.TestCase):
    def test_status_binds_report_to_live_service_pid_and_rejects_stale_or_dead(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            state = auto.state_directory(home)
            report = dict(version=1, pid=4242, uid=os.getuid(), start_ticks='123', updated_unix=100.0,
                          **{key: 0 for key in auto.COUNTS}, watch_error=False, scan_limited=False,
                          capacity_reached=False, last_result='waiting', private_filename='never-export')
            auto.atomic_private_json(state / 'report.json', report)
            with mock.patch.object(auto.time, 'time', return_value=101), \
                    mock.patch.object(auto, 'process_identity', return_value=(os.getuid(), '123',
                        [b'/usr/bin/python3', os.fsencode(str(auto.INSTALLED_HELPER)), b'--watch'])):
                public = auto.safe_public_report(home, os.getuid(), 4242)
                self.assertNotIn('private_filename', public)
                self.assertEqual(public['cleaned'], 0)
                with self.assertRaises(auto.SafetyError):
                    auto.safe_public_report(home, os.getuid(), 4243)
            with mock.patch.object(auto, 'process_identity', side_effect=FileNotFoundError), self.assertRaises(OSError):
                auto.safe_public_report(home, os.getuid(), 4242)
            with mock.patch.object(auto.time, 'time', return_value=300), \
                    mock.patch.object(auto, 'process_identity', return_value=(os.getuid(), '123',
                        [os.fsencode(str(auto.INSTALLED_HELPER)), b'--watch'])), self.assertRaises(auto.SafetyError):
                auto.safe_public_report(home, os.getuid(), 4242)

    def test_user_unit_installation_and_fixed_read_only_control(self):
        unit = (KIT / 'server/oniondesk-auto-cleaner.service').read_text()
        setup = (KIT / 'server/guest-workstation-setup.sh').read_text()
        control = (KIT / 'server/control.sh').read_text()
        upload = (KIT / 'server/install.sh').read_text()
        self.assertIn('ConditionUser=user', unit)
        self.assertNotIn('User=root', unit)
        self.assertIn('KillMode=control-group', unit)
        self.assertIn('systemctl --global enable oniondesk-auto-cleaner.service', setup)
        self.assertIn('auto-cleaner)', control)
        branch = control.split('auto-cleaner)', 1)[1].split(';;', 1)[0]
        self.assertLess(branch.index('runtime-audit.py'), branch.index('guest-status.py'))
        self.assertIn('--auto-cleaner', branch)
        self.assertIn('guest-auto-cleaner.py', upload)
        self.assertIn('/etc/systemd/user/oniondesk-auto-cleaner.service', upload)


try:
    from PIL import Image, PngImagePlugin
    from docx import Document
    from reportlab.pdfgen import canvas
    from libmat2 import parser_factory
    REAL_AUTO_DEPENDENCIES = True
except ImportError:
    REAL_AUTO_DEPENDENCIES = False


@unittest.skipUnless(REAL_AUTO_DEPENDENCIES and os.geteuid() != 0,
                     'Actual Debian mat2 and an unprivileged user required')
class ActualAutomaticMat2Tests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and sys.platform == 'linux', 'Linux byte filenames required')
    def test_non_utf8_filename_gets_verified_copy_and_reversible_private_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, clock = Path(temporary), [0.0]
            engine = auto.load_engine()
            watcher = auto.Watcher(home, engine, clock=lambda: clock[0])
            self.addCleanup(watcher.close)
            source = home / 'Downloads' / os.fsdecode(b'private-\xff.png')
            fields = PngImagePlugin.PngInfo()
            fields.add_text('Author', 'Private Author')
            Image.new('RGB', (32, 24), 'blue').save(source, pnginfo=fields)
            watcher.scan()
            clock[0] = auto.STABLE_SECONDS
            watcher.scan()
            report = watcher.report()
            self.assertEqual(report['cleaned'], 1)
            self.assertEqual(report['failed'], 0)
            self.assertEqual(report['pending'], 0)
            self.assertEqual(report['processing'], 0)
            saved = json.loads((watcher.state_dir / 'history.json').read_text())
            output = home / 'OnionDesk-Clean' / next(iter(saved['copies']))
            parser, mime = parser_factory.get_parser(str(output))
            engine._verify_meta(parser.get_meta(), mime)
            mapping = (watcher.state_dir / 'Соответствия файлов.txt').read_text()
            row = next(line for line in mapping.splitlines() if ' → ' in line)
            original_name = json.loads(row.split(' → ', 1)[0])
            self.assertEqual(os.fsencode(original_name), b'Downloads/private-\xff.png')
            self.assertIn('\\udcff', row)
            public = (watcher.state_dir / 'report.json').read_text()
            self.assertNotIn('private-', public)
            self.assertNotIn('\\udcff', public)
            self.assertEqual(len(list((home / 'OnionDesk-Clean').iterdir())), 1)

    def test_real_stable_downloads_are_automatically_verified_copies(self):
        import hashlib
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            engine = auto.load_engine()
            watcher = auto.Watcher(home, engine)
            self.addCleanup(watcher.close)
            downloads = home / 'Downloads'
            jpeg = downloads / 'private-photo.jpg'
            Image.new('RGB', (32, 24), 'red').save(jpeg)
            subprocess.run(['/usr/bin/exiftool', '-overwrite_original', '-GPSLatitude=55.75',
                            '-GPSLatitudeRef=N', '-GPSLongitude=37.61', '-GPSLongitudeRef=E',
                            '-Artist=Private Author', str(jpeg)], check=True, stdout=subprocess.DEVNULL)
            png = downloads / 'Telegram Desktop/private-image.png'
            fields = PngImagePlugin.PngInfo()
            fields.add_text('Author', 'Private Author')
            Image.new('RGB', (32, 24), 'blue').save(png, pnginfo=fields)
            pdf = downloads / 'private-document.pdf'
            document = canvas.Canvas(str(pdf))
            document.setAuthor('Private Author')
            document.drawString(10, 20, 'Document content')
            document.save()
            docx = downloads / 'private-letter.docx'
            letter = Document()
            letter.core_properties.author = 'Private Author'
            letter.add_paragraph('Document content')
            letter.save(docx)
            expected = {}
            for path in (jpeg, png, pdf, docx):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                info = path.stat()
                expected[path] = (digest, info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns)
            watcher.scan()
            self.assertEqual(watcher.report()['pending'], 4)
            self.assertEqual(watcher.report()['cleaned'], 0)
            # Use the real six-second quiet period in the actual automatic path.
            time.sleep(auto.STABLE_SECONDS + 0.1)
            for _ in range(4):
                watcher.scan()
            self.assertEqual(watcher.report()['cleaned'], 4)
            self.assertEqual(watcher.report()['failed'], 0)
            self.assertEqual(watcher.report()['pending'], 0)
            history = json.loads((watcher.state_dir / 'history.json').read_text())
            self.assertEqual(len(history['copies']), 4)
            output_names = [item.name for item in (home / 'OnionDesk-Clean').iterdir()]
            self.assertEqual(len(output_names), 4)
            self.assertTrue(all(name.startswith('file-') for name in output_names))
            self.assertNotIn('private-', json.dumps(output_names))
            mapping = home / '.local/state/oniondesk/auto-clean/Соответствия файлов.txt'
            self.assertIn('private-photo.jpg', mapping.read_text())
            self.assertEqual(stat.S_IMODE(mapping.stat().st_mode), 0o600)
            for path, (digest, atime, mtime, ctime) in expected.items():
                info = path.stat()
                self.assertEqual((info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns), (atime, mtime, ctime))
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                entry = history['entries'][str(path.relative_to(home))]
                cleaned = home / 'OnionDesk-Clean' / entry['output']
                parser, mime = parser_factory.get_parser(str(cleaned))
                engine._verify_meta(parser.get_meta(), mime)
                self.assertEqual(stat.S_IMODE(cleaned.stat().st_mode), 0o600)
            before = set((home / 'OnionDesk-Clean').iterdir())
            watcher.scan()
            self.assertEqual(set((home / 'OnionDesk-Clean').iterdir()), before)
            public = (watcher.state_dir / 'report.json').read_text()
            self.assertNotIn('private-', public)
            self.assertNotIn('Private Author', public)


if __name__ == '__main__':
    unittest.main()
