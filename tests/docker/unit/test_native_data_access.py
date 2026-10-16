"""Native folder consent uses fake Cocoa objects; no real permissions change."""
from pathlib import Path
from contextlib import ExitStack
import tempfile
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

CLIENT = Path(__file__).resolve().parents[3] / "client"
sys.path.insert(0, str(CLIENT))
import app
import offline_bundle as offline_bundle
import offline_catalog


class FakeURL:
    def __init__(self, path, *, scoped=True, local=True):
        self.value = str(path)
        self.scoped = scoped
        self.local = local
        self.started = 0
        self.stopped = 0

    def path(self):
        return self.value

    def isFileURL(self):
        return self.local

    def startAccessingSecurityScopedResource(self):
        self.started += 1
        return self.scoped

    def stopAccessingSecurityScopedResource(self):
        self.stopped += 1


class FakeEvent:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, callback):
        self.handlers.append(callback)
        return self

    def fire(self):
        return all(callback() is not False for callback in self.handlers)


class FakeWindow:
    def __init__(self):
        self.events = SimpleNamespace(loaded=FakeEvent(), closing=FakeEvent(), closed=FakeEvent())
        self.evaluate_js = Mock()
        self.destroyed = 0

    def destroy(self):
        if self.events.closing.fire():
            self.destroyed += 1
            self.events.closed.fire()


class FakeWebview:
    def __init__(self, start):
        self.settings = {}
        self.window = FakeWindow()
        self.on_start = start
        self.created = False

    def create_window(self, *_args, **_kwargs):
        self.created = True
        return self.window

    def start(self, **_kwargs):
        self.on_start(self.window)


class NativeDataAccessTest(unittest.TestCase):
    def setUp(self):
        self.root = Path("/Users/oniondesk-test/Documents/OnionDesk-Data")
        self.selected = FakeURL(self.root)
        self.panel = Mock()
        self.panel.runModal.return_value = 1
        self.panel.URL.side_effect = lambda: self.selected
        self.alert = Mock()
        self.cocoa = SimpleNamespace(
            NSAlert=Mock(), NSApplication=Mock(), NSOpenPanel=Mock(),
            NSModalResponseOK=1,
        )
        self.cocoa.NSAlert.alloc.return_value.init.return_value = self.alert
        self.cocoa.NSOpenPanel.openPanel.return_value = self.panel
        self.foundation = SimpleNamespace(NSURL=Mock())
        self.foundation.NSURL.fileURLWithPath_.side_effect = FakeURL
        self.offline = SimpleNamespace(
            _find_root=Mock(return_value=self.root),
            _embedded_data_root=Mock(return_value=None),
            _check_manifest=Mock(), OfflineError=RuntimeError,
            status=Mock(return_value={"available": True, "message": "Проверено"}),
            prepare_tor=Mock(),
        )
        self.desk = SimpleNamespace(
            offline_engine=Mock(return_value=self.offline), close=Mock(), nonce="test",
        )
        self.platform_patch = patch.object(app.sys, "platform", "darwin")
        self.callbacks = []
        self.call_after = Mock(side_effect=self.callbacks.append)
        self.modules_patch = patch.dict(sys.modules, {
            "AppKit": self.cocoa, "Foundation": self.foundation,
            "PyObjCTools": SimpleNamespace(AppHelper=SimpleNamespace(callAfter=self.call_after)),
        })
        self.platform_patch.start()
        self.modules_patch.start()
        self.addCleanup(self.platform_patch.stop)
        self.addCleanup(self.modules_patch.stop)

    def test_selected_folder_is_verified_and_scope_lasts_through_session(self):
        def verify(root):
            self.assertEqual(root, self.root)
            self.assertEqual(self.selected.started, 1)
            self.assertEqual(self.selected.stopped, 0)

        self.offline._check_manifest.side_effect = verify
        with app.native_data_access(self.desk):
            self.offline._check_manifest.assert_called_once_with(self.root)
            self.assertEqual(self.selected.stopped, 0)
        self.assertEqual(self.selected.stopped, 1)
        self.panel.setCanChooseDirectories_.assert_called_once_with(True)
        self.panel.setCanChooseFiles_.assert_called_once_with(False)
        self.panel.setAllowsMultipleSelection_.assert_called_once_with(False)
        self.panel.setCanCreateDirectories_.assert_called_once_with(False)
        self.panel.setResolvesAliases_.assert_called_once_with(False)
        self.panel.setPrompt_.assert_called_once_with("Открыть")
        self.foundation.NSURL.fileURLWithPath_.assert_called_once_with(str(self.root))
        self.alert.runModal.assert_not_called()

    def test_open_panel_consent_without_explicit_security_scope_still_verifies(self):
        self.selected.scoped = False
        with app.native_data_access(self.desk):
            self.offline._check_manifest.assert_called_once_with(self.root)
        self.assertEqual(self.selected.started, 1)
        self.assertEqual(self.selected.stopped, 0)

    def test_cancellation_exits_before_file_read_or_native_session(self):
        self.panel.runModal.return_value = 0
        with self.assertRaises(SystemExit) as result:
            with app.native_data_access(self.desk):
                self.fail("A cancelled picker must never start polling")
        self.assertEqual(result.exception.code, 1)
        self.offline._check_manifest.assert_not_called()
        self.assertEqual(self.selected.started, 0)
        self.alert.runModal.assert_called_once_with()
        self.assertIn("не предоставлен", self.alert.setInformativeText_.call_args.args[0])

    def test_other_folder_missing_url_and_non_file_url_are_rejected(self):
        for selection in (FakeURL(self.root.parent), None,
                          FakeURL(self.root, local=False),
                          FakeURL(self.root.parent / "Other" / "OnionDesk-Data")):
            with self.subTest(selection=selection):
                self.selected = selection
                with self.assertRaises(SystemExit):
                    with app.native_data_access(self.desk):
                        self.fail("A different folder must never be used")
        self.offline._check_manifest.assert_not_called()

    def test_manifest_failure_closes_scope_and_prevents_polling(self):
        self.offline._check_manifest.side_effect = RuntimeError("Описание комплекта изменено.")
        with self.assertRaises(SystemExit):
            with app.native_data_access(self.desk):
                self.fail("An invalid manifest must never start polling")
        self.assertEqual(self.selected.stopped, 1)
        self.alert.setInformativeText_.assert_called_once_with("Описание комплекта изменено.")

    def test_scope_is_released_if_native_session_fails(self):
        with self.assertRaisesRegex(ValueError, "WebKit failed"):
            with app.native_data_access(self.desk):
                raise ValueError("WebKit failed")
        self.assertEqual(self.selected.stopped, 1)
        self.alert.runModal.assert_not_called()

    def test_non_mac_does_not_load_offline_or_cocoa(self):
        for system in ("linux", "win32"):
            with self.subTest(system=system), patch.object(app.sys, "platform", system):
                with app.native_data_access(self.desk):
                    pass
        self.desk.offline_engine.assert_not_called()
        self.cocoa.NSApplication.sharedApplication.assert_not_called()

    def test_missing_distribution_keeps_existing_missing_files_ui(self):
        self.offline._find_root.return_value = None
        with app.native_data_access(self.desk):
            pass
        self.cocoa.NSOpenPanel.openPanel.assert_not_called()
        self.offline._check_manifest.assert_not_called()

    def test_application_folders_do_not_need_picker(self):
        for applications in (Path("/Applications"), Path.home() / "Applications"):
            with self.subTest(applications=applications):
                self.offline._find_root.return_value = applications / "OnionDesk" / "OnionDesk-Data"
                with app.native_data_access(self.desk):
                    pass
        self.cocoa.NSOpenPanel.openPanel.assert_not_called()

    def test_embedded_pinned_manifest_is_verified_without_folder_prompt(self):
        root = Path("/Users/oniondesk-test/Documents/OnionDesk.app/Contents/Resources/OnionDesk-Data")
        self.offline._find_root.return_value = root
        self.offline._embedded_data_root.return_value = root
        with app.native_data_access(self.desk):
            self.offline._check_manifest.assert_called_once_with(root)
        self.cocoa.NSOpenPanel.openPanel.assert_not_called()
        self.assertEqual(self.selected.started, 0)

    def test_damaged_embedded_manifest_aborts_without_external_prompt(self):
        root = Path("/Users/oniondesk-test/Documents/OnionDesk.app/Contents/Resources/OnionDesk-Data")
        self.offline._find_root.return_value = root
        self.offline._embedded_data_root.return_value = root
        self.offline._check_manifest.side_effect = RuntimeError("Встроенный комплект изменён")
        with self.assertRaises(SystemExit):
            with app.native_data_access(self.desk):
                self.fail("Damaged embedded data must stop startup")
        self.cocoa.NSOpenPanel.openPanel.assert_not_called()
        self.alert.setInformativeText_.assert_called_once_with("Встроенный комплект изменён")

    def test_missing_embedded_root_keeps_the_strict_legacy_picker(self):
        self.offline._embedded_data_root.return_value = Path("/Applications/OnionDesk.app/Contents/Resources/OnionDesk-Data")
        with app.native_data_access(self.desk):
            self.offline._check_manifest.assert_called_once_with(self.root)
        self.panel.runModal.assert_called_once_with()
        self.assertEqual((self.selected.started, self.selected.stopped), (1, 1))

    def native_desk(self, *, wallets=None):
        usb = SimpleNamespace(system_info=Mock(return_value={"platform": "Darwin"}))
        return app.Desk(usb=usb, offline=self.offline, wallets=wallets)

    def load_on_worker(self, window):
        worker = threading.Thread(target=window.events.loaded.fire)
        worker.start()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    def run_callback(self):
        self.assertEqual(len(self.callbacks), 1)
        self.callbacks.pop(0)()

    def test_main_starts_native_window_before_requesting_folder_access(self):
        server = SimpleNamespace(origin="http://127.0.0.1:12345", server_close=Mock())

        def native(*args):
            self.offline._check_manifest.assert_not_called()
            self.panel.runModal.assert_not_called()

        with patch.object(app.sys, "argv", ["oniondesk", "--native"]), \
                patch.object(app, "Desk", return_value=self.desk), \
                patch.object(app, "LocalServer", return_value=server), \
                patch.object(app, "native_window", side_effect=native) as window, \
                patch.dict(sys.modules, {"webview": SimpleNamespace()}):
            app.main()
        window.assert_called_once()
        server.server_close.assert_called_once_with()

    def test_pending_parallel_state_does_not_read_offline_or_construct_wallet(self):
        desk = self.native_desk()
        desk.native_access_pending = True
        with patch.object(desk, "wallet_manager", side_effect=AssertionError("No pre-consent wallet access")):
            with ThreadPoolExecutor(max_workers=4) as workers:
                states = list(workers.map(lambda _: desk.state(), range(8)))
        for state in states:
            self.assertTrue(state["offline"]["access_pending"])
            self.assertFalse(state["offline"]["available"])
            self.assertFalse(state["wallet"]["available"])
        self.offline.status.assert_not_called()
        self.offline._check_manifest.assert_not_called()

    def test_pending_dispatch_blocks_operations_and_keeps_forget_clear_safe(self):
        desk = self.native_desk()
        desk.native_access_pending = True
        for path in ("/api/tor/start", "/api/tor/check", "/api/usb/download", "/api/usb/write",
                     "/api/wallet/create", "/api/wallet/unlock", "/api/wallet/reveal",
                     "/api/wallet/seed", "/api/wallet/confirm", "/api/wallet/lock",
                     "/api/server/connect", "/api/server/install",
                     "/api/phone/list", "/api/phone/install", "/api/phone/close"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "^Проверяю установочные файлы приложения…$"):
                desk.dispatch(path, {})
        with patch.object(desk, "wallet_manager", side_effect=AssertionError("Forget must not initialize files")):
            self.assertEqual(desk.dispatch("/api/wallet/forget", {}), {"forgotten": True})
        desk.credentials = {"test": "secret"}
        self.assertEqual(desk.dispatch("/api/secrets/clear", {}), {"cleared": True})
        self.assertIsNone(desk.credentials)
        self.assertIsNone(desk.job)
        self.offline.prepare_tor.assert_not_called()

    def test_pending_forget_clears_an_existing_controller(self):
        wallets = SimpleNamespace(forget=Mock())
        desk = self.native_desk(wallets=wallets)
        desk.native_access_pending = True
        desk.dispatch("/api/wallet/forget", {})
        wallets.forget.assert_called_once_with()

    def test_window_load_keeps_http_responsive_then_verifies_on_main_thread(self):
        wallets = SimpleNamespace(state=Mock(return_value={"available": True}), close=Mock(), forget=Mock())
        desk = self.native_desk(wallets=wallets)
        server = app.LocalServer(desk)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        main_thread = threading.get_ident()

        def request(path, data=None):
            headers = {"X-App-Nonce": desk.nonce, "Origin": server.origin}
            body = None if data is None else json.dumps(data).encode()
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                with urlopen(Request(server.origin + path, data=body, headers=headers), timeout=2) as response:
                    return response.status, json.load(response)
            except HTTPError as error:
                with error:
                    return error.code, json.load(error)

        def start(window):
            self.panel.runModal.assert_not_called()
            self.load_on_worker(window)
            with ThreadPoolExecutor(max_workers=4) as workers:
                responses = list(workers.map(lambda _: request("/api/state"), range(8)))
            self.assertTrue(all(code == 200 and state["offline"]["access_pending"] for code, state in responses))
            self.assertEqual(request("/api/wallet/list")[0], 400)
            self.assertEqual(request("/api/tor/start", {})[0], 400)
            self.assertEqual(request("/api/wallet/forget", {})[0], 200)
            self.offline.status.assert_not_called()
            wallets.state.assert_not_called()
            self.panel.runModal.side_effect = lambda: (
                self.assertEqual(threading.get_ident(), main_thread) or 1)
            self.run_callback()
            self.assertFalse(desk.native_access_pending)
            self.assertEqual((self.selected.started, self.selected.stopped), (1, 0))
            self.offline._check_manifest.assert_called_once_with(self.root)
            self.assertTrue(request("/api/state")[1]["offline"]["available"])
            window.destroy()

        app.native_window(server, desk, server.origin, FakeWebview(start))
        self.assertEqual(self.selected.stopped, 1)
        self.assertTrue(desk.closed)

    def test_cancellation_closes_existing_window_without_reading_manifest(self):
        self.panel.runModal.return_value = 0
        desk = self.native_desk()
        server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())

        def start(window):
            self.load_on_worker(window)
            self.run_callback()
            self.assertEqual(window.destroyed, 1)
            self.assertTrue(desk.closed)
            self.assertTrue(desk.native_access_pending)

        app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.offline._check_manifest.assert_not_called()
        server.shutdown.assert_called_once_with()

    def test_manifest_failure_closes_window_and_scope_before_polling_can_read(self):
        self.offline._check_manifest.side_effect = RuntimeError("Неверный комплект")
        desk = self.native_desk()
        server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())

        def start(window):
            self.load_on_worker(window)
            self.run_callback()
            self.assertEqual(window.destroyed, 1)
            self.assertTrue(desk.native_access_pending)
            self.assertEqual(self.selected.stopped, 1)

        app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.assertEqual(self.selected.stopped, 1)
        self.offline.status.assert_not_called()

    def test_duplicate_load_events_only_request_consent_once(self):
        desk = self.native_desk()
        server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())

        def start(window):
            with ThreadPoolExecutor(max_workers=4) as workers:
                list(workers.map(lambda _: window.events.loaded.fire(), range(8)))
            self.call_after.assert_called_once()
            self.run_callback()
            window.events.loaded.fire()
            self.assertEqual(len(self.callbacks), 0)

        app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.panel.runModal.assert_called_once_with()
        self.assertEqual((self.selected.started, self.selected.stopped), (1, 1))

    def test_queued_callback_after_window_closes_does_not_open_panel(self):
        desk = self.native_desk()
        server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())

        def start(window):
            self.load_on_worker(window)
            window.destroy()

        app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.run_callback()
        self.panel.runModal.assert_not_called()
        self.offline._check_manifest.assert_not_called()

    def test_native_window_failure_releases_scope_on_the_main_thread(self):
        desk = self.native_desk()
        server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())
        main_thread = threading.get_ident()
        stopped_threads = []
        self.selected.stopAccessingSecurityScopedResource = lambda: stopped_threads.append(threading.get_ident())

        def start(window):
            self.load_on_worker(window)
            self.run_callback()
            raise RuntimeError("WebKit failure")

        with self.assertRaisesRegex(RuntimeError, "WebKit failure"):
            app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.assertEqual(stopped_threads, [main_thread])
        self.assertTrue(desk.native_access_pending)

    def test_non_mac_native_window_never_schedules_cocoa_access(self):
        for platform in ("linux", "win32"):
            desk = self.native_desk()
            server = SimpleNamespace(serve_forever=Mock(), shutdown=Mock())

            def start(window):
                self.assertFalse(desk.native_access_pending)
                window.events.loaded.fire()

            with self.subTest(platform=platform), patch.object(app.sys, "platform", platform):
                app.native_window(server, desk, "http://127.0.0.1", FakeWebview(start))
        self.call_after.assert_not_called()
        self.panel.runModal.assert_not_called()


class FrozenDataDiscovery(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.application = self.base / "OnionDesk.app"
        self.executable = self.application / "Contents/MacOS/OnionDesk"
        self.executable.parent.mkdir(parents=True)
        self.embedded = self.application / "Contents/Resources/OnionDesk-Data"
        self.external = self.base / "OnionDesk-Data"
        self.external.mkdir()
        self.stack.enter_context(patch.object(sys, "frozen", True, create=True))
        self.stack.enter_context(patch.object(sys, "executable", str(self.executable)))
        self.stack.enter_context(patch.object(offline_bundle.platform, "system", return_value="Darwin"))
        self.stack.enter_context(patch.object(offline_bundle, "_SELECTED_EMBEDDED_ROOT", None))

    def create_embedded(self):
        self.embedded.mkdir(parents=True)
        manifest = {"format": 1, "release_id": offline_catalog.RELEASE_ID, "assets": offline_catalog.ASSETS}
        (self.embedded / "manifest.json").write_text(json.dumps(manifest))

    def test_frozen_mac_prefers_its_exact_embedded_root(self):
        self.create_embedded()
        self.assertEqual(offline_bundle._embedded_data_root(), self.embedded)
        self.assertEqual(offline_bundle._find_root(), self.embedded)
        offline_bundle._check_manifest(offline_bundle._find_root())

    def test_missing_embedded_uses_legacy_external_and_then_missing_state(self):
        self.assertEqual(offline_bundle._find_root(), self.external)
        self.external.rmdir()
        self.assertIsNone(offline_bundle._find_root())

    def test_tampered_or_missing_embedded_manifest_never_selects_external(self):
        self.create_embedded()
        manifest = self.embedded / "manifest.json"
        for content in ('{"format": 999}', None):
            with self.subTest(content=content):
                if content is None:
                    manifest.unlink()
                else:
                    manifest.write_text(content)
                self.assertEqual(offline_bundle._find_root(), self.embedded)
                with self.assertRaises(offline_bundle.OfflineError):
                    offline_bundle._check_manifest(offline_bundle._find_root())

    def test_embedded_redirect_is_rejected_without_selecting_external(self):
        self.create_embedded()
        (self.embedded / "manifest.json").replace(self.external / "manifest.json")
        self.embedded.rmdir()
        self.embedded.symlink_to(self.external, target_is_directory=True)
        self.assertEqual(offline_bundle._find_root(), self.embedded)
        with self.assertRaises(offline_bundle.OfflineError):
            offline_bundle._check_manifest(offline_bundle._find_root())

    def test_embedded_choice_stays_pinned_when_folder_disappears_during_session(self):
        self.create_embedded()
        self.assertEqual(offline_bundle._find_root(), self.embedded)
        self.embedded.rename(self.embedded.with_name("removed-data"))
        self.assertEqual(offline_bundle._find_root(), self.embedded)
        with self.assertRaises(offline_bundle.OfflineError):
            offline_bundle._check_manifest(offline_bundle._find_root())

    def test_other_platform_source_and_unexpected_layout_keep_external_discovery(self):
        self.create_embedded()
        for system in ("Windows", "Linux"):
            with self.subTest(system=system), patch.object(offline_bundle.platform, "system", return_value=system), \
                    patch.object(offline_bundle, "_windows_data_root", return_value=None):
                self.assertIsNone(offline_bundle._embedded_data_root())
                self.assertEqual(offline_bundle._find_root(), self.external)
        with patch.object(sys, "frozen", False):
            self.assertIsNone(offline_bundle._embedded_data_root())
            self.assertEqual(offline_bundle._data_roots(), [CLIENT.parent / "OnionDesk-Data"])
        with patch.object(sys, "executable", str(self.base / "bin/OnionDesk")):
            self.assertIsNone(offline_bundle._embedded_data_root())


if __name__ == "__main__":
    unittest.main()
