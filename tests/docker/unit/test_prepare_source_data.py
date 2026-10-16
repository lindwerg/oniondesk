"""TEST ONLY: synthetic public bytes; no network, payload execution or devices."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("prepare_source_data", ROOT / "tools/prepare-data.py")
if spec is None or spec.loader is None:
    raise ImportError("Cannot load the source-data preparation module")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
windows_spec = importlib.util.spec_from_file_location("windows_data_verifier", ROOT / "client/build-windows-data.py")
if windows_spec is None or windows_spec.loader is None:
    raise ImportError("Cannot load the real Windows Data verifier")
windows_data = importlib.util.module_from_spec(windows_spec)
windows_spec.loader.exec_module(windows_data)


class PublicDataRecipe(unittest.TestCase):
    def test_every_catalog_asset_has_exact_local_metadata_or_https_source(self):
        rows = prepare.plan()
        self.assertEqual({row["path"] for row in rows}, set(prepare.records()))
        self.assertGreater(len(rows), 30)
        for row in rows:
            with self.subTest(path=row["path"]):
                if "local_metadata" in row:
                    path = ROOT / row["local_metadata"]
                    self.assertEqual(path.stat().st_size, row["size_bytes"])
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"])
                else:
                    self.assertEqual(prepare.safe_url(row["url"]), row["url"])

    def test_existing_foreign_directory_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "owner-file").write_text("keep me")
            with self.assertRaisesRegex(ValueError, "occupied"):
                prepare.check_destination(foreign)
            self.assertEqual((foreign / "owner-file").read_text(), "keep me")
            if hasattr(Path, "symlink_to"):
                link = root / "link"
                try:
                    link.symlink_to(foreign, target_is_directory=True)
                except OSError:
                    return
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    prepare.check_destination(link)

    def test_download_rejects_tamper_and_https_downgrade(self):
        good = b"TEST ONLY public bytes"
        record = {"path": "test.dat", "size_bytes": len(good), "sha256": hashlib.sha256(good).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            session = Mock()
            session.get.return_value = Mock(status_code=200, iter_content=Mock(return_value=iter([b"wrong"])))
            with self.assertRaisesRegex(ValueError, "do not match"):
                prepare.download(session, "https://example.org/test", Path(directory) / "tampered", record)
            response = Mock(status_code=302, headers={"Location": "http://example.org/test"})
            session.get.return_value = response
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                prepare.download(session, "https://example.org/test", Path(directory) / "downgrade", record)
            response.close.assert_called_once()

    def test_explicit_fetch_uses_socks5h_and_never_executes_payload(self):
        good = b"TEST ONLY public bytes"
        record = {"path": "vendor/test.dat", "size_bytes": len(good), "sha256": hashlib.sha256(good).hexdigest(), "url": "https://example.org/test"}
        session = Mock()
        response = Mock(status_code=200, iter_content=Mock(return_value=iter([good])))
        session.get.return_value = response
        with tempfile.TemporaryDirectory() as directory, patch.object(prepare, "plan", return_value=[record]), \
                patch.object(prepare, "records", return_value={record["path"]: record}), \
                patch("requests.Session", return_value=session), patch.object(prepare, "verify") as verify:
            root = Path(directory).resolve() / "public-build"
            prepare.fetch(root, 9150)
            self.assertEqual((root / record["path"]).read_bytes(), good)
            self.assertEqual((root / record["path"]).stat().st_nlink, 1)
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies, {"http": "socks5h://127.0.0.1:9150", "https": "socks5h://127.0.0.1:9150"})
            verify.assert_called_once_with(root)
            session.close.assert_called_once()

    def test_repeated_fetch_does_not_overwrite_tampered_file(self):
        record = {"path": "test.dat", "size_bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest(), "url": "https://example.org/test"}
        with tempfile.TemporaryDirectory() as directory:
            root = prepare.check_destination(Path(directory).resolve() / "owned-build")
            (root / "test.dat").write_bytes(b"bad!")
            with patch.object(prepare, "plan", return_value=[record]), patch("requests.Session") as session:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    prepare.fetch(root, 9150)
                session.return_value.get.assert_not_called()
            self.assertEqual((root / "test.dat").read_bytes(), b"bad!")

    def test_network_failure_closes_session_and_publishes_nothing(self):
        import requests
        record = {"path": "test.dat", "size_bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest(), "url": "https://example.org/test"}
        session = Mock()
        session.get.side_effect = requests.ConnectionError("TEST ONLY simulated network failure")
        with tempfile.TemporaryDirectory() as directory, patch.object(prepare, "plan", return_value=[record]), \
                patch("requests.Session", return_value=session):
            root = Path(directory).resolve() / "public-build"
            with self.assertRaisesRegex(RuntimeError, "HTTPS through Tor failed"):
                prepare.fetch(root, 9150)
            self.assertFalse((root / "test.dat").exists())
            self.assertFalse((root / "manifest.json").exists())
            self.assertFalse(list(root.glob(".download-*")))
            session.close.assert_called_once()

    def test_completed_fetch_passes_real_windows_verifier_and_is_idempotent(self) -> None:
        self._check_synthetic_fetch_completion(interrupt_first_verification=False)

    def test_failed_verification_retains_owned_marker_for_safe_resume(self) -> None:
        self._check_synthetic_fetch_completion(interrupt_first_verification=True)

    def _check_synthetic_fetch_completion(self, *, interrupt_first_verification: bool) -> None:
        payloads = {"vendor/test.dat": b"TEST ONLY payload", "public/hashes.txt": b"TEST ONLY hashes",
                    "public/key.asc": b"TEST ONLY public key"}
        records = {name: {"path": name, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                   for name, content in payloads.items()}
        fixture_assets = {"synthetic": records["vendor/test.dat"]}
        verification_markers = []

        def verify_synthetic_complete(root: Path) -> None:
            verification_markers.append((root / prepare.MARKER).exists())
            for record in records.values():
                prepare.verify_file(root, record)
            self.assertEqual(json.loads((root / "manifest.json").read_text()),
                             {"format": 1, "release_id": "synthetic-test-only", "assets": fixture_assets})
            if interrupt_first_verification and len(verification_markers) == 1:
                raise RuntimeError("TEST ONLY simulated publisher verification failure")

        def response(url: str, **_kwargs: object) -> Mock:
            content = payloads[url.removeprefix("https://example.org/")]
            return Mock(status_code=200, iter_content=Mock(return_value=iter([content])))

        session = Mock()
        session.get.side_effect = response
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, client = base / "public-build", base / "synthetic-client"
            client.mkdir()
            (client / "offline_catalog.py").write_text(f"RELEASE_ID='synthetic-test-only'\nASSETS={fixture_assets!r}\n")
            (client / "wallet_catalog.py").write_text(
                f"HASHES={records['public/hashes.txt']!r}\nKEY={records['public/key.asc']!r}\nPLATFORMS={{}}\n")
            for name in ("phone_catalog.py", "feather_catalog.py"):
                (client / name).write_text("ASSETS={}\n")
            planned = [{**row, "url": "https://example.org/" + name} for name, row in records.items()]
            with patch.object(prepare, "records", return_value=records), \
                    patch.object(prepare, "plan", return_value=planned), \
                    patch.object(prepare.offline_catalog, "ASSETS", fixture_assets), \
                    patch.object(prepare.offline_catalog, "RELEASE_ID", "synthetic-test-only"), \
                    patch.object(prepare, "verify", side_effect=verify_synthetic_complete), \
                    patch("requests.Session", return_value=session) as session_factory:
                if interrupt_first_verification:
                    with self.assertRaisesRegex(RuntimeError, "publisher verification failure"):
                        prepare.fetch(root, 9150)
                    self.assertEqual((root / prepare.MARKER).read_text(), prepare.MARKER_TEXT)
                    foreign = root / "unexpected-file.dat"
                    foreign.write_bytes(b"TEST ONLY foreign bytes; preserve")
                    with self.assertRaisesRegex(ValueError, "occupied"):
                        prepare.fetch(root, 9150)
                    self.assertEqual(foreign.read_bytes(), b"TEST ONLY foreign bytes; preserve")
                    self.assertEqual((root / prepare.MARKER).read_text(), prepare.MARKER_TEXT)
                    foreign.unlink()
                    prepare.fetch(root, 9150)
                else:
                    prepare.fetch(root, 9150)
                self.assertFalse((root / prepare.MARKER).exists())
                verified = windows_data.verified_records(root, client)
                self.assertEqual({row["path"] for row in verified}, {*records, "manifest.json"})
                downloads_before, factories_before = session.get.call_count, session_factory.call_count
                prepare.fetch(root, 9150)
                self.assertEqual(session.get.call_count, downloads_before)
                self.assertEqual(session_factory.call_count, factories_before)
                self.assertFalse((root / prepare.MARKER).exists())
                self.assertEqual(verification_markers, [True, True, False] if interrupt_first_verification else [True, False])
                foreign = root / "unexpected-file.dat"
                foreign.write_bytes(b"TEST ONLY foreign bytes; preserve")
                with self.assertRaisesRegex(ValueError, "occupied"):
                    prepare.fetch(root, 9150)
                self.assertEqual(foreign.read_bytes(), b"TEST ONLY foreign bytes; preserve")
                self.assertFalse((root / prepare.MARKER).exists())
                self.assertEqual(session_factory.call_count, factories_before)

    def test_verification_cannot_authorize_removal_of_a_replaced_marker(self) -> None:
        record = {"path": "test.dat", "size_bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest(), "url": "https://example.org/test"}
        session = Mock()
        session.get.return_value = Mock(status_code=200, iter_content=Mock(return_value=iter([b"good"])))

        def replace_marker(root: Path) -> None:
            (root / prepare.MARKER).write_text("TEST ONLY foreign marker; preserve\n")

        with tempfile.TemporaryDirectory() as directory, patch.object(prepare, "plan", return_value=[record]), \
                patch.object(prepare, "records", return_value={record["path"]: record}), \
                patch.object(prepare, "verify", side_effect=replace_marker), patch("requests.Session", return_value=session):
            root = Path(directory).resolve() / "public-build"
            with self.assertRaisesRegex(ValueError, "marker changed"):
                prepare.fetch(root, 9150)
            self.assertEqual((root / prepare.MARKER).read_text(), "TEST ONLY foreign marker; preserve\n")


if __name__ == "__main__":
    unittest.main()
