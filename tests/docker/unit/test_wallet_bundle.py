"""Monero distribution boundaries, with small offline fixtures."""
from contextlib import ExitStack
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import wallet_bundle as bundle
import wallet_catalog as catalog
import wallet_engine as engine


def valid_signature(fingerprint=catalog.PUBLISHER_FINGERPRINT, digest="8"):
    return f"[GNUPG:] GOODSIG F0AF4D462A0BDF92 Publisher\n[GNUPG:] VALIDSIG {fingerprint} 2026-10-06 1791255240 0 4 0 1 {digest} 01 {fingerprint}\n"


@unittest.skipUnless(os.name == "posix", "POSIX preparation tests")
class WalletBundle(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.source = self.folder / "data"
        (self.source / "Monero").mkdir(parents=True)
        self.payload = b"official-rpc-fixture"
        self.record = {"path": "Monero/release.tar.bz2", "rpc_member": "official/monero-wallet-rpc",
                       "rpc_bytes": len(self.payload), "rpc_sha256": hashlib.sha256(self.payload).hexdigest()}
        self.archive = self.source / self.record["path"]
        self.tar()
        self.pin = self.asset(self.record["path"])
        self.record.update(self.pin)
        (self.source / "Monero/hashes.txt").write_text("signed fixture")
        (self.source / "Monero/key.asc").write_text("public fixture")
        self.stack.enter_context(patch.object(catalog, "HASHES", self.asset("Monero/hashes.txt")))
        self.stack.enter_context(patch.object(catalog, "KEY", self.asset("Monero/key.asc")))
        self.stack.enter_context(patch.object(catalog, "PLATFORMS", {"macos-arm64": self.record}))
        self.stack.enter_context(patch.object(bundle, "_platform_key", return_value="macos-arm64"))
        self.stack.enter_context(patch.object(bundle.offline, "_find_root", return_value=self.source))
        self.stack.enter_context(patch.object(bundle, "_cache_root", return_value=self.folder / "cache"))
        self.stack.enter_context(patch.object(engine, "default_wallet_root", return_value=self.folder / "wallets"))

    def asset(self, path):
        target = self.source / path
        return {"path": path, "size_bytes": target.stat().st_size,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}

    def tar(self, *, duplicate=False, symlink=False, extra=False):
        with tarfile.open(self.archive, "w:bz2") as archive:
            item = tarfile.TarInfo(self.record["rpc_member"])
            item.size = len(self.payload)
            if symlink:
                item.type = tarfile.SYMTYPE
                item.linkname = "../../foreign"
                item.size = 0
            archive.addfile(item, None if symlink else io.BytesIO(self.payload))
            if duplicate:
                archive.addfile(item, io.BytesIO(self.payload))
            if extra:
                item = tarfile.TarInfo("../../must-not-extract")
                item.size = 1
                archive.addfile(item, io.BytesIO(b"x"))

    def test_prepare_verifies_before_extract_and_rechecks_cached_binary(self):
        events = []
        with patch.object(bundle, "_verify_hashes", side_effect=lambda *a: events.append("signature")), \
             patch.object(bundle.subprocess, "Popen") as popen:
            ready = bundle.prepare_engine(network=engine.Network.STAGENET)
            self.assertEqual(events, ["signature"])
            self.assertEqual(ready.binary.read_bytes(), self.payload)
            self.assertEqual(ready.binary.stat().st_mode & 0o777, 0o700)
            self.assertEqual(ready.network, engine.Network.STAGENET)
            popen.assert_not_called()
            ready.binary.write_bytes(b"tampered")
            with self.assertRaises(engine.WalletError):
                bundle.prepare_engine(network=engine.Network.STAGENET)

    def test_bad_pgp_and_bad_archive_never_extract(self):
        with patch.object(bundle, "_verify_hashes", side_effect=engine.WalletError("bad signature")), \
             patch.object(bundle, "_extract_rpc") as extract:
            with self.assertRaises(engine.WalletError):
                bundle.prepare_engine()
            extract.assert_not_called()
        self.archive.write_bytes(b"tampered")
        with patch.object(bundle, "_verify_hashes"), patch.object(bundle, "_extract_rpc") as extract:
            with self.assertRaises(engine.WalletError):
                bundle.prepare_engine()
            extract.assert_not_called()

    def test_public_asset_symlink_refused(self):
        original = self.folder / "original"
        self.archive.rename(original)
        self.archive.symlink_to(original)
        with self.assertRaises(engine.WalletError):
            bundle._copy_asset(self.source, self.record, self.folder / "copied")

    def test_tar_extracts_only_fixed_rpc_ignores_path_traversal_entries(self):
        self.tar(extra=True)
        target = self.folder / "rpc"
        bundle._extract_rpc(self.archive, self.record, target)
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertFalse((self.folder.parent / "must-not-extract").exists())
        self.assertEqual(sorted(path.name for path in self.folder.iterdir()), ["data", "rpc"])

    def test_tar_duplicate_link_wrong_size_or_wrong_hash_refused(self):
        for mode in ("duplicate", "symlink", "size", "hash"):
            with self.subTest(mode=mode):
                self.tar(duplicate=mode == "duplicate", symlink=mode == "symlink")
                record = dict(self.record)
                if mode == "size":
                    record["rpc_bytes"] += 1
                if mode == "hash":
                    record["rpc_sha256"] = "0" * 64
                with self.assertRaises(engine.WalletError):
                    bundle._extract_rpc(self.archive, record, self.folder / mode)

    def test_zip_fixed_member_success_and_duplicate_refused(self):
        archive = self.folder / "release.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(self.record["rpc_member"], self.payload)
            output.writestr("../../escape", b"x")
        target = self.folder / "zip-rpc"
        bundle._extract_rpc(archive, self.record, target)
        self.assertEqual(target.read_bytes(), self.payload)
        with zipfile.ZipFile(archive, "w") as output:
            for _ in range(2):
                output.writestr(self.record["rpc_member"], self.payload)
        with self.assertRaises(engine.WalletError):
            bundle._extract_rpc(archive, self.record, self.folder / "duplicate")

    def test_pgp_pin_digest_and_failure_tags_checked(self):
        self.assertTrue(bundle._valid_signature(valid_signature()))
        self.assertFalse(bundle._valid_signature(valid_signature("A" * 40)))
        self.assertFalse(bundle._valid_signature(valid_signature(digest="2")))
        for tag in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"):
            self.assertFalse(bundle._valid_signature(valid_signature() + f"[GNUPG:] {tag}\n"))
        self.assertFalse(bundle._valid_signature(valid_signature() * 2))


if __name__ == "__main__":
    unittest.main()
