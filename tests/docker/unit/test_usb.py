"""All write tests use temporary regular files. No native disk is ever opened."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import usb_tails as usb
import usb_privileged as helper


def disk(**changes):
    result = {"platform": "Linux", "native_id": "sdb", "bus": "usb", "whole": True,
              "internal": False, "size_bytes": 16_000_000_000, "serial": "USB-TEST-123",
              "hardware": ["usb-port-1", "wwn-123"], "name": "Test USB", "mounts": [], "sector_size": 512}
    result.update(changes)
    return result


class Guards(unittest.TestCase):
    def test_safe_usb(self):
        self.assertEqual(usb._guard_disk(disk())["native_id"], "sdb")

    def test_reject_every_unsafe_flag(self):
        for flag in ("system", "boot", "swap", "readonly", "complex", "protected_device"):
            with self.subTest(flag=flag), self.assertRaises(usb.USBError):
                usb._guard_disk(disk(**{flag: True}))

    def test_reject_non_usb_internal_partition_small_no_identity(self):
        for changes in ({"bus": "sata"}, {"internal": True}, {"whole": False},
                        {"size_bytes": 7_000_000_000}, {"serial": ""}, {"serial": "000000"}, {"hardware": None}):
            with self.subTest(changes=changes), self.assertRaises(usb.USBError):
                usb._guard_disk(disk(**changes))

    def test_reject_all_system_mounts(self):
        for mount in ("/", "/boot", "/boot/efi", "/usr", "/var", "/private/var/vm", "/home"):
            with self.subTest(mount=mount), self.assertRaises(usb.USBError):
                usb._guard_disk(disk(mounts=[mount]))

    def test_reject_source_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / "image.img"
            image.write_bytes(b"safe")
            with self.assertRaises(usb.USBError):
                usb._guard_disk(disk(mounts=[folder]), [image])

    def test_public_selection_has_no_raw_path(self):
        with patch.object(usb, "_scan_disks", return_value=[disk(), disk(native_id="sdc", system=True)]):
            rows = usb.list_usb_disks()
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), {"id", "name", "size_bytes", "identity", "platform"})
        self.assertNotIn("/dev/", json.dumps(rows))

    def test_revalidate_rejects_identity_or_size_changes(self):
        original = disk()
        original["identity"] = usb._identity(original)
        for changes in ({"serial": "OTHER"}, {"hardware": ["usb-other"]}, {"size_bytes": 32_000_000_000}, {"system": True}):
            with self.subTest(changes=changes), patch.object(usb, "_scan_disks", return_value=[disk(**changes)]), self.assertRaises(usb.USBError):
                usb._revalidate(original)

    def test_revalidate_removed(self):
        original = disk()
        original["identity"] = usb._identity(original)
        with patch.object(usb, "_scan_disks", return_value=[]), self.assertRaises(usb.USBError):
            usb._revalidate(original)

    def test_no_confirmation_no_admin(self):
        with patch.object(usb, "_launch_admin") as admin:
            for word in ("", "стереть", "СТЕРЕТЬ ", "ERASE"):
                with self.assertRaises(usb.USBError):
                    usb.write_verified_image("fake", word)
        admin.assert_not_called()

    def test_arbitrary_http_path_is_never_selection(self):
        with patch.object(usb, "_launch_admin") as admin, self.assertRaises(usb.USBError):
            usb.write_verified_image({"id": "/dev/sda", "path": "/dev/sda"}, "СТЕРЕТЬ")
        admin.assert_not_called()

    def test_none_gpg_fails_before_download(self):
        with patch.object(usb, "_find_gpg", return_value=None), patch.object(usb, "_fetch") as fetch:
            with self.assertRaisesRegex(usb.USBError, "GnuPG"):
                usb.download_verified_image()
        fetch.assert_not_called()


class Trust(unittest.TestCase):
    def metadata(self, version="7.15"):
        return {"product-name": "Tails", "build_target": "amd64", "channel": "stable",
                "installations": [{"version": version, "installation-paths": [{"type": "img", "target-files": [{
                    "url": f"https://download.tails.net/tails/stable/tails-amd64-{version}/tails-amd64-{version}.img",
                    "sha256": "a" * 64, "size": 1889533952}]}]}]}

    def test_current_metadata_img_only(self):
        self.assertEqual(usb._parse_release(self.metadata())["version"], "7.15")

    def test_metadata_rollback_wrong_architecture_arbitrary_url(self):
        bad = [self.metadata("7.14"), self.metadata(), self.metadata()]
        bad[1]["build_target"] = "arm64"
        bad[2]["installations"][0]["installation-paths"][0]["target-files"][0]["url"] = "http://127.0.0.1/file.img"
        for value in bad:
            with self.subTest(value=value), self.assertRaises(usb.USBError):
                usb._parse_release(value)

    def status(self, primary=usb.PUBLISHER_FINGERPRINT, hash_algo="8"):
        return f"[GNUPG:] GOODSIG ABC Tails\n[GNUPG:] VALIDSIG {'B' * 40} 2026-10-13 1791907200 0 4 0 22 {hash_algo} 00 {primary}\n"

    def test_only_pinned_valid_publisher_signature(self):
        self.assertTrue(usb._valid_signature(self.status()))
        self.assertFalse(usb._valid_signature(self.status("C" * 40)))
        self.assertFalse(usb._valid_signature(self.status(hash_algo="2")))
        self.assertFalse(usb._valid_signature("[GNUPG:] GOODSIG ABC Tails\n"))

    def test_expired_revoked_bad_and_multiple_signatures_rejected(self):
        for flag in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "FAILURE"):
            with self.subTest(flag=flag):
                self.assertFalse(usb._valid_signature(self.status() + f"[GNUPG:] {flag} ABC\n"))
        self.assertFalse(usb._valid_signature(self.status() + self.status()))

    def test_urls_https_origin_and_mirror_filename(self):
        for url in ("http://tails.net/x", "https://tails.net.evil.example/x", "https://127.0.0.1/x", "https://user@tails.net/x"):
            with self.subTest(url=url), self.assertRaises(usb.USBError):
                usb._validate_url(url)
        self.assertEqual(usb._mirror_url("https://ftp.fau.de/tails/stable/tails-amd64-7.15.img", "tails-amd64-7.15.img"),
                         "https://ftp.fau.de/tails/stable/tails-amd64-7.15.img")
        with self.assertRaises(usb.USBError):
            usb._mirror_url("https://ftp.fau.de/tails/image.iso", "tails-amd64-7.15.img")

    def test_public_dns_rejects_private(self):
        with patch.object(usb, "_verified_tor_port", return_value=9150), patch.object(usb, "_tor_resolve", side_effect=usb.USBError("Адрес не публичный")), self.assertRaises(usb.USBError):
            usb._public_request("https://tails.net/x")


class RegularFileSafety(unittest.TestCase):
    def test_symlink_and_hardlink_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(usb, "CACHE", Path(folder).resolve()):
            source = Path(folder).resolve() / "source.img"
            source.write_bytes(b"safe")
            link = Path(folder).resolve() / "link.img"
            try:
                link.symlink_to(source)
            except OSError:
                return
            with self.assertRaises(usb.USBError):
                usb._open_regular(link)
            link.unlink()
            os.link(source, link)
            with self.assertRaises(usb.USBError):
                usb._open_regular(source)

    def test_snapshot_hash_change_rejects_before_device_open(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as snapshot, patch.object(usb, "CACHE", Path(folder).resolve()):
            image = Path(folder).resolve() / "image.img"
            image.write_bytes(b"altered")
            artifact = {"path": str(image), "sha256": hashlib.sha256(b"original").hexdigest(), "size_bytes": 7}
            with self.assertRaisesRegex(usb.USBError, "изменился"):
                helper._snapshot(artifact, snapshot, threading.Event())

    def test_request_outside_own_cache_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            request = Path(folder) / "request.json"
            request.write_text("{}")
            with self.assertRaises(usb.USBError):
                helper._read_request(request)


class SimulatedWrite(unittest.TestCase):
    def execute(self, source, target, data, event=None, emit=None):
        return helper._write_and_verify(source, target, len(data), hashlib.sha256(data).hexdigest(),
                                        emit or (lambda *args, **kw: None), event or threading.Event())

    def test_write_flush_readback_regular_file_and_tail_untouched(self):
        data = b"Tails signed image simulation" * 90000
        with tempfile.TemporaryFile("w+b") as source, tempfile.TemporaryFile("w+b") as target:
            source.write(data)
            target.write(b"x" * len(data) + b"TAIL")
            messages = []
            result = self.execute(source, target, data, emit=lambda stage, *a, **kw: messages.append(stage))
            self.assertTrue(result["verified"])
            target.seek(0)
            self.assertEqual(target.read(), data + b"TAIL")
            self.assertIn("flush", messages)
            self.assertIn("readback", messages)

    def test_corrupt_readback_is_rejected(self):
        class Corrupt(io.BytesIO):
            def flush(self):
                self.seek(0)
                super().write(b"!")
        data = b"safe-image" * 100
        with self.assertRaisesRegex(usb.USBError, "не совпали"):
            self.execute(io.BytesIO(data), Corrupt(), data)

    def test_source_mutation_rejected(self):
        with self.assertRaisesRegex(usb.USBError, "изменился"):
            self.execute(io.BytesIO(b"wrong"), io.BytesIO(), b"image")

    def test_cancel_before_write_leaves_target_intact(self):
        event = threading.Event()
        event.set()
        target = io.BytesIO(b"old-data")
        with self.assertRaises(usb.USBCancelled):
            self.execute(io.BytesIO(b"new-data"), target, b"new-data", event)
        self.assertEqual(target.getvalue(), b"old-data")

    def test_cancel_after_first_chunk_marks_media_incomplete(self):
        event = threading.Event()
        data = b"x" * (usb.CHUNK + 512)
        def emit(stage, *args, **kwargs):
            if stage == "write":
                event.set()
        with self.assertRaisesRegex(usb.USBCancelled, "неполный образ"):
            self.execute(io.BytesIO(data), io.BytesIO(), data, event, emit)


if __name__ == "__main__":
    unittest.main()
