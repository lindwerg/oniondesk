"""Tor-only download tests. No live Tor or external destination is required."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "client"))
import usb_tails as usb


class FakeSocket:
    def __init__(self, response, fragment=1):
        self.response = bytearray(response)
        self.fragment = fragment
        self.sent = []
        self.connected = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, seconds):
        self.timeout = seconds

    def connect(self, address):
        self.connected = address

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        amount = min(size, self.fragment, len(self.response))
        data = bytes(self.response[:amount])
        del self.response[:amount]
        return data


def resolve_reply(address):
    ip = ipaddress.ip_address(address)
    address_type = 1 if ip.version == 4 else 4
    return b"\x05\x00" + bytes([5, 0, 0, address_type]) + ip.packed + b"\x00\x00"


class TorResolve(unittest.TestCase):
    def resolve(self, reply, hostname="tails.net", port=9150):
        fake = FakeSocket(reply)
        with patch.object(usb.socket, "socket", return_value=fake), patch.object(usb.socket, "getaddrinfo", side_effect=AssertionError("Local DNS must not be used")):
            result = usb._tor_resolve(hostname, port)
        return result, fake

    def test_remote_ipv4_resolution_and_exact_extension_command(self):
        address, fake = self.resolve(resolve_reply("93.184.216.34"))
        self.assertEqual(address, "93.184.216.34")
        self.assertEqual(fake.connected, ("127.0.0.1", 9150))
        self.assertEqual(fake.sent, [b"\x05\x01\x00", b"\x05\xf0\x00\x03\x09tails.net\x00\x00"])
        self.assertEqual(fake.timeout, 30)
        self.assertTrue(fake.closed)

    def test_remote_ipv6_resolution(self):
        address, fake = self.resolve(resolve_reply("2606:4700:4700::1111"), port=9050)
        self.assertEqual(address, "2606:4700:4700::1111")
        self.assertEqual(fake.connected, ("127.0.0.1", 9050))

    def test_private_reserved_multicast_and_mapped_ips_rejected(self):
        for ip in ("127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                   "0.0.0.0", "198.51.100.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "::ffff:8.8.8.8"):
            with self.subTest(ip=ip), self.assertRaisesRegex(usb.USBError, "публичным"):
                self.resolve(resolve_reply(ip))

    def test_protocol_errors_and_truncated_replies_close_socket(self):
        valid = resolve_reply("93.184.216.34")
        replies = [b"", b"\x05", b"\x04\x00", b"\x05\xff", b"\x05\x02", valid[:-1], valid[:-4],
                   b"\x05\x00\x04\x00\x00\x01", b"\x05\x00\x05\x00\x01\x01",
                   b"\x05\x00\x05\x04\x00\x01", b"\x05\x00\x05\x00\x00\x03"]
        for reply in replies:
            fake = FakeSocket(reply)
            with self.subTest(reply=reply), patch.object(usb.socket, "socket", return_value=fake), self.assertRaises(usb.USBError):
                usb._tor_resolve("tails.net", 9150)
            self.assertTrue(fake.closed)

    def test_invalid_port_hostname_and_non_ip_rejected(self):
        with patch.object(usb.socket, "socket") as raw:
            for host, port in (("tails.net", 1080), ("x" * 254, 9150), ("bad host.example", 9150)):
                with self.subTest(host=host, port=port), self.assertRaises(usb.USBError):
                    usb._tor_resolve(host, port)
        raw.assert_not_called()
        with self.assertRaises(usb.USBError):
            usb._public_ip("untrusted hostname")

    def test_disconnected_tor_does_not_connect_to_destination(self):
        fake = FakeSocket(b"")
        fake.connect = Mock(side_effect=OSError("local Tor absent"))
        with patch.object(usb.socket, "socket", return_value=fake), self.assertRaisesRegex(usb.USBError, "Откройте Tor Browser"):
            usb._tor_resolve("tails.net", 9150)
        fake.connect.assert_called_once_with(("127.0.0.1", 9150))
        self.assertTrue(fake.closed)


class TorRouting(unittest.TestCase):
    def test_no_tor_prevents_direct_socket_dns_and_http_pool(self):
        launcher = types.SimpleNamespace(find_tor_proxy=Mock(side_effect=RuntimeError("Tor not connected")))
        with patch.dict(sys.modules, {"launcher": launcher}), patch.object(usb.socket, "socket") as raw, \
             patch.object(usb.socket, "create_connection") as direct, patch.object(usb.socket, "getaddrinfo") as dns, \
             patch("urllib3.contrib.socks.SOCKSProxyManager") as manager, self.assertRaisesRegex(usb.USBError, "Откройте Tor Browser"):
            usb._public_request(usb.LATEST_URL)
        raw.assert_not_called()
        direct.assert_not_called()
        dns.assert_not_called()
        manager.assert_not_called()

    def test_no_tor_stops_download_before_metadata_key_or_image(self):
        launcher = types.SimpleNamespace(find_tor_proxy=Mock(side_effect=RuntimeError("Tor not connected")))
        with patch.dict(sys.modules, {"launcher": launcher}), patch.object(usb, "_find_gpg", return_value="/gpg"), \
             patch.object(usb, "_fetch") as fetch, patch.object(usb, "_secure_directory") as cache, \
             patch("offline_bundle.prepare_tails", return_value=None), \
             self.assertRaisesRegex(usb.USBError, "Откройте Tor Browser"):
            usb.download_verified_image()
        fetch.assert_not_called()
        cache.assert_not_called()

    def test_only_verified_local_ports_are_accepted(self):
        for port in (9150, 9050):
            launcher = types.SimpleNamespace(find_tor_proxy=Mock(return_value=port))
            with patch.dict(sys.modules, {"launcher": launcher}):
                self.assertEqual(usb._verified_tor_port(), port)
        launcher = types.SimpleNamespace(find_tor_proxy=Mock(return_value=1080))
        with patch.dict(sys.modules, {"launcher": launcher}), self.assertRaises(usb.USBError):
            usb._verified_tor_port()

    def test_tls_sni_hostname_and_http_host_retained_with_pinned_public_ip(self):
        with patch.object(usb, "_verified_tor_port", return_value=9150), \
             patch.object(usb, "_tor_resolve", return_value="93.184.216.34") as resolve, \
             patch.object(usb.socket, "getaddrinfo", side_effect=AssertionError("Local DNS forbidden")), \
             patch("urllib3.contrib.socks.SOCKSProxyManager") as manager:
            response, pool = usb._public_request("https://tails.net/install/latest.json?current=1")
        resolve.assert_called_once_with("tails.net", 9150)
        args, options = manager.call_args
        self.assertEqual(args, ("socks5h://127.0.0.1:9150",))
        self.assertEqual(options["server_hostname"], "tails.net")
        self.assertEqual(options["assert_hostname"], "tails.net")
        self.assertEqual(options["cert_reqs"], "CERT_REQUIRED")
        manager.return_value.connection_from_host.assert_called_once_with("93.184.216.34", port=443, scheme="https")
        call_args, call_options = pool.urlopen.call_args
        self.assertEqual(call_args, ("GET", "/install/latest.json?current=1"))
        self.assertEqual(call_options["headers"]["Host"], "tails.net")
        self.assertFalse(call_options["redirect"])
        self.assertFalse(call_options["retries"])

    def test_real_urllib3_pool_is_socks_only_and_retains_hostname(self):
        from urllib3.contrib.socks import SOCKSHTTPSConnectionPool
        with patch.object(usb, "_verified_tor_port", return_value=9150), \
             patch.object(usb, "_tor_resolve", return_value="93.184.216.34"), \
             patch.object(SOCKSHTTPSConnectionPool, "urlopen", return_value=object()), \
             patch.object(usb.socket, "socket") as raw, patch.object(usb.socket, "getaddrinfo") as dns:
            response, pool = usb._public_request(usb.LATEST_URL)
        try:
            self.assertIsInstance(pool, SOCKSHTTPSConnectionPool)
            self.assertEqual(pool.host, "93.184.216.34")
            self.assertEqual(pool.conn_kw["server_hostname"], "tails.net")
            self.assertEqual(pool.assert_hostname, "tails.net")
            self.assertEqual(pool.conn_kw["_socks_options"]["proxy_host"], "127.0.0.1")
            self.assertEqual(pool.conn_kw["_socks_options"]["proxy_port"], 9150)
            self.assertTrue(pool.conn_kw["_socks_options"]["rdns"])
        finally:
            pool.close()
        raw.assert_not_called()
        dns.assert_not_called()

    def test_broken_socks_pool_has_no_direct_fallback(self):
        import urllib3
        with patch.object(usb, "_verified_tor_port", return_value=9050), \
             patch.object(usb, "_tor_resolve", return_value="93.184.216.34"), \
             patch("urllib3.contrib.socks.SOCKSProxyManager") as manager, \
             patch("urllib3.HTTPSConnectionPool") as direct, \
             patch.object(usb.socket, "create_connection") as direct_socket:
            pool = manager.return_value.connection_from_host.return_value
            pool.urlopen.side_effect = urllib3.exceptions.NewConnectionError(None, "Tor stopped")
            with self.assertRaisesRegex(usb.USBError, "прямого подключения не будет"):
                usb._public_request(usb.LATEST_URL)
        pool.close.assert_called_once()
        direct.assert_not_called()
        direct_socket.assert_not_called()

    def test_download_info_explicitly_requires_tor(self):
        notice = usb.system_info()["download_notice"]
        self.assertIn("только через", notice)
        self.assertIn("Прямого соединения", notice)


@unittest.skipIf(os.name == "nt", "POSIX credentials only")
class GpgPrivilegeDrop(unittest.TestCase):
    def test_privilege_drop_uses_native_subprocess_credentials_no_preexec(self):
        calls = []
        def run(args, **options):
            calls.append(options)
            if "show-only" in args:
                stdout = f"pub:::::::::\nfpr:::::::::{usb.PUBLISHER_FINGERPRINT}:\n".encode()
            elif "--verify" in args:
                stdout = (f"[GNUPG:] GOODSIG ABC Tails\n[GNUPG:] VALIDSIG {'B' * 40} 2026-10-13 1 0 4 0 22 8 00 {usb.PUBLISHER_FINGERPRINT}\n").encode()
            else:
                stdout = b""
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr=b"")
        with patch.object(usb.os, "geteuid", return_value=0), patch.object(usb.os, "chown"), \
             patch.object(usb.subprocess, "run", side_effect=run):
            usb._verify_signature("image", "signature", "key", gpg="gpg", run_as=(501, 20))
        self.assertEqual(len(calls), 3)
        for options in calls:
            self.assertNotIn("preexec_fn", options)
            self.assertEqual(options["user"], 501)
            self.assertEqual(options["group"], 20)
            self.assertEqual(options["extra_groups"], [])


if __name__ == "__main__":
    unittest.main()
