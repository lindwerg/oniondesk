import importlib.util
import io
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

SERVER = Path(__file__).resolve().parents[3] / "server"
spec = importlib.util.spec_from_file_location("host_tor", SERVER / "host_tor.py")
tor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tor)


class HostConfigTests(unittest.TestCase):
    def test_public_mode_applies_bridge_to_host_and_uses_private_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "torrc"
            tor.configure(output, "public-obfs4", SERVER / "public-obfs4.conf")
            text = output.read_text()
        self.assertIn("UseBridges 1\n", text)
        self.assertIn("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n", text)
        self.assertIn("Bridge obfs4 212.83.43.95:443", text)
        self.assertIn("ControlSocket /run/tor/control RelaxDirModeCheck\n", text)
        self.assertIn("CookieAuthFileGroupReadable 0\n", text)
        self.assertNotIn("ControlPort", text)
        self.assertNotIn("UseBridges 0", text)

    def test_other_modes_preserve_direct_host_connection(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in ("wizard", "direct"):
                output = Path(temporary) / "torrc"
                tor.configure(output, mode, SERVER / "public-obfs4.conf")
                self.assertNotIn("Bridge obfs4", output.read_text())

    def test_direct_fallback_or_unknown_bridge_directives_are_rejected(self):
        text = (SERVER / "public-obfs4.conf").read_text()
        for bad in (text + "UseBridges 0\n", text.replace("/usr/bin/obfs4proxy", "/tmp/unknown"), text.replace("iat-mode=1", "iat-mode=invalid"), text.replace("212.83.43.95:443", "example.com:443")):
            with self.subTest(text=bad[-80:]), self.assertRaises(ValueError):
                tor.validated_bridge(bad)

    def test_installer_masks_tor_before_packages_and_requires_control_bootstrap(self):
        text = (SERVER / "install.sh").read_text()
        self.assertLess(text.index("systemctl mask nginx.service tor.service tor@default.service"), text.index("apt-get -y --no-install-recommends install"))
        self.assertIn("tor_packages=(obfs4proxy)", text)
        self.assertLess(text.index("host_tor.py\" configure"), text.index("systemctl unmask tor.service"))
        self.assertLess(text.index("--verify-config --defaults-torrc"), text.index("systemctl unmask tor.service"))
        self.assertLess(text.index("host_tor.py\" wait"), text.index("frontend/install-auth.sh\" \"$hostname\""))


class TorControlTests(unittest.TestCase):
    def test_malformed_replies_and_control_rejection_are_not_ready(self):
        for data in (b"515 Authentication failed\r\n", b"250 OK\n", b"250+unexpected=\r\n", b"250-" + b"a"*17000 + b"\r\n"):
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                tor.reply(io.BytesIO(data))

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux Tor control peer credentials required")
    def test_real_unix_socket_cookie_auth_and_bootstrap_are_both_required(self):
        for progress, circuit, use_bridges, mode, ready in ((100, 1, 1, 0o600, True), (99, 1, 1, 0o600, False), (100, 0, 1, 0o600, False), (100, 1, 0, 0o600, False), (100, 1, 1, 0o640, False)):
            with self.subTest(progress=progress, circuit=circuit, bridges=use_bridges, mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                endpoint = directory / "control"
                cookie_file = directory / "cookie"
                cookie = os.urandom(32)
                cookie_file.write_bytes(cookie)
                cookie_file.chmod(mode)
                errors = []
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(str(endpoint))
                    endpoint.chmod(0o600)
                    listener.listen(1)
                    listener.settimeout(5)
                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection, connection.makefile("rwb", buffering=0) as stream:
                                if mode != 0o600:
                                    return
                                self.assertEqual(stream.readline(), b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n")
                                stream.write(b"250 OK\r\n")
                                self.assertEqual(stream.readline(), b"GETCONF DisableNetwork UseBridges\r\n")
                                stream.write(f"250-DisableNetwork=0\r\n250 UseBridges={use_bridges}\r\n".encode())
                                if not use_bridges:
                                    return
                                self.assertEqual(stream.readline(), b"GETINFO status/bootstrap-phase status/circuit-established\r\n")
                                stream.write(f'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG=done SUMMARY="Done"\r\n250-status/circuit-established={circuit}\r\n250 OK\r\n'.encode())
                        except Exception as error:
                            errors.append(error)
                    thread = threading.Thread(target=serve)
                    thread.start()
                    try:
                        if not use_bridges or mode != 0o600:
                            with self.assertRaises(ValueError):
                                tor.query(endpoint, cookie_file, os.getpid(), os.getuid(), True)
                        else:
                            self.assertEqual(tor.query(endpoint, cookie_file, os.getpid(), os.getuid(), True), ready)
                    finally:
                        thread.join(6)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])

    def test_no_bootstrap_times_out_without_positive_proof(self):
        with patch.object(tor, "query", return_value=False), patch.object(tor.time, "monotonic", side_effect=[0, 1, 1, 1, 61]), patch.object(tor.time, "sleep"):
            with self.assertRaises(TimeoutError):
                tor.wait_bootstrap(Path("socket"), Path("cookie"), 123, 100, True, 60)


if __name__ == "__main__":
    unittest.main()
