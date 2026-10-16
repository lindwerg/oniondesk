import base64
import hashlib
import http.client
from http import cookies
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode


FRONTEND = Path(__file__).resolve().parents[3] / "frontend"
spec = importlib.util.spec_from_file_location("oniondesk_auth", FRONTEND / "auth.py")
auth = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = auth
spec.loader.exec_module(auth)
listener_spec = importlib.util.spec_from_file_location("nginx_listeners", FRONTEND / "check-nginx-listeners.py")
listeners = importlib.util.module_from_spec(listener_spec)
listener_spec.loader.exec_module(listeners)
builder_spec = importlib.util.spec_from_file_location("nginx_builder", FRONTEND / "build-nginx-config.py")
builder = importlib.util.module_from_spec(builder_spec)
builder_spec.loader.exec_module(builder)
ORIGIN = "http://" + "a" * 56 + ".onion"
HOST = ORIGIN.removeprefix("http://")
PASSWORD = "a long unique test password"
SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        salt = b"s" * 32
        cls.config = auth.Config("owner", salt, auth.password_hash(PASSWORD, salt), SECRET, ORIGIN)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.now = [1_600_000_000]
        self.state = auth.AuthState(self.config, self.directory.name, clock=lambda: self.now[0])
        self.server = auth.AuthHTTPServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.jar = {}
        self.last_headers = []
        self.csrf = ""

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.directory.cleanup()

    def request(self, method, path, form=None, headers=None):
        request_headers = {"Host": HOST}
        if self.jar:
            request_headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.jar.items())
        body = None
        if form is not None:
            body = urlencode(form)
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            request_headers["Origin"] = ORIGIN
        if headers:
            request_headers.update(headers)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        content = response.read().decode("utf-8")
        self.last_headers = response.getheaders()
        for key, value in self.last_headers:
            if key.lower() == "set-cookie":
                parsed = cookies.SimpleCookie(value)
                for name, morsel in parsed.items():
                    if morsel["max-age"] == "0":
                        self.jar.pop(name, None)
                    else:
                        self.jar[name] = morsel.value
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', content)
        if csrf:
            self.csrf = csrf.group(1)
        status = response.status
        connection.close()
        return status, content

    def start_login(self):
        self.assertEqual(self.request("GET", "/login")[0], 200)
        self.assertTrue(self.csrf)

    def login(self, password=PASSWORD, otp=None, csrf=None, login="owner", headers=None):
        if otp is None:
            otp = auth.totp(SECRET, self.now[0] // 30)
        return self.request("POST", "/login", {"login": login, "password": password, "otp": otp,
                                               "csrf": self.csrf if csrf is None else csrf}, headers)

    def sign_in(self):
        self.start_login()
        self.assertEqual(self.login()[0], 303)

    def auth_request(self, original="/novnc/app/ui.js", origin=None, method="GET"):
        headers = {"X-Original-URI": original, "X-Original-Method": method}
        if origin is not None:
            headers["Origin"] = origin
        return self.request("GET", "/auth-check", headers=headers)[0]

    def test_totp_rfc6238_sha1_vector(self):
        self.assertEqual(auth.totp(SECRET, 59 // 30), "287082")

    def test_success_and_cookie_attributes(self):
        self.sign_in()
        session_header = next(value for name, value in self.last_headers
                              if name == "Set-Cookie" and value.startswith(auth.SESSION_COOKIE + "="))
        self.assertIn("HttpOnly", session_header)
        self.assertIn("SameSite=Strict", session_header)
        self.assertIn("Path=/", session_header)
        self.assertNotIn("Secure", session_header)
        self.assertGreaterEqual(len(self.jar[auth.SESSION_COOKIE]), 40)
        self.assertEqual(self.auth_request(), 204)
        status, content = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("path=/ws/workstation", content)
        self.assertIn("path=/ws/gateway", content)

    def test_invalid_password_is_rejected_without_secret_logs(self):
        self.start_login()
        with self.assertLogs(level="INFO") as logs:
            self.assertEqual(self.login(password="wrong secret password")[0], 401)
        self.assertNotIn("wrong secret password", "".join(logs.output))
        self.assertNotIn(SECRET, "".join(logs.output))
        self.assertNotIn(auth.SESSION_COOKIE, self.jar)
        self.assertEqual(self.auth_request(), 401)

    def test_invalid_otp_is_rejected(self):
        self.start_login()
        correct = auth.totp(SECRET, self.now[0] // 30)
        incorrect = "000000" if correct != "000000" else "999999"
        self.assertEqual(self.login(otp=incorrect)[0], 401)
        self.assertNotIn(auth.SESSION_COOKIE, self.jar)

    def test_non_ascii_inputs_fail_closed(self):
        self.start_login()
        self.assertEqual(self.login(login="владелец", otp="абвгде")[0], 401)
        self.assertEqual(self.login(csrf="не токен")[0], 403)

    def test_login_csrf_is_required_and_does_not_count_as_password_failure(self):
        self.start_login()
        self.assertEqual(self.login(csrf="forged")[0], 403)
        self.assertEqual(len(self.state.failures), 0)
        self.jar.pop(auth.PRELOGIN_COOKIE)
        self.assertEqual(self.login()[0], 403)
        self.assertNotIn(auth.SESSION_COOKIE, self.jar)

    def test_login_requires_exact_origin_and_host(self):
        self.start_login()
        self.assertEqual(self.login(headers={"Origin": "http://attacker.invalid"})[0], 403)
        self.assertEqual(self.login(headers={"Origin": "null"})[0], 403)
        self.assertEqual(self.login(headers={"Origin": ""})[0], 403)
        self.assertEqual(self.login(headers={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.request("GET", "/login", headers={"Host": "localhost"})[0], 403)

    def test_lockout_and_expiration(self):
        self.start_login()
        for _ in range(auth.MAX_FAILURES):
            self.assertEqual(self.login(password="bad")[0], 401)
        self.assertEqual(self.login()[0], 429)
        self.assertNotIn(auth.SESSION_COOKIE, self.jar)
        self.now[0] += auth.LOCK_SECONDS + 1
        self.start_login()
        self.assertEqual(self.login()[0], 303)

    def test_session_has_absolute_expiry(self):
        self.sign_in()
        self.now[0] += auth.SESSION_SECONDS + 1
        self.assertEqual(self.auth_request(), 401)

    def test_logout_requires_csrf_and_origin_then_revokes_session(self):
        self.sign_in()
        self.assertEqual(self.request("GET", "/")[0], 200)
        session_csrf = self.csrf
        self.assertEqual(self.request("POST", "/logout", {"csrf": "wrong"})[0], 403)
        self.assertEqual(self.auth_request(), 204)
        self.assertEqual(self.request("POST", "/logout", {"csrf": session_csrf},
                                      {"Origin": "http://attacker.invalid"})[0], 403)
        self.assertEqual(self.request("POST", "/logout", {"csrf": session_csrf})[0], 303)
        self.assertEqual(self.auth_request(), 401)
        self.assertNotIn(auth.SESSION_COOKIE, self.jar)

    def test_totp_replay_and_next_step(self):
        self.sign_in()
        self.jar.clear()
        self.start_login()
        self.assertEqual(self.login()[0], 401)
        self.now[0] += 30
        self.assertEqual(self.login()[0], 303)

    def test_totp_replay_survives_process_restart(self):
        self.sign_in()
        restarted = auth.AuthState(self.config, self.directory.name, clock=lambda: self.now[0])
        token, csrf = restarted.new_prelogin()
        form = {"login": "owner", "password": PASSWORD, "otp": auth.totp(SECRET, self.now[0] // 30), "csrf": csrf}
        self.assertEqual(restarted.authenticate(token, form), (401, None))
        self.assertEqual((Path(self.directory.name) / "totp-state.json").stat().st_mode & 0o777, 0o600)

    def test_websocket_auth_request_requires_session_and_same_origin(self):
        self.assertEqual(self.auth_request("/ws/workstation", ORIGIN), 401)
        self.sign_in()
        self.assertEqual(self.auth_request("/ws/workstation"), 403)
        self.assertEqual(self.auth_request("/ws/workstation", "http://attacker.invalid"), 403)
        self.assertEqual(self.auth_request("/ws/workstation", ORIGIN, method="POST"), 403)
        self.assertEqual(self.auth_request("/ws/workstation", ORIGIN), 204)
        self.assertEqual(self.auth_request("/ws/gateway", ORIGIN), 204)
        self.assertEqual(self.auth_request("/ws%2fworkstation"), 403)
        self.assertEqual(self.auth_request("/tmp/../ws/workstation"), 403)
        self.assertEqual(self.request("GET", "/auth-check", headers={"X-Original-Upgrade": "websocket, h2c"})[0], 403)
        self.assertEqual(self.auth_request("/novnc/app/ui.js", "http://attacker.invalid"), 403)

    def test_duplicate_form_fields_are_rejected(self):
        self.start_login()
        form = [("login", "owner"), ("login", "other"), ("password", PASSWORD),
                ("otp", auth.totp(SECRET, self.now[0] // 30)), ("csrf", self.csrf)]
        self.assertEqual(self.request("POST", "/login", form)[0], 400)

    def test_forged_session_is_rejected(self):
        self.jar[auth.SESSION_COOKIE] = "forged-token"
        self.assertEqual(self.auth_request(), 401)


class InstallationDataTests(unittest.TestCase):
    def test_csp_hashes_inline_novnc_bootstrap_without_allowing_arbitrary_scripts(self):
        script = '\nimport "./app/ui.js";\n'
        fixture = '<script src="./other.js"></script><script type="module">' + script + '</script>'
        template = (FRONTEND / "nginx.conf.in").read_text()
        rendered = builder.render(HOST, template, fixture)
        expected = "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"
        self.assertIn("script-src 'self' " + expected + ";", rendered)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", rendered)
        self.assertNotIn("__ONION_HOST__", rendered)
        self.assertNotIn("__NOVNC_SCRIPT_HASHES__", rendered)
        self.assertEqual(builder.render(HOST, template, fixture.replace("\n", "\r\n")), rendered)

    def test_nginx_referrer_policy_preserves_same_origin_form_origin(self):
        configuration = (FRONTEND / "nginx.conf.in").read_text()
        self.assertIn('add_header Referrer-Policy "same-origin" always;', configuration)
        self.assertNotIn('add_header Referrer-Policy "no-referrer"', configuration)

    def test_initialize_preserves_credentials_and_root_only_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            auth.initialize(directory, ORIGIN)
            credentials_file = Path(directory) / "credentials.json"
            runtime_file = Path(directory) / "auth.json"
            original = credentials_file.read_bytes()
            credentials = json.loads(original)
            self.assertEqual(credentials["login"], "owner")
            self.assertIn("otpauth://totp/", credentials["otpauth_uri"])
            self.assertNotIn("password", json.loads(runtime_file.read_text()))
            self.assertNotIn(credentials["password"], runtime_file.read_text())
            auth.initialize(directory, ORIGIN)
            self.assertEqual(credentials_file.read_bytes(), original)
            self.assertEqual(credentials_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(runtime_file.stat().st_mode & 0o777, 0o600)
            other_origin = "http://" + "b" * 56 + ".onion"
            auth.initialize(directory, other_origin)
            self.assertEqual(credentials_file.read_bytes(), original)
            self.assertEqual(auth.Config.load(runtime_file).origin, other_origin)

    def test_runtime_only_does_not_reset_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime_file = Path(directory) / "auth.json"
            runtime_file.write_text("{}")
            with self.assertRaises(ValueError):
                auth.initialize(directory, ORIGIN)
            self.assertFalse((Path(directory) / "credentials.json").exists())
            self.assertEqual(runtime_file.read_text(), "{}")

    def test_nginx_checker_detects_public_listener_even_inline(self):
        for text in ("server { listen 80; }", "server { listen 0.0.0.0:443 ssl; }",
                     "server { listen [::]:80; }", "server { listen localhost:80; }"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                listeners.check(text)
        listeners.check("# listen 80;\nserver { listen 127.0.0.1:18080; listen [::1]:8080; }")


if __name__ == "__main__":
    unittest.main()
