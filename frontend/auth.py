#!/usr/bin/env python3
"""Loopback-only password/TOTP authentication for the OnionDesk nginx frontend."""

import argparse
import base64
from collections import OrderedDict, deque
from dataclasses import dataclass
import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import posixpath
import re
import secrets
import struct
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit


SCRYPT_N = 131072
SCRYPT_R = 8
SCRYPT_P = 1
SESSION_SECONDS = 8 * 60 * 60
PRELOGIN_SECONDS = 10 * 60
FAILURE_WINDOW = 5 * 60
LOCK_SECONDS = 10 * 60
MAX_FAILURES = 5
SESSION_COOKIE = "oniondesk_session"
PRELOGIN_COOKIE = "oniondesk_prelogin"
MAX_BODY = 4096
ONION_ORIGIN = re.compile(r"http://[a-z2-7]{56}\.onion\Z")


def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N,
                          r=SCRYPT_R, p=SCRYPT_P, dklen=64, maxmem=256 * 1024 * 1024)


def text_matches(left, right):
    # compare_digest(str, str) rejects non-ASCII input; bytes safely reject it.
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def totp(secret, counter):
    key = base64.b32decode(secret, casefold=False)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1000000:06d}"


def atomic_json(path, value):
    """Write a private file and durably replace it; never print its contents."""
    path = Path(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Config:
    login: str
    salt: bytes
    digest: bytes
    totp_secret: str
    origin: str

    @classmethod
    def load(cls, path):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("version") != 1 or not ONION_ORIGIN.fullmatch(raw["origin"]):
            raise ValueError("Unsupported authentication configuration")
        salt = base64.b64decode(raw["password_salt"], validate=True)
        digest = base64.b64decode(raw["password_hash"], validate=True)
        key = base64.b32decode(raw["totp_secret"], casefold=False)
        if len(salt) != 32 or len(digest) != 64 or len(key) != 20:
            raise ValueError("Invalid authentication configuration")
        if raw["scrypt"] != {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": 64}:
            raise ValueError("Unsupported password derivation")
        if not isinstance(raw["login"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", raw["login"]):
            raise ValueError("Invalid login name")
        return cls(raw["login"], salt, digest, raw["totp_secret"], raw["origin"])


def initialize(directory, origin):
    """Keep plaintext recovery credentials root-only; runtime gets only a derived file."""
    if not ONION_ORIGIN.fullmatch(origin):
        raise ValueError("Expected the HTTP origin of a Tor v3 onion service")
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    credentials_path = directory / "credentials.json"
    auth_path = directory / "auth.json"
    if credentials_path.exists():
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", credentials["login"]):
            raise ValueError("Invalid saved credentials; refusing to reset them")
        if not isinstance(credentials["password"], str) or not 1 <= len(credentials["password"]) <= 256:
            raise ValueError("Invalid saved credentials; refusing to reset them")
        if len(base64.b32decode(credentials["totp_secret"], casefold=False)) != 20:
            raise ValueError("Invalid saved TOTP secret; refusing to reset it")
        if not isinstance(credentials["otpauth_uri"], str) or not credentials["otpauth_uri"].startswith("otpauth://totp/"):
            raise ValueError("Invalid saved enrollment URI; refusing to reset it")
    else:
        if auth_path.exists():
            raise ValueError("Runtime credentials exist without recovery credentials; refusing reset")
        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
        credentials = {"login": "owner", "password": secrets.token_urlsafe(24), "totp_secret": secret}
        credentials["otpauth_uri"] = "otpauth://totp/" + quote("OnionDesk:owner", safe="") + "?" + urlencode({
            "secret": secret, "issuer": "OnionDesk", "algorithm": "SHA1", "digits": 6, "period": 30})
        atomic_json(credentials_path, credentials)
    if auth_path.exists():
        existing = Config.load(auth_path)
        matches = (hmac.compare_digest(existing.login, credentials["login"])
                   and hmac.compare_digest(existing.totp_secret, credentials["totp_secret"])
                   and hmac.compare_digest(existing.digest, password_hash(credentials["password"], existing.salt)))
        if not matches:
            raise ValueError("Recovery and runtime credentials differ; refusing automatic reset")
        if existing.origin == origin:
            os.chmod(credentials_path, 0o600)
            os.chmod(auth_path, 0o600)
            return
        salt = existing.salt
        digest = existing.digest
    else:
        salt = secrets.token_bytes(32)
        digest = password_hash(credentials["password"], salt)
    atomic_json(auth_path, {"version": 1, "login": credentials["login"],
                          "password_salt": base64.b64encode(salt).decode("ascii"),
                          "password_hash": base64.b64encode(digest).decode("ascii"),
                          "scrypt": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": 64},
                          "totp_secret": credentials["totp_secret"], "origin": origin})
    os.chmod(credentials_path, 0o600)
    os.chmod(auth_path, 0o600)


class AuthState:
    def __init__(self, config, state_dir, clock=time.time):
        self.config = config
        self.clock = clock
        self.lock = threading.RLock()
        self.prelogins = OrderedDict()
        self.sessions = OrderedDict()
        self.failures = deque()
        self.blocked_until = 0
        self.state_file = Path(state_dir) / "totp-state.json"
        self.last_counter = -1
        if self.state_file.exists():
            value = json.loads(self.state_file.read_text(encoding="utf-8"))
            if value.get("version") != 1 or type(value.get("last_counter")) is not int or value["last_counter"] < 0:
                raise ValueError("Invalid saved TOTP replay state")
            self.last_counter = value["last_counter"]

    def expire(self):
        now = self.clock()
        for records in (self.prelogins, self.sessions):
            for token in list(records):
                if records[token]["expires"] <= now:
                    del records[token]
        while self.failures and self.failures[0] <= now - FAILURE_WINDOW:
            self.failures.popleft()

    def new_prelogin(self):
        with self.lock:
            self.expire()
            while len(self.prelogins) >= 256:
                self.prelogins.popitem(last=False)
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            self.prelogins[token] = {"csrf": csrf, "expires": self.clock() + PRELOGIN_SECONDS}
            return token, csrf

    def session(self, token):
        with self.lock:
            self.expire()
            return self.sessions.get(token)

    def authenticate(self, prelogin, form):
        # The lock also bounds expensive scrypt to one simultaneous invocation.
        with self.lock:
            self.expire()
            record = self.prelogins.get(prelogin)
            if not record or not text_matches(record["csrf"], form.get("csrf", "")):
                return 403, None
            now = self.clock()
            if now < self.blocked_until:
                return 429, None
            digest = password_hash(form["password"], self.config.salt)
            password_ok = hmac.compare_digest(digest, self.config.digest)
            login_ok = text_matches(form["login"], self.config.login)
            counter = int(now) // 30
            matches = [step for step in (counter - 1, counter, counter + 1)
                       if step >= 0 and text_matches(totp(self.config.totp_secret, step), form["otp"])]
            accepted = max(matches, default=-1)
            if not (password_ok and login_ok and accepted > self.last_counter):
                self.failures.append(now)
                if len(self.failures) >= MAX_FAILURES:
                    self.blocked_until = now + LOCK_SECONDS
                logging.info("Sign-in rejected")
                return 401, None
            # Persist before creating a session: storage failure must fail closed.
            atomic_json(self.state_file, {"version": 1, "last_counter": accepted})
            self.last_counter = accepted
            self.failures.clear()
            del self.prelogins[prelogin]
            while len(self.sessions) >= 64:
                self.sessions.popitem(last=False)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {"csrf": secrets.token_urlsafe(32), "expires": now + SESSION_SECONDS}
            logging.info("Sign-in accepted")
            return 303, token


class AuthHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state):
        self.state = state
        super().__init__(address, Handler)

    def handle_error(self, request, client_address):
        # Never emit request bodies, headers, configuration or traceback locals.
        logging.error("Authentication request failed internally")


class Handler(BaseHTTPRequestHandler):
    server_version = "OnionDesk"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    @property
    def state(self):
        return self.server.state

    def cookie(self, name):
        header = self.headers.get("Cookie", "")
        if len(header) > 8192 or len(self.headers.get_all("Cookie", [])) > 1:
            return ""
        if sum(item.strip().split("=", 1)[0] == name for item in header.split(";")) != 1:
            return ""
        try:
            parsed = cookies.SimpleCookie(header)
            return parsed[name].value if name in parsed else ""
        except cookies.CookieError:
            return ""

    def same_host(self):
        return self.headers.get("Host", "") == urlsplit(self.state.config.origin).netloc

    def same_origin(self):
        return self.headers.get("Origin", "") == self.state.config.origin

    def respond(self, status, content=b"", *, location=None, cookie_values=()):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if location:
            self.send_header("Location", location)
        for name, value, max_age in cookie_values:
            # Tor encrypts onion HTTP. Do not rely on a browser's Secure-cookie
            # exception for onion origins; ordinary HTTP clients may reject it.
            self.send_header("Set-Cookie", f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(content)

    def page(self, filename, csrf, message=""):
        template = Path(__file__).with_name(filename).read_text(encoding="utf-8")
        return template.replace("{{CSRF}}", csrf).replace("{{MESSAGE}}", message).encode("utf-8")

    def do_GET(self):
        if not self.same_host():
            self.respond(403)
            return
        path = urlsplit(self.path).path
        if path == "/login":
            if self.state.session(self.cookie(SESSION_COOKIE)):
                self.respond(303, location="/")
                return
            token, csrf = self.state.new_prelogin()
            self.respond(200, self.page("login.html", csrf),
                         cookie_values=[(PRELOGIN_COOKIE, token, PRELOGIN_SECONDS)])
        elif path == "/auth-check":
            if not self.state.session(self.cookie(SESSION_COOKIE)):
                self.respond(401)
                return
            original_path = urlsplit(self.headers.get("X-Original-URI", "/")).path
            original_path = "/" + posixpath.normpath(unquote(original_path)).lstrip("/")
            websocket = (original_path in ("/ws/workstation", "/ws/gateway")
                         or bool(self.headers.get("X-Original-Upgrade")))
            if websocket and (not self.same_origin() or self.headers.get("X-Original-Method") != "GET"):
                self.respond(403)
            elif self.headers.get("Origin") and not self.same_origin():
                self.respond(403)
            else:
                self.respond(204)
        elif path == "/":
            session = self.state.session(self.cookie(SESSION_COOKIE))
            if session:
                self.respond(200, self.page("menu.html", session["csrf"]))
            else:
                self.respond(303, location="/login")
        else:
            self.respond(404)

    def read_form(self, expected):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            return None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if not 0 < length <= MAX_BODY or self.headers.get_content_type() != "application/x-www-form-urlencoded":
            return None
        try:
            data = self.rfile.read(length).decode("utf-8", errors="strict")
            values = parse_qs(data, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
        except (UnicodeError, ValueError):
            return None
        if set(values) != expected or any(len(value) != 1 or len(value[0]) > 256 for value in values.values()):
            return None
        return {key: value[0] for key, value in values.items()}

    def do_POST(self):
        if not self.same_host() or not self.same_origin():
            self.respond(403)
            return
        path = urlsplit(self.path).path
        if path == "/login":
            form = self.read_form({"login", "password", "otp", "csrf"})
            if form is None:
                self.respond(400)
                return
            status, session = self.state.authenticate(self.cookie(PRELOGIN_COOKIE), form)
            if status == 303:
                self.respond(303, location="/", cookie_values=[(SESSION_COOKIE, session, SESSION_SECONDS),
                                                             (PRELOGIN_COOKIE, "", 0)])
            else:
                token, csrf = self.state.new_prelogin()
                message = {401: "Не удалось войти. Проверьте имя, пароль и код.",
                           403: "Форма устарела. Используйте новую форму ниже.",
                           429: "Вход временно заблокирован. Подождите 10 минут и попробуйте снова."}[status]
                self.respond(status, self.page("login.html", csrf, message),
                             cookie_values=[(PRELOGIN_COOKIE, token, PRELOGIN_SECONDS)])
        elif path == "/logout":
            form = self.read_form({"csrf"})
            token = self.cookie(SESSION_COOKIE)
            with self.state.lock:
                session = self.state.session(token)
                if form is None or not session or not text_matches(session["csrf"], form["csrf"]):
                    self.respond(403)
                    return
                del self.state.sessions[token]
            logging.info("Session ended")
            self.respond(303, location="/login", cookie_values=[(SESSION_COOKIE, "", 0)])
        else:
            self.respond(404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--config-dir", required=True)
    init.add_argument("--origin", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--config", required=True)
    serve.add_argument("--state-dir", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        if args.command == "init":
            initialize(args.config_dir, args.origin)
            print("Данные входа сохранены в /etc/oniondesk/credentials.json (только для root).")
        else:
            state = AuthState(Config.load(args.config), args.state_dir)
            AuthHTTPServer(("127.0.0.1", 18081), state).serve_forever(poll_interval=0.5)
    except (ValueError, KeyError, TypeError, OSError):
        logging.error("Authentication configuration or storage failed; no credentials were reset")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
