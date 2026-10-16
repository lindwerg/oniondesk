#!/usr/bin/env python3
"""Laptop bootstrap through a verified local Tor SOCKS proxy. Never connects directly."""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shlex
import stat
import tarfile
import threading
import time
import sys

import paramiko
import requests
import socks

KIT = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
MAX_RESULT = 1024 * 1024
ONION_RE = re.compile(r"[a-z2-7]{56}\.onion")
INSTALL_STATE_DIR = "/var/lib/oniondesk-client"
INSTALL_STATE_FILE = INSTALL_STATE_DIR + "/install-state.json"
INSTALL_MARKER = "/var/lib/oniondesk/host-installed"
MAX_STATE = 4096
CHANNEL_REQUEST_TIMEOUT = 60
MAX_RUNTIME_FILE = 2 * 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
STAGING_RE = re.compile(r"/var/tmp/oniondesk-input\.[A-Za-z0-9]{8}")
UNIT_RE = re.compile(r"oniondesk-install-[0-9a-f]{8}")
RUNTIME_FILES = (
    "server/common.sh", "server/control.sh", "server/guest-status.py",
    "server/guest-workstation-setup.sh", "server/guest-workstation-status.py",
    "server/guest-clean-files.py", "server/oniondesk-clean-files.desktop",
    "server/guest-auto-cleaner.py", "server/oniondesk-auto-cleaner.service",
    "server/first_boot.py", "server/oniondesk-first-boot.service",
    "server/public-obfs4.conf",
    "server/host_tor.py",
    "server/image_tools.py", "server/install.sh", "server/preflight.py",
    "server/runtime-audit.py", "server/seal.sh", "server/validate-guest.py",
    "server/verify-image.sh", "server/vm-service.sh",
    "frontend/auth.py", "frontend/build-nginx-config.py",
    "frontend/check-nginx-listeners.py", "frontend/install-auth.sh",
    "frontend/login.html", "frontend/menu.html", "frontend/nginx.conf.in",
    "frontend/oniondesk-auth.service",
)

# Executed only through the pinned root SSH connection. lexists also rejects
# dangling links; an existing installation is never removed or overwritten.
INSTALL_GUARD = '''import os, subprocess
for path in ("/opt/oniondesk", "/var/lib/oniondesk", "/var/lib/libvirt/images/oniondesk", "/etc/oniondesk", "/etc/tor/oniondesk.conf"):
    if os.path.lexists(path):
        raise SystemExit("Найдена прежняя или частичная установка. Повторное развёртывание запрещено; продолжите наблюдение или проверьте сервер через консоль провайдера.")
units = subprocess.run(["systemctl", "list-units", "--all", "--plain", "--no-legend", "oniondesk-install-*"], check=True, capture_output=True, text=True)
if units.stdout.strip():
    raise SystemExit("Обнаружена прежняя задача установки, в том числе возможная задача старой версии мастера. Второй установщик не запущен; используйте консоль провайдера.")
'''


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def validate_host(value: str) -> str:
    value = value.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Введите IP сервера из панели провайдера, без http:// и порта.") from exc
    if not address.is_global:
        raise ValueError("Нужен публичный IP купленного сервера.")
    return str(address)


def validate_fingerprint(value: str) -> str:
    value = value.strip().rstrip("=")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value):
        raise ValueError("Нужен отпечаток SHA256 из консоли провайдера; пример есть в PDF.")
    return value


class PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        if not secrets.compare_digest(fingerprint(key), self.expected):
            raise paramiko.SSHException(
                "Ключ сервера не совпал с отпечатком из панели. Подключение остановлено."
            )
        client.get_host_keys().add(hostname, key.get_name(), key)


def find_tor_proxy() -> int:
    """Only loopback SOCKS is allowed, with TLS-verified IsTor evidence."""
    failures = []
    for port in (9150, 9050):
        session = requests.Session()
        session.trust_env = False
        proxy = f"socks5h://127.0.0.1:{port}"
        try:
            response = session.get(
                "https://check.torproject.org/api/ip",
                proxies={"http": proxy, "https": proxy},
                # SOCKS connection setup includes building the Tor circuit.
                # A verified live route took 17 seconds in the network test.
                timeout=(30, 45),
            )
            response.raise_for_status()
            if response.json().get("IsTor") is True:
                return port
            failures.append(f"{port}: маршрут не подтверждён как Tor")
        except (requests.RequestException, ValueError):
            failures.append(f"{port}: Tor недоступен или проверка не завершилась")
        finally:
            session.close()
    raise RuntimeError(
        "Откройте Tor Browser, дождитесь подключения и повторите. "
        "Прямого подключения не будет. " + "; ".join(failures)
    )


def connect(host: str, password: str, expected: str, proxy_port: int):
    tunnel = socks.socksocket()
    tunnel.set_proxy(socks.SOCKS5, "127.0.0.1", proxy_port, rdns=True)
    tunnel.settimeout(60)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey(expected))
    try:
        tunnel.connect((host, 22))
        client.connect(
            hostname=host, username="root", password=password, sock=tunnel,
            look_for_keys=False, allow_agent=False, timeout=60,
            auth_timeout=60, banner_timeout=60, channel_timeout=60,
            disabled_algorithms={"keys": ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"]},
        )
        client.get_transport().set_keepalive(30)
        return client
    except Exception:
        client.close()
        tunnel.close()
        raise


def _bounded_channel_request(channel, request, *, timeout):
    """Paramiko exec/subsystem acknowledgements ignore Channel.settimeout()."""
    acknowledged = threading.Event()
    errors = []
    def invoke():
        try:
            request()
        except Exception as error:
            errors.append(error)
        finally:
            acknowledged.set()
    threading.Thread(target=invoke, daemon=True, name="ssh-request").start()
    if not acknowledged.wait(timeout):
        channel.close()
        raise TimeoutError("Сервер не подтвердил запрос вовремя. Подключитесь заново; прямого подключения не будет.")
    if errors:
        raise errors[0]


def run(client, command: str, timeout: int = 60) -> str:
    # Commands are fixed or interpolate shlex-quoted, locally validated values.
    channel = client.get_transport().open_session(timeout=30)
    try:
        channel.settimeout(timeout)
        deadline = time.monotonic() + timeout
        _bounded_channel_request(channel, lambda: channel.exec_command(command),
                                 timeout=min(timeout, CHANNEL_REQUEST_TIMEOUT))
        output, errors = bytearray(), bytearray()
        while True:
            if channel.recv_ready():
                output.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(65536))
            if len(output) + len(errors) > MAX_RESULT:
                raise RuntimeError("Слишком большой ответ сервера; операция остановлена.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Сервер не ответил вовремя. Повторите проверку из его консоли.")
            time.sleep(0.05)
        result = output.decode("utf-8", errors="replace")
        if channel.recv_exit_status() != 0:
            detail = errors.decode("utf-8", errors="replace") or result
            raise RuntimeError(detail[:1500] or "Сервер вернул ошибку.")
        return result
    finally:
        channel.close()


def package_payload() -> bytes:
    buffer = io.BytesIO()
    for folder in ("server", "frontend"):
        base = KIT / folder
        if base.is_symlink() or not base.is_dir():
            raise RuntimeError("Комплект распакован не полностью или содержит символическую ссылку.")
        if any(path.is_symlink() for path in base.iterdir()):
            raise RuntimeError("В комплекте обнаружена символическая ссылка.")
    total = 0
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for relative in RUNTIME_FILES:
            path = KIT / relative
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("Комплект распакован не полностью: отсутствует обязательный файл программы.")
            with path.open("rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RUNTIME_FILE:
                    raise RuntimeError("Неожиданный тип или размер файла программы.")
                content = source.read(MAX_RUNTIME_FILE + 1)
            total += len(content)
            if len(content) > MAX_RUNTIME_FILE or total > MAX_PAYLOAD:
                raise RuntimeError("Размер комплекта превышает допустимый предел.")
            member = tarfile.TarInfo(relative)
            member.size = len(content)
            member.mode = 0o750 if path.suffix == ".sh" else 0o644
            archive.addfile(member, io.BytesIO(content))
    payload = buffer.getvalue()
    if len(payload) > MAX_PAYLOAD:
        raise RuntimeError("Размер архива превышает допустимый предел.")
    return payload


def open_sftp(client):
    """Bound both the subsystem handshake and subsequent SFTP operations."""
    channel = client.get_transport().open_session(timeout=30)
    try:
        channel.settimeout(60)
        _bounded_channel_request(channel, lambda: channel.invoke_subsystem("sftp"),
                                 timeout=CHANNEL_REQUEST_TIMEOUT)
        return paramiko.SFTPClient(channel)
    except Exception:
        channel.close()
        raise


def _private_directory(sftp, path, *, mode=0o700):
    metadata = sftp.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise RuntimeError("Небезопасные права серверной папки; операция остановлена.")


def _read_remote_file(sftp, path, limit, *, private=False):
    metadata = sftp.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
        raise RuntimeError("Неожиданный тип или размер серверного файла.")
    if private and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise RuntimeError("Небезопасные права серверного файла; операция остановлена.")
    with sftp.file(path, "rb") as source:
        content = source.read(limit + 1)
    if len(content) > limit or len(content) != metadata.st_size:
        raise RuntimeError("Серверный файл изменился или превышает допустимый размер.")
    return content


def _unique_json(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("Повторяющиеся поля серверного состояния.")
        document[key] = value
    return document


def _validate_install_state(document):
    if (not isinstance(document, dict)
            or set(document) != {"version", "unit", "staging", "sha256"}
            or type(document["version"]) is not int or document["version"] != 1
            or not isinstance(document["unit"], str) or not UNIT_RE.fullmatch(document["unit"])
            or not isinstance(document["staging"], str) or not STAGING_RE.fullmatch(document["staging"])
            or not isinstance(document["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", document["sha256"])):
        raise RuntimeError("Сохранённое состояние установки повреждено. Повторное развёртывание запрещено; используйте консоль провайдера.")
    return document


def _load_install_state(client):
    sftp = open_sftp(client)
    try:
        try:
            _private_directory(sftp, INSTALL_STATE_DIR)
        except FileNotFoundError:
            return None
        document = json.loads(_read_remote_file(sftp, INSTALL_STATE_FILE, MAX_STATE, private=True), object_pairs_hook=_unique_json)
        return _validate_install_state(document)
    except (ValueError, UnicodeError, FileNotFoundError) as error:
        raise RuntimeError("Сохранённое состояние установки отсутствует или повреждено. Повторное развёртывание запрещено; используйте консоль провайдера.") from error
    finally:
        sftp.close()


def _python_command(source, *arguments):
    return "/usr/bin/python3 -c " + shlex.quote(source) + "".join(" " + shlex.quote(argument) for argument in arguments)


def _ensure_install_allowed(client):
    if _load_install_state(client) is not None:
        raise RuntimeError("Найдена сохранённая установка. Нажмите «Продолжить проверку установки»; второй установщик не запущен.")
    run(client, _python_command(INSTALL_GUARD))


def _reserve_and_start_install(client, document, tor_mode):
    _validate_install_state(document)
    # The exclusive reservation is durable BEFORE starting systemd. If SSH or
    # the host dies between these steps, resume refuses to redeploy blindly.
    source = INSTALL_GUARD + '''import hashlib, json, stat, sys
state_dir = "/var/lib/oniondesk-client"
state_path = state_dir + "/install-state.json"
document = json.loads(sys.argv[1])
staging = document["staging"]
metadata = os.lstat(staging)
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("Небезопасная папка переданного комплекта; установка не началась.")
archive = staging + "/kit.tar.gz"
metadata = os.lstat(archive)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("Небезопасный архив комплекта; установка не началась.")
with open(archive, "rb") as stream:
    if hashlib.sha256(stream.read(8 * 1024 * 1024 + 1)).hexdigest() != document["sha256"]:
        raise SystemExit("Переданный комплект изменился; установка не началась.")
try:
    os.mkdir(state_dir, 0o700)
except FileExistsError:
    raise SystemExit("Уже существует состояние другой установки. Второй установщик не запущен.")
directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fchmod(directory, 0o700)
    descriptor = os.open("install-state.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(document, sort_keys=True) + "\\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory)
finally:
    os.close(directory)
subprocess.run(["systemd-run", "--quiet", "--unit=" + document["unit"], "--property=Type=oneshot", "--property=RemainAfterExit=yes", "/bin/bash", staging + "/server/install.sh", "--yes-licenses", "--tor-mode", sys.argv[2]], check=True)
'''
    run(client, _python_command(source, json.dumps(document, sort_keys=True), tor_mode))


def read_credentials(client, *, require_complete=True):
    sftp = open_sftp(client)
    try:
        _private_directory(sftp, "/etc/oniondesk")
        if require_complete:
            # The dedicated auth user must traverse this parent to its own
            # private replay-state directory. Host markers remain root:0600.
            _private_directory(sftp, "/var/lib/oniondesk", mode=0o711)
            marker = _read_remote_file(sftp, INSTALL_MARKER, 128, private=True).decode("ascii").strip()
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", marker):
                raise ValueError("Неверный маркер завершения установки.")
            datetime.fromisoformat(marker)
        credentials = json.loads(_read_remote_file(sftp, "/etc/oniondesk/credentials.json", 65536, private=True), object_pairs_hook=_unique_json)
        onion = _read_remote_file(sftp, "/var/lib/tor/oniondesk/hostname", 256).decode("ascii").strip()
        if not ONION_RE.fullmatch(onion):
            raise ValueError("Неверный адрес доступа.")
        if not isinstance(credentials, dict):
            raise ValueError("Неверный формат карточки.")
        keys = ("login", "password", "totp_secret", "otpauth_uri")
        if any(not isinstance(credentials.get(key), str) or not 1 <= len(credentials[key]) <= 2048 for key in keys):
            raise ValueError("Неполная карточка.")
        return {"url": "http://" + onion + "/", **{key: credentials[key] for key in keys}}
    except (ValueError, UnicodeError, FileNotFoundError) as error:
        raise RuntimeError("Завершение установки или карточка доступа не подтверждены. Повторное развёртывание не выполнялось; продолжите проверку установки либо используйте консоль провайдера.") from error
    finally:
        sftp.close()


def _observe_install(client, document, emit):
    _validate_install_state(document)
    unit = document["unit"]
    emit("Продолжаю проверку той же серверной задачи. Файлы повторно не передаются.")
    deadline = time.monotonic() + 3 * 3600
    last = None
    while time.monotonic() < deadline:
        source = '''import subprocess, sys
result = subprocess.run(["systemctl", "show", sys.argv[1], "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus"], capture_output=True, text=True, timeout=30)
if result.returncode and "LoadState=not-found" not in result.stdout.splitlines():
    raise SystemExit("Не удалось проверить сохранённую задачу установки; повторное развёртывание запрещено.")
sys.stdout.write(result.stdout)
'''
        state = run(client, _python_command(source, unit))
        status = dict(line.split("=", 1) for line in state.splitlines() if "=" in line)
        if status.get("LoadState") == "not-found":
            try:
                credentials = read_credentials(client)
            except RuntimeError:
                raise RuntimeError("Сохранённая задача отсутствует, например после перезагрузки сервера; завершение установки не подтверждено. Новый установщик не запущен. Используйте консоль провайдера.") from None
            emit("Сервер уже завершил установку; проверенный маркер и карточка получены.")
            return credentials
        if status.get("LoadState") != "loaded":
            raise RuntimeError("Состояние сохранённой задачи не подтверждено. Повторное развёртывание запрещено; используйте консоль провайдера.")
        lines = run(client, "journalctl -u " + unit + " --no-pager -n 8 -o cat").strip()
        if lines and lines != last:
            emit(lines)
            last = lines
        if status.get("ActiveState") == "failed" or status.get("Result") not in (None, "success"):
            raise RuntimeError("Установка завершилась ошибкой. Повторное развёртывание не выполнялось; используйте консоль провайдера.")
        if status.get("SubState") == "exited":
            if status.get("ExecMainStatus") != "0":
                raise RuntimeError("Установщик вернул ошибку.")
            return read_credentials(client)
        if status.get("ActiveState") not in ("active", "activating", "reloading"):
            raise RuntimeError("Сохранённая задача не работает и не подтвердила завершение. Новый установщик не запущен; используйте консоль провайдера.")
        time.sleep(5)
    raise TimeoutError("Наблюдение заняло более 3 часов. Серверная задача может продолжаться; нажмите «Продолжить проверку установки» позже.")


def resume_install(client, emit):
    document = _load_install_state(client)
    if document is None:
        # In particular, do not guess a random transient unit used by old kits.
        run(client, _python_command(INSTALL_GUARD))
        raise RuntimeError("Сохранённая задача установки не найдена. Если сервер уже настроен, получите карточку; повторная установка не запускалась.")
    return _observe_install(client, document, emit)


def install(client, emit, *, tor_mode: str = "public-obfs4") -> dict:
    if tor_mode not in ("wizard", "direct", "public-obfs4"):
        raise ValueError("Неизвестный способ подключения Tor.")
    emit("Проверяю отсутствие прежней установки и совместимость сервера...")
    _ensure_install_allowed(client)
    run(client, "test \"$(id -u)\" = 0 && . /etc/os-release && test \"$ID\" = debian && test \"$VERSION_ID\" = 13")
    payload = package_payload()
    digest = hashlib.sha256(payload).hexdigest()
    staging = run(client, "umask 077; mktemp -d /var/tmp/oniondesk-input.XXXXXXXX").strip()
    if not STAGING_RE.fullmatch(staging):
        raise RuntimeError("Неожиданный путь временной папки сервера.")
    remote_archive = staging + "/kit.tar.gz"
    emit("Передаю файлы программы через Tor на ваш сервер...")
    sftp = open_sftp(client)
    try:
        with sftp.file(remote_archive, "wb") as remote:
            remote.write(payload)
        sftp.chmod(remote_archive, 0o600)
    finally:
        sftp.close()
    emit("Проверяю копию файлов на сервере перед установкой...")
    actual = run(client, "sha256sum " + shlex.quote(remote_archive)).split()[0]
    if not secrets.compare_digest(actual, digest):
        raise RuntimeError("Комплект повреждён при передаче. Установка не началась.")
    run(client, "tar -xzf " + shlex.quote(remote_archive) + " -C " + shlex.quote(staging))
    run(client, "bash " + shlex.quote(staging + "/server/install.sh") + " --check")
    document = {"version": 1, "unit": "oniondesk-install-" + secrets.token_hex(4), "staging": staging, "sha256": digest}
    _reserve_and_start_install(client, document, tor_mode)
    emit("Установка запущена. Загрузка Whonix занимает время; сервер продолжит работу при разрыве связи.")
    return _observe_install(client, document, emit)


def main():
    import tkinter as tk
    from tkinter import messagebox, ttk
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.title("OnionDesk - первая установка")
    root.geometry("820x670")
    root.minsize(650, 560)
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Подготовка удалённого рабочего стола", font=("Arial", 17, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Сначала откройте Tor Browser и подключитесь. Нужен свежий Debian 13 на купленном сервере.", wraplength=740).pack(anchor="w", pady=(8, 16))
    inputs = {}
    for name, label, masked in (
        ("host", "IP сервера из панели провайдера", False),
        ("password", "Первоначальный пароль root", True),
        ("fingerprint", "Отпечаток SSH-ключа SHA256 из консоли провайдера", False),
    ):
        ttk.Label(frame, text=label).pack(anchor="w")
        entry = ttk.Entry(frame, show="*" if masked else "")
        entry.pack(fill="x", pady=(3, 10))
        inputs[name] = entry
    ttk.Label(frame, text="В консоли провайдера выполните: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", wraplength=740).pack(anchor="w")
    consent = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, variable=consent, text="Я прочитал условия Whonix (ссылки в PDF) и разрешаю установку на этом свежем сервере.").pack(anchor="w", pady=12)
    log = ScrolledText(frame, height=11, wrap="word", state="disabled")
    log.pack(fill="both", expand=True, pady=(8, 8))
    events = queue.Queue()

    def append(text):
        log.configure(state="normal")
        log.insert("end", str(text) + "\n")
        log.see("end")
        log.configure(state="disabled")

    def show_access(data):
        window = tk.Toplevel(root)
        window.title("Доступ к рабочему столу - сохраните в защищённом месте")
        window.geometry("760x470")
        body = ttk.Frame(window, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Серверная часть установлена. Whonix ещё требует первого подключения и установки Telegram.", wraplength=710).pack(anchor="w", pady=10)
        for label, key in (("Адрес: открыть вручную в Tor-клиенте", "url"), ("Имя входа", "login"), ("Пароль", "password"), ("Секрет TOTP: добавить в приложение кодов", "totp_secret")):
            ttk.Label(body, text=label).pack(anchor="w")
            entry = ttk.Entry(body)
            entry.insert(0, data[key])
            entry.configure(state="readonly")
            entry.pack(fill="x", pady=(3, 8))
        ttk.Label(body, text="Пароль и секрет не записаны на ноутбук автоматически. Сохраните их в зашифрованном менеджере. Никому не отправляйте скриншот этого окна. Затем пройдите первые шаги Whonix из PDF; SSH закройте отдельным seal.sh после проверок.", wraplength=710).pack(anchor="w", pady=12)

    def worker(host, password, expected):
        connection = None
        try:
            events.put(("log", "Проверяю, что подключение идёт через Tor..."))
            proxy = find_tor_proxy()
            connection = connect(host, password, expected, proxy)
            events.put(("log", "Ключ сервера совпал. Подключение установлено через Tor."))
            data = install(connection, lambda item: events.put(("log", item)))
            events.put(("access", data))
        except Exception as exc:
            # Error messages intentionally contain no entered password or OTP.
            events.put(("error", str(exc)))
        finally:
            if connection:
                connection.close()
            events.put(("done", None))

    def start():
        try:
            if not consent.get():
                raise ValueError("Сначала прочитайте условия и отметьте согласие на установку.")
            host = validate_host(inputs["host"].get())
            expected = validate_fingerprint(inputs["fingerprint"].get())
            password = inputs["password"].get()
            if not password:
                raise ValueError("Введите пароль root из панели провайдера.")
        except ValueError as exc:
            messagebox.showerror("Проверьте данные", str(exc))
            return
        inputs["password"].delete(0, "end")
        button.configure(state="disabled")
        threading.Thread(target=worker, args=(host, password, expected), daemon=True).start()

    button = ttk.Button(frame, text="Проверить сервер и установить", command=start)
    button.pack(anchor="e", pady=8)

    def pump():
        try:
            while True:
                kind, value = events.get_nowait()
                if kind == "log":
                    append(value)
                elif kind == "error":
                    append("Ошибка: " + value)
                    messagebox.showerror("Установка не подтверждена", value)
                elif kind == "access":
                    show_access(value)
                elif kind == "done":
                    button.configure(state="normal")
        except queue.Empty:
            pass
        root.after(150, pump)

    inputs["host"].focus_set()
    pump()
    root.mainloop()


if __name__ == "__main__":
    main()
