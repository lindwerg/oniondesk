#!/usr/bin/env python3
"""Configure host Tor and certify its current bootstrap over a private control socket."""
import argparse
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import sys
import time

HOST_CONFIG = """# OnionDesk ingress and private, cookie-authenticated bootstrap probe.
HiddenServiceDir /var/lib/tor/oniondesk
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:18080
ControlSocket /run/tor/control RelaxDirModeCheck
ControlSocketsGroupWritable 0
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie
CookieAuthFileGroupReadable 0
"""


def validated_bridge(text):
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 4 or lines[:3] != ["DisableNetwork 0", "UseBridges 1", "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"]:
        raise ValueError("Публичный мост содержит неизвестные настройки; direct fallback запрещён.")
    parts = lines[3].split()
    if len(parts) != 6 or parts[:2] != ["Bridge", "obfs4"]:
        raise ValueError("Неизвестный формат публичного obfs4-моста.")
    address, port = parts[2].rsplit(":", 1)
    ipaddress.IPv4Address(address)
    if not port.isdecimal() or not 1 <= int(port) <= 65535 or not re.fullmatch(r"[A-F0-9]{40}", parts[3]):
        raise ValueError("Неверный endpoint или fingerprint obfs4-моста.")
    if not parts[4].startswith("cert=") or parts[5] not in {"iat-mode=0", "iat-mode=1", "iat-mode=2"}:
        raise ValueError("Не подтверждены cert/iat-mode obfs4-моста.")
    certificate = parts[4][5:]
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", certificate) or len(base64.b64decode(certificate + "=" * (-len(certificate) % 4), validate=True)) != 52:
        raise ValueError("Неверный сертификат obfs4-моста.")
    return "\n".join(lines) + "\n"


def configure(path, mode, bridge_file):
    bridge = validated_bridge(bridge_file.read_text()) if mode == "public-obfs4" else ""
    path.write_text(HOST_CONFIG + bridge)
    path.chmod(0o644)  # Contains no secrets and must be readable by debian-tor.


def reply(stream):
    values = []
    for _ in range(32):
        line = stream.readline(16385)
        if len(line) > 16384 or not line.endswith(b"\r\n") or not line.startswith(b"250") or line[3:4] not in {b"-", b" "}:
            raise ValueError("Tor Control отклонил запрос или вернул неизвестный ответ.")
        values.append(line[4:-2].decode("ascii"))
        if line[3:4] == b" ":
            return values
    raise ValueError("Ответ Tor Control превышает допустимый размер.")


def query(control_socket, cookie_file, expected_pid, expected_uid, bridges):
    metadata = control_socket.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("Tor Control socket должен принадлежать Tor и иметь права 0600.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(control_socket))
        peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if peer_pid != expected_pid or peer_uid != expected_uid:
            raise ValueError("Control socket не принадлежит текущему процессу Tor.")
        fd = os.open(cookie_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            cookie_metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(cookie_metadata.st_mode) or cookie_metadata.st_uid != expected_uid or stat.S_IMODE(cookie_metadata.st_mode) != 0o600:
                raise ValueError("Tor Control cookie должен принадлежать Tor и иметь права 0600.")
            cookie = source.read(33)
        if len(cookie) != 32:
            raise ValueError("Неизвестный формат Tor Control cookie.")
        with connection.makefile("rwb", buffering=0) as stream:
            stream.write(b"AUTHENTICATE " + cookie.hex().encode("ascii") + b"\r\n")
            if reply(stream) != ["OK"]:
                raise ValueError("Аутентификация Tor Control не подтверждена.")
            stream.write(b"GETCONF DisableNetwork UseBridges\r\n")
            config = dict(line.split("=", 1) for line in reply(stream) if "=" in line)
            if config != {"DisableNetwork": "0", "UseBridges": "1" if bridges else "0"}:
                raise ValueError("Текущий Tor не соответствует выбранному режиму сети.")
            stream.write(b"GETINFO status/bootstrap-phase status/circuit-established\r\n")
            info = dict(line.split("=", 1) for line in reply(stream) if "=" in line)
    phase = info.get("status/bootstrap-phase", "")
    progress = re.search(r"(?:^| )PROGRESS=([0-9]{1,3})(?: |$)", phase)
    return bool(phase.startswith("NOTICE BOOTSTRAP ") and progress and progress[1] == "100"
                and info.get("status/circuit-established") == "1")


def wait_bootstrap(control_socket, cookie_file, expected_pid, expected_uid, bridges, timeout):
    deadline = time.monotonic() + timeout
    next_notice = 0
    while time.monotonic() < deadline:
        try:
            ready = query(control_socket, cookie_file, expected_pid, expected_uid, bridges)
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            ready = False
        if ready:
            return {"bootstrap_progress": 100, "circuit_established": True,
                    "use_bridges": bridges, "tor_pid": expected_pid,
                    "checked_at": datetime.now(timezone.utc).isoformat()}
        if time.monotonic() >= next_notice:
            print("Ожидаю bootstrap 100% и рабочую цепочку host Tor…", file=sys.stderr, flush=True)
            next_notice = time.monotonic() + 30
        time.sleep(3)
    raise TimeoutError("Host Tor не достиг bootstrap 100% с рабочей цепочкой; доступ не объявлен готовым.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    config = commands.add_parser("configure")
    config.add_argument("--output", type=Path, default=Path("/etc/tor/oniondesk.conf"))
    config.add_argument("--tor-mode", choices=["wizard", "direct", "public-obfs4"], required=True)
    config.add_argument("--bridge-file", type=Path, default=Path(__file__).with_name("public-obfs4.conf"))
    wait = commands.add_parser("wait")
    wait.add_argument("--pid", type=int, required=True)
    wait.add_argument("--public-obfs4", action="store_true")
    wait.add_argument("--timeout", type=int, default=1800)
    wait.add_argument("--socket", type=Path, default=Path("/run/tor/control"))
    wait.add_argument("--cookie", type=Path, default=Path("/run/tor/control.authcookie"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("Нужен root для host Tor configuration/control cookie.")
    if args.action == "configure":
        configure(args.output, args.tor_mode, args.bridge_file)
    else:
        if args.pid < 1 or not 1 <= args.timeout <= 3600:
            raise ValueError("Неверный PID или таймаут Tor probe.")
        result = wait_bootstrap(args.socket, args.cookie, args.pid, pwd.getpwnam("debian-tor").pw_uid,
                                args.public_obfs4, args.timeout)
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError) as error:
        print("Host Tor не подтверждён: " + str(error), file=sys.stderr)
        raise SystemExit(1)
