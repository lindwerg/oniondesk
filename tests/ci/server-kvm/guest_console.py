"""Owned guests' existing loopback RFB consoles, fixed read-only diagnostics."""
from contextlib import contextmanager
import fcntl
import io
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import struct
import subprocess
import time

import confidential

PROFILES = {"workstation": ("oniondesk-workstation", 5902),
            "gateway": ("oniondesk-gateway", 5901)}
SUPPRESSION_MARKERS = {
    "workstation": Path("/run/oniondesk-ci-private-workstation-console-active"),
    "gateway": Path("/run/oniondesk-ci-private-gateway-console-active"),
}
LOCK_FILES = {
    "workstation": Path("/run/oniondesk-ci-workstation-console.lock"),
    "gateway": Path("/run/oniondesk-ci-gateway-console.lock"),
}
RAW_IMAGES = {"workstation": Path("/run/oniondesk-ci-private-workstation.ppm"),
              "gateway": Path("/run/oniondesk-ci-private-gateway.ppm")}
OUTPUTS = {"workstation": Path("/ci-evidence/workstation-console.cms"),
           "gateway": Path("/ci-evidence/gateway-console.cms")}
KEY_EVENT_INTERVAL = 0.02
MAX_LITERAL_BYTES = 1100
MAX_KEY_EVENTS = 2600
MAX_CAPTURE_SECONDS = 115
LOCK_WAIT_SECONDS = 10
# These are complete literals. No commands, paths or keys come from arguments or
# guest output. timeout also bounds the read-only shell after RFB disconnects.
READ_ONLY_COMMANDS = {
    "workstation": (
        "timeout 30 sh -c 'clear; echo FIRST_BOOT; "
        "systemctl status oniondesk-first-boot.service --no-pager -l -n0; "
        "journalctl -u oniondesk-first-boot.service -n6 --no-pager -o cat; "
        "echo PROCESSES; ps -eo pid,ppid,euid,comm,args | "
        'grep -E "[o]niondesk-workstation-setup|[c]url|[t]orsocks|[a]pt|[s]leep" | head -n10; '
        "echo NETWORK; ip -o route; "
        "timeout 8 getent ahostsv4 check.torproject.org | head -n2; "
        "curl --fail --silent --show-error --max-time 15 https://check.torproject.org/api/ip; "
        "echo CURL_EXIT=$?; dpkg-query -W telegram-desktop qemu-guest-agent; "
        "test -f /var/lib/oniondesk/setup.complete && echo SETUP_COMPLETE_PRESENT'"
    ),
    "gateway": (
        "timeout 30 sh -c 'clear; echo TOR_UNITS; "
        "systemctl status tor@default.service tor.service --no-pager -l -n0; "
        "journalctl -u tor@default.service -u tor.service -n8 --no-pager -o cat; "
        "echo TOR_CONFIG; "
        'grep -hE "^(%include|DisableNetwork|UseBridges|SocksPort|TransPort|DNSPort)" '
        "/etc/tor/torrc /etc/torrc.d/95_whonix.conf /usr/local/etc/torrc.d/50_user.conf | head -n12; "
        "echo NETWORK; ss -lnt | head -n10; ip -o route'"
    ),
}


def profile(role):
    if not isinstance(role, str) or role not in PROFILES:
        raise ValueError("PrivateConsoleRoleInvalid")
    return PROFILES[role]


def public_capture_suppressed(role):
    profile(role)
    try:
        SUPPRESSION_MARKERS[role].lstat()
    except FileNotFoundError:
        return False
    return True  # Malformed markers fail closed too, including dangling links.


def lock_owner_uid():
    # Root and the existing sandboxed browser use the same 0600 lock inode.
    return pwd.getpwnam("oniondesk-ci-browser").pw_uid


def secure_file(path, owner):
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(path, flags)
    try:
        if created and os.geteuid() == 0:
            os.fchown(descriptor, owner, -1)
        attributes = os.fstat(descriptor)
        if (not stat.S_ISREG(attributes.st_mode) or attributes.st_nlink != 1
                or stat.S_IMODE(attributes.st_mode) != 0o600 or attributes.st_uid != owner):
            raise ValueError("PrivateConsoleFileInvalid")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def role_lock(role):
    profile(role)
    path = LOCK_FILES[role]
    descriptor = secure_file(path, lock_owner_uid())
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("PrivateConsoleLockTimeout") from None
                time.sleep(0.05)
        attributes = os.fstat(descriptor)
        named = path.lstat()
        if (not stat.S_ISREG(attributes.st_mode) or attributes.st_nlink != 1
                or stat.S_IMODE(attributes.st_mode) != 0o600 or attributes.st_uid != lock_owner_uid()
                or (attributes.st_dev, attributes.st_ino)
                != (named.st_dev, named.st_ino)):
            raise ValueError("PrivateConsoleLockReplaced")
        yield
    finally:
        os.close(descriptor)  # Closing, process exit and SIGKILL release flock.


@contextmanager
def public_capture(role):
    if public_capture_suppressed(role):
        raise RuntimeError("PrivateConsolePublicCaptureSuppressed")
    with role_lock(role):
        if public_capture_suppressed(role):
            raise RuntimeError("PrivateConsolePublicCaptureSuppressed")
        # The caller holds this through capture AND public PNG publication.
        yield


def activate_private(role):
    with role_lock(role):
        descriptor = secure_file(SUPPRESSION_MARKERS[role], os.geteuid())
        os.close(descriptor)


@contextmanager
def capture_deadline():
    """Bound the entire capture, including socket, image processing and CMS."""
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("PrivateConsoleExistingTimer")

    def expired(_signal, _frame):
        raise TimeoutError("PrivateConsoleRuntimeLimit")

    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, MAX_CAPTURE_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def receive(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("RFBUnexpectedEOF")
        result.extend(chunk)
    return bytes(result)


def key_event(key, down):
    return struct.pack("!BBHI", 4, int(down), 0, key)


def send_key(connection, key, down):
    # QEMU's emulated keyboard has a bounded queue; never burst a command.
    connection.sendall(key_event(key, down))
    time.sleep(KEY_EVENT_INTERVAL)


def chord(connection, keys):
    for key in keys:
        send_key(connection, key, True)
    for key in reversed(keys):
        send_key(connection, key, False)


def character_keys(char):
    # Preserve actual uppercase/punctuation keysyms and explicit US Shift.
    # Shift + lowercase makes QEMU's CapsLock sync cancel the case.
    shifted = '~!@#$%^&*()_+{}|:"<>?'
    return (0xFFE1, ord(char)) if "A" <= char <= "Z" or char in shifted else (ord(char),)


def command_for(role):
    profile(role)
    command = READ_ONLY_COMMANDS[role]
    # Include the fixed terminal-open/fullscreen/Return events in this limit.
    events = 10 + sum(2 * len(character_keys(char)) for char in command)
    if (not command.isascii() or len(command.encode("ascii")) > MAX_LITERAL_BYTES
            or events > MAX_KEY_EVENTS):
        raise ValueError("PrivateConsoleInputLimit")
    return command


def type_read_only_command(connection, role):
    for char in command_for(role):
        chord(connection, character_keys(char))


def capture(role):
    """No credential bypass: only the two owned production loopback consoles."""
    domain, port = profile(role)
    command_for(role)  # Reject a future overlong literal before touching a guest.
    raw = RAW_IMAGES[role]
    try:
        with capture_deadline():
            # Serialize with public capture/publication before any input.
            activate_private(role)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                connection.settimeout(5)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if receive(connection, 12) != b"RFB 003.008\n":
                    raise ValueError("RFBVersionUnexpected")
                connection.sendall(b"RFB 003.008\n")
                count = receive(connection, 1)[0]
                if not 1 <= count <= 16 or 1 not in receive(connection, count):
                    raise ValueError("RFBExpectedProductionNoneSecurity")
                connection.sendall(b"\x01")
                if receive(connection, 4) != b"\0\0\0\0":
                    raise ValueError("RFBSecurityFailed")
                connection.sendall(b"\x01")
                header = receive(connection, 24)
                name_length = struct.unpack("!I", header[20:24])[0]
                if name_length > 1024:
                    raise ValueError("RFBNameLimit")
                receive(connection, name_length)
                chord(connection, (0xFFE3, 0xFFE9, ord("t")))  # Ctrl+Alt+T
                time.sleep(3)
                chord(connection, (0xFFC8,))                  # QTerminal F11
                time.sleep(1)
                type_read_only_command(connection, role)
                chord(connection, (0xFF0D,))                  # Return
                time.sleep(31)  # The guest's literal timeout is 30 seconds.
                subprocess.run(["virsh", "--connect", "qemu:///system", "screenshot", domain, str(raw)],
                               capture_output=True, check=True, timeout=15)
                if raw.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("PrivateConsoleImageLimit")
                from PIL import Image
                with Image.open(raw) as pixels:
                    pixels.thumbnail((1280, 1024))
                    buffer = io.BytesIO()
                    pixels.convert("L").quantize(colors=16).save(buffer, format="PNG", optimize=True)
                data = buffer.getvalue()
                if len(data) > 60 * 1024:
                    raise ValueError("EncryptedConsoleImageLimit")
                return confidential.encrypt_diagnostic(data, OUTPUTS[role])
    finally:
        raw.unlink(missing_ok=True)
