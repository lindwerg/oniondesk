"""Owned Workstation's existing loopback RFB console, fixed read-only commands."""
import io
from pathlib import Path
import socket
import struct
import subprocess
import time

import confidential

DOMAIN = "oniondesk-workstation"
SUPPRESSION_MARKER = Path("/run/oniondesk-ci-private-console-active")
KEY_EVENT_INTERVAL = 0.02
# The command is a literal, never assembled from guest output or arguments.
READ_ONLY_COMMAND = (
    "clear; systemctl show oniondesk-first-boot.service "
    "-p LoadState,ActiveState,SubState,Result,Restart,ConditionResult,ExecMainStatus; "
    "sudo -n journalctl -u oniondesk-first-boot.service -n 16 --no-pager -o cat; "
    "systemctl --no-pager list-jobs; "
    "cat /proc/cmdline; "
    "dpkg-query -W telegram-desktop qemu-guest-agent; "
    "test -f /var/lib/oniondesk/setup.complete && echo SETUP_COMPLETE_PRESENT"
)


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


def type_read_only_command(connection):
    # RFC 6143 keysyms describe characters, not physical unshifted keys.
    # QEMU also needs explicit Shift for its emulated US keyboard. Sending
    # Shift + lowercase instead makes QEMU's CapsLock sync cancel the case.
    shifted = '~!@#$%^&*()_+{}|:"<>?'
    for char in READ_ONLY_COMMAND:
        if "A" <= char <= "Z" or char in shifted:
            keys = (0xFFE1, ord(char))
        else:
            keys = (ord(char),)
        chord(connection, keys)


def capture(target):
    """No credential bypass: production VNC is already host-loopback only."""
    raw = Path("/run/oniondesk-ci-private-workstation.ppm")
    # This survives the outer host's later --snapshot-only invocation too.
    SUPPRESSION_MARKER.touch(mode=0o600, exist_ok=True)
    with socket.create_connection(("127.0.0.1", 5902), timeout=5) as connection:
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
        # Open the existing LXQt terminal; its own F11 avoids WM-specific binds.
        chord(connection, (0xFFE3, 0xFFE9, ord("t")))  # Ctrl+Alt+T
        time.sleep(3)
        chord(connection, (0xFFC8,))                  # F11, QTerminal fullscreen
        time.sleep(1)
        type_read_only_command(connection)
        chord(connection, (0xFF0D,))                  # Return
        time.sleep(5)
        try:
            subprocess.run(["virsh", "--connect", "qemu:///system", "screenshot", DOMAIN, str(raw)],
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
            confidential.encrypt_diagnostic(data, target)
        finally:
            raw.unlink(missing_ok=True)
    return True
