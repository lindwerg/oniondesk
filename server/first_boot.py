#!/usr/bin/env python3
"""Prepare fresh vendor disks offline, then supervise the one-time maintenance boot."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

MAINTENANCE_TITLE = "PERSISTENT Mode | SYSMAINT Session | system maintenance tasks"
USER_TITLE = "PERSISTENT Mode | USER Session | daily activities"
SETUP_MARKER = "/var/cache/setup-dist/status-files/setup-dist.done"
COMPLETE_MARKER = "/var/lib/oniondesk/setup.complete"
WORKSTATION = "oniondesk-workstation"
IMAGE = "/var/lib/libvirt/images/oniondesk/workstation.qcow2"
STATE = Path("/var/lib/oniondesk")
SERVER = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, capture_output=True,
                          timeout=kwargs.pop("timeout", 120), **kwargs).stdout


def guestfish(disk, *commands):
    return run(["guestfish", "--rw", "--format=qcow2", "-a", str(disk), "-i", *commands])


def read_guest(disk, path):
    return run(["guestfish", "--ro", "--format=qcow2", "-a", str(disk), "-i", "cat", path])


def maintenance_title(grub):
    """Accept only the known top-level persistent entries, never duplicate IDs."""
    entries = []
    for match in re.finditer(r"^menuentry ([^\n]+)\n(.*?)^\}", grub, re.MULTILINE | re.DOTALL):
        header = shlex.split(match.group(1))
        if not header or header[-1] != "{":
            raise ValueError("Неизвестный формат GRUB menuentry.")
        entries.append((header[0], match.group(2)))
    if not entries or entries[0][0] != USER_TITLE:
        raise ValueError("Не подтверждена обычная USER загрузка по умолчанию.")
    user_linux = [shlex.split(line.strip()) for line in entries[0][1].splitlines()
                  if line.strip().startswith("linux\t") or line.strip().startswith("linux ")]
    if len(user_linux) != 1 or any(x.startswith("boot-role=") or x == "rootovl" or x == "remove-sysmaint"
                                    for x in user_linux[0]):
        raise ValueError("Первый GRUB entry не является обычным PERSISTENT USER.")
    candidates = [body for title, body in entries if title == MAINTENANCE_TITLE]
    if len(candidates) != 1:
        raise ValueError("Не найден единственный точный PERSISTENT SYSMAINT title.")
    linux = [shlex.split(line.strip()) for line in candidates[0].splitlines()
             if line.strip().startswith("linux\t") or line.strip().startswith("linux ")]
    if (len(linux) != 1 or "boot-role=sysmaint" not in linux[0]
            or "systemd.unit=sysmaint-boot.target" not in linux[0]
            or "rootovl" in linux[0] or "remove-sysmaint" in linux[0]):
        raise ValueError("SYSMAINT entry не соответствует штатному persistent boot.")
    expected = ('load_env', 'set default="${next_entry}"', 'set next_entry=',
                'save_env next_entry', 'set boot_once=true', 'set default="0"')
    if not all(text in grub for text in expected):
        raise ValueError("GRUB не подтверждает одноразовый next_entry и возврат к USER.")
    return MAINTENANCE_TITLE


def validate_setup_marker(done_helper, start_checker):
    commands = [line.strip() for line in done_helper.splitlines()
                if line.strip() and not line.lstrip().startswith("#") and not line.startswith("set ")]
    if commands != ['mkdir --parents "/var/cache/setup-dist/status-files"',
                    f'touch "{SETUP_MARKER}"'] or repr(SETUP_MARKER) not in start_checker:
        raise ValueError("Не подтверждён официальный setup-dist done marker; образ не меняется.")


def prepare(disk, role, source_dir, stage_dir, tor_mode, licenses_accepted):
    if not licenses_accepted:
        raise ValueError("Нужно явное принятие условий Whonix перед подготовкой guest.")
    done = read_guest(disk, "/usr/libexec/setup-dist/setup-dist-done")
    checker = read_guest(disk, "/usr/libexec/setup-wizard-dist/setup-dist_check_for_start")
    validate_setup_marker(done, checker)
    operations = ["mkdir-p", str(Path(SETUP_MARKER).parent), ":", "touch", SETUP_MARKER,
                  ":", "chmod", "0644", SETUP_MARKER]
    if role == "workstation":
        title = maintenance_title(read_guest(disk, "/boot/grub/grub.cfg"))
        target = read_guest(disk, "/usr/lib/systemd/system/sysmaint-boot.target")
        if "DefaultDependencies=no" not in target:
            raise ValueError("Изменился ordering штатного SYSMAINT target; требуется проверка.")
        env_path = stage_dir / "workstation-grubenv"
        # Work only on a cold, private copy. Preserve the vendor environment block.
        run(["guestfish", "--ro", "--format=qcow2", "-a", str(disk), "-i",
             "download", "/boot/grub/grubenv", str(env_path)])
        previous = run(["grub-editenv", str(env_path), "list"])
        if any(line.startswith("next_entry=") and line != "next_entry=" for line in previous.splitlines()):
            raise ValueError("У vendor grubenv уже выбран next_entry; перезапись запрещена.")
        run(["grub-editenv", str(env_path), "set", "next_entry=" + title])
        if ("next_entry=" + title) not in run(["grub-editenv", str(env_path), "list"]).splitlines():
            raise ValueError("Не удалось проверить одноразовый SYSMAINT в grubenv.")
        operations += [":", "upload", str(env_path), "/boot/grub/grubenv",
                       ":", "mkdir-p", "/etc/systemd/system/sysmaint-boot.target.wants",
                       ":", "upload", str(source_dir / "oniondesk-first-boot.service"),
                       "/etc/systemd/system/oniondesk-first-boot.service",
                       ":", "chmod", "0644", "/etc/systemd/system/oniondesk-first-boot.service",
                       ":", "ln-s", "/etc/systemd/system/oniondesk-first-boot.service",
                       "/etc/systemd/system/sysmaint-boot.target.wants/oniondesk-first-boot.service"]
    elif role == "gateway":
        if tor_mode == "public-obfs4":
            if run(["guestfish", "--ro", "--format=qcow2", "-a", str(disk), "-i",
                    "is-file", "/usr/bin/obfs4proxy"]).strip() != "true":
                raise ValueError("В Gateway нет штатного obfs4proxy.")
            operations += [":", "upload", str(source_dir / "public-obfs4.conf"),
                           "/usr/local/etc/torrc.d/50_user.conf",
                           ":", "chmod", "0644", "/usr/local/etc/torrc.d/50_user.conf"]
    else:
        raise ValueError("Неизвестная роль guest.")
    guestfish(disk, *operations)
    print(f"Подготовлен {role}: официальный setup marker; "
          + ("одноразовый SYSMAINT." if role == "workstation" else f"Tor {tor_mode}."))


def domain_state():
    return " ".join(run(["virsh", "--connect", "qemu:///system", "domstate", WORKSTATION, "--reason"],
                        env={**os.environ, "LC_ALL": "C"}, timeout=15).split())


def write_state(path, data):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".first-boot.", delete=False) as output:
        temporary = Path(output.name)
        try:
            os.chmod(temporary, 0o600)
            json.dump(data, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def complete_first_boot(state_dir, pending, state, result):
    state["phase"] = "user"
    state["completed_at"] = datetime.now(timezone.utc).isoformat()
    write_state(state_dir / "first-boot.complete", state)
    pending.unlink()
    print(result, end="")


def finish(timeout=2700, state_dir=STATE, server=SERVER):
    pending = state_dir / "first-boot.pending"
    if not pending.is_file():
        if not (state_dir / "first-boot.complete").is_file():
            raise ValueError("Нет состояния автоматической подготовки. Нужна диагностика установленной версии.")
        run([sys.executable, "-B", str(server / "runtime-audit.py")])
        print(run([sys.executable, "-B", str(server / "guest-status.py")], timeout=125), end="")
        return
    state = json.loads(pending.read_text())
    if state.get("phase") not in {"maintenance", "user"}:
        raise ValueError("Неизвестное состояние первого запуска; VM не меняется.")
    # Workstation can already be cold after successful setup or an interruption.
    # The full live audit runs after the guarded VM start, before readiness.
    run([sys.executable, "-B", str(server / "runtime-audit.py"), "--pre-start"])
    deadline = time.monotonic() + timeout
    if state["phase"] == "maintenance":
        print("Ожидаю автоматическую установку Telegram в SYSMAINT и корректное выключение Workstation.", flush=True)
        while True:
            current = domain_state()
            if current.startswith("shut off"):
                if current != "shut off (shutdown)":
                    raise ValueError("Workstation не завершила штатное выключение: " + current)
                marker = run(["guestfish", "--ro", "--format=qcow2", "-a", IMAGE, "-i", "is-file", COMPLETE_MARKER])
                if marker.strip() != "true":
                    raise ValueError("Workstation выключилась без успешного setup marker; USER не запускается.")
                state["phase"] = "user"
                write_state(pending, state)
                break
            if current != "running (booted)" and not current.startswith("running ("):
                raise ValueError("Неожиданное состояние Workstation: " + current)
            # A host reboot can consume the one-shot entry and auto-start USER
            # before the supervisor records phase=user. Certify that live guest
            # instead of reading its mounted disk or waiting for another stop.
            run([sys.executable, "-B", str(server / "runtime-audit.py")])
            try:
                recovered = run([sys.executable, "-B", str(server / "guest-status.py")], timeout=125)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass  # Genuine SYSMAINT or an unready guest must finish normally.
            else:
                complete_first_boot(state_dir, pending, state, recovered)
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("SYSMAINT не завершился вовремя. VM сохранена, готовность не подтверждена.")
            time.sleep(5)
    print("Загружаю обычный USER и проверяю текущие Tor/Telegram через guest agent.", flush=True)
    run(["bash", str(server / "vm-service.sh"), "start"], timeout=120)
    last_error = "Guest agent ещё недоступен."
    while time.monotonic() < deadline:
        run([sys.executable, "-B", str(server / "runtime-audit.py")])
        try:
            result = run([sys.executable, "-B", str(server / "guest-status.py")], timeout=125)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            detail = error.stderr or error.stdout or str(error)
            last_error = (detail.decode("utf-8", errors="replace") if isinstance(detail, bytes) else str(detail)).strip()
            time.sleep(10)
        else:
            complete_first_boot(state_dir, pending, state, result)
            return
    raise TimeoutError("USER/Tor/Telegram не подтверждены вовремя: " + last_error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    stage = actions.add_parser("stage")
    stage.add_argument("--disk", required=True, type=Path)
    stage.add_argument("--role", required=True, choices=["gateway", "workstation"])
    stage.add_argument("--source-dir", type=Path, default=SERVER)
    stage.add_argument("--stage-dir", type=Path, required=True)
    stage.add_argument("--tor-mode", choices=["wizard", "direct", "public-obfs4"], required=True)
    stage.add_argument("--licenses-accepted", action="store_true", required=True)
    wait = actions.add_parser("finish")
    wait.add_argument("--timeout", type=int, default=2700)
    args = parser.parse_args()
    if args.action == "stage":
        prepare(args.disk, args.role, args.source_dir, args.stage_dir, args.tor_mode, args.licenses_accepted)
    else:
        if not 60 <= args.timeout <= 3600:
            raise ValueError("Допустимое ожидание: от 60 до 3600 секунд.")
        finish(args.timeout)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
        print("Первый запуск не завершён: " + str(error), file=sys.stderr)
        raise SystemExit(1)
