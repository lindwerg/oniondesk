#!/usr/bin/env python3
"""Root-only, read-only host isolation checks; never repairs or prints secrets."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess


def load_validator():
    spec = importlib.util.spec_from_file_location("oniondesk_validate_guest", Path(__file__).with_name("validate-guest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    VALIDATOR = load_validator()
except Exception:
    # A missing/corrupt installed validator must still yield the JSON failure
    # contract rather than a traceback or an accidental partial audit.
    VALIDATOR = None
DOMAINS = ("oniondesk-gateway", "oniondesk-workstation")
UNITS = ("tor@default.service", "nginx.service", "oniondesk-auth.service", "oniondesk-vms.service", "oniondesk-websockify-gateway.service", "oniondesk-websockify-workstation.service")
TCP = {5901: DOMAINS[0], 5902: DOMAINS[1], 16081: UNITS[4], 16082: UNITS[5], 18080: UNITS[1], 18081: UNITS[2]}
UDP = {6688: DOMAINS[0], 5577: DOMAINS[1]}


def run(arguments):
    result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=15)
    if result.returncode:
        # Command output can contain addresses, keys or configuration; keep it private.
        raise ValueError("Системная команда проверки не завершилась успешно.")
    return result.stdout


def process(pid):
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError("Нет подтверждённого PID владельца listener.")
    root = Path("/proc") / str(pid)
    uid = None
    for line in (root / "status").read_text().splitlines():
        if line.startswith("Uid:"):
            values = line.split()[1:]
            if len(values) != 4 or len(set(values)) != 1:
                raise ValueError("Неоднозначные UID процесса listener.")
            uid = int(values[0])
    if uid is None:
        raise ValueError("UID владельца listener недоступен.")
    cgroups = [row.split(":", 2)[2] for row in (root / "cgroup").read_text().splitlines() if row.count(":") >= 2]
    return {"uid": uid, "cgroups": cgroups}


def listeners(text):
    result = []
    for row in text.splitlines():
        fields = row.split()
        if len(fields) < 5:
            raise ValueError("Неизвестный формат ss; listeners не подтверждены.")
        endpoint = fields[3]
        host, separator, raw_port = endpoint.rpartition(":")
        if not separator or not raw_port.isdecimal():
            raise ValueError("Неизвестный endpoint ss.")
        result.append({"host": host.strip("[]"), "port": int(raw_port), "pids": {int(pid) for pid in re.findall(r"\bpid=(\d+)", row)}})
    return result


def loopback(address):
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def check_public_bindings(sockets, monitored_pids=()):
    """Reject protected ports, and any public listener of our known processes."""
    monitored = set(monitored_pids)
    for item in sockets:
        if item["port"] in TCP and item["host"] != "127.0.0.1":
            raise ValueError("Защищённый TCP port слушает вне IPv4 127.0.0.1.")
        if item["pids"] & monitored and not loopback(item["host"]):
            raise ValueError("Собственный процесс имеет внешний TCP listener.")


def check_listener(sockets, port, owner, lookup=None):
    lookup = process if lookup is None else lookup
    matches = [item for item in sockets if item["port"] == port]
    if len(matches) != 1 or matches[0]["host"] != "127.0.0.1":
        raise ValueError("Ожидался ровно один listener на IPv4 127.0.0.1.")
    pids = matches[0]["pids"]
    if owner["pid"] not in pids:
        raise ValueError("Listener не принадлежит ожидаемому PID.")
    for pid in pids:
        info = lookup(pid)
        if info["uid"] not in owner["uids"]:
            raise ValueError("Неожиданный UID владельца listener.")
        if owner.get("cgroup") and not any(group == owner["cgroup"] or group.startswith(owner["cgroup"] + "/") for group in info["cgroups"]):
            raise ValueError("Listener не принадлежит ожидаемой systemd service.")
        if not owner.get("cgroup") and pid != owner["pid"]:
            raise ValueError("Неожиданный процесс разделяет listener VM.")


def unit_state(text, name):
    values = dict(row.split("=", 1) for row in text.splitlines() if "=" in row)
    expected_substate = "exited" if name == "oniondesk-vms.service" else "running"
    if values.get("ActiveState") != "active" or values.get("SubState") != expected_substate:
        raise ValueError("Ожидаемая служба не активна в рабочем состоянии.")
    if name == "oniondesk-vms.service":
        return None
    try:
        pid = int(values.get("MainPID", "0"))
    except ValueError as error:
        raise ValueError("Неизвестный PID службы.") from error
    cgroup = values.get("ControlGroup", "")
    allowed_cgroups = {"/system.slice/" + name}
    if name == "tor@default.service":
        allowed_cgroups.add("/system.slice/system-tor.slice/" + name)
    if pid <= 0 or cgroup not in allowed_cgroups:
        raise ValueError("Не подтверждены PID/cgroup службы.")
    account = {"tor@default.service": "debian-tor", "nginx.service": "root", "oniondesk-auth.service": "oniondesk-auth"}.get(name, "oniondesk-proxy")
    uids = {pwd.getpwnam(account).pw_uid}
    if name == "nginx.service":
        uids.add(pwd.getpwnam("www-data").pw_uid)
    info = process(pid)
    if info["uid"] != pwd.getpwnam(account).pw_uid or cgroup not in info["cgroups"]:
        raise ValueError("MainPID не принадлежит ожидаемому UID/cgroup службы.")
    return {"pid": pid, "uids": uids, "cgroup": cgroup}


def private_file(path, mode=0o600, directory=False):
    metadata = Path(path).lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError("Не подтверждены root ownership/type/private permissions.")


def audit(*, pre_start=False, topology_only=False):
    if VALIDATOR is None:
        raise RuntimeError("Installed validator unavailable")
    checks = []
    owners = {}

    def check(identifier, operation):
        try:
            result = operation()
            checks.append({"id": identifier, "ok": True, "detail": "Проверено сейчас."})
            return result
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            # Never include subprocess output, XML, hostnames or credentials.
            detail = str(error) if isinstance(error, ValueError) else "Проверка недоступна; безопасность не подтверждена."
            checks.append({"id": identifier, "ok": False, "detail": detail[:240]})
            return None

    active = check("vm.active-list", lambda: set(run(["virsh", "--connect", "qemu:///system", "list", "--name"]).split()))
    for name in DOMAINS:
        role = name.removeprefix("oniondesk-")
        check(name + ".inactive-xml", lambda name=name, role=role: VALIDATOR.validate_domain(run(["virsh", "--connect", "qemu:///system", "dumpxml", "--inactive", name]), role))
        if active is not None and name in active:
            check(name + ".live-xml", lambda name=name, role=role: VALIDATOR.validate_domain(run(["virsh", "--connect", "qemu:///system", "dumpxml", name]), role))
            def domain_owner(name=name):
                raw_pid = Path(f"/run/libvirt/qemu/{name}.pid").read_text().strip()
                if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_pid):
                    raise ValueError("Не подтверждён QEMU PID.")
                pid = int(raw_pid)
                uid = pwd.getpwnam("libvirt-qemu").pw_uid
                if uid == 0 or process(pid)["uid"] != uid:
                    raise ValueError("QEMU должен работать под штатным non-root libvirt-qemu.")
                return {"pid": pid, "uids": {uid}}
            owner = check(name + ".owner", domain_owner)
            if owner:
                owners[name] = owner
        elif not pre_start:
            checks.append({"id": name + ".live-xml", "ok": False, "detail": "VM не запущена; текущая изоляция не подтверждена."})
    if not pre_start and not topology_only:
        for unit in UNITS:
            owner = check(unit, lambda unit=unit: unit_state(run(["systemctl", "show", unit, "--property=ActiveState,SubState,MainPID,ControlGroup"]), unit))
            if owner:
                owners[unit] = owner
        for path, mode in (("/etc/oniondesk", 0o700), ("/var/lib/oniondesk", 0o711)):
            check("private." + path, lambda path=path, mode=mode: private_file(path, mode, directory=True))
        for path in ("/etc/oniondesk/credentials.json", "/etc/oniondesk/auth.json"):
            check("private." + path, lambda path=path: private_file(path))
    tcp = check("tcp.snapshot", lambda: listeners(run(["ss", "-H", "-ltnp"])))
    if tcp is not None:
        check("tcp.no-public-bindings", lambda: check_public_bindings(tcp, [item["pid"] for item in owners.values()]))
        if not pre_start:
            for port, name in TCP.items():
                if topology_only and name not in DOMAINS:
                    continue
                def verify_tcp(port=port, name=name):
                    if name not in owners:
                        raise ValueError("Владелец listener не подтверждён.")
                    check_listener(tcp, port, owners[name])
                check("tcp." + str(port), verify_tcp)
    if not pre_start:
        udp = check("udp.snapshot", lambda: listeners(run(["ss", "-H", "-lunp"])))
        if udp is not None:
            for port, name in UDP.items():
                def verify_udp(port=port, name=name):
                    if name not in owners:
                        raise ValueError("Владелец UDP listener не подтверждён.")
                    check_listener(udp, port, owners[name])
                check("udp." + str(port), verify_udp)
    return {"ok": bool(checks) and all(item["ok"] for item in checks), "checks": checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--pre-start", action="store_true")
    modes.add_argument("--topology-only", action="store_true")
    args = parser.parse_args(argv)
    exit_code = 1
    try:
        if os.geteuid() != 0:
            raise PermissionError("Нужен root для проверки реальных владельцев listeners.")
        report = audit(pre_start=args.pre_start, topology_only=args.topology_only)
        exit_code = 0 if report["ok"] else 1
    except Exception:
        report = {"ok": False, "checks": [{"id": "audit.internal", "ok": False, "detail": "Аудит не выполнен. Нужны root и штатные Debian/libvirt/systemd tools."}]}
        exit_code = 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        for item in report["checks"]:
            print(("OK" if item["ok"] else "ОТКАЗ") + ": " + item["id"] + ": " + item["detail"])
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
