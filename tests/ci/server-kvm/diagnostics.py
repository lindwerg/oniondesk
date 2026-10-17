"""Owned-fixture failure evidence. Every exported string is a static token.

Raw installer output, journal messages and QEMU logs are private inputs only.
Source error tokens point to literal error sites in the hash-verified payload;
the payload is parsed, never imported or executed to build the error catalog.
"""
import ast
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

SOURCE = Path("/src")
MAX_PRIVATE_BYTES = 64 * 1024
ROLES = ("gateway", "workstation")
UNITS = {
    "host_tor": "tor@default.service", "nginx": "nginx.service",
    "auth": "oniondesk-auth.service", "vms": "oniondesk-vms.service",
    "gateway_proxy": "oniondesk-websockify-gateway.service",
    "workstation_proxy": "oniondesk-websockify-workstation.service",
}
ERROR_SIGNATURES = (
    (b"libguestfs: error", "libguestfs"), (b"No space left", "disk_space"),
    (b"Permission denied", "permission"), (b"Operation not permitted", "operation_not_permitted"),
    (b"Read-only file system", "read_only_filesystem"),
    (b"Could not access KVM", "kvm_permissions"),
    (b"Cannot allocate memory", "memory_allocation"),
    (b"cannot set up guest memory", "guest_memory"),
    (b"process exited while connecting to monitor", "qemu_start"),
    (b"failed to connect to monitor", "qemu_monitor"),
    (b"Could not open", "file_open"),
    (b"could not load PC BIOS", "qemu_firmware"),
    (b"failed to find romfile", "qemu_firmware"),
    (b"Unable to start passt", "passt_start"),
    (b"Failed to start passt", "passt_start"),
    (b"unsupported configuration:", "libvirt_configuration"),
    (b"XML error:", "libvirt_xml"),
    (b"HTTP response code said error", "download_http"),
    (b"Could not resolve host", "download_dns"),
    (b"Connection timed out", "network_timeout"),
    (b"BAD signature", "image_signature_or_key"),
)
STOP_PREFIX = "Установка остановлена на строке "
STOP_SUFFIX = ". Диски/VM не удалялись; Nginx может оставаться masked. Не выполняйте повторную установку поверх существующих данных. Для нового старта проверьте частичное состояние и сохранность данных; переустановка Debian 13 на этом свежем сервере через панель провайдера удаляет его данные и требует вашего отдельного решения."
AUDIT_IDS = {
    "vm.active-list": "active_domains", "tcp.snapshot": "tcp_snapshot",
    "tcp.no-public-bindings": "tcp_private_bindings", "udp.snapshot": "udp_snapshot",
    "audit.internal": "audit_internal",
    "private./etc/oniondesk": "config_permissions",
    "private./var/lib/oniondesk": "state_permissions",
    "private./etc/oniondesk/credentials.json": "credentials_permissions",
    "private./etc/oniondesk/auth.json": "auth_permissions",
    **{unit: token for token, unit in UNITS.items()},
    **{f"oniondesk-{role}.{kind}": f"{role}_{kind.replace('-', '_')}"
       for role in ROLES for kind in ("inactive-xml", "live-xml", "owner")},
    **{f"tcp.{port}": token for port, token in (
        (5901, "gateway_vnc"), (5902, "workstation_vnc"),
        (16081, "gateway_websocket"), (16082, "workstation_websocket"),
        (18080, "nginx_listener"), (18081, "auth_listener"))},
    "udp.6688": "gateway_internal_udp", "udp.5577": "workstation_internal_udp",
}
ACCESS_PATHS = {
    "var_lib": ("/var/lib", True),
    "libvirt_state": ("/var/lib/libvirt", True),
    "images_parent": ("/var/lib/libvirt/images", True),
    "images_leaf": ("/var/lib/libvirt/images/oniondesk", True),
    "gateway_disk": ("/var/lib/libvirt/images/oniondesk/gateway.qcow2", False),
    "workstation_disk": ("/var/lib/libvirt/images/oniondesk/workstation.qcow2", False),
    "libvirt_run": ("/run/libvirt", True),
    "qemu_run": ("/run/libvirt/qemu", True),
    "passt_run": ("/run/libvirt/qemu/passt", True),
    "kvm_device": ("/dev/kvm", False),
    "passt_binary": ("/usr/bin/passt", False),
}
DENIAL_RESOURCES = {token: path.encode() for token, (path, _) in ACCESS_PATHS.items()}
DENIAL_RESOURCES.update({"cgroup": b"/sys/fs/cgroup", "kernel_sysctl": b"/proc/sys",
                         "apparmor_policy": b"/sys/kernel/security/apparmor"})
DENIAL_OPERATIONS = ((b"Cannot access storage file", "storage_access"),
                     (b'operation="open"', "open"), (b'operation="exec"', "execute"),
                     (b'operation="mkdir"', "create"),
                     (b"cannot open", "open"), (b"Cannot open", "open"),
                     (b"unable to open", "open"), (b"Unable to open", "open"),
                     (b"failed to open", "open"), (b"Failed to open", "open"),
                     (b"Cannot create", "create"), (b"cannot create", "create"),
                     (b"Unable to create", "create"), (b"unable to create", "create"),
                     (b"failed to create", "create"), (b"Failed to create", "create"),
                     (b"failed to execute", "execute"), (b"Failed to execute", "execute"))


def denial_summary(data):
    """Same-line associations only; never emit a path, suffix, UID or message."""
    resources, operations = set(), set()
    for line in data[-MAX_PRIVATE_BYTES:].splitlines():
        if not any(marker in line for marker in (b"Permission denied", b"Operation not permitted", b'apparmor="DENIED"')):
            continue
        for token, prefix in DENIAL_RESOURCES.items():
            if re.search(re.escape(prefix) + rb"(?=$|[/\s\"':,)])", line):
                resources.add(token)
        operations.update(token for needle, token in DENIAL_OPERATIONS if needle in line)
        if b'apparmor="DENIED"' in line:
            resources.add("apparmor")
        if b"SECCOMP" in line or b"seccomp" in line:
            resources.add("seccomp")
    return {"resource_tokens": sorted(resources), "operation_tokens": sorted(operations)}


def qemu_access_snapshot():
    try:
        account = pwd.getpwnam("libvirt-qemu")
    except KeyError:
        return {"available": False}
    result = {"available": True, "paths": {}}
    for token, (path, directory) in ACCESS_PATHS.items():
        facts = {"exists": False}
        try:
            metadata = Path(path).lstat()
            facts = {"exists": True, "directory": stat.S_ISDIR(metadata.st_mode),
                     "regular_file": stat.S_ISREG(metadata.st_mode),
                     "symlink": stat.S_ISLNK(metadata.st_mode),
                     "uid": metadata.st_uid, "gid": metadata.st_gid,
                     "mode": stat.S_IMODE(metadata.st_mode),
                     "owner_qemu": metadata.st_uid == account.pw_uid,
                     "group_qemu": metadata.st_gid == account.pw_gid}
            flag = "-x" if directory else "-r"
            response = run(["runuser", "--user", "libvirt-qemu", "--", "test", flag, path])
            facts["access_probe_completed"] = response.returncode in {0, 1}
            facts["qemu_search_access" if directory else "qemu_read_access"] = response.returncode == 0
        except (OSError, subprocess.SubprocessError):
            facts["access_probe_completed"] = False
        result["paths"][token] = facts
    return result


def static_error_sites(source=SOURCE):
    sites = []
    for filename, token in (("runtime-audit.py", "runtime_audit"),
                            ("validate-guest.py", "validate_guest"),
                            ("host_tor.py", "host_tor"), ("first_boot.py", "first_boot")):
        tree = ast.parse((source / "server" / filename).read_text())
        for node in ast.walk(tree):
            value = None
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and node.exc.args:
                value = node.exc.args[0]
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == "require" and len(node.args) == 2):
                value = node.args[1]
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 10:
                sites.append((value.value.encode(), token + "_L" + str(node.lineno)))
    return sites


def error_tokens(data, sites=()):
    return sorted({token for needle, token in (*ERROR_SIGNATURES, *sites) if needle in data})


def output_summary(data, source=SOURCE, sites=()):
    stop = re.compile(re.escape(STOP_PREFIX) + r"([1-9][0-9]{0,3})" + re.escape(STOP_SUFFIX))
    maximum = len((source / "server/install.sh").read_text().splitlines())
    lines = {int(match[1]) for line in data.decode("utf-8", errors="replace").splitlines()
             if (match := stop.fullmatch(line)) and int(match[1]) <= maximum}
    return {"ERR_reported_lines": sorted(lines), "known_error_tokens": error_tokens(data, sites)}


def private_tail(path):
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - MAX_PRIVATE_BYTES))
        return stream.read(MAX_PRIVATE_BYTES)


def run(arguments, timeout=20):
    return subprocess.run(arguments, capture_output=True, timeout=timeout)


def audit_summary(response, sites=()):
    report = json.loads(response.stdout)
    checks = report.get("checks") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or type(report.get("ok")) is not bool or not isinstance(checks, list)
            or not 1 <= len(checks) <= 64
            or any(not isinstance(check, dict) or type(check.get("ok")) is not bool
                   or not isinstance(check.get("id"), str) for check in checks)):
        raise ValueError("UnknownDiagnosticAuditFormat")
    safe = []
    for check in checks:
        if check["id"] in AUDIT_IDS:
            detail = check.get("detail", "")
            safe.append({"check": AUDIT_IDS[check["id"]], "ok": check["ok"],
                         "known_error_tokens": error_tokens(detail.encode() if isinstance(detail, str) else b"", sites)})
    return {"available": True, "ok": report["ok"], "checks": safe,
            "unknown_check_count": len(checks) - len(safe),
            "exit_success": response.returncode == 0}


def gateway_start_retry(snapshot_result, sites=()):
    """One authorized retry in the failed, owned fixture; never makes CI pass."""
    domains = snapshot_result.get("domains", {})
    pre_start = snapshot_result.get("audits", {}).get("pre_start", {})
    vms = snapshot_result.get("units", {}).get("vms", {})
    if (not all(all(domains.get(role, {}).get(key) is True
                    for key in ("probe_completed", "defined", "shut_off"))
                and all(domains.get(role, {}).get(key) is False
                        for key in ("running", "paused", "qemu_pid_file_present"))
                for role in ROLES)
            or not all(pre_start.get(key) is True for key in ("available", "ok", "exit_success"))
            or not all(vms.get(key) is True for key in ("probe_completed", "failed"))):
        return {"attempted": False}
    try:
        response = run(["virsh", "--connect", "qemu:///system", "start", "oniondesk-gateway"], timeout=60)
        private = (response.stdout + response.stderr)[-MAX_PRIVATE_BYTES:]
        return {"attempted": True, "exit_success": response.returncode == 0,
                "known_error_tokens": error_tokens(private, sites), "denial": denial_summary(private)}
    except (OSError, subprocess.SubprocessError):
        return {"attempted": True, "probe_completed": False}


def snapshot(sites=()):
    """Capture failure, then one gated retry; never replace installer failure."""
    result = {"domains": {}, "units": {}, "audits": {}}
    for role in ROLES:
        domain = "oniondesk-" + role
        facts = {"probe_completed": False}
        try:
            response = run(["virsh", "--connect", "qemu:///system", "domstate", domain])
            state = response.stdout.strip()
            facts = {"probe_completed": True, "defined": response.returncode == 0,
                     "running": response.returncode == 0 and state == b"running",
                     "shut_off": response.returncode == 0 and state == b"shut off",
                     "paused": response.returncode == 0 and state == b"paused"}
            pid_path = Path("/run/libvirt/qemu/" + domain + ".pid")
            facts["qemu_pid_file_present"] = pid_path.is_file()
            if pid_path.is_file():
                raw_pid = pid_path.read_text().strip()
                if re.fullmatch(r"[1-9][0-9]{0,9}", raw_pid):
                    uid = next(row.split()[1] for row in Path("/proc", raw_pid, "status").read_text().splitlines()
                               if row.startswith("Uid:"))
                    facts["qemu_non_root"] = int(uid) > 0
        except (OSError, ValueError, StopIteration, subprocess.SubprocessError):
            facts["process_probe_available"] = False
        try:
            private = private_tail(Path("/var/log/libvirt/qemu/" + domain + ".log"))
            facts["known_qemu_error_tokens"] = error_tokens(private, sites)
            facts["denial"] = denial_summary(private)
        except OSError:
            facts["qemu_log_available"] = False
        result["domains"][role] = facts
    for token, unit in UNITS.items():
        facts = {"probe_completed": False}
        try:
            response = run(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus"])
            values = dict(row.split("=", 1) for row in response.stdout.decode(errors="replace").splitlines() if "=" in row)
            facts = {"probe_completed": response.returncode == 0,
                     "loaded": values.get("LoadState") == "loaded",
                     "active": values.get("ActiveState") == "active",
                     "failed": values.get("ActiveState") == "failed",
                     "running": values.get("SubState") == "running",
                     "exited": values.get("SubState") == "exited"}
            code = values.get("ExecMainStatus", "")
            if re.fullmatch(r"[0-9]{1,3}", code) and int(code) <= 255:
                facts["exit_status"] = int(code)
            journal = run(["journalctl", "--unit=" + unit, "--no-pager", "--output=cat", "--lines=80"])
            facts["known_journal_error_tokens"] = error_tokens(journal.stdout[-MAX_PRIVATE_BYTES:], sites)
            facts["denial"] = denial_summary(journal.stdout)
        except (OSError, ValueError, subprocess.SubprocessError):
            facts["journal_probe_available"] = False
        result["units"][token] = facts
    for token, mode in (("pre_start", "--pre-start"), ("topology", "--topology-only"), ("full", None)):
        try:
            arguments = ["python3", "-B", "/opt/oniondesk/server/runtime-audit.py", "--json"]
            if mode:
                arguments.append(mode)
            result["audits"][token] = audit_summary(run(arguments, timeout=45), sites)
        except (OSError, ValueError, AttributeError, subprocess.SubprocessError):
            result["audits"][token] = {"available": False}
    result["milestones"] = {
        "host_tor_bootstrap_record_present": Path("/var/lib/oniondesk/host-tor-bootstrap.json").is_file(),
        "first_boot_pending_present": Path("/var/lib/oniondesk/first-boot.pending").is_file(),
        "credentials_created": Path("/etc/oniondesk/credentials.json").is_file(),
        "auth_config_created": Path("/etc/oniondesk/auth.json").is_file(),
        "image_version_record_present": Path("/var/lib/oniondesk/image-version").is_file(),
    }
    result["qemu_file_access"] = qemu_access_snapshot()
    try:
        daemon = run(["journalctl", "--unit=libvirtd.service", "--no-pager", "--output=cat", "--lines=80"])
        result["libvirt_daemon_denial"] = denial_summary(daemon.stdout)
    except (OSError, subprocess.SubprocessError):
        result["libvirt_daemon_denial"] = {"available": False}
    # Snapshot is the original failed state. This separate, explicitly labeled
    # retry uses the same production XML and cannot alter installer_exit_code.
    result["unchanged_gateway_start_retry"] = gateway_start_retry(result, sites)
    return result
