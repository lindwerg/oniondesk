"""Read-only failure evidence. Every exported string is a static token.

Raw installer output, journal messages and QEMU logs are private inputs only.
Source error tokens point to literal error sites in the hash-verified payload;
the payload is parsed, never imported or executed to build the error catalog.
"""
import ast
import json
import os
from pathlib import Path
import re
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


def snapshot(sites=()):
    """Bounded, read-only probes; failure here cannot replace install failure."""
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
            facts["known_qemu_error_tokens"] = error_tokens(
                private_tail(Path("/var/log/libvirt/qemu/" + domain + ".log")), sites)
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
    return result
