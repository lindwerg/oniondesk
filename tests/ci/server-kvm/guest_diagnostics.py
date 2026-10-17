"""Read-only Workstation diagnostics over its existing production QGA channel."""
import base64
import json
import subprocess
import time

DOMAIN = "oniondesk-workstation"
MAX_OUTPUT = 32 * 1024
STATE_SCRIPT = """import json, os, pathlib, subprocess
unit = subprocess.run(['/usr/bin/systemctl', 'show', 'oniondesk-first-boot.service',
 '--property=LoadState,ActiveState,SubState,Result,Restart,ConditionResult,ExecMainCode,ExecMainStatus'],
 capture_output=True, text=True, timeout=8)
properties = dict(line.split('=', 1) for line in unit.stdout.splitlines() if '=' in line)
print(json.dumps({'uptime_seconds': int(float(pathlib.Path('/proc/uptime').read_text().split()[0])),
 'sysmaint_boot': 'boot-role=sysmaint' in pathlib.Path('/proc/cmdline').read_text().split(),
 'setup_complete': pathlib.Path('/var/lib/oniondesk/setup.complete').is_file(),
 'telegram_executable': pathlib.Path('/usr/bin/telegram-desktop').is_file(),
 'proxy_environment_present': any(bool(os.environ.get(key)) for key in
  ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')),
 'unit_query_exit': unit.returncode, 'unit': properties}))
"""
COMMANDS = {
    "state": ("/usr/bin/python3", "-I", "-c", STATE_SCRIPT),
    "first_boot_journal": ("/usr/bin/journalctl", "--unit=oniondesk-first-boot.service",
                           "--no-pager", "--output=cat", "--lines=100"),
    "kernel_cmdline": ("/usr/bin/cat", "/proc/cmdline"),
    "apt_term_tail": ("/usr/bin/tail", "--bytes=16384", "/var/log/apt/term.log"),
    "packages": ("/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Status}\t${Version}\n",
                 "telegram-desktop", "qemu-guest-agent", "user-sysmaint-split"),
    "default_route": ("/usr/sbin/ip", "-o", "route", "show", "default"),
    "tor_readiness": ("/usr/bin/curl", "--fail", "--silent", "--show-error", "--max-time", "15",
                      "https://check.torproject.org/api/ip"),
}


def agent(request):
    response = subprocess.run(["virsh", "--connect", "qemu:///system", "qemu-agent-command",
                               DOMAIN, "--timeout", "3", json.dumps(request)],
                              check=True, capture_output=True, timeout=5)
    if len(response.stdout) > 128 * 1024:
        raise ValueError("GuestAgentResponseLimit")
    document = json.loads(response.stdout)
    if not isinstance(document, dict) or "error" in document or "return" not in document:
        raise ValueError("GuestAgentResponseInvalid")
    return document["return"]


def execute(key):
    command = COMMANDS[key]  # Only static allowlisted command vectors.
    task = agent({"execute": "guest-exec", "arguments": {
        "path": command[0], "arg": list(command[1:]), "capture-output": True}})
    if not isinstance(task, dict) or type(task.get("pid")) is not int or not 0 < task["pid"] <= 2**31 - 1:
        raise ValueError("GuestAgentTaskInvalid")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = agent({"execute": "guest-exec-status", "arguments": {"pid": task["pid"]}})
        if not isinstance(result, dict):
            raise ValueError("GuestAgentResultInvalid")
        if result.get("exited") is True:
            code = result.get("exitcode")
            if type(code) is not int or not 0 <= code <= 255:
                raise ValueError("GuestAgentExitInvalid")
            output = {}
            for field in ("out", "err"):
                encoded = result.get(field + "-data", "")
                if not isinstance(encoded, str) or len(encoded) > 4 * MAX_OUTPUT // 3 + 4:
                    raise ValueError("GuestAgentOutputLimit")
                data = base64.b64decode(encoded, validate=True)
                if len(data) > MAX_OUTPUT or result.get(field + "-truncated", False) is not False:
                    raise ValueError("GuestAgentOutputTruncated")
                output[field] = data
            return code, output["out"], output["err"]
        time.sleep(0.25)
    raise TimeoutError("GuestDiagnosticTaskTimeout")


def state():
    code, output, _ = execute("state")
    if code:
        raise ValueError("GuestStateProbeFailed")
    report = json.loads(output)
    required = {"uptime_seconds", "sysmaint_boot", "setup_complete", "telegram_executable",
                "proxy_environment_present", "unit_query_exit", "unit"}
    if not isinstance(report, dict) or set(report) != required:
        raise ValueError("GuestStateFormatInvalid")
    if (type(report["uptime_seconds"]) is not int or not 0 <= report["uptime_seconds"] <= 366 * 86400
            or type(report["unit_query_exit"]) is not int or not 0 <= report["unit_query_exit"] <= 255
            or any(type(report[key]) is not bool for key in
                   ("sysmaint_boot", "setup_complete", "telegram_executable", "proxy_environment_present"))
            or not isinstance(report["unit"], dict)
            or any(not isinstance(key, str) or not isinstance(value, str) for key, value in report["unit"].items())):
        raise ValueError("GuestStateFormatInvalid")
    return report


def terminal_reason(report):
    """Unknown/incomplete states never authorize terminating the installer."""
    if (report.get("sysmaint_boot") is not True or report.get("setup_complete") is not False
            or type(report.get("uptime_seconds")) is not int or report["uptime_seconds"] < 120
            or type(report.get("unit_query_exit")) is not int or not isinstance(report.get("unit"), dict)):
        return None
    unit = report.get("unit", {})
    if (unit.get("LoadState") == "not-found" and report.get("unit_query_exit") in {0, 1, 4}
            and unit.get("ActiveState") == "inactive" and unit.get("SubState") == "dead"):
        return "first_boot_unit_not_found"
    if report.get("unit_query_exit") != 0 or unit.get("LoadState") != "loaded" or unit.get("Restart") != "no":
        return None
    if (unit.get("ActiveState") == "failed" and unit.get("SubState") == "failed"
            and unit.get("Result") in {"exit-code", "signal", "core-dump", "timeout", "resources", "protocol"}):
        return "first_boot_unit_failed"
    if (unit.get("ActiveState") == "inactive" and unit.get("SubState") == "dead"
            and unit.get("ConditionResult") == "no"):
        return "first_boot_unit_condition_failed"
    return None


class Monitor:
    def __init__(self):
        self.next_probe = 0
        self.candidate = None
        self.candidate_since = None

    def observe(self, now, report):
        reason = terminal_reason(report)
        if reason is None:
            self.candidate = self.candidate_since = None
            return None
        if reason != self.candidate:
            self.candidate, self.candidate_since = reason, now
            return None
        return reason if now - self.candidate_since >= 30 else None


def public_state(report):
    return {"qga_available": True, "uptime_seconds": report["uptime_seconds"],
            "sysmaint_boot": report["sysmaint_boot"], "setup_complete": report["setup_complete"],
            "telegram_executable": report["telegram_executable"],
            "unit_loaded": report["unit"].get("LoadState") == "loaded",
            "unit_failed": report["unit"].get("ActiveState") == "failed"}


def collect(private):
    result = {"qga_available": False}
    for key in COMMANDS:
        try:
            code, output, error = execute(key)
            private.add("workstation_" + key, output + b"\n[stderr]\n" + error)
            result["qga_available"] = True
            result[key + "_exit_success"] = code == 0
            if key == "tor_readiness" and code == 0:
                tor = json.loads(output)
                result["tor_confirmed"] = isinstance(tor, dict) and tor.get("IsTor") is True
        except (OSError, ValueError, KeyError, TimeoutError, subprocess.SubprocessError):
            result[key + "_available"] = False
    return result
