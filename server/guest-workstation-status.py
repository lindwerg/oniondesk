#!/usr/bin/env python3
"""Read-only guest readiness. Never prints exit IP, cmdline or credentials."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

SESSION_PROPERTIES = ("Name", "User", "Active", "Remote", "Type", "Class", "State")


def graphical_session_evidence(session, user_uid):
    return (type(user_uid) is int and user_uid > 0
            and session.get("Name") == "user"
            and session.get("User") == str(user_uid)
            and session.get("Active") == "yes" and session.get("Remote") == "no"
            and session.get("Type") in ("x11", "wayland")
            and session.get("Class") == "user" and session.get("State") == "active")


def user_session_evidence(cmdline, split_installed, boot_state, graphical, session, user_uid):
    # Upstream sysmaint-boot handle-boot defines USER by absence of
    # boot-role=sysmaint. Confirm its successful execution, not just a boot flag.
    # https://github.com/Kicksecure/user-sysmaint-split/blob/master/usr/libexec/user-sysmaint-split/sysmaint-boot
    parameters = cmdline.split()
    roles = [value for value in parameters if value.startswith("boot-role=")]
    return (split_installed and roles in ([], ["boot-role=user"])
            and "boot-role=sysmaint" not in cmdline
            and "systemd.unit=sysmaint-boot.target" not in parameters
            and "remove-sysmaint-qubes" not in cmdline
            and boot_state.get("ActiveState") == "active"
            and boot_state.get("SubState") == "exited"
            and boot_state.get("Result") == "success"
            and boot_state.get("ExecMainStatus") == "0"
            and graphical == "active" and graphical_session_evidence(session, user_uid))


def command(arguments, *, timeout=5):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout.strip()


def active_user_graphical_session(user_uid):
    deadline = time.monotonic() + 10
    result, listing = command(["/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"])
    if result:
        return {}
    for row in listing.splitlines()[:32]:
        columns = row.split()
        if len(columns) < 3 or columns[1:3] != [str(user_uid), "user"] or not columns[0].isalnum():
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # loginctl requires one --property option for each property; unlike
        # systemctl, a comma-separated name returns an empty successful reply.
        result, output = command(["/usr/bin/loginctl", "show-session", columns[0],
                                  *("--property=" + name for name in SESSION_PROPERTIES), "--no-pager"],
                                 timeout=min(5, remaining))
        session = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if result == 0 and graphical_session_evidence(session, user_uid):
            return session
    return {}


def user_session():
    try:
        user_uid = pwd.getpwnam("user").pw_uid
        result, installed = command(["/usr/bin/dpkg-query", "-W", "-f=${Status}", "user-sysmaint-split"])
        boot_result, boot = command(["/usr/bin/systemctl", "show", "sysmaint-boot.service", "--property=ActiveState,SubState,Result,ExecMainStatus"])
        graphical_result, graphical = command(["/usr/bin/systemctl", "is-active", "graphical.target"])
        # In the signed18.2.1.9 image sysmaint-boot.target can also be active
        # during USER boot. Use the upstream role flag plus a positive logind
        # USER graphical login, not that target's non-discriminating state.
        return (boot_result == 0 and graphical_result == 0
                and user_session_evidence(Path("/proc/cmdline").read_text(), result == 0 and installed == "install ok installed",
                                          dict(line.split("=", 1) for line in boot.splitlines() if "=" in line), graphical,
                                          active_user_graphical_session(user_uid), user_uid))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return False



def auto_cleaner_status(*, user_ready=None):
    status = {"installed": False, "enabled": False, "running": False,
              "user_session": False, "auto_cleaner": False, "report": None}
    try:
        account = pwd.getpwnam("user")
        helper = Path("/usr/local/lib/oniondesk/auto-cleaner.py")
        for path in (helper, Path("/usr/local/lib/oniondesk/clean-files.py"),
                     Path("/etc/systemd/user/oniondesk-auto-cleaner.service")):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return status
        status["installed"] = True
        status["user_session"] = user_session() if user_ready is None else user_ready
        if not status["user_session"]:
            return status
        runtime = "/run/user/" + str(account.pw_uid)
        result, output = command([
            "/usr/sbin/runuser", "-u", "user", "--", "/usr/bin/env", "XDG_RUNTIME_DIR=" + runtime,
            "DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus", "/usr/bin/systemctl", "--user",
            "show", "oniondesk-auto-cleaner.service", "--no-pager",
            "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState"], timeout=10)
        if result:
            return status
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        status["enabled"] = properties.get("UnitFileState") in {"enabled", "enabled-runtime"}
        if (properties.get("LoadState") != "loaded" or properties.get("ActiveState") != "active"
                or properties.get("SubState") != "running"):
            return status
        pid = int(properties.get("MainPID", "0"))
        if pid <= 1:
            return status
        spec = importlib.util.spec_from_file_location("oniondesk_auto_status", helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        status["report"] = module.safe_public_report(Path(account.pw_dir), account.pw_uid, pid)
        status["running"] = True
        status["auto_cleaner"] = status["enabled"] and not status["report"]["watch_error"]
    except (OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError):
        pass
    except Exception:
        # User-owned health files never propagate private content or exception text.
        pass
    return status


def main():
    if sys.argv[1:] == ["--auto-cleaner"]:
        print(json.dumps(auto_cleaner_status()))
        return
    if sys.argv[1:]:
        raise SystemExit(2)
    user_ready = user_session()
    automatic = auto_cleaner_status(user_ready=user_ready)
    tor = False
    try:
        response = subprocess.run(["/usr/bin/curl", "--fail", "--silent", "--max-time", "45", "https://check.torproject.org/api/ip"], check=True, capture_output=True, text=True, timeout=50)
        tor = json.loads(response.stdout).get("IsTor") is True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    print(json.dumps({
        "setup_complete": Path("/var/lib/oniondesk/setup.complete").is_file(),
        "telegram": Path("/usr/bin/telegram-desktop").is_file(),
        "agent_installed": Path("/usr/sbin/qemu-ga").is_file(),
        "user_session": user_ready, "auto_cleaner": automatic["auto_cleaner"],
        "tor": tor, "checked_at": datetime.now(timezone.utc).isoformat(),
    }))


if __name__ == "__main__":
    main()

