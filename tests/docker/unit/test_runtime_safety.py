import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "server"
FIXTURES = Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SERVER / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load("runtime_safety", "runtime-audit.py")
images = load("runtime_images", "image_tools.py")
guest = load("workstation_status", "guest-workstation-status.py")


def domain(role):
    return images.transform((FIXTURES / f"upstream_{role}.xml").read_text(), role,
                            f"/var/lib/libvirt/images/oniondesk/{role}.qcow2")


def socket_line(port, pid, host="127.0.0.1", state="LISTEN"):
    return f'{state} 0 511 {host}:{port} 0.0.0.0:* users:(("process",pid={pid},fd=7))\n'


class RuntimeXmlTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("virsh"), "Requires libvirt's test driver (available in Debian Docker).")
    def test_real_libvirt_test_driver_normalizes_inactive_and_live_xml(self):
        # The test driver exercises libvirt's parser without a real VM or KVM.
        with tempfile.TemporaryDirectory() as temporary:
            for role in ("gateway", "workstation"):
                path = Path(temporary) / f"{role}.xml"
                path.write_text(domain(role))
                name = f"oniondesk-{role}"
                result = subprocess.run(["virsh", "--connect", "test:///default"],
                                        input=f"define {path}\nstart {name}\ndumpxml --inactive {name}\ndumpxml {name}\nquit\n",
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                documents = re.findall(r"<domain\b.*?</domain>", result.stdout, re.DOTALL)
                self.assertEqual(len(documents), 2, result.stdout + result.stderr)
                for text in documents:
                    runtime.VALIDATOR.validate_domain(text, role)

    def test_official_topology_and_libvirt_generated_fields_pass(self):
        for role in ("gateway", "workstation"):
            root = ET.fromstring(domain(role))
            root.set("id", "4")
            ET.SubElement(root, "uuid").text = "test-uuid"
            devices = root.find("devices")
            ET.SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"
            for index, interface in enumerate(devices.findall("interface")):
                ET.SubElement(interface, "mac", address="52:54:00:01:02:03")
                ET.SubElement(interface, "alias", name=f"net{index}")
                ET.SubElement(interface, "address", type="pci", bus="0x01")
                ET.SubElement(interface, "target", dev=f"vnet{index}")
            devices.find("disk/source").set("index", "1")
            ET.SubElement(devices.find("disk"), "backingStore")
            runtime.VALIDATOR.validate_domain(ET.tostring(root, encoding="unicode"), role)

    def test_extra_workstation_nic_is_rejected(self):
        root = ET.fromstring(domain("workstation"))
        extra = ET.SubElement(root.find("devices"), "interface", type="network")
        ET.SubElement(extra, "source", network="default")
        with self.assertRaises(ValueError):
            runtime.VALIDATOR.validate_domain(ET.tostring(root, encoding="unicode"), "workstation")

    def test_wrong_passt_udp_bind_or_vnc_is_rejected(self):
        for xpath, attribute, value in (("devices/interface/backend", "type", "slirp"),
                                        ("devices/interface/source/local", "address", "0.0.0.0"),
                                        ("devices/interface/source", "port", "6688"),
                                        ("devices/graphics", "listen", "::")):
            root = ET.fromstring(domain("gateway"))
            root.find(xpath).set(attribute, value)
            with self.subTest(xpath=xpath), self.assertRaises(ValueError):
                runtime.VALIDATOR.validate_domain(ET.tostring(root, encoding="unicode"), "gateway")


class ListenerTests(unittest.TestCase):
    def setUp(self):
        self.owner = {"pid": 123, "uids": {100}, "cgroup": "/system.slice/oniondesk-auth.service"}
        self.process = lambda _pid: {"uid": 100, "cgroups": [self.owner["cgroup"]]}

    def test_ipv4_loopback_and_exact_process_owner_pass(self):
        sockets = runtime.listeners(socket_line(18081, 123))
        runtime.check_public_bindings(sockets)
        runtime.check_listener(sockets, 18081, self.owner, self.process)

    def test_public_ipv4_ipv6_and_ipv6_loopback_are_rejected(self):
        for host in ("0.0.0.0", "198.51.100.7", "[::]", "[2001:db8::1]", "[::1]", "*"):
            sockets = runtime.listeners(socket_line(5902, 123, host))
            with self.subTest(host=host), self.assertRaises(ValueError):
                runtime.check_public_bindings(sockets)
            with self.assertRaises(ValueError):
                runtime.check_listener(sockets, 5902, self.owner, self.process)

    def test_missing_duplicate_unknown_pid_uid_or_cgroup_fail(self):
        good = runtime.listeners(socket_line(18081, 123))
        for sockets, lookup in (([], self.process), (good * 2, self.process),
                                (runtime.listeners(socket_line(18081, 124)), self.process),
                                (good, lambda _pid: {"uid": 0, "cgroups": [self.owner["cgroup"]]}),
                                (good, lambda _pid: {"uid": 100, "cgroups": ["/unrelated.service"]})):
            with self.subTest(sockets=sockets), self.assertRaises(ValueError):
                runtime.check_listener(sockets, 18081, self.owner, lookup)

    def test_own_service_cannot_listen_publicly_on_another_port(self):
        with self.assertRaises(ValueError):
            runtime.check_public_bindings(runtime.listeners(socket_line(8080, 123, "0.0.0.0")), [123])
        # Audit does not assert ownership of unrelated host services.
        runtime.check_public_bindings(runtime.listeners(socket_line(22, 999, "0.0.0.0")), [123])


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.xml = {name: domain(name.removeprefix("oniondesk-")) for name in runtime.DOMAINS}
        self.inactive = dict(self.xml)
        self.live = dict(self.xml)
        self.active = set(runtime.DOMAINS)
        self.states = {}
        self.processes = {501: {"uid": 100, "cgroups": ["/machine.slice/gateway"]},
                          502: {"uid": 100, "cgroups": ["/machine.slice/workstation"]}}
        self.uids = {"libvirt-qemu": 100, "root": 0, "debian-tor": 101, "www-data": 33,
                     "oniondesk-auth": 102, "oniondesk-proxy": 103}
        self.owner_pids = dict(zip(runtime.DOMAINS, (501, 502)))
        for index, name in enumerate(runtime.UNITS):
            cgroup = "/system.slice/" + name
            pid = 601 + index
            if name == "tor@default.service":
                cgroup = "/system.slice/system-tor.slice/" + name
            self.states[name] = f"ActiveState=active\nSubState={'exited' if name == 'oniondesk-vms.service' else 'running'}\nMainPID={pid}\nControlGroup={cgroup}\n"
            account = {"tor@default.service": "debian-tor", "nginx.service": "root", "oniondesk-auth.service": "oniondesk-auth"}.get(name, "oniondesk-proxy")
            self.processes[pid] = {"uid": self.uids[account], "cgroups": [cgroup]}
            self.owner_pids[name] = pid
        self.tcp = "".join(socket_line(port, self.owner_pids[owner]) for port, owner in runtime.TCP.items())
        self.udp = "".join(socket_line(port, self.owner_pids[owner], state="UNCONN") for port, owner in runtime.UDP.items())

    def run_command(self, args):
        if args[:4] == ["virsh", "--connect", "qemu:///system", "list"]:
            return "\n".join(sorted(self.active))
        if args[:4] == ["virsh", "--connect", "qemu:///system", "dumpxml"]:
            return (self.inactive if "--inactive" in args else self.live)[args[-1]]
        if args[0] == "systemctl":
            return self.states[args[2]]
        if args == ["ss", "-H", "-ltnp"]:
            return self.tcp
        if args == ["ss", "-H", "-lunp"]:
            return self.udp
        raise AssertionError(args)

    def report(self, **kwargs):
        def read_pid(path, *_args, **_kwargs):
            return str(self.owner_pids[path.name.removesuffix(".pid")])
        with patch.object(runtime, "run", side_effect=self.run_command), patch.object(runtime, "process", side_effect=lambda pid: self.processes[pid]), \
             patch.object(runtime.pwd, "getpwnam", side_effect=lambda name: SimpleNamespace(pw_uid=self.uids[name])), \
             patch.object(runtime.Path, "read_text", read_pid), patch.object(runtime, "private_file"):
            return runtime.audit(**kwargs)

    def test_full_current_host_passes_without_guest_telegram(self):
        report = self.report()
        self.assertTrue(report["ok"], report)
        self.assertFalse(any("telegram" in item["id"] for item in report["checks"]))

    def test_live_and_inactive_tampering_each_fail_independently(self):
        for collection in (self.live, self.inactive):
            original = collection[runtime.DOMAINS[1]]
            collection[runtime.DOMAINS[1]] = original.replace('<interface type="udp">', '<interface type="network">')
            report = self.report()
            self.assertFalse(report["ok"], report)
            failed = [item["id"] for item in report["checks"] if not item["ok"]]
            self.assertTrue(any("xml" in name for name in failed), failed)
            collection[runtime.DOMAINS[1]] = original

    def test_stopped_expected_service_gates_readiness(self):
        self.states["oniondesk-auth.service"] = "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\n"
        self.assertFalse(self.report()["ok"])

    def test_udp_listener_is_required_and_owned_by_correct_qemu(self):
        self.udp = self.udp.replace("pid=501", "pid=502")
        self.assertFalse(self.report()["ok"])

    def test_pre_start_accepts_stopped_vms_but_rejects_unsafe_definition(self):
        self.active.clear()
        self.tcp = ""
        self.assertTrue(self.report(pre_start=True)["ok"])
        self.inactive[runtime.DOMAINS[1]] = self.inactive[runtime.DOMAINS[1]].replace('<interface type="udp">', '<interface type="user">')
        self.assertFalse(self.report(pre_start=True)["ok"])

    def test_json_exit_codes_and_no_internal_trace_or_secret(self):
        for report, expected in (({"ok": True, "checks": []}, 0), ({"ok": False, "checks": []}, 1)):
            with patch.object(runtime.os, "geteuid", return_value=0), patch.object(runtime, "audit", return_value=report), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runtime.main(["--json"]), expected)
            self.assertEqual(json.loads(output.getvalue()), report)
        with patch.object(runtime.os, "geteuid", return_value=0), patch.object(runtime, "audit", side_effect=RuntimeError("secret-value")), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runtime.main(["--json"]), 2)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertNotIn("secret-value", output.getvalue())
        with patch.object(runtime.os, "geteuid", return_value=0), patch.object(runtime, "VALIDATOR", None), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runtime.main(["--json"]), 2)
        self.assertFalse(json.loads(output.getvalue())["ok"])


class UserSessionTests(unittest.TestCase):
    # Captured from the signed Whonix18.2.1.9 image, actual USER login via QGA.
    SESSION = {"Name": "user", "User": "1000", "Active": "yes", "Remote": "no",
               "Type": "wayland", "Class": "user", "State": "active"}

    def evidence(self, **changes):
        values = dict(cmdline="BOOT_IMAGE=/boot/vmlinuz root=/dev/vda1 quiet", split_installed=True,
                      boot_state={"ActiveState": "active", "SubState": "exited", "Result": "success", "ExecMainStatus": "0"},
                      graphical="active", session=self.SESSION, user_uid=1000)
        return guest.user_session_evidence(**{**values, **changes})

    def test_user_boot_and_successful_split_hook_pass(self):
        self.assertTrue(self.evidence())
        self.assertTrue(self.evidence(cmdline="boot-role=user"))
        self.assertTrue(self.evidence(session={**self.SESSION, "Type": "x11"}))

    def test_sysmaint_missing_split_failed_hook_or_no_desktop_fail(self):
        cases = [dict(cmdline="boot-role=sysmaint systemd.unit=sysmaint-boot.target"),
                 dict(cmdline="systemd.unit=sysmaint-boot.target"),
                 dict(cmdline="remove-sysmaint-qubes"),
                 dict(cmdline="remove-sysmaint-qubes=1"),
                 dict(cmdline="boot-role=user boot-role=sysmaint"),
                 dict(cmdline="boot-role=unknown"), dict(split_installed=False),
                 dict(boot_state={"ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": "1"}),
                 dict(graphical="inactive"), dict(session={}), dict(user_uid=0)]
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertFalse(self.evidence(**changes))

    def test_positive_login_must_be_local_active_graphical_user_with_actual_uid(self):
        for field, value in (("Name", "sysmaint"), ("User", "1001"), ("Active", "no"),
                             ("Remote", "yes"), ("Type", "tty"), ("Class", "manager"),
                             ("State", "closing")):
            with self.subTest(field=field):
                self.assertFalse(self.evidence(session={**self.SESSION, field: value}))

    def test_actual_user_runtime_passes_when_sysmaint_target_is_also_active(self):
        # The target is active in the real stock USER boot; it does not select
        # the privileged role. Positive logind evidence remains mandatory.
        replies = {
            ("/usr/bin/dpkg-query", "-W", "-f=${Status}", "user-sysmaint-split"): (0, "install ok installed"),
            ("/usr/bin/systemctl", "show", "sysmaint-boot.service", "--property=ActiveState,SubState,Result,ExecMainStatus"): (0, "ActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0"),
            ("/usr/bin/systemctl", "is-active", "graphical.target"): (0, "active"),
            ("/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"): (0, "1 1000 user seat0 1753 user tty7 no -\n2 1000 user - 1786 manager - no -"),
            ("/usr/bin/loginctl", "show-session", "1", "--property=Name", "--property=User", "--property=Active", "--property=Remote", "--property=Type", "--property=Class", "--property=State", "--no-pager"): (0, "\n".join(f"{key}={value}" for key, value in self.SESSION.items())),
        }
        def command(args, **_kwargs):
            if args == ["/usr/bin/systemctl", "is-active", "sysmaint-boot.target"]:
                return 0, "active"
            return replies[tuple(args)]
        with patch.object(guest, "command", side_effect=command), patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000)), patch.object(guest.Path, "read_text", return_value="BOOT_IMAGE=/boot/vmlinuz quiet"):
            self.assertTrue(guest.user_session())


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Requires Debian Docker root to drop real process privileges.")
class PrivilegeAndWiringTests(unittest.TestCase):
    def test_nonroot_auth_can_persist_totp_through_private_state_parent(self):
        account = pwd.getpwnam("nobody")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            state = directory / "state"
            state.mkdir(mode=0o711)
            auth_state = state / "auth"
            auth_state.mkdir(mode=0o700)
            os.chown(auth_state, account.pw_uid, account.pw_gid)
            script = '''import base64, importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("auth_fixture", sys.argv[1])
auth = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = auth
spec.loader.exec_module(auth)
secret = base64.b32encode(b"12345678901234567890").decode("ascii")
salt = b"s" * 32
config = auth.Config("owner", salt, auth.password_hash("fixture-password", salt), secret, "http://" + "a" * 56 + ".onion")
state = auth.AuthState(config, sys.argv[2], clock=lambda: 1600000000)
token, csrf = state.new_prelogin()
status, _ = state.authenticate(token, {"login": "owner", "password": "fixture-password", "csrf": csrf, "otp": auth.totp(secret, 1600000000 // 30)})
assert status == 303
assert auth.AuthState(config, sys.argv[2]).last_counter == 1600000000 // 30
'''
            result = subprocess.run([sys.executable, "-B", "-c", script, str(ROOT / "frontend/auth.py"), str(auth_state)],
                                    user=account.pw_uid, group=account.pw_gid, extra_groups=[], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = (auth_state / "totp-state.json").stat()
            self.assertEqual(metadata.st_uid, account.pw_uid)
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            runtime.private_file(state, 0o711, directory=True)
            state.chmod(0o700)
            inaccessible = subprocess.run([sys.executable, "-B", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).read_text()", str(auth_state / "totp-state.json")],
                                          user=account.pw_uid, group=account.pw_gid, extra_groups=[], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(inaccessible.returncode, 0)

    def test_failed_host_audit_never_runs_guest_readiness_or_starts_vm(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / "unsafe-action"
            binaries = {
                "systemctl": '#!/bin/bash\nprintf "active\\n"\n',
                "virsh": '#!/bin/bash\nif [[ $* == *" start "* ]]; then touch "$ACTION_MARKER"; fi\nprintf "running\\n"\n',
                "cat": '#!/bin/bash\nprintf "%s.onion\\n" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n',
                "python3": '#!/bin/bash\nif [[ $* == *runtime-audit.py* ]]; then printf "ОТКАЗ: fixture\\n"; exit 1; fi\ntouch "$ACTION_MARKER"\nprintf "ГОТОВО: Telegram fixture\\n"\n',
            }
            for name, text in binaries.items():
                path = directory / name
                path.write_text(text)
                path.chmod(0o755)
            environment = {**os.environ, "PATH": f"{directory}:{os.environ['PATH']}", "ACTION_MARKER": str(marker)}
            result = subprocess.run(["bash", str(SERVER / "control.sh"), "status"], env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("НЕ ГОТОВО:", result.stdout)
            self.assertFalse(any(line.startswith("ГОТОВО:") for line in result.stdout.splitlines()))
            self.assertFalse(marker.exists())
            result = subprocess.run(["bash", str(SERVER / "vm-service.sh"), "start"], env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
