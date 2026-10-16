import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
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


images = load("image_tools", "image_tools.py")
preflight = load("preflight", "preflight.py")
guest = load("validate_guest", "validate-guest.py")
status = load("guest_status", "guest-status.py")


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.facts = dict(id="debian", version="13", arch="x86_64", kvm=True,
                          cpus=4, memory=8*1024**3, free=60*1024**3, apt=True)

    def test_supported_machine_passes(self):
        self.assertTrue(all(ok for _, ok in preflight.evaluate(self.facts)))

    def test_each_required_property_fails_closed(self):
        for key, value in (("id", "ubuntu"), ("version", "12"), ("arch", "aarch64"),
                           ("kvm", False), ("cpus", 3), ("memory", 7*1024**3),
                           ("free", 49*1024**3), ("apt", False)):
            with self.subTest(key=key):
                self.assertFalse(all(ok for _, ok in preflight.evaluate({**self.facts, key: value})))

    def test_os_release_is_parsed_as_data(self):
        fields = preflight.os_fields('ID=debian\nVERSION_ID="13"\nATTACK="$(touch /bad)"\n')
        self.assertEqual(fields["VERSION_ID"], "13")
        self.assertEqual(fields["ATTACK"], "$(touch /bad)")

    def test_check_never_installs_on_current_mac(self):
        if os.uname().sysname != "Darwin":
            self.skipTest("This negative real-host test is specific to the authoring Mac.")
        result = subprocess.run(["bash", str(SERVER / "install.sh"), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("НЕТ: Debian 13", result.stdout)
        self.assertNotIn("Загружаю", result.stdout)


class XmlTests(unittest.TestCase):
    def source(self, role):
        return (FIXTURES / f"upstream_{role}.xml").read_text()

    def converted(self, role, text=None):
        return ET.fromstring(images.transform(text or self.source(role), role,
                            f"/var/lib/libvirt/images/oniondesk/{role}.qcow2"))

    def test_gateway_preserves_full_upstream_network_topology(self):
        old = ET.fromstring(self.source("gateway"))
        new = self.converted("gateway")
        def structure(node):
            return (node.tag, node.attrib, (node.text or "").strip(), [structure(child) for child in node])
        self.assertEqual([structure(x) for x in old.findall("devices/interface")],
                         [structure(x) for x in new.findall("devices/interface")])
        self.assertEqual(new.find("name").text, "oniondesk-gateway")
        self.assertNotIn("cpuset", new.find("vcpu").attrib)

    def test_workstation_cannot_have_external_interface(self):
        new = self.converted("workstation")
        self.assertEqual(len(new.findall("devices/interface")), 1)
        self.assertEqual(new.find("devices/interface").get("type"), "udp")
        self.assertEqual(new.find("devices/interface/source").get("address"), "127.0.0.1")
        malicious = self.source("workstation").replace("<controller type='virtio-serial'", "<interface type='network'><source network='default'/></interface><controller type='virtio-serial'")
        with self.assertRaises(ValueError):
            self.converted("workstation", malicious)

    def test_graphics_and_agent_channels_are_exactly_scoped(self):
        for role, port in (("gateway", "5901"), ("workstation", "5902")):
            with self.subTest(role=role):
                root = self.converted(role)
                graphics = root.find("devices/graphics")
                self.assertEqual(graphics.attrib, {"type":"vnc", "port":port, "autoport":"no", "listen":"127.0.0.1"})
                self.assertEqual(graphics.find("listen").get("address"), "127.0.0.1")
                self.assertFalse(root.findall("devices/channel[@type='spicevmc']"))
                self.assertEqual(len(root.findall("devices/channel")), int(role == "workstation"))
                self.assertEqual(root.find("devices/disk").get("type"), "file")

    def test_unexpected_xml_and_disk_paths_are_rejected(self):
        altered = [self.source("gateway").replace("type='kvm'", "type='qemu'", 1),
                   self.source("gateway").replace("<genid/>", "<qemu:commandline/>").replace("<domain type='kvm'>", "<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>"),
                   self.source("gateway").replace("port=\"5577\"", "port=\"7777\""),
                   self.source("gateway").replace("<devices>", "<devices><hostdev mode='subsystem'/>")]
        for text in altered:
            with self.assertRaises(ValueError):
                self.converted("gateway", text)
        with self.assertRaises(ValueError):
            images.transform(self.source("gateway"), "gateway", "/etc/forbidden.qcow2")
        with self.assertRaises(ValueError):
            images.transform('<!DOCTYPE domain [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + self.source("gateway"), "gateway", "/var/lib/libvirt/images/oniondesk/gateway.qcow2")


class SignatureTests(unittest.TestCase):
    def line(self, signer, primary):
        return f"[GNUPG:] VALIDSIG {signer} 2026-07-15 1784090000 0 4 0 1 10 00 {primary}\n"

    def test_exact_primary_or_signed_subkey_is_accepted(self):
        images.verify_status(self.line(images.FINGERPRINT, images.FINGERPRINT))
        images.verify_status(self.line("A"*40, images.FINGERPRINT))

    def test_wrong_missing_or_multiple_signature_status_is_rejected(self):
        for text in ("", "[GNUPG:] GOODSIG x y", self.line("B"*40, "C"*40), self.line(images.FINGERPRINT, images.FINGERPRINT)*2):
            with self.assertRaises(ValueError):
                images.verify_status(text)

    def test_shell_rejects_crypto_failure_even_with_validsig_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binaries = directory / "bin"
            binaries.mkdir()
            for name, body in {
                "sha512sum": "#!/bin/bash\nprintf '%s  archive\\n' '84b30da63af4750159006cdf1b5fbf6ab06c3a7ada697428f3b3b125286d85c33b11ee443464c119824aa7f4316e9a84c4a42eb1a50b5570b4105028099ffbe9'\n",
                "gpg": "#!/bin/bash\nif [[ $* == *--with-colons* ]]; then printf 'fpr:::::::::916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA:\\n'; fi\n",
                "gpgv": "#!/bin/bash\nprintf '[GNUPG:] VALIDSIG 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA 2026-07-15 1784090000 0 4 0 1 10 00 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA\\n'\nexit 1\n",
            }.items():
                path = binaries / name
                path.write_text(body)
                path.chmod(0o700)
            for name in ("archive", "signature", "key"):
                (directory / name).write_text("not real signed data")
            workspace = directory / "verification"
            workspace.mkdir()
            result = subprocess.run(["bash", str(SERVER / "verify-image.sh"),
                                    str(directory / "archive"), str(directory / "signature"),
                                    str(directory / "key"), str(workspace)],
                                    env={**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("проверены", result.stdout)


class GuestContractTests(unittest.TestCase):
    def contract(self):
        return dict(role="workstation", passwd="user:x:1000:1000::/home/user:/bin/bash\nsysmaint:x:1001:1001::/home/sysmaint:/bin/bash",
                    grub="linux /kernel boot-role=sysmaint systemd.unit=sysmaint-boot.target",
                    target="Description=sysmaint\nWants=network.target tor@default.service",
                    boot_script="if [[ $kernel_cmdline =~ boot-role=sysmaint ]]; then sysmaint_mode=yes; fi", marker=True)

    def test_known_sysmaint_contract_is_accepted(self):
        guest.validate_contract(**self.contract())

    def test_missing_split_bootrole_target_or_marker_is_rejected(self):
        for key, value in (("passwd", "user:x:1000:1000::/home/user:/bin/bash"), ("grub", "standard user boot"),
                           ("target", "multi-user.target"), ("boot_script", "no role machinery"), ("marker", False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guest.validate_contract(**{**self.contract(), key: value})


class ControlTests(unittest.TestCase):
    def test_libvirt_uri_and_domain_checks_stay_in_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake = directory / "virsh"
            log = directory / "calls"
            fake.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALL_LOG"\nprintf "%s\\n" "oniondesk-gateway" "unrelated-domain"\n')
            fake.chmod(0o700)
            result = subprocess.run(["bash", "-c", 'source "$1"; is_active_domain oniondesk-gateway; ! is_active_domain oniondesk-workstation', "test", str(SERVER / "common.sh")],
                                    env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}", "CALL_LOG": str(log)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(log.read_text().splitlines(), ['--connect qemu:///system list --name']*2)

    def test_libvirt_failure_is_never_treated_as_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "virsh"
            fake.write_text('#!/bin/bash\nexit 1\n')
            fake.chmod(0o700)
            result = subprocess.run(["bash", "-c", 'source "$1"; if is_active_domain oniondesk-gateway; then :; fi; echo BAD_SUCCESS', "test", str(SERVER / "common.sh")], env={**os.environ, "PATH": f"{temporary}:{os.environ['PATH']}"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("BAD_SUCCESS", result.stdout)

    def test_readiness_requires_installation_and_live_tor(self):
        import base64
        import json
        report = dict(setup_complete=True, telegram=True, agent_installed=True, user_session=True, tor=False, auto_cleaner=True, checked_at="now")
        result = {"exited": True, "exitcode": 0, "out-data": base64.b64encode(json.dumps(report).encode()).decode()}
        with patch.object(status, "agent", side_effect=[{"pid": 42}, result]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(status.main(), 1)
        self.assertIn("НЕ ГОТОВО", output.getvalue())
        report["tor"] = True
        result["out-data"] = base64.b64encode(json.dumps(report).encode()).decode()
        with patch.object(status, "agent", side_effect=[{"pid": 42}, result]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(status.main(), 0)
        self.assertIn("ГОТОВО:", output.getvalue())
        report["user_session"] = False
        result["out-data"] = base64.b64encode(json.dumps(report).encode()).decode()
        with patch.object(status, "agent", side_effect=[{"pid": 42}, result]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(status.main(), 1)
        self.assertFalse(any(line.startswith("ГОТОВО:") for line in output.getvalue().splitlines()))


if __name__ == "__main__":
    unittest.main()

