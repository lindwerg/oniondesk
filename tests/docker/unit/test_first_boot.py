"""Behavioral guards for offline first-boot staging and its host supervisor."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SERVER = Path(__file__).resolve().parents[3] / "server"
spec = importlib.util.spec_from_file_location("first_boot", SERVER / "first_boot.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def grub_fixture():
    # The signed 18.2.1.9 image really reuses this ID for the distinct modes.
    return '''load_env
if [ "${next_entry}" ]; then
 set default="${next_entry}"
 set next_entry=
 save_env next_entry
 set boot_once=true
else
 set default="0"
fi
menuentry 'PERSISTENT Mode | USER Session | daily activities' --id duplicate {
 linux /boot/kernel root=UUID=vendor ro
}
menuentry 'PERSISTENT Mode | SYSMAINT Session | system maintenance tasks' --id duplicate {
 linux /boot/kernel root=UUID=vendor ro boot-role=sysmaint systemd.unit=sysmaint-boot.target
}
menuentry 'REMOVE user-sysmaint-split | enable unrestricted admin mode' --id duplicate {
 linux /boot/kernel ro boot-role=sysmaint systemd.unit=sysmaint-boot.target remove-sysmaint
}
'''


DONE = '''#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
mkdir --parents "/var/cache/setup-dist/status-files"
touch "/var/cache/setup-dist/status-files/setup-dist.done"
'''
CHECKER = "paths = ['/var/cache/setup-dist/status-files/setup-dist.done']"


class BootEntryTests(unittest.TestCase):
    def test_duplicate_vendor_ids_use_the_unique_exact_title(self):
        self.assertEqual(boot.maintenance_title(grub_fixture()), boot.MAINTENANCE_TITLE)

    def test_ambiguous_maintenance_title_is_rejected(self):
        text = grub_fixture()
        text += text[text.index("menuentry 'PERSISTENT Mode | SYSMAINT"):text.index("menuentry 'REMOVE")]
        with self.assertRaisesRegex(ValueError, "единственный"):
            boot.maintenance_title(text)

    def test_wrong_roles_live_mode_and_missing_return_to_user_are_rejected(self):
        variants = [grub_fixture().replace("ro boot-role=sysmaint", "ro rootovl boot-role=sysmaint", 1),
                    grub_fixture().replace("systemd.unit=sysmaint-boot.target", "systemd.unit=graphical.target", 1),
                    grub_fixture().replace("boot-role=sysmaint", "boot-role=user", 1),
                    grub_fixture().replace('set default="0"', 'set default="1"'),
                    grub_fixture().replace("save_env next_entry", "# no one-shot clear"),
                    grub_fixture().replace("root=UUID=vendor ro\n", "root=UUID=vendor ro boot-role=sysmaint\n", 1)]
        for text in variants:
            with self.subTest(text=text[-220:]), self.assertRaises(ValueError):
                boot.maintenance_title(text)

    def test_vendor_marker_helper_is_checked_before_any_writes(self):
        boot.validate_setup_marker(DONE, CHECKER)
        for done, checker in ((DONE.replace("setup-dist.done", "other.done"), CHECKER),
                              (DONE + "rm -rf /unexpected\n", CHECKER), (DONE, "unknown format")):
            with self.assertRaises(ValueError):
                boot.validate_setup_marker(done, checker)


class StagingTests(unittest.TestCase):
    def reads(self, disk, path):
        return {"/usr/libexec/setup-dist/setup-dist-done": DONE,
                "/usr/libexec/setup-wizard-dist/setup-dist_check_for_start": CHECKER,
                "/boot/grub/grub.cfg": grub_fixture(),
                "/usr/lib/systemd/system/sysmaint-boot.target": "DefaultDependencies=no\n"}[path]

    def test_no_acceptance_means_no_guest_reads_or_writes(self):
        with patch.object(boot, "read_guest") as read, patch.object(boot, "guestfish") as write:
            with self.assertRaises(ValueError):
                boot.prepare(Path("disk"), "workstation", SERVER, Path("stage"), "direct", False)
            read.assert_not_called()
            write.assert_not_called()

    def test_workstation_stages_one_time_role_and_service_without_rewriting_grub(self):
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            if command[:1] == ["grub-editenv"] and command[-1] == "list":
                return "" if len([x for x in calls if x[-1] == "list"]) == 1 else "next_entry=" + boot.MAINTENANCE_TITLE + "\n"
            return ""
        with patch.object(boot, "read_guest", side_effect=self.reads), patch.object(boot, "run", side_effect=execute), patch.object(boot, "guestfish") as write:
            boot.prepare(Path("disk"), "workstation", SERVER, Path("stage"), "direct", True)
        self.assertIn(["grub-editenv", "stage/workstation-grubenv", "set", "next_entry=" + boot.MAINTENANCE_TITLE], calls)
        payload = write.call_args.args
        self.assertIn("/boot/grub/grubenv", payload)
        self.assertIn("/etc/systemd/system/sysmaint-boot.target.wants/oniondesk-first-boot.service", payload)
        self.assertNotIn("/boot/grub/grub.cfg", payload)
        self.assertNotIn("user-sysmaint-split", payload)

    def test_unknown_vendor_boot_environment_is_not_overwritten(self):
        with patch.object(boot, "read_guest", side_effect=self.reads), patch.object(boot, "run", return_value="next_entry=unexpected\n"), patch.object(boot, "guestfish") as write:
            with self.assertRaises(ValueError):
                boot.prepare(Path("disk"), "workstation", SERVER, Path("stage"), "direct", True)
            write.assert_not_called()

    def test_public_bridge_requires_the_stock_transport_binary(self):
        for installed in (False, True):
            with self.subTest(installed=installed), patch.object(boot, "read_guest", side_effect=self.reads), patch.object(boot, "run", return_value=str(installed).lower()), patch.object(boot, "guestfish") as write:
                if installed:
                    boot.prepare(Path("disk"), "gateway", SERVER, Path("stage"), "public-obfs4", True)
                    self.assertIn("/usr/local/etc/torrc.d/50_user.conf", write.call_args.args)
                else:
                    with self.assertRaises(ValueError):
                        boot.prepare(Path("disk"), "gateway", SERVER, Path("stage"), "public-obfs4", True)
                    write.assert_not_called()


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        (self.state / "first-boot.pending").write_text('{"phase":"maintenance"}')

    def test_only_clean_shutdown_with_guest_setup_marker_boots_user(self):
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            return "true\n" if command[0] == "guestfish" else "ready\n"
        with patch.object(boot, "domain_state", return_value="shut off (shutdown)"), patch.object(boot, "run", side_effect=execute):
            boot.finish(state_dir=self.state)
        self.assertEqual(calls[0][-1], "--pre-start")
        self.assertFalse((self.state / "first-boot.pending").exists())
        self.assertEqual(json.loads((self.state / "first-boot.complete").read_text())["phase"], "user")
        self.assertEqual(sum(x[0] == "bash" for x in calls), 1)
        self.assertEqual(sum(x[-1].endswith("guest-status.py") for x in calls), 1)

    def test_crash_destroyed_or_missing_setup_marker_never_boot_user(self):
        for state, marker in (("shut off (destroyed)", "true"), ("crashed (panicked)", "true"), ("shut off (shutdown)", "false")):
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                return marker
            with self.subTest(state=state, marker=marker), patch.object(boot, "domain_state", return_value=state), patch.object(boot, "run", side_effect=execute):
                with self.assertRaises(ValueError):
                    boot.finish(state_dir=self.state)
                self.assertFalse(any(x[0] == "bash" for x in calls))
                self.assertTrue((self.state / "first-boot.pending").exists())

    def test_libvirt_error_is_not_treated_as_a_poweroff(self):
        with patch.object(boot, "domain_state", side_effect=subprocess.CalledProcessError(1, ["virsh"])), patch.object(boot, "run") as execute:
            with self.assertRaises(subprocess.CalledProcessError):
                boot.finish(state_dir=self.state)
            self.assertFalse(any(x.args[0][0] == "bash" for x in execute.call_args_list))

    def test_runtime_isolation_failure_aborts_before_readiness(self):
        (self.state / "first-boot.pending").write_text('{"phase":"user"}')
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            if command[-1].endswith("runtime-audit.py"):
                raise subprocess.CalledProcessError(1, command, output="ОТКАЗ")
            return ""
        with patch.object(boot, "run", side_effect=execute):
            with self.assertRaises(subprocess.CalledProcessError):
                boot.finish(state_dir=self.state)
        self.assertFalse(any(x[-1].endswith("guest-status.py") for x in calls))
        self.assertFalse((self.state / "first-boot.complete").exists())

    def test_maintenance_timeout_preserves_vm_and_pending_state(self):
        def execute(command, **kwargs):
            if command[-1].endswith("guest-status.py"):
                raise subprocess.CalledProcessError(1, command, output="НЕ ГОТОВО")
            return ""
        with patch.object(boot, "domain_state", return_value="running (booted)"), patch.object(boot, "run", side_effect=execute) as invoke, patch.object(boot.time, "monotonic", side_effect=[0, 61]):
            with self.assertRaises(TimeoutError):
                boot.finish(timeout=60, state_dir=self.state)
            self.assertFalse(any(x.args[0][0] == "bash" for x in invoke.call_args_list))
            self.assertTrue((self.state / "first-boot.pending").exists())

    def test_reboot_after_clean_shutdown_recovers_running_user_without_cold_reads(self):
        # Exact crash window: setup powered off; host rebooted before phase=user
        # was persisted; VM autostart consumed the one-shot entry and is USER.
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            self.assertNotEqual(command[0], "guestfish", "Running disks must never be mounted for recovery")
            self.assertNotEqual(command[0], "bash", "Certified running USER must not be restarted")
            return "ГОТОВО: current USER/setup/Telegram/IsTor confirmed\n"
        with patch.object(boot, "domain_state", return_value="running (booted)"), patch.object(boot, "run", side_effect=execute), patch.object(boot.time, "sleep", side_effect=AssertionError("Recovery must not wait for another shutdown")):
            boot.finish(state_dir=self.state)
        self.assertFalse((self.state / "first-boot.pending").exists())
        self.assertEqual(json.loads((self.state / "first-boot.complete").read_text())["phase"], "user")
        self.assertTrue(any(command[-1].endswith("runtime-audit.py") for command in calls))
        self.assertTrue(any(command[-1].endswith("guest-status.py") for command in calls))

    def test_unready_user_does_not_get_a_completion_flag(self):
        (self.state / "first-boot.pending").write_text('{"phase":"user"}')
        def execute(command, **kwargs):
            if command[-1].endswith("guest-status.py"):
                raise subprocess.CalledProcessError(1, command, output="НЕ ГОТОВО")
            return ""
        with patch.object(boot, "run", side_effect=execute), patch.object(boot.time, "sleep"), patch.object(boot.time, "monotonic", side_effect=[0, 1, 61]):
            with self.assertRaises(TimeoutError):
                boot.finish(timeout=60, state_dir=self.state)
        self.assertTrue((self.state / "first-boot.pending").exists())
        self.assertFalse((self.state / "first-boot.complete").exists())

    def test_qga_timeout_with_partial_bytes_preserves_a_clear_failure(self):
        (self.state / "first-boot.pending").write_text('{"phase":"user"}')
        def execute(command, **kwargs):
            if command[-1].endswith("guest-status.py"):
                raise subprocess.TimeoutExpired(command, 125, output=b"still waiting")
            return ""
        with patch.object(boot, "run", side_effect=execute), patch.object(boot.time, "sleep"), patch.object(boot.time, "monotonic", side_effect=[0, 1, 61]):
            with self.assertRaisesRegex(TimeoutError, "still waiting"):
                boot.finish(timeout=60, state_dir=self.state)
        self.assertFalse((self.state / "first-boot.complete").exists())

    def test_completed_installation_checks_live_readiness_without_new_boot(self):
        (self.state / "first-boot.pending").rename(self.state / "first-boot.complete")
        with patch.object(boot, "run", return_value="ready\n") as execute:
            boot.finish(state_dir=self.state)
        self.assertEqual(len(execute.call_args_list), 2)
        self.assertFalse(any(x.args[0][0] == "bash" for x in execute.call_args_list))


if __name__ == "__main__":
    unittest.main()
