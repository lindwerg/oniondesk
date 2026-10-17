#!/usr/bin/env python3
"""Genuine install and live evidence inside this job's disposable Debian host.

All command output stays in memory. Public output consists of literal states,
booleans, bounded numeric hardware facts and source hashes; no raw diagnostics.
"""
import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import selectors
import signal
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import diagnostics

EVIDENCE = Path("/ci-evidence")
SOURCE = Path("/src")
STATE = Path("/var/lib/oniondesk")
DOMAINS = {"gateway": "oniondesk-gateway", "workstation": "oniondesk-workstation"}
INSTALL_TIMEOUT = 5100
MAX_TAIL = 64 * 1024
BROWSER_HOME = Path("/var/lib/oniondesk-ci-browser")


def command(arguments, timeout=60):
    return subprocess.run(arguments, capture_output=True, check=True, timeout=timeout)


def virsh(*arguments, timeout=30):
    return command(["virsh", "--connect", "qemu:///system", *arguments], timeout=timeout).stdout


def save(status):
    EVIDENCE.mkdir(exist_ok=True)
    temporary = EVIDENCE / "status.tmp"
    temporary.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    temporary.replace(EVIDENCE / "status.json")


def source_hashes():
    source = json.loads((SOURCE / "source.json").read_text())
    if source["file_count"] != 29 or len(source["sha256"]) != 29:
        raise ValueError("SourceCountMismatch")
    for relative, expected in source["sha256"].items():
        if not re.fullmatch(r"(?:server|frontend)/[a-zA-Z0-9_.-]+", relative):
            raise ValueError("UnsafeSourcePath")
        if hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() != expected:
            raise ValueError("SourceHashMismatch")
    return source


def kvm_device():
    fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    try:
        version = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION
        vm = fcntl.ioctl(fd, 0xAE01, 0)       # KVM_CREATE_VM, real kernel VM fd
        os.close(vm)
    finally:
        os.close(fd)
    if version != 12:
        raise RuntimeError("UnexpectedKVMAPI")
    return {"api_version": version, "create_vm_ioctl": True}


def boot_environment():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        response = subprocess.run(["systemctl", "is-system-running"], capture_output=True, timeout=5)
        if response.stdout.strip() in {b"running", b"degraded"}:
            break
        time.sleep(1)
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("SystemdPID1Required")
    detected = command(["systemd-detect-virt", "--container"]).stdout.decode().strip()
    if detected != "docker":
        raise RuntimeError("UnexpectedContainerType")
    mounts = [line.split() for line in Path("/proc/mounts").read_text().splitlines()]
    sys_ro = any(row[1] == "/sys" and "ro" in row[3].split(",") for row in mounts)
    cgroup_rw = any(row[1] == "/sys/fs/cgroup" and row[2] == "cgroup2"
                    and "rw" in row[3].split(",") for row in mounts)
    if not sys_ro or not cgroup_rw or Path("/var/run/docker.sock").exists():
        raise RuntimeError("ContainerIsolationContractFailed")
    return {"pid1_systemd": True, "detected_virtualization": detected,
            "sys_read_only": sys_ro, "private_cgroup2_writable": cgroup_rw,
            "docker_socket_absent": True}


def preflight():
    result = command(["bash", "/src/server/install.sh", "--check"])
    if result.returncode != 0:
        raise RuntimeError("ProductionPreflightFailed")
    result = command(["python3", "-B", "/src/server/preflight.py", "--json"])
    facts = json.loads(result.stdout.splitlines()[-1])
    keys = {"id", "version", "arch", "memory", "cpus", "kvm", "free", "apt"}
    if set(facts) != keys or facts["id"] != "debian" or facts["version"] != "13" or facts["arch"] != "x86_64":
        raise RuntimeError("ProductionPreflightFormatChanged")
    return facts


def qmp_kvm(domain):
    document = json.loads(virsh("qemu-monitor-command", domain, '{"execute":"query-kvm"}'))
    result = document["return"]
    if result.get("enabled") is not True or result.get("present") is not True:
        raise RuntimeError("KVMNotEnabledForLiveDomain")
    return {"present": True, "enabled": True}


def probe_libvirt():
    command(["systemctl", "enable", "--now", "libvirtd.socket"])
    deadline = time.monotonic() + 30
    while True:
        try:
            virsh("version")
            break
        except subprocess.CalledProcessError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    name = "oniondesk-ci-kvm-probe"
    path = Path("/run/oniondesk-ci-kvm-probe.xml")
    # This is a real, diskless KVM BIOS boot, only to fail early if libvirt
    # cannot launch non-root QEMU in the delegated cgroup. No substitute binary.
    path.write_text("<domain type='kvm'><name>" + name + "</name>"
                    "<memory unit='MiB'>128</memory><vcpu>1</vcpu>"
                    "<os><type arch='x86_64' machine='pc'>hvm</type></os>"
                    "<devices><emulator>/usr/bin/qemu-system-x86_64</emulator></devices></domain>")
    virsh("create", str(path))
    try:
        result = qmp_kvm(name)
        pid = int(Path("/run/libvirt/qemu/" + name + ".pid").read_text())
        uid_line = next(line for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                        if line.startswith("Uid:"))
        if int(uid_line.split()[1]) == 0:
            raise RuntimeError("QEMUUnexpectedRootUID")
        return {**result, "qemu_non_root": True, "libvirt_domain_type": "kvm"}
    finally:
        # Only the transient probe created above; production guests are removed
        # solely with their owning disposable Docker container.
        virsh("destroy", name)
        path.unlink(missing_ok=True)


def classify(tail):
    """Return a literal classification, never attacker-controlled log fragments."""
    signatures = (
        (b"libguestfs: error", "libguestfs"),
        (b"No space left", "disk_space"),
        (b"Permission denied", "permission"),
        (b"Could not access KVM", "kvm_permissions"),
        (b"HTTP response code said error", "download_http"),
        (b"Could not resolve host", "download_dns"),
        (b"Connection timed out", "network_timeout"),
        (b"BAD signature", "image_signature_or_key"),
    )
    for needle, label in signatures:
        if needle in tail:
            return label
    text = tail.decode("utf-8", errors="replace")
    if "SHA-512 не совпадает" in text or "Неверный fingerprint" in text:
        return "image_verification"
    if "Host Tor не подтверждён:" in text:
        return "host_tor_bootstrap"
    if ("SYSMAINT не завершился вовремя." in text
            or "USER/Tor/Telegram не подтверждены вовремя:" in text):
        return "guest_first_boot_or_readiness"
    return "production_install_exit"


def install(mode, status):
    args = ["bash", "/src/server/install.sh", "--yes-licenses", "--tor-mode", mode]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + INSTALL_TIMEOUT
    tail = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    try:
        while child.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("production_install", INSTALL_TIMEOUT)
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fileobj.fileno(), 8192)
                tail.extend(chunk)
                del tail[:-MAX_TAIL]
            status["observed"] = installation_markers()
            save(status)
        tail.extend(child.stdout.read(MAX_TAIL))
        del tail[:-MAX_TAIL]
        status["installer_exit_code"] = child.returncode
        if child.returncode:
            status["failure_stage"] = classify(tail)
            raise RuntimeError("ProductionInstallFailed")
    finally:
        # Existing production ERR trap is observed, never replaced/injected.
        # Store static error-site tokens and validated line numbers only.
        try:
            status["installer_diagnostics"] = diagnostics.output_summary(
                bytes(tail), sites=diagnostics.static_error_sites())
        except (OSError, ValueError, SyntaxError):
            status["installer_diagnostics"] = {"available": False}
        selector.close()
        child.stdout.close()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)


def signature_observed(data):
    for line in data.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            fingerprint = "916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA"
            if len(fields) >= 3 and (fields[2] == fingerprint or (len(fields) >= 12 and fields[11] == fingerprint)):
                return True
    return False


def installation_markers():
    staging = STATE / "staging"
    verified = False
    if staging.is_dir():
        for path in staging.glob("install.*/signature.status"):
            try:
                data = path.read_bytes()
                verified = verified or signature_observed(data)
            except OSError:
                pass
    return {"signature_validsig_observed": verified,
            "gateway_disk_present": Path("/var/lib/libvirt/images/oniondesk/gateway.qcow2").is_file(),
            "workstation_disk_present": Path("/var/lib/libvirt/images/oniondesk/workstation.qcow2").is_file(),
            "host_installed_marker": (STATE / "host-installed").is_file(),
            "first_boot_complete_marker": (STATE / "first-boot.complete").is_file()}


def verified_archive():
    stages = list((STATE / "staging").glob("install.*"))
    if len(stages) != 1:
        raise RuntimeError("UnexpectedArchiveStage")
    stage = stages[0]
    archive = stage / "Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz"
    # Validate the real status with the production parser, and independently
    # hash the downloaded bytes. Successful unmodified install also certifies
    # that verify-image.sh accepted these bytes before extraction/import.
    status = (stage / "signature.status").read_bytes()
    subprocess.run(["python3", "-B", "/src/server/image_tools.py", "verify-status"],
                   input=status, capture_output=True, check=True, timeout=15)
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha512").hexdigest()
    expected = re.search(r"^SHA512=([0-9a-f]{128})$", (SOURCE / "server/verify-image.sh").read_text(), re.M)
    if expected is None or digest != expected[1]:
        raise RuntimeError("ArchiveDigestMismatch")
    return {"release": "18.2.1.9", "sha512": digest,
            "OpenPGP_primary_fingerprint": "916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA",
            "production_verifier_pass_before_import": True,
            "official_https_download": True}


def audit():
    report = json.loads(command(["python3", "-B", "/opt/oniondesk/server/runtime-audit.py", "--json"]).stdout)
    checks = report["checks"]
    if not isinstance(checks, list) or not checks or any(type(check.get("ok")) is not bool for check in checks):
        raise ValueError("UnknownAuditFormat")
    if report["ok"] is not True or not all(check["ok"] for check in checks):
        raise RuntimeError("ProductionRuntimeAuditFailed")
    # Production IDs include system-unit names and private filesystem paths.
    # Only counts and booleans are necessary public evidence.
    return {"ok": True, "check_count": len(checks), "all_checks_passed": True}


def live_readiness():
    command(["python3", "-B", "/opt/oniondesk/server/guest-status.py"], timeout=125)
    result = {}
    for role, domain in DOMAINS.items():
        xml = ET.fromstring(virsh("dumpxml", domain))
        if xml.attrib.get("type") != "kvm":
            raise RuntimeError("ProductionDomainNotKVM")
        result[role] = {"running": virsh("domstate", domain).strip() == b"running", **qmp_kvm(domain)}
    if not all(role["running"] for role in result.values()):
        raise RuntimeError("ProductionDomainNotRunning")
    return {"production_guest_status_pass": True, "domains": result,
            "workstation_tor_and_USER_confirmed_by_production_probe": True,
            "gateway_path_supported_by_workstation_Tor_probe": True}


def screenshot(role):
    from PIL import Image
    raw = Path("/run/oniondesk-ci-" + role + ".ppm")
    virsh("screenshot", DOMAINS[role], str(raw), timeout=30)
    try:
        if raw.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("ScreenshotSizeLimit")
        with Image.open(raw) as image:
            image.thumbnail((1280, 1024))
            # Re-encode pixels only; never copy metadata or browser chrome.
            image.convert("RGB").save(EVIDENCE / (role + ".png"), optimize=True)
    finally:
        raw.unlink(missing_ok=True)


def cold_boot():
    command(["bash", "/opt/oniondesk/server/control.sh", "stop"], timeout=260)
    if any(virsh("domstate", domain).strip() != b"shut off" for domain in DOMAINS.values()):
        raise RuntimeError("GracefulColdStopNotConfirmed")
    command(["bash", "/opt/oniondesk/server/control.sh", "start"], timeout=150)
    deadline = time.monotonic() + 240
    while True:
        try:
            result = live_readiness()
            return {"both_guests_gracefully_stopped": True, "cold_boot_live_readiness": result}
        except subprocess.SubprocessError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


def otp(secret):
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def browser_session(hostname, credentials):
    if os.geteuid() == 0 or Path.home() != BROWSER_HOME:
        raise RuntimeError("NonRootPrivateBrowserHomeRequired")
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", hostname):
        raise ValueError("UnexpectedOnionHostname")
    options = webdriver.ChromeOptions()
    for argument in ("--headless=new", "--disable-dev-shm-usage", "--disable-gpu",
                     "--window-size=1280,1024", "--proxy-server=socks5://127.0.0.1:9050",
                     "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
                     "--user-data-dir=" + str(BROWSER_HOME / "profile")):
        options.add_argument(argument)
    service = Service(log_output=subprocess.DEVNULL)
    driver = webdriver.Chrome(service=service, options=options)
    try:
        driver.set_page_load_timeout(120)
        wait = WebDriverWait(driver, 60)
        driver.get("chrome://sandbox/")
        wait.until(lambda current: current.find_element(By.ID, "evaluation").text
                   == "You are adequately sandboxed.")
        driver.get("http://" + hostname + "/")
        wait.until(lambda current: current.find_element(By.ID, "password"))
        driver.find_element(By.ID, "login").clear()
        driver.find_element(By.ID, "login").send_keys(credentials["login"])
        driver.find_element(By.ID, "password").send_keys(credentials["password"])
        driver.find_element(By.ID, "otp").send_keys(otp(credentials["totp_secret"]))
        driver.find_element(By.CSS_SELECTOR, "form button").click()
        wait.until(lambda current: len(current.find_elements(By.CSS_SELECTOR, "a.desktop")) == 2)
        result = {"real_onion_route_via_Tor": True, "password_TOTP_login": True,
                  "non_root_browser": True, "chromium_sandbox_confirmed": True}
        for role in DOMAINS:
            driver.get("http://" + hostname + "/novnc/vnc.html?autoconnect=1&resize=scale&path=/ws/" + role)
            canvas = wait.until(lambda current: current.find_element(By.CSS_SELECTOR, "#noVNC_container canvas"))
            # A connected RFB display is required; an empty/error page does not pass.
            wait.until(lambda current: "noVNC_connected" in current.find_element(By.TAG_NAME, "html").get_attribute("class"))
            time.sleep(2)
            canvas.screenshot(str(BROWSER_HOME / ("browser-" + role + ".png")))
            result[role + "_real_noVNC_connected"] = True
        return result
    finally:
        driver.quit()


def browser():
    from PIL import Image
    hostname = Path("/var/lib/tor/oniondesk/hostname").read_text().strip()
    credentials = json.loads(Path("/etc/oniondesk/credentials.json").read_text())
    private_input = {"hostname": hostname, "credentials": {
        key: credentials[key] for key in ("login", "password", "totp_secret")}}
    # Credentials travel over an anonymous pipe, never argv/environment/files.
    response = subprocess.run(["runuser", "--user", "oniondesk-ci-browser", "--",
                               "python3", "-B", "/ci/container.py", "--browser-only"],
                              input=json.dumps(private_input).encode(), capture_output=True,
                              check=True, timeout=600)
    result = json.loads(response.stdout)
    expected = {"real_onion_route_via_Tor", "password_TOTP_login", "non_root_browser",
                "chromium_sandbox_confirmed", "gateway_real_noVNC_connected",
                "workstation_real_noVNC_connected"}
    if not isinstance(result, dict) or set(result) != expected or any(value is not True for value in result.values()):
        raise RuntimeError("UnknownBrowserResult")
    for role in DOMAINS:
        raw = BROWSER_HOME / ("browser-" + role + ".png")
        if raw.is_symlink() or not raw.is_file() or raw.stat().st_size > MAX_TAIL * 256:
            raise ValueError("BrowserScreenshotInvalid")
        with Image.open(raw) as pixels:
            pixels.thumbnail((1280, 1024))
            pixels.convert("RGB").save(EVIDENCE / raw.name, optimize=True)
        raw.unlink()
    return result


def main(mode):
    status = {"result": "RUNNING", "tor_mode": mode, "phase": "container_boot",
              "scope": "ephemeral Debian 13 container on public Ubuntu KVM; not physical Debian host",
              "host_reboot_tested": False, "RDP_tested": False}
    save(status)
    success = False
    try:
        source = source_hashes()
        (EVIDENCE / "source.json").write_text(json.dumps(source, indent=2, sort_keys=True) + "\n")
        status["environment"] = boot_environment()
        status["phase"] = "production_preflight"
        status["preflight"] = preflight()
        status["real_kvm_device"] = kvm_device()
        status["phase"] = "libvirt_kvm_probe"
        save(status)
        status["real_libvirt_kvm_probe"] = probe_libvirt()
        status["phase"] = "unmodified_production_install"
        save(status)
        install(mode, status)
        status["observed"] = installation_markers()
        if not all(status["observed"].values()):
            raise RuntimeError("InstallMarkersIncomplete")
        status["verified_official_Whonix_archive"] = verified_archive()
        status["runtime_audit"] = audit()
        status["live_readiness"] = live_readiness()
        status["phase"] = "cold_boot"
        save(status)
        status["cold_boot"] = cold_boot()
        status["runtime_audit_after_cold_boot"] = audit()
        status["phase"] = "real_browser_onion_login_and_noVNC"
        save(status)
        status["browser"] = browser()
        success = True
    except Exception as error:
        # Exception messages, subprocess output, endpoints and filenames are not public evidence.
        status["error_class"] = type(error).__name__
        if status["phase"] == "unmodified_production_install":
            status["observed"] = installation_markers()
            try:
                status["failure_diagnostics"] = diagnostics.snapshot(diagnostics.static_error_sites())
            except Exception:
                status["failure_diagnostics"] = {"available": False}
    finally:
        for role in DOMAINS:
            try:
                screenshot(role)
                status[role + "_screen_captured"] = True
            except Exception as error:
                status[role + "_screen_error_class"] = type(error).__name__
        try:
            status["production_payload_unchanged"] = source_hashes() == source
        except Exception:
            status["production_payload_unchanged"] = False
        status["result"] = "PASS" if success and status["production_payload_unchanged"] else "FAIL_OR_INCOMPLETE"
        save(status)
    return 0 if status["result"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tor-mode", choices=("direct", "public-obfs4"))
    parser.add_argument("--snapshot-only", action="store_true")
    parser.add_argument("--browser-only", action="store_true")
    arguments = parser.parse_args()
    if arguments.browser_only:
        try:
            raw_input = sys.stdin.buffer.read(MAX_TAIL + 1)
            if len(raw_input) > MAX_TAIL:
                raise ValueError("BrowserInputLimit")
            request = json.loads(raw_input)
            print(json.dumps(browser_session(request["hostname"], request["credentials"])))
        except Exception:
            # Selenium exceptions may contain the private hostname/page state.
            print("SandboxedBrowserFailed", file=sys.stderr)
            raise SystemExit(1)
    elif arguments.snapshot_only:
        for role in DOMAINS:
            try:
                screenshot(role)
            except Exception:
                pass
    elif arguments.tor_mode:
        raise SystemExit(main(arguments.tor_mode))
    else:
        parser.error("--tor-mode or --snapshot-only is required")
