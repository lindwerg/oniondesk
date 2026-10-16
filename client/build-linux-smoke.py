#!/usr/bin/env python3
"""Developer smoke test of the actual ELF in Debian without Python or GnuPG.

The target container runs as nobody, with no host devices or elevated rights.
The host's Python only drives HTTP and Docker; it is never mounted into Linux.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

KIT = Path(__file__).resolve().parent.parent
BUILD_MARKER = ".oniondesk-linux-build"
BUILD_MARKER_TEXT = "OnionDesk Linux build staging v1\n"
EVIDENCE_MARKER = ".oniondesk-linux-smoke"
EVIDENCE_MARKER_TEXT = "OnionDesk Linux smoke evidence v1\n"


def run(args, *, check=True, timeout=120):
    result = subprocess.run([str(item) for item in args], check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and result.returncode:
        raise RuntimeError(f"Probe command failed ({result.returncode}): {args[0]}\n{result.stdout[-5000:]}")
    return result


def owned_marker(path, expected):
    try:
        return not path.is_symlink() and path.is_file() and path.read_text() == expected
    except (OSError, UnicodeError):
        return False


def evidence_directory(work):
    """Validate both owners before creating, changing or cleaning evidence."""
    if work.is_symlink() or work.resolve() != work or not work.is_dir() or not owned_marker(work / BUILD_MARKER, BUILD_MARKER_TEXT):
        raise RuntimeError("Smoke workspace is not an owned Linux build directory.")
    evidence = work / "smoke"
    if evidence.is_symlink() or evidence.resolve() != evidence:
        raise RuntimeError("Smoke evidence directory must not be a symlink.")
    if evidence.exists():
        if not evidence.is_dir():
            raise RuntimeError("Smoke evidence path is not a directory.")
        existing = list(evidence.iterdir())
        if existing and not owned_marker(evidence / EVIDENCE_MARKER, EVIDENCE_MARKER_TEXT):
            raise RuntimeError("Smoke evidence directory is not owned by this test.")
        if any(item.is_symlink() or not item.is_file() for item in existing):
            raise RuntimeError("Smoke evidence must not contain links or nested directories.")
    evidence.mkdir(exist_ok=True)
    marker = evidence / EVIDENCE_MARKER
    if not marker.exists():
        with marker.open("x") as target:
            target.write(EVIDENCE_MARKER_TEXT)
    # The restricted target container's nobody user must write synthetic output.
    evidence.chmod(0o777)
    return evidence


def http(origin, path, token=None, data=None, extra_headers=None):
    headers = {"Origin": origin}
    if token:
        headers["X-App-Nonce"] = token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    headers.update(extra_headers or {})
    request = Request(origin + path, data=data, headers=headers)
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def http_probe():
    """Run in a separate container sharing only the target network namespace."""
    evidence = Path("/evidence")
    launch = urlsplit((evidence / "browser-url").read_text().strip())
    origin = "http://" + launch.netloc
    token = launch.fragment
    result = {}
    linked_assets = set()
    for asset in ("/", "/app.js", "/style.css", "/favicon.svg", "/assets/agent-cover.png",
                  "/fonts/JetBrainsMono-Regular.ttf", "/fonts/JetBrainsMono-Bold.ttf"):
        status, body, headers = http(origin, asset)
        assert status == 200 and len(body) > 100, f"Missing packaged asset: {asset}"
        assert headers.get("Cache-Control") == "no-store"
        if asset.endswith('.ttf'):
            assert body[:4] == b'\x00\x01\x00\x00', 'Invalid packaged TrueType font'
        if asset in ("/", "/app.js", "/style.css"):
            linked_assets.update(re.findall(r"/assets/[A-Za-z0-9_./-]+\.(?:png|svg|jpg|webp)", body.decode("utf-8")))
    for asset in sorted(linked_assets):
        status, body, _ = http(origin, asset)
        assert status == 200 and len(body) > 100, f"Missing linked UI image: {asset}"
    expected_steps = {f"/assets/steps/{name}.png" for name in
                      ("01-device", "02-usb", "03-purchase", "04-setup", "05-access", "06-daily")}
    assert expected_steps <= linked_assets, "The UI does not reference every step illustration"
    result["packaged_assets"] = "PASS; HTML, JS, CSS, favicon, cover, both local Cyrillic fonts"
    result["linked_ui_images"] = len(linked_assets)
    result["step_illustrations"] = 6
    status, _, _ = http(origin, "/api/state")
    assert status == 403, "API accepted an unauthorized caller"
    status, _, _ = http(origin, "/api/state", token, extra_headers={"Host": "example.invalid"})
    assert status == 403, "API accepted an unexpected Host"
    status, body, _ = http(origin, "/api/state", token)
    state = json.loads(body)
    assert status == 200 and state["system"]["platform"] == "Linux", body
    assert state["system"]["verifier_available"] is True, body
    assert state["usb_written"] is False
    assert state["safety_checked"] is False and state["safety_ok"] is False
    assert state["safety_report"] == ""
    assert http(origin, "/api/access-note", token)[0] == 400
    assert http(origin, "/api/access-note")[0] == 403
    assert http(origin, "/api/server/resume", token, {})[0] == 400
    assert http(origin, "/api/server/action", token, {"action": "audit"})[0] == 400
    result["automation_boundaries"] = "PASS; no stale safety evidence, no note or resume/audit without credentials or connection"
    result["authorized_state"] = "PASS; Linux, bundled verifier available, no USB write"
    result["unauthorized_api"] = "PASS; HTTP403 with missing nonce or wrong Host"
    status, _, _ = http(origin, "/api/tor/check", token, {})
    assert status == 200
    for _ in range(100):
        _, body, _ = http(origin, "/api/state", token)
        job = json.loads(body)["job"]
        if job["state"] != "running":
            break
        time.sleep(0.1)
    assert job["state"] == "error" and "Tor" in job["message"], job
    assert "No module named" not in job["message"], job
    result["network_engine_dependencies"] = "PASS; engine loaded and absent local Tor rejected"
    status, _, _ = http(origin, "/api/quit", token, {})
    assert status == 200
    (evidence / "http-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), default="x86_64")
    parser.add_argument("--work", type=Path)
    parser.add_argument("--port", type=int, default=54391)
    parser.add_argument("--http-probe", action="store_true")
    options = parser.parse_args()
    if options.http_probe:
        http_probe()
        return
    if options.work is None:
        parser.error("--work is required unless --http-probe is used")
    if not 1024 <= options.port <= 65535:
        raise ValueError("Use an unprivileged TCP port.")
    application = KIT / "Linux" / options.architecture / "OnionDesk"
    work = options.work.absolute()
    fixture = work / "signature-fixture"
    evidence = evidence_directory(work)
    for filename in ("browser-url", "browser-library-path", "controlled-bad.txt"):
        target = evidence / filename
        if target.exists() or target.is_symlink():
            target.unlink()
    (evidence / "capture-browser").write_text('#!/bin/sh\nprintf "%s\\n" "$1" > /evidence/browser-url\nprintf "%s\\n" "${LD_LIBRARY_PATH-unset}" > /evidence/browser-library-path\n')
    (evidence / "capture-browser").chmod(0o755)
    platform_name = "linux/amd64" if options.architecture == "x86_64" else "linux/arm64"
    name = "oniondesk-linux-smoke-" + options.architecture + "-" + secrets.token_hex(4)
    base = ["docker", "run", "--platform", platform_name,
            "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--mount", f"type=bind,src={application},dst=/app,readonly",
            "--mount", f"type=bind,src={evidence},dst=/evidence",
            "--mount", f"type=bind,src={fixture},dst=/fixture,readonly"]
    image = "debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587"
    result = {"architecture": options.architecture, "runtime_image": image,
              "runtime_user": 65534, "usb_writes": 0, "external_downloads": 0, "status": "FAIL"}
    started = False
    try:
        run([*base, "--detach", "--name", name,
             "--env", "HOME=/tmp", "--env", "DISPLAY=:0", "--env", "BROWSER=/evidence/capture-browser %s",
             image, "/app/OnionDesk", "--port", str(options.port)])
        started = True
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if (evidence / "browser-url").is_file():
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("The packaged application did not launch the browser.")
        launch = urlsplit((evidence / "browser-url").read_text().strip())
        if launch.scheme != "http" or launch.netloc != f"127.0.0.1:{options.port}" or len(launch.fragment) != 43:
            raise RuntimeError("Unexpected browser launch URL.")
        result["default_browser_launch"] = "PASS; loopback URL and nonce fragment"
        result["browser_library_path"] = (evidence / "browser-library-path").read_text().strip()
        assert result["browser_library_path"] == "unset", "System browser inherited bundled library paths"
        missing = run(["docker", "exec", name, "/bin/sh", "-c", "test ! -e /usr/bin/python3 && test ! -e /usr/local/bin/python && test ! -e /usr/bin/gpg"])
        assert missing.returncode == 0
        result["system_python_and_gpg"] = "absent"
        run(["docker", "exec", name, "/bin/mkdir", "-m", "700", "/tmp/gpg-smoke"])
        gpg = ["docker", "exec", name, "/app/_internal/tools/gpg/bin/gpg", "--no-options", "--homedir", "/tmp/gpg-smoke",
               "--batch", "--no-tty", "--no-autostart", "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        imported = run([*gpg, "--import", "/fixture/public.asc"])
        good = run([*gpg, "--verify", "/fixture/controlled.txt.sig", "/fixture/controlled.txt"])
        assert "Good signature" in good.stdout, good.stdout
        (evidence / "controlled-bad.txt").write_text("Deliberately modified controlled Linux fixture\n")
        bad = run([*gpg, "--verify", "/fixture/controlled.txt.sig", "/evidence/controlled-bad.txt"], check=False)
        assert bad.returncode != 0 and "BAD signature" in bad.stdout, bad.stdout
        (evidence / "gpg-valid.log").write_text(imported.stdout + good.stdout)
        (evidence / "gpg-invalid.log").write_text(bad.stdout)
        result["bundled_gpg_without_system_gpg"] = "PASS; valid signature accepted, changed payload rejected"
        run(["docker", "run", "--rm", "--platform", platform_name, "--network", "container:" + name,
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/probe.py,readonly",
             "--mount", f"type=bind,src={evidence},dst=/evidence", "--entrypoint", "python",
             "oniondesk-linux-builder:" + options.architecture, "/probe.py", "--http-probe"])
        result.update(json.loads((evidence / "http-result.json").read_text()))
        result["http_probe"] = "separate container sharing target loopback; no Python installed in target"
        exited = run(["docker", "wait", name])
        assert exited.stdout.strip() == "0", exited.stdout
        result["graceful_quit"] = "PASS"
        helper = run([*base, "--rm", image, "/app/OnionDesk", "--usb-privileged", "/tmp/invalid-request.json"], check=False, timeout=20)
        assert helper.returncode == 1, "Unprivileged helper unexpectedly accepted a request or failed to start"
        result["privileged_dispatch"] = "PASS; nonroot rejected before GUI or listener"
        result["executable_sha256"] = hashlib.sha256((application / "OnionDesk").read_bytes()).hexdigest()
        result["status"] = "PASS"
    finally:
        if started:
            logs = run(["docker", "logs", name], check=False)
            if logs.returncode == 0:
                (evidence / "app.log").write_text(logs.stdout)
            run(["docker", "rm", "--force", name], check=False)
        # A launch nonce is temporary authorization, not part of saved evidence.
        if (evidence / "browser-url").exists():
            (evidence / "browser-url").unlink()
        (evidence / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
