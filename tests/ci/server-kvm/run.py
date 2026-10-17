#!/usr/bin/env python3
"""Public-runner-only lifecycle; never connects to local Docker or an existing VM."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "server-kvm-evidence"
LABEL = "io.oniondesk.server-kvm-ci"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


def invoke(args, timeout=60, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout, **kwargs)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def payload(root):
    """Read the launcher's literal manifest without importing/executing it."""
    tree = ast.parse((root / "client/launcher.py").read_text())
    entries = [ast.literal_eval(node.value) for node in tree.body
               if isinstance(node, ast.Assign) and any(
                   isinstance(target, ast.Name) and target.id == "RUNTIME_FILES"
                   for target in node.targets)]
    if len(entries) != 1 or not isinstance(entries[0], tuple) or len(entries[0]) != 29:
        raise ValueError("UnexpectedPayloadManifest")
    paths = entries[0]
    if len(set(paths)) != 29 or any(
        not isinstance(path, str) or not re.fullmatch(r"(?:server|frontend)/[a-zA-Z0-9_.-]+", path)
        or not (root / path).is_file() or (root / path).is_symlink() for path in paths
    ):
        raise ValueError("UnsafePayloadManifest")
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}


def require_public_runner():
    expected = {"CI_PUBLIC_REPOSITORY": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("PublicGitHubLinuxRunnerRequired")
    if not Path("/dev/kvm").is_char_device():
        raise RuntimeError("KVMDeviceUnavailable")


def state_path():
    path = Path(os.environ["CI_STATE_FILE"])
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    if path.parent.resolve() != temporary or not re.fullmatch(
        r"oniondesk-server-kvm-[0-9]+-[0-9]+\.json", path.name
    ):
        raise ValueError("UnsafeStatePath")
    return path


def cleanup():
    """Remove immutable IDs only after verifying this job's random ownership label."""
    path = state_path()
    if not path.exists():
        return
    state = json.loads(path.read_text())
    owner = state["owner"]
    if not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise ValueError("UnsafeOwnerLabel")
    checks = {}
    identity_files = []
    for kind, key in (("container", "container_id"), ("image", "image_id")):
        identity_file = path.parent / ("oniondesk-server-kvm-" + owner + (".cid" if kind == "container" else ".iid"))
        identity_files.append(identity_file)
        identity = state.get(key) or (identity_file.read_text().strip() if identity_file.exists() else None)
        if not identity:
            continue
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", identity):
            raise ValueError("UnsafeDockerIdentity")
        found = subprocess.run(["docker", kind, "inspect", "--format",
                                '{{ index .Config.Labels "' + LABEL + '" }}', identity],
                               capture_output=True, text=True, timeout=20)
        if found.returncode:
            # docker inspect returns 1 for an already removed ID. Prove absence
            # with a successful inventory, rather than treating daemon failure as cleanup.
            inventory = invoke(["docker", kind, "ls", "--quiet", "--no-trunc"]
                               + (["--all"] if kind == "container" else []), timeout=20)
            checks[kind + "_removed"] = identity.removeprefix("sha256:") not in inventory.stdout.decode()
            if not checks[kind + "_removed"]:
                raise RuntimeError("CleanupInspectFailed")
            continue
        if found.stdout.strip() != owner:
            raise RuntimeError("CleanupOwnershipMismatch")
        command = ["docker", kind, "rm"] + (["--force"] if kind == "container" else []) + [identity]
        invoke(command, timeout=60)
        checks[kind + "_removed"] = True
    write_json(EVIDENCE / "cleanup.json", {"owned_resources_only": True, **checks})
    for identity_file in identity_files:
        identity_file.unlink(missing_ok=True)
    path.unlink()


def export_evidence(container, temporary):
    destination = temporary / "export"
    destination.mkdir()
    invoke(["docker", "cp", container + ":/ci-evidence/.", str(destination)], timeout=60)
    files = sorted(destination.iterdir())
    names = {"status.json", "source.json", "gateway.png", "workstation.png",
             "browser-gateway.png", "browser-workstation.png"}
    if any(path.name not in names or path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("UnexpectedEvidenceFile")
    if sum(path.stat().st_size for path in files) > MAX_ARTIFACT_BYTES:
        raise ValueError("EvidenceSizeLimit")
    for path in files:
        shutil.copyfile(path, EVIDENCE / path.name)


def run():
    require_public_runner()
    EVIDENCE.mkdir(exist_ok=True)
    path = state_path()
    if path.exists():
        raise RuntimeError("OwnedStateAlreadyExists")
    mode = os.environ.get("CI_TOR_MODE", "direct")
    if mode not in {"public-obfs4", "direct"}:
        raise ValueError("UnknownTorMode")
    source_sha = invoke(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.decode().strip()
    if source_sha != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("CheckoutSHAMismatch")
    before = payload(ROOT)
    owner = uuid.uuid4().hex
    state = {"owner": owner}
    write_json(path, state)
    image_file = path.parent / ("oniondesk-server-kvm-" + owner + ".iid")
    container_file = path.parent / ("oniondesk-server-kvm-" + owner + ".cid")
    failed = True
    phase = "image_build"
    write_json(EVIDENCE / "host.json", {"source_commit": source_sha, "tor_mode": mode,
               "public_github_hosted_runner": True, "phase": phase, "result": "RUNNING"})
    try:
        with tempfile.TemporaryDirectory(prefix="oniondesk-server-kvm-", dir=os.environ["RUNNER_TEMP"]) as temp:
            temporary = Path(temp)
            source = temporary / "payload"
            source.mkdir()
            for relative in before:
                target = source / relative
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            write_json(source / "source.json", {"commit": source_sha, "file_count": 29, "sha256": before})
            result = invoke(["docker", "build", "--quiet", "--iidfile", str(image_file), "--label", LABEL + "=" + owner,
                             "--tag", "oniondesk-server-kvm:" + owner,
                             str(Path(__file__).resolve().parent)], timeout=600)
            identity = result.stdout.decode().strip().splitlines()[-1]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
                raise ValueError("UnexpectedImageIdentity")
            state["image_id"] = identity
            write_json(path, state)
            phase = "container_start"
            result = invoke(["docker", "create", "--cidfile", str(container_file), "--name", "oniondesk-server-kvm-" + owner,
                             "--label", LABEL + "=" + owner, "--privileged", "--cgroupns=private",
                             "--device=/dev/kvm", "--log-driver=none", "--network=bridge",
                             "--tmpfs", "/run:rw,nosuid,nodev,mode=755,size=512m",
                             "--tmpfs", "/run/lock:rw,nosuid,nodev,noexec,size=16m",
                             "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m", identity], timeout=60)
            container = result.stdout.decode().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", container):
                raise ValueError("UnexpectedContainerIdentity")
            state["container_id"] = container
            write_json(path, state)
            invoke(["docker", "cp", str(source), container + ":/src"], timeout=60)
            # Persist the immutable ID before starting any processes. If boot
            # fails, cleanup still owns and removes this created container.
            invoke(["docker", "start", container], timeout=60)
            phase = "production_install_and_live_checks"
            print("Running genuine Debian/systemd/KVM installation; public evidence is allowlisted.", flush=True)
            try:
                result = subprocess.run(["docker", "exec", container, "python3", "-B", "/ci/container.py",
                                         "--tor-mode", mode], capture_output=True, timeout=6000)
            finally:
                # Preserve partial/manual-gate proof even if the exec client was
                # interrupted. Its output and stderr are never forwarded.
                subprocess.run(["docker", "exec", container, "python3", "-B", "/ci/container.py",
                                "--snapshot-only"], capture_output=True, timeout=75)
                export_evidence(container, temporary)
            if result.returncode:
                raise RuntimeError("ContainerChecksFailed")
            failed = False
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, InterruptedError) as error:
        write_json(EVIDENCE / "failure.json", {"phase": phase, "error_class": type(error).__name__,
                                               "result": "FAIL_OR_INCOMPLETE"})
    finally:
        unchanged = payload(ROOT) == before
        write_json(EVIDENCE / "host.json", {"source_commit": source_sha, "tor_mode": mode,
                   "public_github_hosted_runner": True, "production_payload_unchanged": unchanged,
                   "result": "PASS" if not failed and unchanged else "FAIL_OR_INCOMPLETE"})
        cleanup()
    return 1 if failed or not unchanged else 0


def interrupted(_signal, _frame):
    raise InterruptedError("CIInterrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if sys.argv[1:] == ["cleanup"]:
            cleanup()
        elif sys.argv[1:] == ["run"]:
            raise SystemExit(run())
        else:
            raise ValueError("ExpectedRunOrCleanup")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, InterruptedError) as error:
        # No exception message: subprocess exceptions can carry raw output.
        print("Server CI stopped: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
