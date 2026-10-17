"""One-minute Windows reproduction; frozen sources and production ACLs stay unchanged."""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
import urllib.request


def source_pins(native):
    return json.loads((native.HERE / "windows-probe/source-pins.json").read_text(encoding="utf-8"))


def extract_frozen_sources(native, archive, destination):
    pins = source_pins(native)
    if archive.stat().st_size != pins["archive_bytes"] or native.digest(archive) != pins["archive_sha256"]:
        raise ValueError("ProbeSourceArchiveMismatch")
    prefix = "oniondesk-r5-corresponding-source-20261017/"
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        catalog_member = next(item for item in members if item.name == prefix + "SOURCES.json")
        if not catalog_member.isfile() or catalog_member.size > 2 * 1024 * 1024:
            raise ValueError("ProbeSourceCatalogMismatch")
        with source.extractfile(catalog_member) as incoming:
            catalog = json.loads(incoming.read().decode("utf-8"))
        records = {item["path"]: item for item in catalog["files"]}
        copied = set()
        for item in members:
            if not item.name.startswith(prefix + "integration/windows-r5/"):
                continue
            name = item.name.removeprefix(prefix + "integration/windows-r5/")
            if name not in pins["files"]:
                continue
            expected = pins["files"][name]
            catalog_record = records["integration/windows-r5/" + name]
            if name in copied or not item.isfile() or item.size != expected["bytes"] or item.size > 256 * 1024 or \
                    catalog_record["sha256"] != expected["sha256"] or catalog_record["bytes"] != expected["bytes"]:
                raise ValueError("ProbeFrozenSourceMismatch")
            with source.extractfile(item) as incoming:
                data = incoming.read(item.size + 1)
            if len(data) != item.size or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise ValueError("ProbeFrozenSourceMismatch")
            target = destination.joinpath(*native.safe_member(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            copied.add(name)
        if copied != set(pins["files"]):
            raise ValueError("ProbeFrozenSourceMismatch")


def build_probe(native, harness, archive):
    frozen = harness.root / "frozen"
    extract_frozen_sources(native, archive, frozen)
    probe = harness.root / "probe"
    probe.mkdir()
    shutil.copyfile(native.HERE / "windows-probe/main.go", probe / "main.go")
    shutil.copyfile(native.HERE / "contracts/windows-x64.json", probe / "manifest.json")
    (probe / "go.mod").write_text(
        "module oniondesk.local/native-r5-cache-probe\n\ngo 1.26.2\n\n"
        "require (\n oniondesk.local/offline/engine v0.0.0\n oniondesk.local/online/transport v0.0.0\n)\n"
        "replace oniondesk.local/offline/engine => ../frozen/engine\n"
        "replace oniondesk.local/online/transport => ../frozen/transport\n", encoding="utf-8")
    environment = dict(harness.environment)
    environment.update({"GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
                        "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GOCACHE": str(harness.root / "go-cache"),
                        "GOPATH": str(harness.root / "go-path"), "GOMODCACHE": str(harness.root / "go-mod-cache")})
    version = subprocess.run(["go", "version"], check=True, capture_output=True, text=True, encoding="utf-8", timeout=10)
    if "go version go1.26.2 " not in version.stdout:
        raise RuntimeError("ProbeExactGoVersionRequired")
    executable = probe / "OnionDesk-Cache-Probe.exe"
    subprocess.run(["go", "build", "-trimpath", "-o", str(executable), "."], cwd=probe, env=environment,
                   check=True, capture_output=True, timeout=120)
    harness.facts["probe_source_verified"] = True
    harness.save()
    return executable


def public_probe_facts(result):
    facts = {key: result[key] for key in ("token_owner_equals_user", "token_owner_is_admin", "token_elevated")}
    facts.update({"probe_exact_go_version": result["go_version"] == "go1.26.2", "probe_unsafe_error": result["unsafe_error"],
                  "probe_download_progress_seen": result["download_progress_seen"], "probe_deadline_reached": result["deadline_reached"],
                  "probe_restore_lock_exists": result["restore_lock_exists"]})
    for source, prefix in (("root_after", "cache"), ("child_after", "manifest_child")):
        for name in ("owner_is_user", "owner_is_admin", "dacl_protected"):
            facts[prefix + "_" + name] = result[source][name]
    facts["manifest_child_exists"] = result["child_after"]["exists"]
    facts["cache_exists"] = result["root_after"]["exists"]
    error = result.get("restore_error", "")
    facts["probe_error_kind"] = next((kind for literal, kind in (
        ("cache handle owner/DACL differs", "owned_handle_owner_dacl"),
        ("cache owner/protected DACL differs", "root_owner_dacl"),
        ("writable or unsupported cache ancestor ACL", "ancestor_acl")) if literal in error), "other" if error else "none")
    return facts


def run_diagnostic(native):
    harness = None
    captured = False
    try:
        if os.name != "nt":
            raise RuntimeError("WindowsDiagnosticRunnerRequired")
        harness = native.Harness("windows-x64")
        harness.phase("windows_cache_diagnostic")
        harness.download()
        pins = source_pins(native)
        archive = harness.root / "source.tar.gz"
        url = "https://github.com/lindwerg/oniondesk/releases/download/" + native.PINS["release"] + "/" + pins["archive_asset"]
        with urllib.request.urlopen(url, timeout=60) as response, archive.open("xb") as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > pins["archive_bytes"]:
                    raise ValueError("ProbeSourceArchiveMismatch")
                output.write(chunk)
        probe = build_probe(native, harness, archive)
        harness.phase("windows_cache_diagnostic")
        environment = dict(harness.environment)
        environment.update({key: os.environ[key] for key in ("USERPROFILE", "LOCALAPPDATA", "APPDATA")})
        launcher = harness.spawn(harness.entry, environment)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            code = harness.native_terminal_error()
            if code:
                harness.facts["native_error_code"] = code
                harness.native_snapshot()
                break
            if launcher.poll() is not None:
                raise RuntimeError("NativePreparationExitedBeforeReady")
            time.sleep(0.2)
        harness.cache_progress(launcher)
        environment.update({key: os.environ[key] for key in ("RUNNER_ENVIRONMENT", "CI_PUBLIC_REPOSITORY", "GITHUB_REPOSITORY", "RUNNER_OS", "RUNNER_ARCH")})
        environment.update({"ONIONDESK_CI_OWNER": harness.owner, "ONIONDESK_CI_PACKAGE_ROOT": str(harness.package)})
        result = subprocess.run([str(probe)], cwd=probe.parent, env=environment, capture_output=True, timeout=30)
        raw = result.stdout.decode("utf-8", errors="replace")
        native.encrypt_browser_diagnostic(RuntimeError(raw + "\n" + result.stderr.decode("utf-8", errors="replace")), "windows_cache_diagnostic")
        captured = True
        if result.returncode or len(result.stdout) > 64 * 1024:
            raise RuntimeError("ProbeExecutionIncomplete")
        harness.facts.update(public_probe_facts(json.loads(raw)))
        if "native_error_code" not in harness.facts or harness.facts["probe_deadline_reached"]:
            raise RuntimeError("ProbeExecutionIncomplete")
        harness.facts.update({"result": "WINDOWS_CACHE_DIAGNOSTIC_ONLY", "probe_diagnostic_complete": True,
                              "browser_diagnostic_encrypted": True})
        harness.save()
        return 0
    except Exception as error:
        if harness and not captured:
            detail = str(error)
            for value in (getattr(error, "stdout", b""), getattr(error, "stderr", b"")):
                if value:
                    detail += "\n" + (value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value)
            try:
                native.encrypt_browser_diagnostic(RuntimeError(detail), "windows_cache_diagnostic")
                harness.facts["browser_diagnostic_encrypted"] = True
            except Exception as diagnostic_error:
                harness.facts["browser_diagnostic_encrypted"] = False
                harness.facts["diagnostic_error_class"] = type(diagnostic_error).__name__
                code = native.trusted_error_facts(diagnostic_error).get("error_code")
                if code:
                    harness.facts["diagnostic_error_code"] = code
        native.record_failure(error, harness)
        return 1
    finally:
        try:
            native.cleanup()
        except Exception as error:
            native.record_failure(error, harness)
            raise
