#!/usr/bin/env python3
"""Build the portable Linux directory, including Python, dependencies and GPG.

Run build-linux.sh from a development machine with Docker. No build tools are
needed on the destination computer. Build and test each architecture on Linux.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

KIT = Path(__file__).resolve().parents[1]
MARKER = ".oniondesk-linux-build"
MARKER_TEXT = "OnionDesk Linux build staging v1\n"
GLIBC = re.compile(r"(?:ld-linux[^/]*|lib(?:c|m|pthread|dl|rt|util|resolv)\.so(?:\..*)?)$")


def run(args, *, log=None, timeout=900, env=None, check=True):
    result = subprocess.run([str(arg) for arg in args], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=timeout, env=env)
    if log:
        Path(log).write_text(result.stdout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}\n{result.stdout[-4000:]}")
    return result


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def workspace(path):
    if path.is_symlink():
        raise RuntimeError("Build staging directory must not be a symlink.")
    if path.exists() and any(path.iterdir()):
        marker = path / MARKER
        if marker.is_symlink() or not marker.is_file() or marker.read_text() != MARKER_TEXT:
            raise RuntimeError("Build staging directory is not owned by this builder.")
    path.mkdir(parents=True, exist_ok=True)
    (path / MARKER).write_text(MARKER_TEXT)


def stage_resources(destination):
    records = []
    for folder in ("assets", "client/ui", "server", "frontend", "screenshots/real"):
        base = KIT / folder
        if not base.is_dir() or base.is_symlink():
            raise RuntimeError(f"Missing or linked resource directory: {folder}")
        for source in sorted(base.rglob("*")):
            relative = source.relative_to(KIT)
            if source.is_symlink():
                raise RuntimeError(f"Linked resource: {relative}")
            if not source.is_file() or any(part in {"__pycache__", "data", ".git", "node_modules"} for part in relative.parts) or source.suffix == ".pyc":
                continue
            if any(part.startswith(".") for part in relative.parts) or source.suffix in {".key", ".pem"}:
                raise RuntimeError(f"Unexpected key or hidden resource: {relative}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            records.append({"path": str(relative), "sha256": digest(source)})
    return records


def stage_client(destination):
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for name in ("app.py", "launcher.py", "usb_tails.py", "usb_privileged.py", "offline_bundle.py", "offline_catalog.py", "phone_usb.py", "phone_catalog.py", "wallet_engine.py", "wallet_bundle.py", "wallet_catalog.py", "wallet_security.py", "wallet_vault.py", "wallet_controller.py", "feather_bundle.py", "feather_catalog.py"):
        source = KIT / "client" / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"Missing or linked client source: {name}")
        target = destination / name
        shutil.copy2(source, target)
        records.append({"path": "client/" + name, "sha256": digest(target)})
    return records


def linked_libraries(path):
    output = run(["ldd", path]).stdout
    if "not found" in output:
        raise RuntimeError(f"Unresolved library for {path}: {output}")
    libraries = []
    for line in output.splitlines():
        match = re.search(r"=>\s+(/\S+)|^\s*(/\S+)", line)
        if match:
            reference = Path(match[1] or match[2])
            if not GLIBC.fullmatch(reference.name):
                libraries.append(reference)
    return libraries


def package_for(path):
    # Debian may record a /lib path even when realpath is under /usr/lib.
    candidates = [str(path)]
    if str(path).startswith("/usr/lib/"):
        candidates.append(str(path).removeprefix("/usr"))
    for candidate in candidates:
        result = run(["dpkg-query", "-S", candidate], check=False)
        if result.returncode == 0:
            return result.stdout.split(": ", 1)[0]
    raise RuntimeError(f"No Debian package owns {path}")


def stage_gpg(destination):
    gpg = Path(shutil.which("gpg") or "").resolve(strict=True)
    sources = {"bin/gpg": gpg}
    pending = [gpg]
    while pending:
        for dependency in linked_libraries(pending.pop()):
            key = "lib/" + dependency.name
            resolved = dependency.resolve(strict=True)
            if key in sources and sources[key] != resolved:
                raise RuntimeError(f"Conflicting GPG libraries: {key}")
            if key not in sources:
                sources[key] = resolved
                pending.append(resolved)
    provenance = {"version": run([gpg, "--version"]).stdout.splitlines()[0],
                  "libraries": [], "source_packages": []}
    packages = set()
    for relative, source in sorted(sources.items()):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o755)
        # DT_RPATH takes precedence over a PyInstaller child LD_LIBRARY_PATH.
        # Every copied DSO also receives its own path for transitive libraries.
        rpath = "$ORIGIN/../lib" if relative == "bin/gpg" else "$ORIGIN"
        run(["patchelf", "--force-rpath", "--set-rpath", rpath, target])
        provenance["libraries"].append({"path": relative, "original_sha256": digest(source),
                                        "bundled_sha256": digest(target)})
        packages.add(package_for(source))
    for package in sorted(packages):
        data = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}", package]).stdout.split("\t")
        name, version, source_name, source_version = data
        plain_name = name.split(":")[0]
        copyright_file = Path("/usr/share/doc") / plain_name / "copyright"
        if not copyright_file.is_file():
            raise RuntimeError(f"Missing package copyright: {plain_name}")
        target = destination / "licenses" / plain_name
        target.mkdir(parents=True)
        shutil.copy2(copyright_file, target / "copyright")
        provenance["source_packages"].append({"binary": name, "version": version,
            "source": source_name, "source_version": source_version,
            "source_url": f"https://sources.debian.org/src/{source_name}/{source_version}/"})
    # Debian copyright files refer to these complete standard license texts.
    standard = destination / "licenses" / "common-licenses"
    shutil.copytree("/usr/share/common-licenses", standard)
    (destination / "SOURCE-PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


def verify_gpg(gpg, work):
    with tempfile.TemporaryDirectory(prefix="oniondesk-signature-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        payload = home / "controlled.txt"
        payload.write_text("OnionDesk controlled Linux verifier fixture\n")
        signing = ["/usr/bin/gpg", "--no-options", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        try:
            run([*signing, "--quick-generate-key", "OnionDesk Linux fixture <test@example.invalid>", "ed25519", "sign", "1d"])
            run([*signing, "--detach-sign", payload])
            key = home / "public.asc"
            run([*signing, "--armor", "--output", key, "--export", "test@example.invalid"])
            fixture = work / "signature-fixture"
            fixture.mkdir(exist_ok=True)
            for source in (payload, Path(str(payload) + ".sig"), key):
                shutil.copy2(source, fixture / source.name)
            verify_home = home / "verify"
            verify_home.mkdir(mode=0o700)
            isolated = {"PATH": "/nonexistent", "LANG": "C.UTF-8", "HOME": str(verify_home)}
            verifier = [gpg, "--no-options", "--homedir", verify_home, "--batch", "--no-tty", "--no-autostart", "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
            run([*verifier, "--import", key], log=work / "gpg-import.log", env=isolated)
            run([*verifier, "--verify", str(payload) + ".sig", payload], log=work / "gpg-valid.log", env=isolated)
            payload.write_text("Deliberately changed controlled fixture\n")
            bad = run([*verifier, "--verify", str(payload) + ".sig", payload], log=work / "gpg-invalid.log", env=isolated, check=False)
            if bad.returncode == 0 or "BAD signature" not in bad.stdout:
                raise RuntimeError("Bundled GPG accepted a changed fixture or failed unexpectedly.")
        finally:
            run(["/usr/bin/gpgconf", "--homedir", home, "--kill", "gpg-agent"], check=False)
    return {"valid_signature": "PASS", "modified_fixture_rejected": "PASS", "system_gpg_path": "unavailable"}


def stage_python_licenses(destination):
    records = []
    for distribution in importlib.metadata.distributions():
        for entry in distribution.files or ():
            if not any(part.upper().startswith(("LICENSE", "COPYING", "NOTICE")) for part in entry.parts):
                continue
            source = Path(distribution.locate_file(entry))
            if not source.is_file():
                continue
            target = destination / distribution.metadata["Name"] / str(entry).replace("../", "")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        records.append({"name": distribution.metadata["Name"], "version": distribution.version})
    python_license = Path(sys.base_prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "LICENSE.txt"
    if not python_license.is_file():
        raise RuntimeError("Build Python license file is missing.")
    shutil.copy2(python_license, destination / "Python-LICENSE.txt")
    return sorted(records, key=lambda item: item["name"].lower())


def audit_elf(application, architecture):
    expected_machine = {"x86_64": 62, "aarch64": 183}[architecture]
    baseline = tuple(map(int, platform.libc_ver()[1].split(".")))
    records = []
    for path in sorted(application.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as source:
            header = source.read(20)
        if not header.startswith(b"\x7fELF"):
            continue
        if header[4:6] != b"\x02\x01" or struct.unpack_from("<H", header, 18)[0] != expected_machine:
            raise RuntimeError(f"Wrong bundled ELF architecture: {path}")
        versions = [tuple(map(int, value.split("."))) for value in
                    re.findall(r"\bGLIBC_([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", run(["readelf", "--version-info", path]).stdout)]
        minimum = max(versions, default=(0, 0))
        if minimum > baseline:
            raise RuntimeError(f"Bundled ELF requires newer glibc than the build baseline: {path}")
        records.append({"path": str(path.relative_to(application)), "architecture": architecture,
                        "glibc_required": ".".join(map(str, minimum)), "sha256": digest(path)})
    if not records:
        raise RuntimeError("No ELF executable found in the application.")
    return records


def stage_debian_licenses(destination):
    # Python's extension modules also collect Debian libraries such as OpenSSL,
    # libffi and liblzma. Preserve every build image copyright file so none of
    # these redistribution notices are lost, including transitive libraries.
    for package in sorted(Path("/usr/share/doc").iterdir()):
        source = package / "copyright"
        if source.is_file():
            target = destination / package.name
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target / "copyright")
    shutil.copytree("/usr/share/common-licenses", destination / "common-licenses")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
    options = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != options.architecture:
        raise RuntimeError("Build must run on Linux of the requested architecture.")
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11+ is required on the build machine.")
    work = options.work.absolute()
    workspace(work)
    # Only descendants of this explicitly marked build directory are replaced.
    for name in ("resources", "tools", "dist", "pyinstaller"):
        target = work / name
        if target.is_symlink():
            raise RuntimeError("Build output descendant must not be a symlink.")
        if target.exists():
            shutil.rmtree(target)
    resources = stage_resources(work / "resources")
    client_sources = stage_client(work / "resources/client-source")
    gpg_record = stage_gpg(work / "tools/gpg")
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
            "--name", "OnionDesk", "--distpath", work / "dist", "--workpath", work / "pyinstaller",
            "--specpath", work, "--paths", work / "resources/client-source", "--hidden-import", "usb_privileged",
            "--hidden-import", "usb_tails", "--hidden-import", "launcher", "--hidden-import", "urllib3.contrib.socks",
            "--hidden-import", "offline_bundle", "--hidden-import", "offline_catalog",
            "--hidden-import", "phone_usb", "--hidden-import", "phone_catalog",
            "--hidden-import", "feather_bundle", "--hidden-import", "feather_catalog",
            "--hidden-import", "wallet_engine", "--hidden-import", "wallet_bundle", "--hidden-import", "wallet_catalog", "--hidden-import", "wallet_security", "--hidden-import", "wallet_vault", "--hidden-import", "wallet_controller",
            "--exclude-module", "webview", "--add-data", f"{work / 'tools/gpg'}:tools/gpg"]
    for folder in ("assets", "client/ui", "server", "frontend", "screenshots/real"):
        args.extend(["--add-data", f"{work / 'resources' / folder}:{folder}"])
    args.append(work / "resources/client-source/app.py")
    (work / "build-command.json").write_text(json.dumps([str(arg) for arg in args], indent=2) + "\n")
    run(args, log=work / "pyinstaller.log", timeout=1800)
    app = work / "dist/OnionDesk"
    # DATA entries have portable contents but PyInstaller need not retain +x.
    for binary in (app / "_internal/tools/gpg/bin/gpg", *(app / "_internal/tools/gpg/lib").iterdir()):
        binary.chmod(0o755)
    verifier_result = verify_gpg(app / "_internal/tools/gpg/bin/gpg", work)
    license_packages = stage_python_licenses(app / "licenses/python")
    stage_debian_licenses(app / "licenses/debian")
    shutil.copy2(KIT / "client/resources/README-LINUX.md", app / "README-LINUX.md")
    elf_record = audit_elf(app, options.architecture)
    record = {"architecture": platform.machine(), "os": platform.freedesktop_os_release(),
              "glibc": platform.libc_ver(), "python": platform.python_version(),
              "packages": {name: importlib.metadata.version(name) for name in ("PyInstaller", "paramiko", "requests", "cryptography", "certifi", "PySocks")},
              "format": "ELF directory; ordinary browser UI", "gpg": gpg_record,
              "gpg_verification": verifier_result, "resources": resources, "client_sources": client_sources}
    record["build_environment_packages"] = license_packages
    record["elf_audit"] = elf_record
    (app / "BUILD-PROVENANCE.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    destination = KIT / "Linux" / options.architecture / "OnionDesk"
    if destination.exists():
        old = destination / "BUILD-PROVENANCE.json"
        if destination.is_symlink() or not old.is_file() or json.loads(old.read_text()).get("architecture") != options.architecture:
            raise RuntimeError("Refusing to replace an unrecognized existing application directory.")
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(app, destination, symlinks=True)
    archive = KIT / "Linux" / f"OnionDesk-Linux-{options.architecture}.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=6) as output:
        output.add(destination, arcname="OnionDesk")
    (work / "build-result.json").write_text(json.dumps({"executable": str(destination / "OnionDesk"),
        "sha256": digest(destination / "OnionDesk"), "archive": str(archive), "archive_sha256": digest(archive),
        "gpg_verification": verifier_result}, indent=2) + "\n")
    print(json.dumps({"archive": str(archive), "size_bytes": archive.stat().st_size, "gpg": verifier_result}))


if __name__ == "__main__":
    main()
