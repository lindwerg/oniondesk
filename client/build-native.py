#!/usr/bin/env python3
"""Build an ARM64 macOS app with an isolated, relocatable GnuPG verifier.

Run with a build-only Python containing PyInstaller, pywebview, and client
dependencies. The resulting app does not need that Python or Homebrew.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

KIT = Path(__file__).resolve().parent.parent
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")
STAGING_MARKER = ".oniondesk-build-staging"


def owned_workspace(path):
    """A mistyped build path must never delete an unrelated existing directory."""
    if path.is_symlink():
        raise RuntimeError("Папка промежуточной сборки является ссылкой.")
    if path.exists() and any(path.iterdir()):
        marker = path / STAGING_MARKER
        if not marker.is_file() or marker.is_symlink() or marker.read_text() != "OnionDesk build staging v1\n":
            raise RuntimeError("Папка промежуточной сборки уже занята. Выберите новую пустую папку.")
    path.mkdir(parents=True, exist_ok=True)
    (path / STAGING_MARKER).write_text("OnionDesk build staging v1\n")


def run(args, log=None, check=True, timeout=600, env=None):
    result = subprocess.run([str(arg) for arg in args], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=timeout, env=env)
    if log:
        Path(log).write_text(result.stdout)
    if check and result.returncode:
        raise RuntimeError(f"Команда завершилась с кодом {result.returncode}: {args[0]}\n{result.stdout[-3000:]}")
    return result


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def dependencies(path):
    lines = run(["/usr/bin/otool", "-L", path]).stdout.splitlines()[1:]
    return [line.strip().split(" (compatibility version", 1)[0] for line in lines if line.strip()]


def minimum_os(path):
    text = run(["/usr/bin/otool", "-l", path]).stdout
    match = re.search(r"\bminos\s+([0-9.]+)", text)
    if not match:
        match = re.search(r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version ([0-9.]+)", text)
    return tuple(map(int, match[1].split("."))) if match else (11, 0)


def stage_gpg(executable, destination):
    executable = Path(executable).resolve(strict=True)
    if not str(executable).startswith("/opt/homebrew/Cellar/"):
        raise RuntimeError("Для этой ARM-сборки нужен уже установленный Homebrew GnuPG из /opt/homebrew/Cellar.")
    original = {"bin/gpg": executable}
    edges: dict[str, list[tuple[str, str]]] = {}
    pending = [("bin/gpg", executable)]
    packages = {}
    minimum = (11, 0)
    while pending:
        relative, source = pending.pop()
        kind = run(["/usr/bin/file", source]).stdout
        if "arm64" not in kind or "Mach-O" not in kind:
            raise RuntimeError(f"Зависимость не является Mach-O ARM64: {source.name}")
        minimum = max(minimum, minimum_os(source))
        cellar = Path("/opt/homebrew/Cellar")
        parts = source.relative_to(cellar).parts
        package_root = cellar / parts[0] / parts[1]
        packages[(parts[0], parts[1])] = package_root
        edges[relative] = []
        for reference in dependencies(source):
            if reference.startswith(SYSTEM_PREFIXES):
                continue
            dependency = Path(reference)
            if not dependency.is_absolute() or not dependency.exists():
                raise RuntimeError(f"Неподдерживаемая зависимость GnuPG: {reference}")
            dependency = dependency.resolve()
            if dependency == source:
                continue  # dylib's install ID is printed first by otool -L.
            if not str(dependency).startswith("/opt/homebrew/Cellar/"):
                raise RuntimeError(f"Зависимость GnuPG не принадлежит установленному Homebrew: {reference}")
            target = "lib/" + Path(reference).name
            if target in original and original[target] != dependency:
                raise RuntimeError(f"Конфликт имён библиотек: {target}")
            edges[relative].append((reference, target))
            if target not in original:
                original[target] = dependency
                pending.append((target, dependency))
    if destination.exists():
        if destination.is_symlink():
            raise RuntimeError("Папка упаковки GnuPG является ссылкой.")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    (destination / STAGING_MARKER).write_text("OnionDesk build staging v1\n")
    provenance = {"verifier": run([executable, "--version"]).stdout.splitlines()[0],
                  "architecture": "arm64", "minimum_macos": ".".join(map(str, minimum)),
                  "source_packages": [], "binaries": []}
    for (name, version), package_root in sorted(packages.items()):
        license_dir = destination / "licenses" / name
        license_dir.mkdir(parents=True)
        for source in sorted(package_root.iterdir()):
            if source.is_file() and (source.name.startswith(("COPYING", "LICENSE")) or source.name == "AUTHORS"):
                shutil.copy2(source, license_dir / source.name)
        formula = package_root / ".brew" / (name + ".rb")
        formula_text = ""
        if formula.is_file():
            formula_text = formula.read_text()
            shutil.copy2(formula, license_dir / (name + ".rb"))
        provenance["source_packages"].append({"name": name, "version": version,
            "source_urls": re.findall(r'^\s*url "([^"\n]+)"', formula_text, re.MULTILINE),
            "source_sha256": re.findall(r'^\s*sha256 "([a-f0-9]{64})"', formula_text, re.MULTILINE),
            "license": re.findall(r'^\s*license (.+)$', formula_text, re.MULTILINE)})
    for relative, source in sorted(original.items()):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        os.chmod(target, 0o755)
        for reference, target_relative in edges[relative]:
            loader = "@loader_path/../" + target_relative if relative == "bin/gpg" else "@loader_path/" + Path(target_relative).name
            run(["/usr/bin/install_name_tool", "-change", reference, loader, target])
        if relative.startswith("lib/"):
            run(["/usr/bin/install_name_tool", "-id", "@loader_path/" + target.name, target])
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", target])
        if any(not ref.startswith((*SYSTEM_PREFIXES, "@loader_path/")) for ref in dependencies(target)):
            raise RuntimeError(f"После упаковки осталась внешняя зависимость: {relative}")
        provenance["binaries"].append({"path": relative, "source_sha256": digest(source), "bundled_sha256": digest(target)})
    (destination / "SOURCE-PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


def stage_resources(destination):
    if destination.exists():
        if destination.is_symlink():
            raise RuntimeError("Папка ресурсов сборки является ссылкой.")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    records = []
    for folder in ("assets", "client/ui", "server", "frontend", "screenshots/real"):
        base = KIT / folder
        if base.is_symlink() or not base.is_dir():
            raise RuntimeError(f"Папка исходных ресурсов отсутствует или является ссылкой: {folder}")
        for source in sorted(base.rglob("*")):
            relative = source.relative_to(KIT)
            if source.is_symlink():
                raise RuntimeError(f"Неожиданная ссылка в исходных ресурсах: {relative}")
            if not source.is_file() or any(part in {"__pycache__", "data", "node_modules", ".git"} for part in relative.parts) or source.suffix == ".pyc":
                continue
            if any(part.startswith(".") for part in relative.parts) or source.suffix in {".pem", ".key"}:
                raise RuntimeError(f"Неожиданный скрытый файл/ключ среди ресурсов: {relative}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            records.append({"path": str(relative), "sha256": digest(source)})
    return records


def clone_copy(source, destination):
    """Use independent APFS clones where available, never hard links."""
    if platform.system() == "Darwin":
        run(["/bin/cp", "-c", "-p", source, destination])
        return str(destination)
    return shutil.copy2(source, destination)


def stage_embedded_data(destination):
    """Embed only public files pinned by the existing distribution catalogs."""
    import offline_bundle as offline
    import wallet_catalog
    import phone_catalog
    import feather_catalog

    source = KIT / "OnionDesk-Data"
    destination = Path(destination).absolute()
    try:
        offline._check_manifest(source)
        records = {}
        for asset in (*offline.catalog.ASSETS.values(), wallet_catalog.HASHES, wallet_catalog.KEY,
                      *wallet_catalog.PLATFORMS.values(), *phone_catalog.ASSETS.values(), *feather_catalog.ASSETS.values()):
            record = {key: asset[key] for key in ("path", "size_bytes", "sha256")}
            offline._relative_path(record["path"])
            if record["path"] == "manifest.json" or (record["path"] in records and records[record["path"]] != record):
                raise RuntimeError("Каталоги сборки содержат конфликтующие официальные файлы.")
            records[record["path"]] = record
        manifest_size = (source / "manifest.json").lstat().st_size
        with offline._open_regular(source, "manifest.json", manifest_size) as manifest:
            manifest_hash = hashlib.file_digest(manifest, "sha256").hexdigest()
        records["manifest.json"] = {"path": "manifest.json", "size_bytes": manifest_size, "sha256": manifest_hash}
        files = [records[path] for path in sorted(records)]

        def verify(root):
            offline._check_manifest(root)
            for record in files:
                with offline._open_regular(root, record["path"], record["size_bytes"]) as asset:
                    actual = hashlib.file_digest(asset, "sha256").hexdigest()
                if actual != record["sha256"]:
                    raise RuntimeError(f"Контрольная сумма официального файла не совпала: {record['path']}")

        # Check every source before copying any file. The second source pass
        # catches changes during staging; copied files are independently checked.
        verify(source)
        if destination.exists() or destination.is_symlink() or destination.resolve() != destination:
            raise RuntimeError("Папка встроенных файлов уже занята или перенаправлена.")
        destination.mkdir(parents=True)
        for record in files:
            target = destination / record["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            clone_copy(source / record["path"], target)
        verify(destination)
        verify(source)
    except (offline.OfflineError, OSError) as error:
        raise RuntimeError(f"Не удалось встроить официальный комплект: {error}") from error
    return {"location": "Contents/Resources/OnionDesk-Data", "release_id": offline.catalog.RELEASE_ID,
            "file_count": len(files), "total_bytes": sum(record["size_bytes"] for record in files),
            "manifest_sha256": manifest_hash, "files": files, "source_reverified": True,
            "copy_method": "independent APFS clones/copies" if platform.system() == "Darwin" else "independent copies"}


def verify_gpg(gpg, work):
    isolated_env = {key: value for key, value in os.environ.items() if not key.startswith("DYLD_")}
    isolated_env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    version = run([gpg, "--version"], env=isolated_env).stdout.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="oniondesk-gpg-", dir="/private/tmp") as temporary:
        home = Path(temporary)
        message = home / "message.txt"
        message.write_text("OnionDesk native build test fixture\n")
        host = shutil.which("gpg")
        base = [host, "--no-options", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        try:
            run([*base, "--quick-generate-key", "OnionDesk build fixture <build@example.invalid>", "ed25519", "sign", "1d"])
            run([*base, "--detach-sign", message])
            public_key = home / "fixture-public.asc"
            run([*base, "--armor", "--output", public_key, "--export", "build@example.invalid"])
            conf = shutil.which("gpgconf")
            if not conf:
                raise RuntimeError("Для остановки агента искусственного тестового ключа нужен установленный gpgconf.")
            run([conf, "--homedir", home, "--kill", "gpg-agent"])
            verifier_home = home / "verify-only"
            verifier_home.mkdir(mode=0o700)
            verifier = [gpg, "--no-options", "--homedir", verifier_home, "--batch", "--no-tty", "--no-autostart",
                        "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
            run([*verifier, "--import", public_key], log=work / "gpg-public-import.txt", env=isolated_env)
            verify = [*verifier, "--verify", str(message) + ".sig", message]
            run(verify, log=work / "gpg-valid-signature.txt", env=isolated_env)
            message.write_text("Changed controlled test fixture\n")
            invalid = run(verify, log=work / "gpg-invalid-signature.txt", check=False, env=isolated_env)
            if invalid.returncode == 0:
                raise RuntimeError("GnuPG приняла повреждённый тестовый файл.")
        finally:
            conf = shutil.which("gpgconf")
            if conf:
                run([conf, "--homedir", home, "--kill", "gpg-agent"], check=False)
    return {"gpg_version": version, "controlled_signature": "PASS", "modified_fixture_rejected": "PASS",
            "public_verification_without_agent_or_homebrew_path": "PASS"}


def stage_client(destination: Path) -> list[dict[str, str]]:
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for name in ("app.py", "launcher.py", "usb_tails.py", "usb_privileged.py", "offline_bundle.py",
                 "offline_catalog.py", "phone_usb.py", "phone_catalog.py", "wallet_engine.py",
                 "wallet_bundle.py", "wallet_catalog.py", "wallet_security.py", "wallet_vault.py",
                 "wallet_controller.py", "feather_bundle.py", "feather_catalog.py"):
        source = KIT / "client" / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"Missing or linked client source: {name}")
        target = destination / name
        shutil.copy2(source, target)
        if digest(source) != digest(target):
            raise RuntimeError(f"Client source changed during staging: {name}")
        records.append({"path": "client/" + name, "sha256": digest(target)})
    return records


def build(work, tools, provenance, destination=None):
    destination = Path(destination).absolute() if destination is not None else KIT / "OnionDesk.app"
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("Выходной путь приложения уже занят. Выберите новый путь через --output-app; существующее приложение сохранено.")
    resources = work / "resources"
    resources_record = stage_resources(resources)
    source_code = stage_client(resources / "client-source")
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
            "--name", "OnionDesk", "--target-architecture", "arm64", "--codesign-identity", "-",
            "--icon", KIT / "assets/hacker-mark.icns",
            "--osx-bundle-identifier", "local.oniondesk.desktop", "--distpath", work / "dist",
            "--workpath", work / "pyinstaller", "--specpath", work,
            "--paths", KIT / "client", "--collect-data", "webview",
            "--hidden-import", "webview.platforms.cocoa", "--hidden-import", "launcher",
            "--hidden-import", "usb_tails", "--hidden-import", "usb_privileged",
            "--hidden-import", "offline_bundle", "--hidden-import", "offline_catalog",
            "--hidden-import", "phone_usb", "--hidden-import", "phone_catalog",
            "--hidden-import", "feather_bundle", "--hidden-import", "feather_catalog",
            "--hidden-import", "wallet_engine", "--hidden-import", "wallet_bundle", "--hidden-import", "wallet_catalog", "--hidden-import", "wallet_security", "--hidden-import", "wallet_vault", "--hidden-import", "wallet_controller",
            "--hidden-import", "urllib3.contrib.socks", "--add-data", f"{tools}:tools/gpg",
            "--add-data", f"{resources / 'client-source'}:client-source"]
    for folder in ("assets", "client/ui", "server", "frontend", "screenshots/real"):
        args.extend(["--add-data", f"{resources / folder}:{folder}"])
    args.append(KIT / "client/app.py")
    (work / "build-command.json").write_text(json.dumps([str(arg) for arg in args], indent=2) + "\n")
    run(args, log=work / "pyinstaller.log", timeout=1800)
    application = work / "dist/OnionDesk.app"
    contents = application / "Contents"
    # This build includes a Homebrew verifier requiring at least macOS 15.
    info = contents / "Info.plist"
    metadata = plistlib.loads(info.read_bytes())
    metadata["LSMinimumSystemVersion"] = provenance["minimum_macos"]
    metadata["CFBundleDisplayName"] = "OnionDesk"
    metadata["CFBundleShortVersionString"] = "1.0.0"
    metadata["NSHumanReadableCopyright"] = "OnionDesk. Bundled component licenses: Contents/Resources/tools/gpg/licenses."
    info.write_bytes(plistlib.dumps(metadata))
    gpg = contents / "Frameworks/tools/gpg/bin/gpg"
    if not gpg.is_file() or not gpg.resolve().is_relative_to((contents / "Frameworks").resolve()):
        raise RuntimeError("GnuPG отсутствует в настоящей папке Frameworks/tools/gpg/bin.")
    # PyInstaller can normalize nested Mach-O load commands to @rpath. Restore
    # the prepared verifier's explicit loader-relative graph after collection.
    for record in provenance["binaries"]:
        target = contents / "Frameworks/tools/gpg" / record["path"]
        if target.is_symlink() or not target.is_file():
            raise RuntimeError(f"Путь бинарного проверяющего модуля неожиданный: {record['path']}")
        shutil.copy2(tools / record["path"], target)
    embedded_data = stage_embedded_data(contents / "Resources/OnionDesk-Data")
    run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", application], log=work / "codesign.txt")
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", application], log=work / "codesign-verify.txt")
    evidence = verify_gpg(gpg, work)
    binary = contents / "MacOS/OnionDesk"
    helper = run([binary, "--usb-privileged", "/nonexistent/oniondesk-build-test/request.json"], check=False, timeout=30)
    if helper.returncode != 1:
        raise RuntimeError("Frozen helper не завершился безопасно на несуществующем запросе.")
    forbidden: list[tuple[str, str]] = []
    for path in contents.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        with open(path, "rb") as source:
            magic = source.read(4)
        if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
            own_ids = run(["/usr/bin/otool", "-D", path]).stdout.splitlines()[1:]
            forbidden.extend((str(path.relative_to(application)), ref) for ref in dependencies(path)
                             if ref.startswith("/") and not ref.startswith(SYSTEM_PREFIXES) and ref not in own_ids)
    if forbidden:
        raise RuntimeError(f"В приложении остались зависимости компьютера сборки: {forbidden[:5]}")
    shutil.copytree(application, destination, symlinks=True, copy_function=clone_copy)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", destination])
    evidence.update({"architecture": "arm64", "minimum_macos": provenance["minimum_macos"],
                     "helper_invalid_request_exit": helper.returncode, "codesign": "ad-hoc; strict verification PASS",
                     "notarized": False, "external_build_library_dependencies": [], "gui_opened": False,
                     "embedded_data": embedded_data,
                     "resources": resources_record,
                     "source_code": source_code,
                     "runtime": {name: importlib.metadata.version(name) for name in ("PyInstaller", "pywebview", "paramiko", "requests")}})
    evidence_path = work / "evidence.json"
    if evidence_path.exists():
        previous = json.loads(evidence_path.read_text())
        if "native_ui_checks" in previous:
            evidence["native_ui_checks"] = previous["native_ui_checks"]
            evidence["native_ui_checks_historical"] = True
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    return destination


def main():
    parser = argparse.ArgumentParser(description="Создать OnionDesk.app для Mac Apple Silicon")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, required=True)
    parser.add_argument("--gpg", type=Path, default=Path("/opt/homebrew/bin/gpg"))
    parser.add_argument("--output-app", type=Path, help="Новый незанятый путь итогового OnionDesk.app")
    parser.add_argument("--prepare-only", action="store_true")
    options = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Самостоятельная сборка этого комплекта поддерживается только на macOS ARM64.")
    work, tools = options.work_dir.resolve(), options.tools_dir.resolve()
    for path in (work, tools):
        if path in {Path("/"), KIT, KIT / "client", Path.home()} or KIT.is_relative_to(path):
            raise SystemExit("Папки промежуточной сборки должны быть отдельными от исходного комплекта.")
    owned_workspace(work)
    owned_workspace(tools)
    provenance = stage_gpg(options.gpg, tools)
    if options.prepare_only:
        result = verify_gpg(tools / "bin/gpg", work)
        (work / "prepare-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
        print("GnuPG подготовлена и проверена. Самостоятельное приложение ещё не собрано.")
        return
    destination = build(work, tools, provenance, options.output_app)
    print(f"Готово: {destination}\nПодписано локально (ad-hoc); notarization не выполнялась.")


if __name__ == "__main__":
    main()
