#!/usr/bin/env python3
"""Build the Windows x64 application using Windows Python/PyInstaller.

The build runtime is separate from the resulting executable. Wine is usable for
packaging and limited smoke tests; a real Windows test is still required.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

KIT = Path(__file__).resolve().parent.parent
MARKER = ".oniondesk-windows-build"
RESOURCE_DIRS = ("assets", "client/ui", "server", "frontend", "screenshots/real")


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def workspace(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("Папка сборки не должна быть ссылкой.")
    marker = path / MARKER
    if path.exists() and any(path.iterdir()):
        if not marker.is_file() or marker.is_symlink() or marker.read_text() != "OnionDesk Windows build v1\n":
            raise RuntimeError("Для сборки нужна новая пустая папка или предыдущая папка OnionDesk Windows build.")
    path.mkdir(parents=True, exist_ok=True)
    marker.write_text("OnionDesk Windows build v1\n")


def stage_resources(destination: Path) -> list[dict]:
    if destination.exists():
        if destination.is_symlink():
            raise RuntimeError("Папка ресурсов является ссылкой.")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    records = []
    for folder in RESOURCE_DIRS:
        base = KIT / folder
        if base.is_symlink() or not base.is_dir():
            raise RuntimeError(f"Отсутствует обычная папка ресурсов: {folder}")
        for source in sorted(base.rglob("*")):
            relative = source.relative_to(KIT)
            if source.is_symlink():
                raise RuntimeError(f"Ссылка среди ресурсов запрещена: {relative}")
            if not source.is_file() or any(part in {"__pycache__", "data", "node_modules", ".git"} for part in relative.parts) or source.suffix == ".pyc":
                continue
            if any(part.startswith(".") for part in relative.parts) or source.suffix in {".pem", ".key"}:
                raise RuntimeError(f"Неожиданный скрытый файл или ключ среди ресурсов: {relative}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            records.append({"path": relative.as_posix(), "sha256": sha256(source)})
    return records


def verify_pe(path: Path) -> dict:
    with path.open("rb") as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise RuntimeError("Собранный файл не является Windows PE.")
        source.seek(struct.unpack_from("<I", header, 60)[0])
        pe = source.read(26)
    if len(pe) != 26 or pe[:4] != b"PE\0\0" or struct.unpack_from("<H", pe, 4)[0] != 0x8664 or struct.unpack_from("<H", pe, 24)[0] != 0x20B:
        raise RuntimeError("Собранный файл не является Windows x64 PE32+.")
    return {"format": "PE32+", "machine": "AMD64", "bytes": path.stat().st_size, "sha256": sha256(path)}


def build(work: Path, output: Path) -> dict:
    workspace(work)
    resources = work / "resources"
    records = stage_resources(resources)
    # A USB helper elevates this executable. Keep its DLLs in the protected
    # installation instead of extracting a one-file application into TEMP.
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
            "--name", "OnionDesk", "--distpath", str(work / "dist"), "--workpath", str(work / "pyinstaller"),
            "--icon", str(KIT / "assets/hacker-mark.ico"),
            "--specpath", str(work), "--paths", str(KIT / "client"), "--exclude-module", "webview",
            "--hidden-import", "launcher", "--hidden-import", "usb_tails", "--hidden-import", "usb_privileged",
            "--hidden-import", "offline_bundle", "--hidden-import", "offline_catalog",
            "--hidden-import", "phone_usb", "--hidden-import", "phone_catalog",
            "--hidden-import", "feather_bundle", "--hidden-import", "feather_catalog",
            "--hidden-import", "wallet_engine", "--hidden-import", "wallet_bundle", "--hidden-import", "wallet_catalog", "--hidden-import", "wallet_security", "--hidden-import", "wallet_vault", "--hidden-import", "wallet_controller",
            "--hidden-import", "urllib3.contrib.socks"]
    for folder in RESOURCE_DIRS:
        args.extend(["--add-data", f"{resources / folder}:{folder}"])
    args.append(str(KIT / "client/app.py"))
    (work / "build-command.json").write_text(json.dumps(args, indent=2) + "\n", encoding="utf-8")
    with (work / "pyinstaller.log").open("w", encoding="utf-8") as log:
        subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
    application = work / "dist/OnionDesk"
    executable = application / "OnionDesk.exe"
    result = verify_pe(executable)
    output.mkdir(parents=True, exist_ok=True)
    published = output / "OnionDesk"
    if published.exists() or published.is_symlink():
        if published.is_symlink() or not published.is_dir() or not (published / MARKER).is_file() or (published / MARKER).is_symlink() or (published / MARKER).read_text() != "OnionDesk Windows build v1\n":
            raise RuntimeError("Папка готового приложения уже занята чужими файлами.")
        shutil.rmtree(published)
    shutil.copytree(application, published)
    (published / MARKER).write_text("OnionDesk Windows build v1\n")
    result.update({"python": platform.python_version(), "pyinstaller": importlib.metadata.version("pyinstaller"),
                   "resources": records, "source_code": [{"path": "client/" + name, "sha256": sha256(KIT / "client" / name)}
                       for name in ("app.py", "launcher.py", "usb_tails.py", "usb_privileged.py", "offline_bundle.py", "offline_catalog.py", "phone_usb.py", "phone_catalog.py", "wallet_engine.py", "wallet_bundle.py", "wallet_catalog.py", "wallet_security.py", "wallet_vault.py", "wallet_controller.py", "feather_bundle.py", "feather_catalog.py")],
                   "interface": "default local browser", "bundle_mode": "onedir; installed under protected Program Files",
                   "code_signed": False, "real_windows_test": "not performed"})
    (work / "build-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Собрать самостоятельное приложение Windows x64")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=KIT / "Windows")
    options = parser.parse_args()
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        parser.error("Нужен Windows Python x64 (можно в изолированном Wine для сборки).")
    result = build(options.work_dir.resolve(), options.output_dir.resolve())
    print(json.dumps({key: value for key, value in result.items() if key not in {"resources", "source_code"}}, indent=2))


if __name__ == "__main__":
    main()
