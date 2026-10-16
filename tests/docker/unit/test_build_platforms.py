"""Build-command smoke checks use synthetic files and never run a built app."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

CLIENT = Path(__file__).resolve().parents[3] / "client"
SOURCES = {"app.py", "launcher.py", "usb_tails.py", "usb_privileged.py", "offline_bundle.py",
           "offline_catalog.py", "phone_usb.py", "phone_catalog.py", "wallet_engine.py",
           "wallet_bundle.py", "wallet_catalog.py", "wallet_security.py", "wallet_vault.py",
           "wallet_controller.py", "feather_bundle.py", "feather_catalog.py"}


def builder(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), CLIENT / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load platform builder: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PlatformBuildIntegration(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.kit = self.base / "kit"
        (self.kit / "client").mkdir(parents=True)
        for name in SOURCES:
            (self.kit / "client" / name).write_text(f"# synthetic {name}\n")

    def assert_phone_imports(self, command):
        imports = {command[index + 1] for index, arg in enumerate(command[:-1]) if arg == "--hidden-import"}
        self.assertTrue({"phone_usb", "phone_catalog", "feather_bundle", "feather_catalog"} <= imports)

    def test_linux_stages_all_sources_and_phone_imports_before_pyinstaller(self):
        linux = builder("build-linux")
        work = self.base / "build"

        class ReachedPyInstaller(Exception):
            pass

        def stop_before_build(command, **kwargs):
            self.assertIn("PyInstaller", command)
            raise ReachedPyInstaller

        with patch.object(linux, "KIT", self.kit), \
                patch.object(linux.platform, "system", return_value="Linux"), \
                patch.object(linux.platform, "machine", return_value="x86_64"), \
                patch.object(linux, "stage_resources", return_value=[]), \
                patch.object(linux, "stage_gpg", return_value={}), \
                patch.object(linux, "run", side_effect=stop_before_build), \
                patch("sys.argv", ["build-linux", "--work", str(work), "--architecture", "x86_64"]):
            with self.assertRaises(ReachedPyInstaller):
                linux.main()
            records = linux.stage_client(self.base / "second-source-copy")
        self.assertEqual({record["path"] for record in records}, {"client/" + name for name in SOURCES})
        for record in records:
            self.assertEqual(record["sha256"], hashlib.sha256((self.kit / record["path"]).read_bytes()).hexdigest())
        self.assertEqual({path.name for path in (work / "resources/client-source").iterdir()}, SOURCES)
        self.assert_phone_imports(json.loads((work / "build-command.json").read_text()))
        self.assertFalse((self.kit / "Linux").exists())

    def test_windows_offline_imports_icon_and_all_source_hashes(self):
        windows = builder("build-windows")
        work, output = self.base / "build", self.base / "output"

        def synthetic_pyinstaller(command, **kwargs):
            self.assertIn("PyInstaller", command)
            executable = work / "dist/OnionDesk/OnionDesk.exe"
            executable.parent.mkdir(parents=True)
            header = bytearray(128)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 60, 64)
            header[64:68] = b"PE\0\0"
            struct.pack_into("<H", header, 68, 0x8664)
            struct.pack_into("<H", header, 88, 0x20B)
            executable.write_bytes(header)

        with patch.object(windows, "KIT", self.kit), \
                patch.object(windows, "stage_resources", return_value=[]), \
                patch.object(windows.subprocess, "run", side_effect=synthetic_pyinstaller), \
                patch.object(windows.importlib.metadata, "version", return_value="synthetic"):
            report = windows.build(work, output)
        command = json.loads((work / "build-command.json").read_text())
        self.assert_phone_imports(command)
        self.assertEqual(command[command.index("--icon") + 1], str(self.kit / "assets/hacker-mark.ico"))
        self.assertEqual({record["path"] for record in report["source_code"]}, {"client/" + name for name in SOURCES})
        for record in report["source_code"]:
            self.assertEqual(record["sha256"], hashlib.sha256((self.kit / record["path"]).read_bytes()).hexdigest())
        self.assertEqual(report["format"], "PE32+")
        self.assertTrue((output / "OnionDesk/OnionDesk.exe").is_file())

    def test_linux_clean_checkout_copies_tracked_runtime_readme_into_archive(self) -> None:
        linux = builder("build-linux")
        work = self.base / "build"
        readme = CLIENT / "resources/README-LINUX.md"
        target_readme = self.kit / "client/resources/README-LINUX.md"
        target_readme.parent.mkdir()
        target_readme.write_bytes(readme.read_bytes())
        self.assertFalse((self.kit / "Linux").exists())

        def synthetic_pyinstaller(command, **_kwargs):
            self.assertIn("PyInstaller", command)
            bundle = work / "dist/OnionDesk"
            (bundle / "_internal/tools/gpg/bin").mkdir(parents=True)
            (bundle / "_internal/tools/gpg/lib").mkdir()
            (bundle / "OnionDesk").write_bytes(b"TEST ONLY synthetic ELF; never executed")
            (bundle / "_internal/tools/gpg/bin/gpg").write_bytes(b"TEST ONLY synthetic verifier")
            (bundle / "_internal/tools/gpg/lib/libfixture.so").write_bytes(b"TEST ONLY synthetic library")

        with patch.object(linux, "KIT", self.kit), \
                patch.object(linux.platform, "system", return_value="Linux"), \
                patch.object(linux.platform, "machine", return_value="x86_64"), \
                patch.object(linux.platform, "freedesktop_os_release", return_value={"ID": "synthetic"}), \
                patch.object(linux, "stage_resources", return_value=[]), \
                patch.object(linux, "stage_gpg", return_value={}), \
                patch.object(linux, "verify_gpg", return_value={"synthetic": True}), \
                patch.object(linux, "stage_python_licenses", return_value=[]), \
                patch.object(linux, "stage_debian_licenses"), \
                patch.object(linux, "audit_elf", return_value={"synthetic": True}), \
                patch.object(linux.importlib.metadata, "version", return_value="synthetic"), \
                patch.object(linux, "run", side_effect=synthetic_pyinstaller), \
                patch("sys.argv", ["build-linux", "--work", str(work), "--architecture", "x86_64"]), \
                redirect_stdout(io.StringIO()):
            linux.main()
        destination = self.kit / "Linux/x86_64/OnionDesk"
        self.assertEqual((destination / "README-LINUX.md").read_bytes(), readme.read_bytes())
        with tarfile.open(self.kit / "Linux/OnionDesk-Linux-x86_64.tar.gz", "r:gz") as archive:
            packed_readme = archive.extractfile("OnionDesk/README-LINUX.md")
            self.assertIsNotNone(packed_readme)
            assert packed_readme is not None
            self.assertEqual(packed_readme.read(), readme.read_bytes())
            self.assertIn("OnionDesk/OnionDesk", archive.getnames())
        self.assertTrue((work / "build-result.json").is_file())


if __name__ == "__main__":
    unittest.main()
