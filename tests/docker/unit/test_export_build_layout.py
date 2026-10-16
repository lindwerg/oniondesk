"""Check a clean checkout's build paths without Docker, network, or an app."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


CLIENT = Path(__file__).resolve().parents[3] / "client"
SHELL = shutil.which("sh")


@unittest.skipUnless(SHELL, "The Linux wrapper requires a POSIX shell")
class ExportedLinuxBuildLayout(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.checkout = self.base / "clean checkout"
        self.client = self.checkout / "client"
        self.client.mkdir(parents=True)
        for name in ("build-linux.sh", "build-linux.Dockerfile", "build-linux.py",
                     "build-linux-requirements.txt"):
            shutil.copyfile(CLIENT / name, self.client / name)
        self.caller = self.base / "unrelated caller"
        self.caller.mkdir()
        self.log = self.base / "docker-calls.jsonl"
        fake_bin = self.base / "fake-bin"
        fake_bin.mkdir()
        recorder = fake_bin / "record.py"
        recorder.write_text(
            "import json, os, sys\n"
            "with open(os.environ['ONIONDESK_TEST_DOCKER_LOG'], 'a') as output:\n"
            "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1] == os.environ.get('ONIONDESK_TEST_DOCKER_FAIL'):\n"
            "    sys.exit(17)\n",
            encoding="utf-8",
        )
        docker = fake_bin / "docker"
        docker.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(recorder))} \"$@\"\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.defpath,
            "ONIONDESK_TEST_DOCKER_LOG": str(self.log),
        }
        self.environment.pop("ONIONDESK_BUILD_ROOT", None)
        self.environment.pop("ONIONDESK_TEST_DOCKER_FAIL", None)

    def run_wrapper(self, *arguments, build_root=None, fail=None):
        environment = dict(self.environment)
        if build_root is not None:
            environment["ONIONDESK_BUILD_ROOT"] = str(build_root)
        if fail is not None:
            environment["ONIONDESK_TEST_DOCKER_FAIL"] = fail
        return subprocess.run(
            [SHELL, str(self.client / "build-linux.sh"), *arguments],
            cwd=self.caller, env=environment, capture_output=True, text=True,
            timeout=10, check=False,
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def assert_build_layout(self, result, architecture, platform, work):
        self.assertEqual(result.returncode, 0, result.stderr)
        build, run = self.calls()
        image = f"oniondesk-linux-builder:{architecture}"
        self.assertEqual(build, [
            "build", "--platform", platform, "--tag", image,
            "--file", str(self.client / "build-linux.Dockerfile"), str(self.client),
        ])
        self.assertEqual(run, [
            "run", "--rm", "--platform", platform,
            "--name", f"oniondesk-linux-build-{architecture}",
            "--mount", f"type=bind,src={self.checkout},dst=/workspace",
            "--mount", f"type=bind,src={work},dst=/buildwork",
            image, "--architecture", architecture, "--work", "/buildwork",
        ])
        self.assertTrue(work.is_dir())
        self.assertFalse(work.is_relative_to(self.checkout))
        self.assertFalse((self.base / "outputs").exists())

    def test_default_checkout_and_work_paths_are_independent_of_caller(self):
        work = Path(str(self.checkout) + "-build") / "linux/x86_64"
        self.assert_build_layout(self.run_wrapper(), "x86_64", "linux/amd64", work)

    def test_arm64_and_explicit_build_root_with_spaces(self):
        root = self.base / "separate build root"
        self.assert_build_layout(
            self.run_wrapper("aarch64", build_root=root),
            "aarch64", "linux/arm64", root / "aarch64",
        )

    def test_relative_build_root_is_resolved_from_caller(self):
        self.assert_build_layout(
            self.run_wrapper("x86_64", build_root="relative build"),
            "x86_64", "linux/amd64", self.caller / "relative build/x86_64",
        )

    def test_unsupported_architecture_stops_before_docker_or_work_creation(self):
        root = self.base / "unused build root"
        result = self.run_wrapper("sparc", build_root=root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Architecture must be", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(root.exists())

    def test_failed_image_build_never_starts_container(self):
        result = self.run_wrapper(fail="build")
        self.assertEqual(result.returncode, 17)
        self.assertEqual([call[0] for call in self.calls()], ["build"])

    def test_linked_work_directory_is_rejected_before_docker(self):
        root = self.base / "build root"
        root.mkdir()
        target = self.base / "unrelated data"
        target.mkdir()
        keep = target / "keep"
        keep.write_text("preserve me")
        (root / "x86_64").symlink_to(target, target_is_directory=True)
        result = self.run_wrapper(build_root=root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not be a symlink", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(keep.read_text(), "preserve me")


class LinuxDockerSourceContract(unittest.TestCase):
    def test_entrypoint_resolves_inside_the_checkout_mount(self):
        lines = (CLIENT / "build-linux.Dockerfile").read_text().splitlines()
        entrypoints = [line.removeprefix("ENTRYPOINT ") for line in lines
                       if line.startswith("ENTRYPOINT ")]
        self.assertEqual(len(entrypoints), 1)
        entrypoint = json.loads(entrypoints[0])
        self.assertEqual(entrypoint, ["python", "/workspace/client/build-linux.py"])
        relative = Path(entrypoint[1]).relative_to("/workspace")
        self.assertTrue((CLIENT.parent / relative).is_file())
        self.assertIn("WORKDIR /workspace", lines)
        self.assertIn("COPY build-linux-requirements.txt /build-requirements.txt", lines)
        self.assertFalse(any("outputs/remote-desktop-kit" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
