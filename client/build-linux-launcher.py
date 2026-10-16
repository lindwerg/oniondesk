#!/usr/bin/env python3
"""Compile a static Linux launcher; run with a native or explicit cross compiler."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess

SOURCE = Path(__file__).with_suffix('.c')
ARCHITECTURES = {'x86_64': ('OnionDesk-Linux-x64', 62), 'aarch64': ('OnionDesk-Linux-ARM64', 183)}


def build(architecture: str, output: Path, compiler: str = 'cc') -> dict:
    name, machine = ARCHITECTURES[architecture]
    output.mkdir(parents=True, exist_ok=True)
    target = output / name
    command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-Wl,--build-id=none',
               f'-DONIONDESK_ARCH="{architecture}"', str(SOURCE), '-o', str(target)]
    subprocess.run(command, check=True, timeout=120)
    header = target.read_bytes()[:20]
    if header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != machine:
        raise RuntimeError('The compiler produced the wrong Linux architecture')
    target.chmod(0o755)
    result = {'architecture': architecture, 'executable': name, 'bytes': target.stat().st_size,
              'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
              'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(), 'command': command}
    (output / (name + '.build.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--architecture', choices=ARCHITECTURES, default=platform.machine())
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', default='cc')
    options = parser.parse_args()
    if options.architecture not in ARCHITECTURES:
        parser.error('Specify x86_64 or aarch64')
    print(json.dumps(build(options.architecture, options.output, options.compiler), indent=2))
