#!/usr/bin/env python3
"""Generate the installer's immutable file allowlist and native verifier pins."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import runpy
import re

CLIENT = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def pinned_records(client: Path = CLIENT) -> list[dict]:
    offline = runpy.run_path(str(client / 'offline_catalog.py'))
    wallet = runpy.run_path(str(client / 'wallet_catalog.py'))
    phone = runpy.run_path(str(client / 'phone_catalog.py'))
    feather = runpy.run_path(str(client / 'feather_catalog.py'))
    records = [*offline['ASSETS'].values(), wallet['HASHES'], wallet['KEY'],
               *wallet['PLATFORMS'].values(), *phone['ASSETS'].values(), *feather['ASSETS'].values()]
    result = []
    paths = set()
    for record in records:
        path = record['path']
        parts = PurePosixPath(path).parts
        if not parts or PurePosixPath(path).is_absolute() or any(part in {'.', '..'} for part in parts) or any(char in path for char in '\\:$"\n\r'):
            raise RuntimeError('Unsafe source-pinned Data path')
        if path in paths or not isinstance(record['size_bytes'], int) or record['size_bytes'] < 1 or not re.fullmatch(r'[0-9a-f]{64}', record['sha256']):
            raise RuntimeError('Invalid or duplicate Data pin')
        bytes.fromhex(record['sha256'])
        paths.add(path)
        result.append({key: record[key] for key in ('path', 'size_bytes', 'sha256')})
    return sorted(result, key=lambda row: row['path'])


def verified_records(data: Path, client: Path = CLIENT) -> list[dict]:
    offline = runpy.run_path(str(client / 'offline_catalog.py'))
    if data.is_symlink() or not data.is_dir():
        raise RuntimeError('Data must be an ordinary directory')
    manifest = data / 'manifest.json'
    expected = {'format': 1, 'release_id': offline['RELEASE_ID'], 'assets': offline['ASSETS']}
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError('Duplicate Data manifest field')
            result[key] = value
        return result
    if (manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 1024 * 1024
            or json.loads(manifest.read_text(), object_pairs_hook=unique_object) != expected):
        raise RuntimeError('Data manifest does not match source catalog')
    records = pinned_records(client)
    records.append({'path': 'manifest.json', 'size_bytes': manifest.stat().st_size, 'sha256': digest(manifest)})
    allowed = {row['path'] for row in records}
    actual = set()
    for path in data.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('Data symlinks are forbidden')
        if path.name in {'.DS_Store', '__pycache__', '.mypy_cache', '.ruff_cache'} or any(part in {'__pycache__', '.mypy_cache', '.ruff_cache'} for part in path.relative_to(data).parts):
            continue
        if path.is_file():
            actual.add(path.relative_to(data).as_posix())
    if actual != allowed:
        raise RuntimeError('Data has missing or unexpected files')
    for row in records:
        path = data / row['path']
        if path.stat().st_size != row['size_bytes'] or digest(path) != row['sha256']:
            raise RuntimeError('Data does not match a source pin: ' + row['path'])
    return sorted(records, key=lambda row: row['path'])


def generate(data: Path, output: Path, extra_bytes: int = 0) -> dict:
    records = verified_records(data)
    if output.is_symlink():
        raise RuntimeError('The Data build directory must not be a symlink')
    marker = output / '.oniondesk-data-build'
    if output.exists() and any(output.iterdir()):
        if marker.is_symlink() or not marker.is_file() or marker.read_text() != 'OnionDesk Data verifier build v1\n':
            raise RuntimeError('Use a new empty directory or the owned Data verifier build directory')
    output.mkdir(parents=True, exist_ok=True)
    marker.write_text('OnionDesk Data verifier build v1\n')
    total = sum(row['size_bytes'] for row in records)
    header = ['/* Generated from verified source catalogs; never from package-supplied pins. */',
              'struct data_pin { const wchar_t *path; uint64_t size; unsigned char sha256[32]; };',
              'static const struct data_pin data_pins[] = {']
    script = ['; Generated source-pinned copy list.', f'!define ONIONDESK_DATA_BYTES {total}',
              f'!define ONIONDESK_REQUIRED_BYTES {total + extra_bytes + 64 * 1024 * 1024}',
              f'!define ONIONDESK_DATA_FILE_COUNT {len(records)}', '!macro CopyPinnedData']
    for row in records:
        native = row['path'].replace('/', '\\')
        c_path = native.replace('\\', '\\\\')
        hash_bytes = ','.join('0x' + row['sha256'][i:i + 2] for i in range(0, 64, 2))
        header.append(f'    {{L"{c_path}", UINT64_C({row["size_bytes"]}), {{{hash_bytes}}}}},')
        directory = str(PurePosixPath(row['path']).parent).replace('/', '\\')
        target = '$INSTDIR\\OnionDesk-Data' + (('\\' + directory) if directory != '.' else '')
        script.extend([f'  CreateDirectory "{target}"', '  IfErrors install_failed', '  ClearErrors',
                       f'  CopyFiles /SILENT "$SourceData\\{native}" "$INSTDIR\\OnionDesk-Data\\{native}"',
                       '  IfErrors install_failed'])
    header.append('};')
    script.append('!macroend')
    (output / 'oniondesk-data-pins.h').write_text('\n'.join(header) + '\n')
    (output / 'oniondesk-data-files.nsh').write_text('\n'.join(script) + '\n')
    result = {'files': records, 'file_count': len(records), 'data_bytes': total,
              'required_bytes': total + extra_bytes + 64 * 1024 * 1024}
    (output / 'data-pins.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extra-tree', type=Path, action='append', default=[])
    options = parser.parse_args()
    extra = sum(path.stat().st_size for tree in options.extra_tree for path in tree.rglob('*') if path.is_file())
    result = generate(options.data, options.output, extra)
    print(json.dumps({key: value for key, value in result.items() if key != 'files'}))
