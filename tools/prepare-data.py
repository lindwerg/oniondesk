#!/usr/bin/env python3
"""Developer-only reconstruction of code-pinned public distribution data.

Default mode prints a plan. Fetch requires an explicit mode and Tor SOCKS port.
No payload is executed, extracted, mounted, installed, or copied from user state.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
from typing import TYPE_CHECKING, NotRequired
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from requests import Session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
# This developer entry point adds its checkout's sibling client modules first.
import offline_catalog as offline_catalog  # noqa: E402
import wallet_catalog as wallet_catalog  # noqa: E402
import phone_catalog as phone_catalog  # noqa: E402
import feather_catalog as feather_catalog  # noqa: E402
from feather_catalog import AssetRecord  # noqa: E402


class PlannedAsset(AssetRecord):
    local_metadata: NotRequired[str]

MARKER = ".oniondesk-public-data-build"
MARKER_TEXT = "OnionDesk code-pinned public distribution data v1\n"
LOCAL_ALIASES = {
    "publisher-keys/tails-signing.key": "publisher-keys/tails-signing.asc",
    "publisher-keys/tor-browser-developers.key": "publisher-keys/tor-browser-developers.asc",
    "Android/tor-browser-developers.key": "publisher-keys/tor-browser-developers.asc",
}


def _asset_pin(record: Mapping[str, object]) -> AssetRecord:
    path, size, sha256 = record["path"], record["size_bytes"], record["sha256"]
    if not isinstance(path, str) or not isinstance(size, int) or isinstance(size, bool) \
            or not isinstance(sha256, str):
        raise ValueError("Invalid catalog field types")
    return {"path": path, "size_bytes": size, "sha256": sha256}


def records() -> dict[str, AssetRecord]:
    """The adjacent JSON is documentation; only compiled catalogs set trust."""
    result: dict[str, AssetRecord] = {}
    for record in (*offline_catalog.ASSETS.values(), wallet_catalog.HASHES,
                   wallet_catalog.KEY, *wallet_catalog.PLATFORMS.values(),
                   *phone_catalog.ASSETS.values(), *feather_catalog.ASSETS.values()):
        current = _asset_pin(record)
        relative = PurePosixPath(current["path"])
        if relative.is_absolute() or ".." in relative.parts or "\\" in current["path"]:
            raise ValueError("Unsafe catalog path")
        if current["path"] in result and result[current["path"]] != current:
            raise ValueError("Conflicting catalog pins")
        result[current["path"]] = current
    return result


def source_url(path: str) -> str:
    if path == offline_catalog.ASSETS["tails-image"]["path"]:
        version = offline_catalog.TAILS_VERSION
        return f"https://download.tails.net/tails/stable/tails-amd64-{version}/tails-amd64-{version}.img"
    if path.startswith("tor-browser/"):
        return f"https://dist.torproject.org/torbrowser/{offline_catalog.TOR_VERSION}/{PurePosixPath(path).name}"
    if path.startswith("Monero/"):
        return "https://downloads.getmonero.org/cli/" + PurePosixPath(path).name
    if path in {r["path"] for r in phone_catalog.PLATFORMS.values()}:
        return "https://dl.google.com/android/repository/" + PurePosixPath(path).name
    if path in {r["path"] for r in phone_catalog.APKS.values()}:
        return f"https://tor.eff.org/dist/torbrowser/{phone_catalog.TOR_VERSION}/{PurePosixPath(path).name}"
    for record in feather_catalog.PLATFORMS.values():
        if path == record["path"]:
            return record["url"]
    raise ValueError("Missing reviewed public source for " + path)


def metadata_path(path: str) -> Path:
    return ROOT / "release-metadata" / LOCAL_ALIASES.get(path, path)


def plan() -> list[PlannedAsset]:
    result: list[PlannedAsset] = []
    for path, record in sorted(records().items()):
        item: PlannedAsset = {"path": record["path"], "size_bytes": record["size_bytes"],
                              "sha256": record["sha256"]}
        if metadata_path(path).is_file():
            item["local_metadata"] = str(metadata_path(path).relative_to(ROOT))
        else:
            item["url"] = source_url(path)
        result.append(item)
    return result


def verify_file(root: Path, record: AssetRecord) -> None:
    import offline_bundle
    with offline_bundle._open_regular(root, record["path"], record["size_bytes"]) as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != record["sha256"]:
            raise ValueError("Pinned SHA-256 mismatch: " + record["path"])


def _check_inventory(root: Path, *, with_marker: bool) -> None:
    expected = {*records(), "manifest.json"}
    if with_marker:
        expected.add(MARKER)
    paths = list(root.rglob("*"))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in paths) or \
            {path.relative_to(root).as_posix() for path in paths if path.is_file()} != expected:
        raise ValueError("Destination is occupied; unexpected or missing public-data files")


def check_destination(destination: Path) -> Path:
    destination = Path(destination).absolute()
    for parent in (destination, *destination.parents):
        if parent.is_symlink():
            raise ValueError("Destination must not contain symlinks")
    if destination.exists():
        if not destination.is_dir():
            raise ValueError("Destination is not a directory")
        marker = destination / MARKER
        if any(destination.iterdir()):
            if marker.exists() or marker.is_symlink():
                if not marker.is_file() or marker.is_symlink() or marker.stat().st_nlink != 1 \
                        or marker.read_text() != MARKER_TEXT:
                    raise ValueError("Destination is occupied; choose a new build-only directory")
            else:
                # A completed tree has no staging marker. Adopt it read-only
                # only after exact inventory and full publisher verification.
                _check_inventory(destination, with_marker=False)
                verify(destination)
                return destination
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    (destination / MARKER).write_text(MARKER_TEXT)
    return destination


def safe_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password \
            or parsed.port not in (None, 443) or parsed.fragment:
        raise ValueError("Only public HTTPS download URLs without credentials are allowed")
    return url


def download(session: Session, url: str, target: Path, record: AssetRecord) -> None:
    """Follow HTTPS mirrors through socks5h; pin actual bytes before publish."""
    url = safe_url(url)
    for _ in range(6):
        response = session.get(url, stream=True, timeout=(45, 120), allow_redirects=False)
        try:
            if response.status_code in {301, 302, 303, 307, 308}:
                from urllib.parse import urljoin
                url = safe_url(urljoin(url, response.headers["Location"]))
                continue
            response.raise_for_status()
            count, digest = 0, hashlib.sha256()
            with target.open("xb") as output:
                for chunk in response.iter_content(1024 * 1024):
                    count += len(chunk)
                    if count > record["size_bytes"]:
                        raise ValueError("Oversized download: " + record["path"])
                    output.write(chunk)
                    digest.update(chunk)
            if count != record["size_bytes"] or digest.hexdigest() != record["sha256"]:
                raise ValueError("Downloaded bytes do not match catalog: " + record["path"])
            return
        finally:
            response.close()
    raise ValueError("Too many HTTPS redirects")


def fetch(destination: Path, socks_port: int) -> None:
    if not 1 <= socks_port <= 65535:
        raise ValueError("Invalid loopback SOCKS port")
    import requests
    root = check_destination(destination)
    marker = root / MARKER
    if not marker.exists():
        return  # Existing complete, unmarked tree was fully verified above.
    session = requests.Session()
    session.trust_env = False
    session.proxies = {scheme: f"socks5h://127.0.0.1:{socks_port}" for scheme in ("http", "https")}
    try:
        for record in plan():
            target = root / record["path"]
            if target.exists() or target.is_symlink():
                verify_file(root, record)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for parent in (target.parent, *target.parent.parents):
                if parent.is_symlink():
                    raise ValueError("Symlink in output path")
            with tempfile.TemporaryDirectory(prefix=".download-", dir=target.parent) as temporary_directory:
                temporary = Path(temporary_directory) / "payload"
                if "local_metadata" in record:
                    shutil.copyfile(ROOT / record["local_metadata"], temporary)
                    with temporary.open("rb") as stream:
                        if temporary.stat().st_size != record["size_bytes"] or \
                                hashlib.file_digest(stream, "sha256").hexdigest() != record["sha256"]:
                            raise ValueError("Pinned public metadata changed: " + record["path"])
                else:
                    download(session, record["url"], temporary, record)
                # Atomic no-clobber publication; unlink the temporary name so
                # the existing regular-file verifier observes nlink == 1.
                os.link(temporary, target)
                temporary.unlink()
        manifest = {"format": 1, "release_id": offline_catalog.RELEASE_ID, "assets": offline_catalog.ASSETS}
        target = root / "manifest.json"
        if target.exists() or target.is_symlink():
            import offline_bundle
            offline_bundle._check_manifest(root)
        else:
            with target.open("x") as output:
                output.write(json.dumps(manifest, indent=2) + "\n")
    except requests.RequestException as error:
        raise RuntimeError("HTTPS through Tor failed; check the local Tor connection and pinned source availability") from error
    finally:
        session.close()
    _check_inventory(root, with_marker=True)
    verify(root)
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_nlink != 1 \
            or marker.read_text() != MARKER_TEXT:
        raise ValueError("Build marker changed; refusing to remove it")
    marker.unlink()


def verify(destination: Path) -> None:
    import offline_bundle
    import usb_tails
    import wallet_bundle
    import feather_bundle
    root = Path(destination).absolute()
    offline_bundle._check_manifest(root)
    all_records = records()
    for record in all_records.values():
        verify_file(root, record)
    def path(record: AssetRecord) -> Path:
        return root / record["path"]
    pins = {name: _asset_pin(record) for name, record in offline_catalog.ASSETS.items()}
    usb_tails._verify_signature(*(path(pins[offline_catalog.TAILS[key]]) for key in ("image", "signature", "key")))
    for tor_row in offline_catalog.TOR.values():
        offline_bundle._verify_tor_signature(*(path(pins[tor_row[key]]) for key in ("binary", "signature", "key")))
    for architecture, apk_record in phone_catalog.APKS.items():
        offline_bundle._verify_tor_signature(path(_asset_pin(apk_record)),
                                            path(_asset_pin(phone_catalog.SIGNATURES[architecture])),
                                            path(_asset_pin(phone_catalog.KEY)))
    for wallet_record in wallet_catalog.PLATFORMS.values():
        wallet_bundle._verify_hashes(path(_asset_pin(wallet_catalog.HASHES)), path(_asset_pin(wallet_catalog.KEY)), wallet_record)
    for feather_record in feather_catalog.PLATFORMS.values():
        feather_bundle._verify_publisher(path(feather_record), path(feather_record["signature"]),
                                         path(feather_catalog.KEY), path(feather_catalog.HASHES), feather_record)
    print(json.dumps({"verified_files": len(all_records), "publisher_signatures": "verified", "payloads_executed": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fetch", action="store_true", help="Download exact public assets through Tor; no execution")
    mode.add_argument("--verify-only", action="store_true", help="Read-only verify an existing public distribution directory")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--socks-port", type=int)
    args = parser.parse_args()
    if (args.fetch or args.verify_only) and args.destination is None:
        parser.error("--destination is required")
    if args.fetch and args.socks_port is None:
        parser.error("--fetch requires an explicit loopback --socks-port")
    try:
        if args.fetch:
            fetch(args.destination, args.socks_port)
        elif args.verify_only:
            verify(args.destination)
        else:
            print(json.dumps({"kind": "PLAN ONLY; no network or writes", "files": plan()}, indent=2))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Public-data preparation stopped: {error}\n")
