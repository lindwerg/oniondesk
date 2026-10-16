"""Release allow-list, built from publisher-verified files on 2026-10-15.

The adjacent distribution manifest is untrusted; it cannot change this catalog.
Tails: https://tails.net/install/v2/Tails/amd64/stable/latest.json
Tor: https://download.torproject.org/tor-browser-for-desktop/
Stable Linux ARM64 is not published; macOS is a Universal Intel/Apple Silicon DMG.
"""
from __future__ import annotations

RELEASE_ID = "2026-10-15-tails7.15-tor15.0.25"
TAILS_VERSION = "7.15"
TOR_VERSION = "15.0.25"
TOR_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
ASSETS = {
    "tails-image": {
        "path": "tails/tails-amd64-7.15.img",
        "size_bytes": 1889533952,
        "sha256": "2bad37833f2e44abbf68646a460759c26d1fc32589c2e0437099743bc6b6197b"
    },
    "tails-signature": {
        "path": "tails/tails-amd64-7.15.img.sig",
        "size_bytes": 228,
        "sha256": "99ad6a16e3bd1c2717a95f5a9ca9b822f9867a7c8a5c16ad334d30ef5fae612d"
    },
    "tails-key": {
        "path": "publisher-keys/tails-signing.key",
        "size_bytes": 1383243,
        "sha256": "c1f19b5ece12d8562fb40313a2d8a41bb6ac47dea4d94dbbbbc606ab66a1ca37"
    },
    "tor-macos": {
        "path": "tor-browser/tor-browser-macos-15.0.25.dmg",
        "size_bytes": 176943035,
        "sha256": "4771ad39f84323e60c1966b270a743c9a23f437569aca36dbb93988919c1a7ae"
    },
    "tor-macos-signature": {
        "path": "tor-browser/tor-browser-macos-15.0.25.dmg.asc",
        "size_bytes": 833,
        "sha256": "b1e94539e1385a5d5da363462d173f40c840cc44153c406e7f76148859b4c4a7"
    },
    "tor-windows": {
        "path": "tor-browser/tor-browser-windows-x86_64-portable-15.0.25.exe",
        "size_bytes": 113637768,
        "sha256": "948f79f7312c7b62dffeb1d65a51d49ea6bcb22b47b271fdd2edee9d5e22d561"
    },
    "tor-windows-signature": {
        "path": "tor-browser/tor-browser-windows-x86_64-portable-15.0.25.exe.asc",
        "size_bytes": 833,
        "sha256": "5e9da290109d34a32af2aba2609c868be0ab551bf08d985c82190705b8a5c484"
    },
    "tor-linux": {
        "path": "tor-browser/tor-browser-linux-x86_64-15.0.25.tar.xz",
        "size_bytes": 137994120,
        "sha256": "37432d6f4d9b1f1190ba2cfbbd4ab9dad5ccd52c14aa47a21795d08273f4a165"
    },
    "tor-linux-signature": {
        "path": "tor-browser/tor-browser-linux-x86_64-15.0.25.tar.xz.asc",
        "size_bytes": 833,
        "sha256": "d318920393b2c297b06ed4d0a2e7b45e42436e3f0ad7215a4dbec3b82b6c2eff"
    },
    "tor-key": {
        "path": "publisher-keys/tor-browser-developers.key",
        "size_bytes": 39452,
        "sha256": "7cec103d0be11b608f61850143101e56f0ba45383b61f44835300ff54ef93032"
    }
}
TAILS = {"image": "tails-image", "signature": "tails-signature", "key": "tails-key"}
TOR = {
    "Darwin": {"binary": "tor-macos", "signature": "tor-macos-signature", "key": "tor-key"},
    "Windows": {"binary": "tor-windows", "signature": "tor-windows-signature", "key": "tor-key"},
    "Linux": {"binary": "tor-linux", "signature": "tor-linux-signature", "key": "tor-key"},
}
