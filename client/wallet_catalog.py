"""Fixed Monero release pins, measured after binaryFate signature verification.

Sources checked 2026-10-15: https://www.getmonero.org/downloads/ and
https://www.getmonero.org/resources/user-guides/verification-allos-advanced.html
The public key originates in monero-project/monero utils/gpg_keys/binaryfate.asc.
No path, executable member, version or trust key is accepted from the UI.
"""

VERSION = "0.18.5.3"
PUBLISHER_FINGERPRINT = "81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92"
HASHES = {"path": "Monero/hashes.txt", "size_bytes": 3041,
          "sha256": "a6acc804b7d7b7df920445e2498830ab17224e8206d2799f03538876754ad568"}
KEY = {"path": "Monero/binaryfate.asc", "size_bytes": 5438,
       "sha256": "7dcb19c87d41a4399b4877054111f7dbfd30531545678bc2be218bd56903904c"}
PLATFORMS = {
    "macos-arm64": {
        "path": "Monero/monero-mac-armv8-v0.18.5.3.tar.bz2", "size_bytes": 70624775,
        "sha256": "7a083ed2e2499dc25ac046ce7ef740c11183bdf4ac92460ffe503a5be46a54ab",
        "rpc_member": "monero-aarch64-apple-darwin11-v0.18.5.3/monero-wallet-rpc",
        "rpc_bytes": 28599228,
        "rpc_sha256": "b72f1901c0cad7f9285180eb5c5dcaf6870f6f7b01d9c39ca659705b4d16ad2b",
    },
    "windows-x64": {
        "path": "Monero/monero-win-x64-v0.18.5.3.zip", "size_bytes": 89532682,
        "sha256": "f58f8f803f0141c77f40f327c516e4721f61d112084eb3d6644028cb9680b82a",
        "rpc_member": "monero-x86_64-w64-mingw32-v0.18.5.3/monero-wallet-rpc.exe",
        "rpc_bytes": 39785566,
        "rpc_sha256": "63449ffe55d5fd58aa7be143d71c5df647279c94e9a11c2f424064d8cefcad95",
    },
    "linux-x64": {
        "path": "Monero/monero-linux-x64-v0.18.5.3.tar.bz2", "size_bytes": 85026860,
        "sha256": "3333d0e04c9cbe3023e7e2b6dd369c407f36bb8df5b05fb0a19d7685b3d56dfc",
        "rpc_member": "monero-x86_64-linux-gnu-v0.18.5.3/monero-wallet-rpc",
        "rpc_bytes": 29283472,
        "rpc_sha256": "cada9d3d652ec80e4c8a17b9b56bf791dad4a27d5bcc5e4f7860c8fd8b7695e0",
    },
    "linux-arm64": {
        "path": "Monero/monero-linux-armv8-v0.18.5.3.tar.bz2", "size_bytes": 74763123,
        "sha256": "1490114f795ad2f67f57bc8d167c3e2539e9f173fc46f02f70ef4abf685f8c66",
        "rpc_member": "monero-aarch64-linux-gnu-v0.18.5.3/monero-wallet-rpc",
        "rpc_bytes": 28258672,
        "rpc_sha256": "4ff59131f961c35a52be398354282183efa3af405014c7efe304ed04ac5d35c2",
    },
}
