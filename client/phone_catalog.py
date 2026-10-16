"""Pinned public release catalog; verified from publisher files on 2026-10-15.

Tor APKs: https://tor.eff.org/dist/torbrowser/15.0.25/ — EFF is named by the
Tor Project at https://support.torproject.org/tor-browser/getting-started/downloading/.
Signatures: https://dist.torproject.org/torbrowser/15.0.25/ (HTTPS through Tor).
Google: https://dl.google.com/android/repository/repository2-1.xml.
Google publishes no official Linux ARM64 platform-tools archive in this release.
The adjacent JSON provenance is informational and cannot alter these pins.
"""
TOR_VERSION = "15.0.25"
PLATFORM_TOOLS_VERSION = "37.0.1"
TOR_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
PACKAGE = "org.torproject.torbrowser"
LAUNCH_ACTIVITY = "org.torproject.torbrowser/org.mozilla.fenix.HomeActivity"
RELEASE_READY = True
PLATFORMS = {'macos': {'path': 'Android/platform-tools_r37.0.1-darwin.zip',
           'size_bytes': 16110554,
           'sha256': 'ee39ad5967e95c2a07f04dbcbde96b1a0c916ba376096db5d2f498b7727a5d1d'},
 'windows-x64': {'path': 'Android/platform-tools_r37.0.1-win.zip',
                 'size_bytes': 8044989,
                 'sha256': '45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99'},
 'linux-x64': {'path': 'Android/platform-tools_r37.0.1-linux.zip',
               'size_bytes': 9054187,
               'sha256': 'd230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1'}}

KEY = {'path': 'Android/tor-browser-developers.key',
 'size_bytes': 39452,
 'sha256': '7cec103d0be11b608f61850143101e56f0ba45383b61f44835300ff54ef93032'}

APKS = {'arm64-v8a': {'path': 'Android/tor-browser-android-aarch64-15.0.25.apk',
               'size_bytes': 111122155,
               'sha256': '43b13364a9adc9b139f7c44279e552b7fdea07aef09a553310c7a8e5743c28b8'},
 'armeabi-v7a': {'path': 'Android/tor-browser-android-armv7-15.0.25.apk',
                 'size_bytes': 108865297,
                 'sha256': 'd917d2c13f4580c225eeced9c22bfcd2b7aa8290992615ee42c3be50624a8aef'},
 'x86_64': {'path': 'Android/tor-browser-android-x86_64-15.0.25.apk',
            'size_bytes': 112518728,
            'sha256': '9f7934ea3a4e68a6e405f04febcd55e6a5a87d112b221b9aac89c6d1bc77597e'}}

SIGNATURES = {'arm64-v8a': {'path': 'Android/tor-browser-android-aarch64-15.0.25.apk.asc',
               'size_bytes': 833,
               'sha256': '57438cbcb2df12e0afdd536f6697db2b34019c098322eb896eb53d24b900182d'},
 'armeabi-v7a': {'path': 'Android/tor-browser-android-armv7-15.0.25.apk.asc',
                 'size_bytes': 833,
                 'sha256': 'c692a3d074babf4f74bc8a042cad4ad6ca6418a9d84fb20f5e73af7eea3f6b6d'},
 'x86_64': {'path': 'Android/tor-browser-android-x86_64-15.0.25.apk.asc',
            'size_bytes': 833,
            'sha256': 'a10345ef8f0a20a53d6b81f9d4b27c018e99f172485a71e9f5ebb1ee88ad90a0'}}
DOCUMENTS = [{'path': 'Android/SOURCE-PROVENANCE.json',
  'size_bytes': 3570,
  'sha256': '353f7a3d37bc51df311f162515fbd79323a7fbe0a60ded1afaff5504182ea4b1'},
 {'path': 'Android/README.txt',
  'size_bytes': 2975,
  'sha256': '359fdcb226f08398d1618dfee986bd37a6c84f096678f89f3a5c063ce824abdf'}]

# One code-pinned allowlist is shared by the native packager and release verifier.
ASSETS = {record['path']: record for record in (
    *PLATFORMS.values(), KEY, *APKS.values(), *SIGNATURES.values(), *DOCUMENTS
)}
