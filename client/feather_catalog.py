"""Official Feather 2.8.1 release pins, verified on 2026-10-16.

Release: https://featherwallet.org/download/
Independent published fingerprint: https://docs.featherwallet.org/guides/release-signing-key
Portable layout: https://docs.featherwallet.org/guides/portable-mode
Each archive and the signed hash list were verified with the pinned primary key.
The distribution manifest and browser cannot alter these trust decisions.
"""

from typing import NotRequired, TypedDict


class AssetRecord(TypedDict):
    path: str
    size_bytes: int
    sha256: str
    url: NotRequired[str]


class ProgramMember(TypedDict):
    size_bytes: int
    sha256: str
    executable: bool


class ReleaseRecord(AssetRecord):
    signature: AssetRecord
    binary: str
    members: dict[str, ProgramMember]


VERSION = "2.8.1"
CHECKED_ON = "2026-10-16"
PUBLISHER_FINGERPRINT = "8185E158A33330C7FD61BC0D1F76E155CEFBA71C"
KEY: AssetRecord = {'path': 'publisher-keys/featherwallet.asc',
 'url': 'https://raw.githubusercontent.com/feather-wallet/feather/2.8.1/utils/pubkeys/featherwallet.asc',
 'size_bytes': 3139,
 'sha256': 'bc01e20d05f84827191486f62c606deda454e6b28926e91061f264c40e158250'}
HASHES: AssetRecord = {'path': 'Feather/hashes-2.8.1.txt',
 'url': 'https://featherwallet.org/files/releases/hashes-2.8.1.txt',
 'size_bytes': 2882,
 'sha256': '0d3a92b54eeb48e06ae4326fa713610565fb2f1264d0ef77346ae8b30cc62097'}
PLATFORMS: dict[str, ReleaseRecord] = {'macos-arm64': {'path': 'Feather/feather-2.8.1-mac-arm64.zip',
                 'url': 'https://featherwallet.org/files/releases/mac-arm64/feather-2.8.1-mac-arm64.zip',
                 'size_bytes': 24130420,
                 'sha256': 'a35f19be74ca59bad96f7331d3ca8e4f56ec47e82c193f5fc50ddbebce017233',
                 'signature': {'path': 'Feather/feather-2.8.1-mac-arm64.zip.asc',
                               'url': 'https://featherwallet.org/files/releases/mac-arm64/feather-2.8.1-mac-arm64.zip.asc',
                               'size_bytes': 833,
                               'sha256': 'b0ec5e783e12988dcedf8518c8c63889d836fda1bf42573c856734e68d15f799'},
                 'binary': 'Feather.app/Contents/MacOS/feather',
                 'members': {'Feather.app/Contents/CodeResources': {'size_bytes': 1738,
                                                                    'sha256': '7bc94d48786a429b8dc97c651fd0f350961aa84e5cc548d79142e918214db64f',
                                                                    'executable': False},
                             'Feather.app/Contents/Info.plist': {'size_bytes': 1807,
                                                                 'sha256': '92800effccfc07717d3a5f7736acb97bad3351b1d390b84841ebd126bf35cfa0',
                                                                 'executable': False},
                             'Feather.app/Contents/MacOS/feather': {'size_bytes': 51725296,
                                                                    'sha256': '1fab6272f742d5ca2701f5dff75f88de510d97fb7a2c526a698be2bf6115293f',
                                                                    'executable': True},
                             'Feather.app/Contents/Resources/appicon.icns': {'size_bytes': 88523,
                                                                             'sha256': 'ad67075a7d80155fad16af296feed8bf08e26a6d3266aec1b6a5d13e974fc3ca',
                                                                             'executable': True},
                             'Feather.app/Contents/_CodeSignature/CodeResources': {'size_bytes': 2973,
                                                                                   'sha256': '8814105e8d5a18119d95559c11b00b66cc1421186a350f5656f6bdce09f7671c',
                                                                                   'executable': False},
                             'Feather.app/Contents/bin/libevent-2.1.7.dylib': {'size_bytes': 839840,
                                                                               'sha256': '43fec0b7eb0552532fa73f77d0c07c42fe6640d6280c83aafe95fc5e79ce90dc',
                                                                               'executable': False},
                             'Feather.app/Contents/bin/tor': {'size_bytes': 14172512,
                                                              'sha256': 'c8275bf33968c4bd8ceff853a61dafb6d967e8e2e8386f825d2ae6edaf81c9df',
                                                              'executable': True}}},
 'windows-x64': {'path': 'Feather/feather-2.8.1-win.zip',
                 'url': 'https://featherwallet.org/files/releases/win/feather-2.8.1-win.zip',
                 'size_bytes': 26764453,
                 'sha256': '7ce53d73605d007d062a1636ec727fa7f151c5c08248122056c7d4224bd200f3',
                 'signature': {'path': 'Feather/feather-2.8.1-win.zip.asc',
                               'url': 'https://featherwallet.org/files/releases/win/feather-2.8.1-win.zip.asc',
                               'size_bytes': 833,
                               'sha256': '5cafdf23a27d65308d1b9c0a56ebe5303bb140979972c98d75cdcb34d50c7ade'},
                 'binary': 'feather-2.8.1.exe',
                 'members': {'feather-2.8.1.exe': {'size_bytes': 68922120,
                                                   'sha256': 'ef7caeab35b16a0f1717088fe91f8a225be35ef343c520cd1b7a1fb636b255a2',
                                                   'executable': False}}},
 'linux-x64': {'path': 'Feather/feather-2.8.1-linux.zip',
               'url': 'https://featherwallet.org/files/releases/linux/feather-2.8.1-linux.zip',
               'size_bytes': 30459335,
               'sha256': '4779c57e9443f7755add3c2414447d1593ebe06998e39a9f765deab5bd64c466',
               'signature': {'path': 'Feather/feather-2.8.1-linux.zip.asc',
                             'url': 'https://featherwallet.org/files/releases/linux/feather-2.8.1-linux.zip.asc',
                             'size_bytes': 833,
                             'sha256': 'f648a80903bcd40917dddb8eec26d4b340b0eee9e87094e66ceb7debe98b5294'},
               'binary': 'feather-2.8.1',
               'members': {'feather-2.8.1': {'size_bytes': 80515352,
                                             'sha256': '86b1359e373d1a4b7f1258662c312fcbb035ae8397679dc13f8185a424fc9419',
                                             'executable': True}}},
 'linux-arm64': {'path': 'Feather/feather-2.8.1-arm64.AppImage',
                 'url': 'https://featherwallet.org/files/releases/linux-arm64-appimage/feather-2.8.1-arm64.AppImage',
                 'size_bytes': 27128480,
                 'sha256': 'ed6e8e885539ee2a76e49ef6cbbeda8586959ae5ad30432f102669a83081aecd',
                 'signature': {'path': 'Feather/feather-2.8.1-arm64.AppImage.asc',
                               'url': 'https://featherwallet.org/files/releases/linux-arm64-appimage/feather-2.8.1-arm64.AppImage.asc',
                               'size_bytes': 833,
                               'sha256': '935a24807ae3b1572c28400223b8624e6204005f2484fe825226ba4f7bdf1890'},
                 'binary': 'feather-2.8.1-arm64.AppImage',
                 'members': {'feather-2.8.1-arm64.AppImage': {'size_bytes': 27128480,
                                                              'sha256': 'ed6e8e885539ee2a76e49ef6cbbeda8586959ae5ad30432f102669a83081aecd',
                                                              'executable': True}}}}

# Flat public allow-list for every platform builder, including notices.
ASSETS: dict[str, AssetRecord] = {'Feather/feather-2.8.1-mac-arm64.zip': {'path': 'Feather/feather-2.8.1-mac-arm64.zip',
                                         'url': 'https://featherwallet.org/files/releases/mac-arm64/feather-2.8.1-mac-arm64.zip',
                                         'size_bytes': 24130420,
                                         'sha256': 'a35f19be74ca59bad96f7331d3ca8e4f56ec47e82c193f5fc50ddbebce017233'},
 'Feather/feather-2.8.1-win.zip': {'path': 'Feather/feather-2.8.1-win.zip',
                                   'url': 'https://featherwallet.org/files/releases/win/feather-2.8.1-win.zip',
                                   'size_bytes': 26764453,
                                   'sha256': '7ce53d73605d007d062a1636ec727fa7f151c5c08248122056c7d4224bd200f3'},
 'Feather/feather-2.8.1-linux.zip': {'path': 'Feather/feather-2.8.1-linux.zip',
                                     'url': 'https://featherwallet.org/files/releases/linux/feather-2.8.1-linux.zip',
                                     'size_bytes': 30459335,
                                     'sha256': '4779c57e9443f7755add3c2414447d1593ebe06998e39a9f765deab5bd64c466'},
 'Feather/feather-2.8.1-arm64.AppImage': {'path': 'Feather/feather-2.8.1-arm64.AppImage',
                                          'url': 'https://featherwallet.org/files/releases/linux-arm64-appimage/feather-2.8.1-arm64.AppImage',
                                          'size_bytes': 27128480,
                                          'sha256': 'ed6e8e885539ee2a76e49ef6cbbeda8586959ae5ad30432f102669a83081aecd'},
 'Feather/hashes-2.8.1.txt': {'path': 'Feather/hashes-2.8.1.txt',
                              'url': 'https://featherwallet.org/files/releases/hashes-2.8.1.txt',
                              'size_bytes': 2882,
                              'sha256': '0d3a92b54eeb48e06ae4326fa713610565fb2f1264d0ef77346ae8b30cc62097'},
 'publisher-keys/featherwallet.asc': {'path': 'publisher-keys/featherwallet.asc',
                                      'url': 'https://raw.githubusercontent.com/feather-wallet/feather/2.8.1/utils/pubkeys/featherwallet.asc',
                                      'size_bytes': 3139,
                                      'sha256': 'bc01e20d05f84827191486f62c606deda454e6b28926e91061f264c40e158250'},
 'licenses/Feather-BSD-3-Clause.txt': {'path': 'licenses/Feather-BSD-3-Clause.txt',
                                       'size_bytes': 1495,
                                       'sha256': 'cda7a6df24e5e3d69b33c15261c9630f6d7f9787832a3e9a3788237fa6020b26'},
 'Feather/feather-2.8.1-mac-arm64.zip.asc': {'path': 'Feather/feather-2.8.1-mac-arm64.zip.asc',
                                             'url': 'https://featherwallet.org/files/releases/mac-arm64/feather-2.8.1-mac-arm64.zip.asc',
                                             'size_bytes': 833,
                                             'sha256': 'b0ec5e783e12988dcedf8518c8c63889d836fda1bf42573c856734e68d15f799'},
 'Feather/feather-2.8.1-win.zip.asc': {'path': 'Feather/feather-2.8.1-win.zip.asc',
                                       'url': 'https://featherwallet.org/files/releases/win/feather-2.8.1-win.zip.asc',
                                       'size_bytes': 833,
                                       'sha256': '5cafdf23a27d65308d1b9c0a56ebe5303bb140979972c98d75cdcb34d50c7ade'},
 'Feather/feather-2.8.1-linux.zip.asc': {'path': 'Feather/feather-2.8.1-linux.zip.asc',
                                         'url': 'https://featherwallet.org/files/releases/linux/feather-2.8.1-linux.zip.asc',
                                         'size_bytes': 833,
                                         'sha256': 'f648a80903bcd40917dddb8eec26d4b340b0eee9e87094e66ceb7debe98b5294'},
 'Feather/feather-2.8.1-arm64.AppImage.asc': {'path': 'Feather/feather-2.8.1-arm64.AppImage.asc',
                                              'url': 'https://featherwallet.org/files/releases/linux-arm64-appimage/feather-2.8.1-arm64.AppImage.asc',
                                              'size_bytes': 833,
                                              'sha256': '935a24807ae3b1572c28400223b8624e6204005f2484fe825226ba4f7bdf1890'},
 'licenses/Feather-SOURCES.txt': {'path': 'licenses/Feather-SOURCES.txt',
                                  'size_bytes': 1112,
                                  'sha256': 'cfc46a7a0f2fa7d9a461df37b7319faa2e259562533b3dbad608dd1074b5ecb2'},
 'licenses/Feather-about.txt': {'path': 'licenses/Feather-about.txt',
                                'size_bytes': 1537,
                                'sha256': '3cf4d023c0258de0f1108966f1449ecdcfb05d127928274ddcb7abdb036542ef'},
 'licenses/Feather-acknowledgements.txt': {'path': 'licenses/Feather-acknowledgements.txt',
                                           'size_bytes': 1272,
                                           'sha256': '1dad485903e27f6266f10591eb6c70d5bf59115e2db8474af5924812f33be6dc'}}
