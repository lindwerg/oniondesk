# Linux R4 private native UI bootstrap

The top-level ELF is a static Go stage0 with no GTK or system loader dependency.
It accepts no CLI arguments. Its embedded, immutable mini-contract covers the
native CUI, configured worker, exact 64-library R3 runtime, approved PNG, two
fonts and fontconfig file. All 70 mini input blobs are embedded as immutable raw
data in the static top-level ELF; final delivery has no external bootstrap pool.
Only the original Core pool remains external, so GitHub archive modes 0775/0664
do not grant executable trust.

Stage0 copies embedded data by pinned lowercase SHA256 names into a bounded,
exclusive owner-only temporary source through held directory handles. Every
byte count/hash is checked, at most 128 blobs/100 MiB are allowed, and cleanup
removes only its own known nodes. The unchanged frozen engine restores it into
the separate
`<user cache>/OnionDesk-Native-UI-R4/<mini digest>/ready-*/payload` tree, validates
hashes, file modes and ownership, then stage0 replaces itself with the verified
private CUI using cwd=payload and exactly `--source-root <original package pool>`.
The original pool remains `<original package>/.oniondesk/transport/blobs`.
The R4 worker accepts this data path only; its original 498-blob Core contract,
Core cache `OnionDesk-Offline`, entrypoint and launch policy remain pinned.

The private CUI preserves the R3 UI, GL isolation, IPC, cancellation, READY,
PNG/worker hashes and strict cache/filesystem guards. Only its required source
path grammar and worker argv differ. Existing code remains GPL-3.0-only;
third-party components retain their original license terms and notices.

## Process environment policy

Before private CUI exec, stage0 removes every variable whose name begins `LD_`,
and these exact code-loading override variables:

- `GTK_MODULES`, `GTK_PATH`, `GTK_EXE_PREFIX`, `GTK_IM_MODULE_FILE`, `GTK3_MODULES`
- `GIO_MODULE_DIR`, `GIO_EXTRA_MODULES`
- `GDK_PIXBUF_MODULE_FILE`, `GDK_PIXBUF_MODULEDIR`
- `GCONV_PATH`

This approved policy applies to the child process chain only. It does not change
the OS environment. Display/Wayland/DBus/session, HOME/locale, user proxy/Tor/NSS,
`GDK_BACKEND`, `GTK_IM_MODULE` and incoming `GDK_GL` values are preserved. The CUI
then snapshots this filtered environment before its existing bootstrap-only GTK
and `GDK_GL=disable` overrides; worker/Core receive that snapshot. No alternate
manifest, cache, executable, command, network fetch or telemetry can be selected.

## Build and verification boundary

`../producer` is build-only. It validates the exact R3 runtime-lock hashes,
approved icon, architecture, static worker, CUI header's Core/worker pins, then
emits the mini-contract, blobs and architecture source copy. It never executes
any packaged binary. The unchanged Core pool is deliberately not duplicated by
this tool; final assembly must retain its exact 498 original blobs.

Go ELF builds use Go 1.26.2, CGO=0, `-trimpath -buildvcs=false -ldflags='-s -w'`.
CUI uses the reviewed Debian GTK SDK and existing frozen hardening/RPATH flags,
with neutral file/debug prefix maps and stripped non-runtime symbols. Each new
ELF must pass raw-byte scans for private username and home-directory prefixes, not just
metadata inspection. Source/build proofs use project-relative paths.

Host tests exercise the actual engine with raw 0775/0664 source data, cold and
warm restore, isolated owner-only cache, corruption/symlink/hardlink/extra data,
unsafe cache modes, cancelled context, strict arguments, exact environment
filtering and real exec of a synthetic Go test helper. Helper modes exist only
in `_test.go`; no real worker/Core/GTK is executed. CUI's actual-callback fixtures
cover cancellation and launch gating separately.

## Early error presentation

Missing/corrupt external bootstrap data is eliminated by embedding its exact
bytes. For unavoidable early failures such as disk exhaustion or unsafe cache
ownership, stage0 writes a fixed Russian error and makes a best-effort OS dialog
attempt: `/usr/bin/zenity`, then `/usr/bin/kdialog`, each with a 20-second limit.
Only root-owned executable regular files with root-owned non-writable ancestors,
no symlinks or special privilege bits qualify. Arguments/message are fixed;
no shell or user-selected executable is used, and no unverified CUI is started.

Dialog environment uses the normal blocklist plus removes `QT_PLUGIN_PATH`,
`QT_QPA_PLATFORM_PLUGIN_PATH`, `QT_QPA_GENERIC_PLUGINS`, `QT_QPA_PLATFORM`,
`QML_IMPORT_PATH`, `QML2_IMPORT_PATH`, and fixes PATH to `/usr/bin` for that error
dialog only. If neither trusted provider is installed/usable, stderr remains
the fallback; a universal graphical early-error guarantee is not claimed.

The source addendum must retain the 70 architecture-specific
`production/blobs/<SHA256>` embedded inputs, or the exact pinned published
sources and reproduction recipe. Third-party runtime notices and corresponding
source obligations remain those of the unchanged reviewed Debian runtime.

Actual Linux window, time to first window, cold/warm Core preparation, Cancel,
Quit and runtime library maps still require root QA of the final native artifacts.

## Distribution source references

R4 configured source addendum (planned, not uploaded by this local stage):
https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-linux-r4-source-20261017.tar.gz
SHA256: `ba98510e06ae5a58aa9dc4bf46197cbcb854895c7fa74a1b5ebc53e8c83611e6`; 59825135 bytes.

Unchanged baseline with50 Debian source packages: 72be43a42e70f0eda28ee5246855eb631e38d5b9abf81d1c599ac9c11081fedf. Full preserved runtime notices remain in this directory’s licenses/; Go notices are in ../licenses/go1.26.2/.
