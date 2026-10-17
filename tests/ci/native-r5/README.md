# Cold native R5 lifecycle

Only `lindwerg/oniondesk`, public GitHub-hosted runners, and the three fixed
Windows/Linux targets are accepted. Nothing is dispatched by these scripts.
The workflow runs only by manual dispatch. Its `suite` choice selects all three
targets, the two Linux targets, or Windows only. Concurrency is per distribution,
so a Linux-only dispatch can proceed while an earlier Windows test is running.

The real release ZIP is hash checked and extracted with a portable path/type
guard. Its top executable is independently pinned. Required empty transport
parents are created; the source blob pool is deliberately absent. R5 must
download its fixed public HTTPS runtime parts itself. No runtime override,
certificate exception, wallet, account, purchase or real host profile is used.

The harness observes the actual native preparation window. It independently
rehashes all 47/498 downloaded blobs and all 45/627 restored Core files, checks
the fixed manifest/index and completion receipts, then exercises the real Core.
Windows uses the ordinary Russian NSIS wizard, its installed Program Files Core,
and the ordinary uninstaller. No `/S`, `/D`, UAC handling or privilege bypass is
used for installation. A secure-desktop gate makes this test incomplete.

The frozen Windows/Linux Core excludes optional pywebview, so the documented
system-browser fallback is selected with `BROWSER`. A private adapter hands its
loopback nonce URL to a headed Chromium instance with `chromium_sandbox=True`.
Linux provisions Chromium's ordinary root-owned 4755 sandbox helper in a unique
`/usr/local/sbin` file, verifies its SHA and mount flags, and removes that exact
owned helper during cleanup. x64 uses the installed system Google Chrome with
Ubuntu's existing profile; ARM64 uses the pinned Playwright Chromium. The normal
`playwright install --with-deps chromium` provisions required system libraries.
Both Linux targets must report a positive `chrome://sandbox` evaluation and
layer-one/PID/network/seccomp status before the product starts. AppArmor,
sysctls, TLS and OS security settings are never weakened. UI selectors perform
the first device action, verify the platform, and click the application's Quit.
The owned listener must then stop. ARM64 additionally verifies the disabled
unsupported official Tor Browser action; no Tor Browser success is claimed.

Linux test tooling pins Playwright Python 1.64.0 (official Chromium
156.0.8078.4/revision 1248, including native ARM64); Windows retains its 1.55.0
tooling pin. Linux reads the browser's ELF architecture before launch. The
ephemeral x64 runner's known root-owned Chrome binary and three parent
directories are tightened to 0755 before the unchanged file guard runs. No
symlink or non-root-owned path is eligible for that operation. Verbose Linux
launch diagnostics go only to the bounded encrypted capture; truncation keeps
both the initial error and final crash context as valid UTF-8.
Linux uses a short `od-` private root and `t` temporary child. The calculated
worst-case Chromium socket path is capped at 100 bytes; long runner temporary
parents select a fresh 0700 `/tmp/od-` root. The full 128-bit owner marker and
private state still authenticate cleanup; only these exact short roots qualify.

Public evidence is an allowlisted JSON status/cleanup pair plus cropped native
windows and browser content. No browser chrome, URL, nonce, process arguments,
raw output, environment dump, trace or full desktop is published. Total bytes
are capped at 8 MiB and artifact retention is one day. Every process cleanup
uses a captured PID plus creation time; directories have fresh ownership state.
Existing Windows caches, installations, registry keys and shortcuts fail closed.

Source contract pins are byte copies of the reviewed Windows/Linux R5 input
manifests and compiled runtime index. Asset pins in `pins.json` bind the release
ZIP and top executable. The contracts are never imported or executed.

Local validation:

```sh
python3.12 -B -m unittest discover -s tests/ci/native-r5 -p 'test_*.py' -v
git diff --check
```

Primary runner reference (standard/free public labels, including native ARM64):
https://docs.github.com/en/actions/reference/runners/github-hosted-runners
Chromium's documented setuid-helper option, without disabling Ubuntu security:
https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md
Browser attestation, launch and sandbox checks have distinct phases. Failures
publish exact allowlisted harness error codes, fixed literal classifications,
signals and boolean file-guard facts. Raw browser diagnostics (at most 64 KiB)
are encrypted in memory with OpenSSL CMS/AES-256-CBC to the pinned public
RSA-3072 recipient certificate. Only `browser-diagnostic.cms` (at most 128 KiB)
may be uploaded. The boundary accepts only definite canonical DER EnvelopedData:
one RSA-3072 key-transport recipient matching the pinned certificate's exact
issuer/serial, AES-256-CBC with a 16-byte IV, and bounded ciphertext. Data,
SignedData, extra recipients/attributes, other ciphers and trailing bytes fail.
No private
key or plaintext diagnostic file enters the checkout or artifact. Encryption
failure preserves the original test failure and reports only a fixed error type.
Controlled text and JSON reads/writes use UTF-8 explicitly on every platform.
Official action SHAs were verified from upstream v4.2.2 checkout, v5.6.0
setup-python and v4.6.2 upload-artifact tags. The local macOS checks do not prove
Windows/Linux runtime success; that requires the actual reviewed CI run.
