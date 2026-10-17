# Real KVM server CI

This workflow runs only in a **public** repository on the standard free
GitHub-hosted `ubuntu-26.04` runner. It refuses local and self-hosted execution.
No larger runner, paid service, persistent cache, host Docker socket or host
filesystem/cgroup bind is used. Do not run it against an existing server.

The ephemeral privileged Docker container runs genuine Debian 13 userland and
systemd PID 1, using the runner's actual `/dev/kvm` and kernel. It is a container
integration test, not a physical Debian host test or host reboot test. Docker's
privileged mode is restricted to this trusted, disposable GitHub job. A real
Debian kernel package supplies the libguestfs appliance kernel. Production
installer, checks, signature/TLS validation and all 29 launcher payload files
are copied unchanged; their exact commit and before/after hashes are recorded.

Stages: genuine production preflight; `KVM_CREATE_VM`; a non-root libvirt KVM
probe with QMP `query-kvm`; two diskless probes adding the Whonix memory settings
and then the production `passt` backend, before any Whonix download;
official Whonix 18.2.1.9 HTTPS download, SHA-512 and
OpenPGP verification through the production installer; automatic SYSMAINT/USER
first boot and current production audit; graceful shutdown and cold boot of
both actual guests; password/TOTP login through the real onion/Tor route in
headless Chromium and live authenticated noVNC for both guests. RDP is not a
component of this server contract and is not claimed. No Telegram account,
phone registration, payment or external user account is created.

The explicitly selected production route defaults to `direct` for this
uncensored CI network. Manual dispatch may select `public-obfs4` as a separate
test. There is no fallback, retry loop or altered bridge/check configuration.
`--yes-licenses` is passed for the authorized isolated test. The installer has
an 85-minute bound, the container invocation 100 minutes, and the entire job
120 minutes. Interactive setup or any other incomplete state fails the job;
no marker or readiness report is invented to continue past it.

Public evidence is limited to fixed status fields, safe numeric hardware facts,
exact source hashes, and pixels from this run's unpersonalized guests/noVNC
canvases. No host onion address, credentials, private host keys, browser profile,
raw command output, journal or disk image is exported. Chromium runs under a
dedicated non-root account with a private home/profile and the packaged sandbox;
its own `chrome://sandbox/` evaluation must confirm adequate sandboxing before
the onion route is tested. Credentials reach the child only over an anonymous
pipe; no sandbox, AppArmor, namespace or host security setting is disabled.
Artifacts are capped at 8 MiB and expire after one day. Container logging is
disabled; installer output is bounded to 64 KiB in memory and never forwarded.
Cleanup verifies a random ownership label before removing immutable container
and image IDs; an `always()` step repeats cleanup after interruption.

On installer failure, the harness observes the existing production ERR trap's
bounded reported line number (Bash may report the currently executing shared
function's line). It publishes fixed error signatures, static source
error-site tokens such as `validate_guest_L53`, milestone existence booleans,
domain/process state booleans, unit state booleans and a small exit status.
Three read-only audit modes publish only allowlisted check tokens and booleans;
unknown identifiers and every detail/message remain private. Error-site tokens
are derived by AST parsing literal error strings in the hash-verified payload,
without executing it. Bounded private journal/QEMU log tails are reduced to
these same tokens and never copied to artifacts. Successful SYSMAINT staging
messages do not imply a first-boot failure.

The permission diagnostic records uid/gid/mode only for a fixed public list of
libvirt image ancestry, the two known disks and runtime/device/binary paths.
It checks effective search/read access using the stock `libvirt-qemu` account,
without changing permissions. Denial lines are reduced to fixed resource and
operation tokens; unknown path suffixes and all messages stay private. After
the original failure snapshot, one separately labeled `virsh start` retry of
the unchanged Gateway is permitted only when both owned domains are defined
and shut off, no QEMU PID exists, the pre-start audit passes and the VM unit
has failed. This retry can mutate this disposable guest's first-boot state;
it never changes the failed installer result or satisfies a readiness gate.

On failure only, up to 64 KiB of private probe stderr and fixed-unit journal
tails are encrypted in memory to the pinned RSA-3072 public recipient shared
with native CI. No plaintext log is written to an artifact or to disk. The
optional `server-diagnostic.cms` envelope is at most 128 KiB and passes the
same reviewed strict DER/CMS boundary before both writing and host export:
exact EnvelopedData, one pinned issuer/serial RSA recipient, AES-256-CBC,
bounded ciphertext, no extra attributes/recipients or trailing bytes. Data,
SignedData, foreign-recipient and alternate-cipher profiles fail closed. Only
the owner-held local private key can decrypt it; no private key is in the
repository, workflow or image. The existing 8 MiB/one-day limit still applies.

The host snapshot only reads the loaded passt/libvirt AppArmor profile names,
the two packaged passt policy files, and bounded kernel denial records filtered
to passt. These private details are published only as
`host-security-diagnostic.cms` under the same pinned recipient and strict CMS
boundary. The container snapshot also reads its package policy and daemon label.
No AppArmor policy is loaded, unloaded, put in complain mode or edited; no host
sysctl or mount changes are made. The current standard Ubuntu 26.04 runner is
selected to obtain its supported packaged policy, while the actual Debian 13
userland, KVM checks and all 29 production source files remain unchanged. The
newer host policy resolving the observed socket denial is a hypothesis until a
real run proves it. Container export reserves 144 KiB for host CMS/JSON so the
total artifact remains below 8 MiB.

During the current guest-maintenance investigation, the existing Workstation
QGA channel may execute only fixed read-only probes: unit properties/journal,
kernel command line, a bounded apt log tail, installed-package status, default
route and the fixed HTTPS Tor check. Gateway gets no guest-agent channel. The
QGA output goes only to a separate pinned `workstation-diagnostic.cms` envelope;
public status contains bounded booleans, uptime and fixed reason tokens.
Unavailable or malformed QGA states never prove a guest service failure. A
terminal failed/non-restarting, missing or condition-failed unit must remain
confirmed for 30 seconds after at least 120 seconds of genuine SYSMAINT uptime.

The diagnostic run stops only its owned installer after such a confirmed
terminal state, or at an explicitly labeled five-minute maintenance cutoff
after host installation. A cutoff remains FAIL/INCOMPLETE and is never described
as a failed guest service or successful installation. The guests remain live.
The installer output tail is also added to private encrypted evidence.
If QGA is unavailable, the existing loopback RFB console opens the vendor's
terminal with its documented Ctrl+Alt+T shortcut, switches QTerminal to fullscreen
with F11, and types a literal read-only status/journal/jobs/package command.
RFB sends each key event separately with a 20 ms pause and preserves the actual
uppercase/punctuation keysym, avoiding input bursts and unwanted Caps Lock changes.
`sudo -n`
never prompts or changes credentials. One console screenshot is encrypted as
`workstation-console.cms`; it is evidence of visible output, not proof that the
command succeeded. Before any console input, a persistent private marker blocks
all public Workstation screenshots, including the outer `--snapshot-only` call.
No new guest agent, service, password, network listener or guest-disk mount is
created. No live guestfish, forced guest shutdown or readiness bypass is used.

Local checks (no Docker/VM start):

```sh
python3 -B -m unittest discover -s tests/ci/server-kvm -p 'test_*.py' -v
bash -n tests/ci/server-kvm/boot.sh
```

Implementation references:

- [Docker run privileges and private cgroup namespace](https://docs.docker.com/reference/cli/docker/container/run/)
- [systemd container interface](https://systemd.io/CONTAINER_INTERFACE/)
- [systemd cgroup delegation](https://systemd.io/CGROUP_DELEGATION/)
- [KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [QEMU query-kvm](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-query-kvm)
- [GitHub standard hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Debian runuser account and HOME behavior](https://manpages.debian.org/trixie/util-linux/runuser.1.en.html)
- [Debian Chromium sandbox package](https://packages.debian.org/trixie/chromium-sandbox)
- [Chromium sandbox evaluation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/resources/sandbox_internals/sandbox_internals.ts)
- [RFB protocol and key events](https://www.rfc-editor.org/rfc/rfc6143.html#section-7.5.4)
- [Vendor terminal and maximize shortcuts](https://github.com/Kicksecure/desktop-config-dist/blob/master/usr/share/desktop-config-dist/labwc/rc.xml)

The Debian amd64 digest was resolved from Docker Hub's official `library/debian`
registry manifest for `13-slim`; checkout v4.2.2 was resolved through the official
GitHub API. Runtime success must be established from a completed actual CI run.
