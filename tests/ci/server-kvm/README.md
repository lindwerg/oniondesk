# Real KVM server CI

This workflow runs only in a **public** repository on the standard free
GitHub-hosted `ubuntu-24.04` runner. It refuses local and self-hosted execution.
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
probe with QMP `query-kvm`; official Whonix 18.2.1.9 HTTPS download, SHA-512 and
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
raw command output, journal or disk image is exported. Chromium uses an isolated
temporary profile and no sandbox only inside this disposable root container.
Artifacts are capped at 8 MiB and expire after one day. Container logging is
disabled; installer output is bounded to 64 KiB in memory and never forwarded.
Cleanup verifies a random ownership label before removing immutable container
and image IDs; an `always()` step repeats cleanup after interruption.

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

The Debian amd64 digest was resolved from Docker Hub's official `library/debian`
registry manifest for `13-slim`; checkout v4.2.2 was resolved through the official
GitHub API. Runtime success must be established from a completed actual CI run.
