#!/bin/bash
set -Eeuo pipefail
# These mounts are private to the disposable container. Do not bind host
# /sys or /sys/fs/cgroup: Docker supplies a private, writable cgroup2 mount.
mount --make-rprivate /
mount --make-rshared /
mount -o remount,bind,ro,nosuid,nodev,noexec /sys
exec /lib/systemd/systemd --log-target=console --log-level=warning
