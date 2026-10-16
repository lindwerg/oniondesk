#!/usr/bin/env bash
set -Eeuo pipefail
oniondesk_test_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
oniondesk_test_logs=${1:?Usage: tests/docker/run.sh ABSOLUTE_LOG_DIRECTORY}
[[ $oniondesk_test_logs == /* ]] || { printf '%s\n' 'Log directory must be absolute.' >&2; exit 2; }
mkdir -p "$oniondesk_test_logs"
docker build --label oniondesk-test=true -t oniondesk-test:debian13 "$oniondesk_test_root/tests/docker" > "$oniondesk_test_logs/build.log" 2>&1
docker run --rm --label oniondesk-test=true --name "oniondesk-test-$PPID-$$" \
  --shm-size=512m --mount "type=bind,source=$oniondesk_test_root,target=/workspace/outputs/remote-desktop-kit,readonly" \
  --mount "type=bind,source=$oniondesk_test_logs,target=/logs" \
  oniondesk-test:debian13 bash /workspace/outputs/remote-desktop-kit/tests/docker/inside.sh
