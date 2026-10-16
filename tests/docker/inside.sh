#!/usr/bin/env bash
set -Eeuo pipefail
oniondesk_test_kit=/workspace/outputs/remote-desktop-kit
dpkg-query -W qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients passt libguestfs-tools \
  python3 gnupg gpgv tor nginx novnc websockify chromium shellcheck > /logs/packages.log
/opt/testenv/bin/pip install --no-cache-dir -r "$oniondesk_test_kit/client/requirements.txt" > /logs/client-dependencies.log 2>&1
oniondesk_test_status=0
/opt/testenv/bin/python -B -m unittest discover -s "$oniondesk_test_kit/tests/docker/unit" -v > /logs/unit.log 2>&1 || oniondesk_test_status=1
runuser -u nobody -- /usr/bin/python3 -B -m unittest discover \
  -s "$oniondesk_test_kit/tests/docker/unit" -p test_metadata_cleaner.py -v \
  > /logs/metadata-unprivileged.log 2>&1 || oniondesk_test_status=1
find "$oniondesk_test_kit/server" "$oniondesk_test_kit/frontend" "$oniondesk_test_kit/client" "$oniondesk_test_kit/tests/docker" -type f -name '*.sh' -print0 |
  xargs -0 shellcheck -x --source-path=SCRIPTDIR > /logs/shellcheck.log 2>&1 || oniondesk_test_status=1
/opt/testenv/bin/python -B "$oniondesk_test_kit/tests/docker/smoke.py" > /logs/smoke.log 2>&1 || oniondesk_test_status=1
/opt/testenv/bin/python -B "$oniondesk_test_kit/tests/docker/app-smoke.py" > /logs/app-smoke.log 2>&1 || oniondesk_test_status=1
[[ $oniondesk_test_status == 0 ]] || { printf '%s\n' 'Docker checks found failures; see mounted logs.' >&2; exit 1; }
printf '%s\n' 'All Docker checks passed; see mounted logs.'
