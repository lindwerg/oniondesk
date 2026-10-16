#!/usr/bin/env bash
set -Eeuo pipefail
oniondesk_test_kit=/workspace/outputs/remote-desktop-kit
oniondesk_test_disk=/artifacts/extracted/Whonix-Workstation-LXQt-18.2.1.9.Intel_AMD64.qcow2
oniondesk_test_archive=/artifacts/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz
oniondesk_test_free=$(df -PB1 /artifacts | awk 'NR == 2 {print $4}')
[[ $oniondesk_test_free =~ ^[0-9]+$ && $oniondesk_test_free -ge 53687091200 ]] || {
  printf '%s\n' 'Guest appliance tests require at least 50 GiB free on the mounted physical artifact filesystem.' >&2
  exit 1
}
mkdir -p /run/image-verification
bash "$oniondesk_test_kit/server/verify-image.sh" "$oniondesk_test_archive" \
  "$oniondesk_test_archive.asc" /artifacts/derivative.asc /run/image-verification > /logs/ws-image-verification.log 2>&1
export LIBGUESTFS_BACKEND=direct
export LIBGUESTFS_BACKEND_SETTINGS=force_tcg
qemu-img info --output=json "$oniondesk_test_disk" > /logs/workstation-image-info.json
python3 -B "$oniondesk_test_kit/server/validate-guest.py" --role workstation --disk "$oniondesk_test_disk" \
  > /logs/workstation-contract.log 2>&1
guestfish --ro --format=qcow2 -a "$oniondesk_test_disk" -i cat /boot/grub/grub.cfg > /logs/workstation-grub.cfg
guestfish --ro --format=qcow2 -a "$oniondesk_test_disk" -i cat /boot/grub/grubenv > /logs/workstation-grubenv
python3 -B "$oniondesk_test_kit/server/image_tools.py" transform \
  --input /artifacts/extracted/Whonix-Workstation.xml --output /logs/workstation-transformed.xml \
  --role workstation --disk /var/lib/libvirt/images/oniondesk/workstation.qcow2
virt-xml-validate /logs/workstation-transformed.xml domain > /logs/workstation-xml-validation.log 2>&1
