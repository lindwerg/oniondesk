#!/usr/bin/env bash
set -Eeuo pipefail
oniondesk_test_kit=/workspace/outputs/remote-desktop-kit
oniondesk_test_archive=/artifacts/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz
oniondesk_test_free=$(df -PB1 /artifacts | awk 'NR == 2 {print $4}')
[[ $oniondesk_test_free =~ ^[0-9]+$ && $oniondesk_test_free -ge 53687091200 ]] || {
  printf '%s\n' 'Guest extraction requires at least 50 GiB available on the mounted physical artifact filesystem.' >&2
  exit 1
}
mkdir -p /run/image-verification /artifacts/extracted
bash "$oniondesk_test_kit/server/verify-image.sh" "$oniondesk_test_archive" \
  "$oniondesk_test_archive.asc" /artifacts/derivative.asc /run/image-verification > /logs/image-verification.log 2>&1
tar --extract --sparse --verbose --file "$oniondesk_test_archive" --directory /artifacts/extracted \
  WHONIX_BINARY_LICENSE_AGREEMENT WHONIX_DISCLAIMER Whonix-Gateway.xml Whonix-Workstation.xml \
  Whonix-Gateway-LXQt-18.2.1.9.Intel_AMD64.qcow2 Whonix-Workstation-LXQt-18.2.1.9.Intel_AMD64.qcow2 \
  > /logs/archive-extraction.log 2>&1
export LIBGUESTFS_BACKEND=direct
export LIBGUESTFS_BACKEND_SETTINGS=force_tcg
for oniondesk_test_role in gateway workstation; do
  if [[ $oniondesk_test_role == gateway ]]; then oniondesk_test_upstream=Whonix-Gateway; else oniondesk_test_upstream=Whonix-Workstation; fi
  oniondesk_test_disk="/artifacts/extracted/$oniondesk_test_upstream-LXQt-18.2.1.9.Intel_AMD64.qcow2"
  qemu-img info --output=json "$oniondesk_test_disk" > "/logs/$oniondesk_test_role-image-info.json"
  python3 -B "$oniondesk_test_kit/server/validate-guest.py" --role "$oniondesk_test_role" --disk "$oniondesk_test_disk" \
    > "/logs/$oniondesk_test_role-contract.log" 2>&1
  guestfish --ro --format=qcow2 -a "$oniondesk_test_disk" -i cat /boot/grub/grub.cfg > "/logs/$oniondesk_test_role-grub.cfg"
  guestfish --ro --format=qcow2 -a "$oniondesk_test_disk" -i cat /boot/grub/grubenv > "/logs/$oniondesk_test_role-grubenv"
  python3 -B "$oniondesk_test_kit/server/image_tools.py" transform \
    --input "/artifacts/extracted/$oniondesk_test_upstream.xml" --output "/logs/$oniondesk_test_role-transformed.xml" \
    --role "$oniondesk_test_role" --disk "/var/lib/libvirt/images/oniondesk/$oniondesk_test_role.qcow2"
  virt-xml-validate "/logs/$oniondesk_test_role-transformed.xml" domain > "/logs/$oniondesk_test_role-xml-validation.log" 2>&1
done
