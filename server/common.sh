#!/bin/bash
# Shared paths; all administrative scripts are deliberately root-only.
set -Eeuo pipefail
umask 077
# These module constants are consumed by scripts that source this file.
# shellcheck disable=SC2034
readonly INSTALL_ROOT=/opt/oniondesk STATE_ROOT=/var/lib/oniondesk \
  IMAGE_ROOT=/var/lib/libvirt/images/oniondesk LIBVIRT_URI=qemu:///system \
  GATEWAY=oniondesk-gateway WORKSTATION=oniondesk-workstation
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
need_root() { [[ ${EUID} == 0 ]] || die 'Запустите эту команду через sudo.'; }
vsh() { virsh --connect "$LIBVIRT_URI" "$@"; }
is_active_domain() {
  local names
  names=$(vsh list --name) || die 'Не удалось прочитать состояние libvirt; оно не считается выключенным.'
  printf '%s\n' "$names" | rg_exact "$1"
}
rg_exact() { grep -Fxq -- "$1"; }
wait_runtime_audit() {
  local attempt
  for ((attempt=0; attempt<10; attempt++)); do
    if python3 -B "$INSTALL_ROOT/server/runtime-audit.py" >/dev/null 2>&1; then
      python3 -B "$INSTALL_ROOT/server/runtime-audit.py"
      return
    fi
    sleep 1
  done
  python3 -B "$INSTALL_ROOT/server/runtime-audit.py"
}

