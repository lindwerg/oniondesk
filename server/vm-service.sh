#!/bin/bash
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/common.sh"
need_root
case ${1:-} in
  start)
    python3 -B "$SCRIPT_DIR/runtime-audit.py" --pre-start
    for domain in "$GATEWAY" "$WORKSTATION"; do
      vsh dominfo "$domain" >/dev/null || die "Не найдена VM $domain."
      if ! is_active_domain "$domain"; then vsh start "$domain"; fi
    done
    python3 -B "$SCRIPT_DIR/runtime-audit.py" --topology-only
    ;;
  stop)
    for domain in "$WORKSTATION" "$GATEWAY"; do
      if is_active_domain "$domain"; then
        vsh shutdown "$domain"
        for ((attempt=0; attempt<60; attempt++)); do
          if ! is_active_domain "$domain"; then break; fi
          sleep 2
        done
        if is_active_domain "$domain"; then
          die "$domain не ответила на корректное выключение. Она оставлена работающей; принудительного destroy нет."
        fi
      fi
    done
    ;;
  *) die 'Допустимо: vm-service.sh start|stop' ;;
esac

