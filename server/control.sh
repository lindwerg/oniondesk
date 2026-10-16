#!/bin/bash
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/common.sh"
need_root
onion_hostname() { cat /var/lib/tor/oniondesk/hostname; }
first_setup() {
  if [[ -f $STATE_ROOT/tor-mode && $(cat "$STATE_ROOT/tor-mode") == wizard ]]; then
    printf 'Если Tor ещё не подключён, откройте Anon Connection Wizard в Gateway и выберите Connect/bridges.\n'
  fi
  python3 -B "$SCRIPT_DIR/first_boot.py" finish
}
status() {
  printf 'Onion адрес: http://%s/\n' "$(onion_hostname)"
  for unit in tor@default nginx oniondesk-auth oniondesk-vms oniondesk-websockify-gateway oniondesk-websockify-workstation; do
    printf '%-38s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
  vsh domstate "$GATEWAY"
  vsh domstate "$WORKSTATION"
  if ! python3 -B "$SCRIPT_DIR/runtime-audit.py"; then
    printf 'НЕ ГОТОВО: текущая изоляция/службы host не подтверждены. Устраните причину отказа.\n'
    return 0
  fi
  python3 -B "$SCRIPT_DIR/guest-status.py" || true
  printf 'Telegram login и ввод кода выполняются самим пользователем в обычной USER session.\n'
}
credentials() {
  [[ -f /etc/oniondesk/credentials.json ]] || die 'Файл credentials.json отсутствует.'
  [[ -t 1 ]] || die 'Секреты показываются только в терминале; перенаправление в файл запрещено.'
  python3 -B - <<'PY'
import json, os, stat
path = '/etc/oniondesk/credentials.json'
metadata = os.stat(path)
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit('Небезопасные права credentials.json: ожидается root:0600.')
with open(path) as source:
    data = json.load(source)
for key in ('login', 'password', 'totp_secret', 'otpauth_uri'):
    print(key + ': ' + data[key])
PY
}
update() {
  printf 'Обновляю установленные серверные пакеты; данные VM сохраняются.\n'
  apt-get update
  apt-get -y --only-upgrade install tor nginx novnc websockify qemu-system-x86 qemu-system-gui qemu-utils libvirt-daemon-system libvirt-clients passt
  # Debian noVNC embeds an inline bootstrap. Recompute its CSP hashes after upgrades.
  bash "$INSTALL_ROOT/frontend/install-auth.sh" "$(onion_hostname)"
  chmod 0700 /etc/oniondesk
  chmod 0711 "$STATE_ROOT"
  nginx -t
  systemctl reload nginx.service
  printf '\nГостевые обновления выполняйте в SYSMAINT session:\n  sudo apt update && sudo apt full-upgrade\nДля Telegram: sudo apt -t trixie-backports install telegram-desktop\n'
}
run_action() {
  case $1 in
    status) status ;;
    auto-cleaner)
      python3 -B "$SCRIPT_DIR/runtime-audit.py" >/dev/null
      python3 -B "$SCRIPT_DIR/guest-status.py" --auto-cleaner
      ;;
    start)
      "$SCRIPT_DIR/vm-service.sh" start
      systemctl start oniondesk-vms.service oniondesk-websockify-gateway.service oniondesk-websockify-workstation.service
      wait_runtime_audit
      printf 'VM запущены. Готовность проверяется отдельно: control.sh status\n'
      ;;
    stop)
      "$SCRIPT_DIR/vm-service.sh" stop
      systemctl stop oniondesk-vms.service
      printf 'VM выключены корректно; диски и данные Telegram сохранены.\n'
      ;;
    update) update ;;
    credentials) credentials ;;
    first-setup) first_setup ;;
    diagnostics) python3 -B "$SCRIPT_DIR/preflight.py"; python3 -B "$SCRIPT_DIR/runtime-audit.py"; vsh version ;;
    *) die 'Доступно: status|start|stop|update|credentials|first-setup|diagnostics|auto-cleaner' ;;
  esac
}
if [[ $# -gt 0 ]]; then run_action "$1"; exit; fi
while true; do
  printf '\n1 Состояние  2 Запуск  3 Выключение  4 Обновление  5 Доступ  6 Первичная настройка  0 Выход\n'
  read -r -p '> ' choice
  case $choice in
    1) run_action status ;; 2) run_action start ;; 3) run_action stop ;;
    4) run_action update ;; 5) run_action credentials ;; 6) run_action first-setup ;;
    0) exit 0 ;; *) printf 'Выберите пункт 0–6.\n' ;;
  esac
done

