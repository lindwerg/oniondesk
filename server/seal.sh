#!/bin/bash
# The explicit confirmation flags attest facts that cannot be inferred remotely.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/common.sh"
need_root
[[ $# == 3 && $1 == --onion-confirmed && $2 == --provider-console-confirmed && $3 == --confirm-disable-ssh ]] || die 'Сначала проверьте вход через onion, пароль + TOTP, обе VM и консоль провайдера. Затем: sudo /opt/oniondesk/server/seal.sh --onion-confirmed --provider-console-confirmed --confirm-disable-ssh'
[[ -f /var/lib/tor/oniondesk/hostname ]] || die 'Onion hostname отсутствует.'
hostname=$(cat /var/lib/tor/oniondesk/hostname)
[[ $hostname =~ ^[a-z2-7]{56}\.onion$ ]] || die 'Неверный onion hostname.'
systemctl --quiet is-active nginx.service || die 'Nginx не работает.'
systemctl --quiet is-active oniondesk-auth.service || die 'Auth service не работает.'
python3 -B "$SCRIPT_DIR/runtime-audit.py" || die 'Изоляция/службы host не подтверждены; SSH сохраняется.'
python3 -B "$SCRIPT_DIR/guest-status.py" || die 'Tor/Telegram в Workstation ещё не готовы; SSH сохраняется.'
for endpoint in gateway workstation; do
  code=$(curl --silent --show-error --max-time 60 --socks5-hostname 127.0.0.1:9050 --output /dev/null --write-out '%{http_code}' "http://$hostname/ws/$endpoint")
  [[ $code == 401 || $code == 302 || $code == 303 || $code == 307 || $code == 308 ]] || die "Onion auth gate /ws/$endpoint вернул $code; SSH сохраняется."
done
printf 'Проверки пройдены. Останавливаю SSH; правила firewall не удаляются и не заменяются.\n'
for unit in ssh.socket ssh.service sshd.socket sshd.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable --now "$unit"; fi
done
mkdir -p "$STATE_ROOT"
date --utc --iso-8601=seconds > "$STATE_ROOT/ssh-sealed"
printf 'SSH отключён. Восстановление из консоли провайдера: systemctl enable --now ssh.service\n'

