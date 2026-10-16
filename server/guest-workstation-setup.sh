#!/bin/bash
# Run this once from the genuine SYSMAINT boot session; never remove the split.
set -Eeuo pipefail
umask 077
fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
[[ ${EUID} == 0 ]] || fail 'Откройте SYSMAINT session и выполните sudo /usr/local/sbin/oniondesk-workstation-setup'
grep -Eq '(^| )boot-role=sysmaint( |$)' /proc/cmdline || fail 'Нужна загрузка PERSISTENT Mode | SYSMAINT Session. Обычная user session не подходит.'
systemctl --quiet is-active sysmaint-boot.target || fail 'SYSMAINT target не активен; установка остановлена.'
[[ -f /usr/share/anon-ws-base-files/workstation ]] || fail 'Это не Whonix-Workstation.'
[[ $(dpkg-query -W -f='${Status}' user-sysmaint-split) == 'install ok installed' ]] || fail 'Не подтверждён установленный user-sysmaint-split.'
grep -Eq '^VERSION_CODENAME="?trixie"?$' /etc/os-release || fail 'Скрипт подготовлен только для Whonix 18 на Debian trixie.'
mkdir -p /var/lib/oniondesk
chmod 0700 /var/lib/oniondesk
trap 'printf "Установка не завершена. Проверьте соединение Tor на Gateway и повторите эту же команду.\n" >&2' ERR
printf 'Проверяю доступ Workstation к Tor; Gateway должен быть включён и подключён.\n'
tor_ok=false
for attempt in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 15 https://check.torproject.org/api/ip 2>/dev/null |
      python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("IsTor") is True else 1)' 2>/dev/null; then
    tor_ok=true
    break
  fi
  printf 'Ожидание Tor: попытка %s из 60…\n' "$attempt"
  sleep 10
done
[[ $tor_ok == true ]] || fail 'Tor в Workstation не подтверждён. Пакеты не устанавливались.'
if ! grep -rEq '^[^#].*trixie-backports' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  [[ ! -e /etc/apt/sources.list.d/oniondesk-backports.sources ]] || fail 'Уже существует отличающийся oniondesk-backports.sources.'
  cat > /etc/apt/sources.list.d/oniondesk-backports.sources <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y --no-install-recommends -t trixie-backports install telegram-desktop
apt-get -y --no-install-recommends install qemu-guest-agent mat2 zenity
[[ -x /usr/bin/telegram-desktop ]] || fail 'Telegram executable не найден после apt.'
[[ -x /usr/bin/zenity && -x /usr/bin/mat2 && -f /usr/local/lib/oniondesk/clean-files.py && -f /usr/local/lib/oniondesk/auto-cleaner.py && -f /etc/systemd/user/oniondesk-auto-cleaner.service && -f /usr/share/applications/oniondesk-clean-files.desktop ]] || fail 'Не найдены компоненты очистки метаданных.'
python3 -I -c 'from libmat2 import parser_factory; assert callable(parser_factory.get_parser)' || fail 'Не загружается официальный libmat2.'
# Enable the user unit for the next genuine USER login; no desktop daemon runs
# in SYSMAINT. ConditionUser and the helper independently reject maintenance.
systemctl --global enable oniondesk-auto-cleaner.service
systemctl start qemu-guest-agent.service
systemctl --quiet is-active qemu-guest-agent.service || fail 'Guest agent не запустился.'
[[ $(dpkg-query -W -f='${Status}' user-sysmaint-split) == 'install ok installed' ]] || fail 'После apt не подтверждён user-sysmaint-split.'
date --utc --iso-8601=seconds > /var/lib/oniondesk/setup.complete
chmod 0600 /var/lib/oniondesk/setup.complete
printf '\nTelegram, автоматические проверенные копии загрузок и guest agent установлены. Workstation выключается.\nНа сервере: sudo /opt/oniondesk/server/control.sh start\nПри следующем старте выберите обычную USER session, если появится меню GRUB.\n'
systemctl poweroff

