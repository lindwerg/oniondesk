#!/bin/bash
# Fresh dedicated Debian 13 host only. Does not delete domains, disks or snapshots.
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
KIT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
source "$SCRIPT_DIR/common.sh"
VERSION=18.2.1.9
ARCHIVE_NAME=Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz
DOWNLOAD_BASE=https://download.whonix.org/libvirt/18.2.1.9
archive='' signature='' tor_mode='' licenses=no check=no
usage() {
  cat <<'EOF'
Fresh Debian 13 amd64: sudo bash server/install.sh [OPTIONS]
  --check                 Только проверка, без изменений и загрузок
  --yes-licenses          Я прочитал и принимаю лицензии/условия Whonix
  --tor-mode wizard       Первый GUI Connect to Tor / bridges (рекомендуется)
  --tor-mode direct       Явно разрешить прямое подключение GW к публичному Tor
  --tor-mode public-obfs4  Подключить host и GW через комплектный публичный мост
  --archive FILE          Локальный официальный архив, подпись обязательна
  --signature FILE        Подпись локального архива (по умолчанию FILE.asc)
Debian 12, VPS без /dev/kvm и готовые production hosts не поддерживаются.
EOF
}
while [[ $# -gt 0 ]]; do
  case $1 in
    --check) check=yes; shift ;;
    --yes-licenses) licenses=yes; shift ;;
    --tor-mode) [[ $# -ge 2 ]] || die 'Нет значения --tor-mode.'; tor_mode=$2; shift 2 ;;
    --archive) [[ $# -ge 2 ]] || die 'Нет значения --archive.'; archive=$2; shift 2 ;;
    --signature) [[ $# -ge 2 ]] || die 'Нет значения --signature.'; signature=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done
command -v python3 >/dev/null || die 'Нужен python3 для безопасной проверки host; свежий Debian installer должен включать python3.'
python3 -B "$SCRIPT_DIR/preflight.py"
[[ $check == no ]] || exit 0
need_root
[[ -z $tor_mode || $tor_mode == wizard || $tor_mode == direct || $tor_mode == public-obfs4 ]] || die '--tor-mode должен быть wizard, direct или public-obfs4.'
[[ -d $KIT_ROOT/frontend && -f $KIT_ROOT/frontend/install-auth.sh ]] || die 'Не найден frontend/install-auth.sh; нужен полный комплект.'
if [[ $licenses != yes ]]; then
  [[ -t 0 ]] || die 'Нужен --yes-licenses после прочтения условий Whonix.'
  printf 'Прочитайте условия: https://www.whonix.org/wiki/License_Agreement и https://www.whonix.org/wiki/Terms_of_Service\n'
  read -r -p 'Введите YES, если принимаете условия Whonix: ' answer
  [[ $answer == YES ]] || die 'Условия не приняты; изменений нет.'
fi
if [[ -z $tor_mode ]]; then
  [[ -t 0 ]] || die 'Нужен явный --tor-mode wizard, direct или public-obfs4.'
  read -r -p 'Tor в Gateway: wizard (GUI) / direct (публичный Tor) / public-obfs4 (публичный мост): ' tor_mode
  [[ $tor_mode == wizard || $tor_mode == direct || $tor_mode == public-obfs4 ]] || die 'Неверный выбор; изменений нет.'
fi
[[ -z $signature || -n $archive ]] || die '--signature используется вместе с --archive.'
if [[ -n $archive ]]; then
  archive=$(realpath -- "$archive")
  [[ -n $signature ]] || signature=$archive.asc
  signature=$(realpath -- "$signature")
  [[ -f $archive && -f $signature ]] || die 'Для локального архива нужна существующая отделённая .asc подпись.'
fi
for path in "$INSTALL_ROOT" "$STATE_ROOT" "$IMAGE_ROOT" /etc/oniondesk /etc/tor/oniondesk.conf; do
  [[ ! -e $path ]] || die "$path уже существует. Повторная установка остановлена; существующие данные сохраняются. Для установленного комплекта используйте control.sh."
done
trap 'printf "Установка остановлена на строке %s. Диски/VM не удалялись; Nginx может оставаться masked. Не выполняйте повторную установку поверх существующих данных. Для нового старта проверьте частичное состояние и сохранность данных; переустановка Debian 13 на этом свежем сервере через панель провайдера удаляет его данные и требует вашего отдельного решения.\n" "$LINENO" >&2' ERR
export DEBIAN_FRONTEND=noninteractive
# Prevent Debian's default site from briefly opening public port 80 during apt.
systemctl mask nginx.service tor.service tor@default.service
apt-get update
tor_packages=()
if [[ $tor_mode == public-obfs4 ]]; then tor_packages=(obfs4proxy); fi
apt-get -y --no-install-recommends install qemu-system-x86 qemu-system-gui qemu-utils libvirt-daemon-system libvirt-clients passt libguestfs-tools libxml2-utils grub-common python3 curl ca-certificates gnupg gpgv xz-utils tor nginx novnc websockify iproute2 openssl "${tor_packages[@]}"
python3 -B - <<'PY'
import subprocess
reserved_tcp = {80, 443, 5901, 5902, 16081, 16082, 18080, 18081}
for mode, reserved in (('-ltn', reserved_tcp), ('-lun', {5577, 6688})):
    output = subprocess.run(['ss', '-H', mode], check=True, capture_output=True, text=True).stdout
    for row in output.splitlines():
        fields = row.split()
        if len(fields) >= 4:
            try:
                port = int(fields[3].rsplit(':', 1)[-1])
            except ValueError:
                continue
            if port in reserved:
                raise SystemExit(f'Порт {port} уже занят. Существующие службы не изменяются; установка остановлена.')
PY
if systemctl cat libvirtd.socket >/dev/null 2>&1; then
  systemctl enable --now libvirtd.socket
elif systemctl cat virtqemud.socket >/dev/null 2>&1; then
  systemctl enable --now virtqemud.socket
else
  die 'Не найден штатный libvirt system socket.'
fi
vsh version >/dev/null
for domain in "$GATEWAY" "$WORKSTATION"; do
  if vsh list --all --name | grep -Fxq "$domain"; then die "Уже есть $domain; она не изменяется."; fi
done
vsh capabilities | python3 -c 'import sys,xml.etree.ElementTree as E; r=E.parse(sys.stdin); sys.exit(0 if r.find(".//domain[@type=\"kvm\"]") is not None else 1)'
qemu_uid=$(id -u libvirt-qemu)
qemu_gid=$(id -g libvirt-qemu)
[[ $qemu_uid != 0 ]] || die 'libvirt-qemu не должен быть root.'
if grep -Eq '^[[:space:]]*(user|group)[[:space:]]*=' /etc/libvirt/qemu.conf; then
  die 'qemu.conf переопределяет user/group; нужен свежий Debian с штатным non-root libvirt-qemu.'
fi
mkdir -m 0700 "$INSTALL_ROOT" "$STATE_ROOT" /etc/oniondesk
mkdir -m 0700 "$INSTALL_ROOT/server" "$STATE_ROOT/staging"
mkdir -p "$IMAGE_ROOT"
chmod 0700 "$IMAGE_ROOT"
cp -a -- "$SCRIPT_DIR/." "$INSTALL_ROOT/server/"
cp -a -- "$KIT_ROOT/frontend" "$INSTALL_ROOT/frontend"
chown -R --no-dereference root:root "$INSTALL_ROOT"
chmod 0700 "$INSTALL_ROOT/server" "$INSTALL_ROOT/frontend"
chmod 0750 "$INSTALL_ROOT/server/"*.sh
chown "$qemu_uid:$qemu_gid" "$IMAGE_ROOT"
stage=$(mktemp -d "$STATE_ROOT/staging/install.XXXXXXXX")
chmod 0700 "$stage"
download() { curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 8 --retry-all-errors --retry-max-time 1800 --connect-timeout 20 --max-time 3600 --output "$2" "$1"; }
if [[ -z $archive ]]; then
  archive=$stage/$ARCHIVE_NAME
  signature=$archive.asc
  printf 'Загружаю официальный Whonix %s (примерно 4 GiB).\n' "$VERSION"
  download "$DOWNLOAD_BASE/$ARCHIVE_NAME" "$archive"
  download "$DOWNLOAD_BASE/$ARCHIVE_NAME.asc" "$signature"
fi
download https://www.whonix.org/keys/derivative.asc "$stage/derivative.asc"
bash "$INSTALL_ROOT/server/verify-image.sh" "$archive" "$signature" "$stage/derivative.asc" "$stage"
mkdir -m 0700 "$stage/extracted"
tar --extract --sparse --file "$archive" --directory "$stage/extracted" \
  WHONIX_BINARY_LICENSE_AGREEMENT WHONIX_DISCLAIMER Whonix-Gateway.xml Whonix-Workstation.xml \
  "Whonix-Gateway-LXQt-$VERSION.Intel_AMD64.qcow2" "Whonix-Workstation-LXQt-$VERSION.Intel_AMD64.qcow2"
for role in gateway workstation; do
  if [[ $role == gateway ]]; then upstream=Whonix-Gateway; else upstream=Whonix-Workstation; fi
  source_disk=$stage/extracted/$upstream-LXQt-$VERSION.Intel_AMD64.qcow2
  qemu-img info --output=json "$source_disk" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("format")=="qcow2" and not d.get("backing-filename") else 1)'
  python3 -B "$INSTALL_ROOT/server/validate-guest.py" --role "$role" --disk "$source_disk"
  python3 -B "$INSTALL_ROOT/server/image_tools.py" transform --input "$stage/extracted/$upstream.xml" --output "$stage/$role.xml" --role "$role" --disk "$IMAGE_ROOT/$role.qcow2"
  virt-xml-validate "$stage/$role.xml" domain
done
ws_disk=$stage/extracted/Whonix-Workstation-LXQt-$VERSION.Intel_AMD64.qcow2
guestfish --rw --format=qcow2 -a "$ws_disk" -i \
  mkdir-p /usr/local/sbin : mkdir-p /usr/local/lib/oniondesk : \
  upload "$INSTALL_ROOT/server/guest-workstation-setup.sh" /usr/local/sbin/oniondesk-workstation-setup : \
  chmod 0755 /usr/local/sbin/oniondesk-workstation-setup : \
  upload "$INSTALL_ROOT/server/guest-workstation-status.py" /usr/local/lib/oniondesk/workstation-status.py : \
  chmod 0644 /usr/local/lib/oniondesk/workstation-status.py : \
  upload "$INSTALL_ROOT/server/guest-clean-files.py" /usr/local/lib/oniondesk/clean-files.py : \
  chmod 0644 /usr/local/lib/oniondesk/clean-files.py : \
  upload "$INSTALL_ROOT/server/guest-auto-cleaner.py" /usr/local/lib/oniondesk/auto-cleaner.py : \
  chmod 0644 /usr/local/lib/oniondesk/auto-cleaner.py : \
  mkdir-p /etc/systemd/user : \
  upload "$INSTALL_ROOT/server/oniondesk-auto-cleaner.service" /etc/systemd/user/oniondesk-auto-cleaner.service : \
  chmod 0644 /etc/systemd/user/oniondesk-auto-cleaner.service : \
  mkdir-p /usr/share/applications : \
  upload "$INSTALL_ROOT/server/oniondesk-clean-files.desktop" /usr/share/applications/oniondesk-clean-files.desktop : \
  chmod 0644 /usr/share/applications/oniondesk-clean-files.desktop
gw_disk=$stage/extracted/Whonix-Gateway-LXQt-$VERSION.Intel_AMD64.qcow2
for role in gateway workstation; do
  if [[ $role == gateway ]]; then disk=$gw_disk; else disk=$ws_disk; fi
  python3 -B "$INSTALL_ROOT/server/first_boot.py" stage --role "$role" --disk "$disk" \
    --stage-dir "$stage" --tor-mode "$tor_mode" --licenses-accepted
done
if [[ $tor_mode == direct ]]; then
  printf '# Direct public Tor explicitly selected during installation.\nDisableNetwork 0\n' > "$stage/gateway-tor.conf"
  guestfish --rw --format=qcow2 -a "$gw_disk" -i \
    mkdir-p /usr/local/etc/torrc.d : upload "$stage/gateway-tor.conf" /usr/local/etc/torrc.d/40_tor_control_panel.conf : \
    chmod 0644 /usr/local/etc/torrc.d/40_tor_control_panel.conf
fi
for role in gateway workstation; do
  if [[ $role == gateway ]]; then upstream=Whonix-Gateway; else upstream=Whonix-Workstation; fi
  [[ ! -e $IMAGE_ROOT/$role.qcow2 ]] || die 'Диск назначения уже существует.'
  mv -- "$stage/extracted/$upstream-LXQt-$VERSION.Intel_AMD64.qcow2" "$IMAGE_ROOT/$role.qcow2"
  chown "$qemu_uid:$qemu_gid" "$IMAGE_ROOT/$role.qcow2"
  chmod 0600 "$IMAGE_ROOT/$role.qcow2"
  vsh define "$stage/$role.xml"
done
if ! id oniondesk-proxy >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oniondesk-proxy
fi
cat > /etc/systemd/system/oniondesk-vms.service <<'EOF'
[Unit]
Description=OnionDesk Whonix virtual machines
After=libvirtd.socket virtqemud.socket libvirtd.service virtqemud.service network.target
Before=oniondesk-websockify-gateway.service oniondesk-websockify-workstation.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/oniondesk/server/vm-service.sh start
ExecStop=/opt/oniondesk/server/vm-service.sh stop
TimeoutStartSec=90
TimeoutStopSec=260
[Install]
WantedBy=multi-user.target
EOF
for role in gateway workstation; do
  if [[ $role == gateway ]]; then web_port=16081; vnc_port=5901; else web_port=16082; vnc_port=5902; fi
  cat > "/etc/systemd/system/oniondesk-websockify-$role.service" <<EOF
[Unit]
Description=OnionDesk loopback noVNC proxy ($role)
After=oniondesk-vms.service
Requires=oniondesk-vms.service
[Service]
User=oniondesk-proxy
Group=oniondesk-proxy
ExecStart=/usr/bin/websockify --web /usr/share/novnc 127.0.0.1:$web_port 127.0.0.1:$vnc_port
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
done
chmod 0644 /etc/systemd/system/oniondesk-*.service
python3 -B "$INSTALL_ROOT/server/host_tor.py" configure --tor-mode "$tor_mode"
if ! grep -Fxq '%include /etc/tor/oniondesk.conf' /etc/tor/torrc; then
  printf '\n# OnionDesk dedicated onion ingress\n%%include /etc/tor/oniondesk.conf\n' >> /etc/tor/torrc
fi
tor --verify-config --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc
systemctl unmask tor.service tor@default.service
systemctl enable tor@default.service
# Restart applies transport binary changes and replaces any old control cookie.
systemctl restart tor@default.service
tor_pid=$(systemctl show tor@default.service --property=MainPID --value)
bootstrap_args=()
if [[ $tor_mode == public-obfs4 ]]; then bootstrap_args=(--public-obfs4); fi
python3 -B "$INSTALL_ROOT/server/host_tor.py" wait --pid "$tor_pid" "${bootstrap_args[@]}" > "$STATE_ROOT/host-tor-bootstrap.json"
chmod 0600 "$STATE_ROOT/host-tor-bootstrap.json"
for ((attempt=0; attempt<60; attempt++)); do
  [[ ! -s /var/lib/tor/oniondesk/hostname ]] || break
  sleep 2
done
[[ -s /var/lib/tor/oniondesk/hostname ]] || die 'Tor не создал onion hostname; SSH не менялся.'
hostname=$(cat /var/lib/tor/oniondesk/hostname)
[[ $hostname =~ ^[a-z2-7]{56}\.onion$ ]] || die 'Tor вернул неправильный onion hostname.'
bash "$INSTALL_ROOT/frontend/install-auth.sh" "$hostname"
# The frontend hook normalizes parent directory modes; host secrets/state
# retain their stricter permissions after its package-readable code install.
chmod 0700 /etc/oniondesk
chmod 0711 "$STATE_ROOT"
nginx -t
systemctl unmask nginx.service
systemctl enable --now nginx.service
printf '{"phase":"maintenance"}\n' > "$STATE_ROOT/first-boot.pending"
chmod 0600 "$STATE_ROOT/first-boot.pending"
printf '%s\n' "$tor_mode" > "$STATE_ROOT/tor-mode"
systemctl daemon-reload
systemctl enable --now oniondesk-vms.service oniondesk-websockify-gateway.service oniondesk-websockify-workstation.service
for domain in "$GATEWAY" "$WORKSTATION"; do
  pid=$(cat "/run/libvirt/qemu/$domain.pid")
  uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$pid/status")
  [[ $uid == "$qemu_uid" && $uid != 0 ]] || die 'QEMU запущен под неожиданным UID; готовность не подтверждается.'
done
for role in gateway workstation; do
  code=$(curl --silent --show-error --max-time 10 --header "Host: $hostname" --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:18080/ws/$role")
  [[ $code == 401 || $code == 302 || $code == 303 || $code == 307 || $code == 308 ]] || die "Auth gate /ws/$role не подтверждён (HTTP $code)."
done
printf '%s\n' "$VERSION" > "$STATE_ROOT/image-version"
wait_runtime_audit
date --utc --iso-8601=seconds > "$STATE_ROOT/host-installed"
chown root:root "$STATE_ROOT/host-installed"
chmod 0600 "$STATE_ROOT/host-installed"
printf '\nСерверный доступ настроен: http://%s/\n' "$hostname"
printf 'SSH сохранён. Готовность Telegram/Tor пока НЕ подтверждена.\n'
printf 'Получить доступ отдельно: sudo /opt/oniondesk/server/control.sh credentials\n'
if [[ $tor_mode == wizard ]]; then
  printf 'В Gateway откройте Anon Connection Wizard и подключите Tor/bridges. Workstation готовится автоматически.\n'
  printf 'После подключения Tor выполните: sudo /opt/oniondesk/server/control.sh first-setup\n'
else
  "$INSTALL_ROOT/server/control.sh" first-setup
fi
printf '\nДанные Telegram сохраняются на диске Workstation между перезагрузками.\n'
printf 'После первичной настройки: sudo /opt/oniondesk/server/control.sh status\n'

