#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# This hook is called by the host installer AFTER Tor produces its v3 hostname.
if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'Нужен root: запустите установщик через sudo.' >&2
    exit 1
fi
if [[ $# -ne 1 || ! $1 =~ ^[a-z2-7]{56}\.onion$ ]]; then
    printf '%s\n' 'Использование: install-auth.sh <v3-hostname.onion>' >&2
    exit 1
fi
oniondesk_host=$1
oniondesk_source=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
oniondesk_destination=/opt/oniondesk/frontend
oniondesk_site=/etc/nginx/sites-available/oniondesk.conf
oniondesk_enabled=/etc/nginx/sites-enabled/oniondesk.conf
oniondesk_default=/etc/nginx/sites-enabled/default

for oniondesk_command in python3 nginx systemctl useradd getent dpkg-query md5sum; do
    command -v "$oniondesk_command" >/dev/null || {
        printf 'Не найден необходимый компонент: %s\n' "$oniondesk_command" >&2
        exit 1
    }
done
[[ -r /usr/share/novnc/vnc.html ]] || { printf '%s\n' 'Установите пакет novnc перед запуском hook.' >&2; exit 1; }
[[ -d /etc/nginx/sites-enabled && -d /etc/nginx/sites-available ]] || {
    printf '%s\n' 'Ожидается штатная структура Nginx из Debian.' >&2; exit 1;
}
if [[ -e $oniondesk_enabled || -L $oniondesk_enabled ]]; then
    [[ -L $oniondesk_enabled && $(readlink -f -- "$oniondesk_enabled") == "$oniondesk_site" ]] || {
        printf '%s\n' 'Путь oniondesk.conf занят чужим конфигом; установка остановлена.' >&2; exit 1;
    }
fi
if [[ -e $oniondesk_site || -L $oniondesk_site ]]; then
    if [[ ! -f $oniondesk_site || -L $oniondesk_site ]] ||
        ! head -n 1 "$oniondesk_site" | grep -Fxq '# Installed by OnionDesk. Only the local Tor process reaches this listener.'; then
        printf '%s\n' 'Файл oniondesk.conf не принадлежит этому комплекту; установка остановлена.' >&2; exit 1;
    fi
fi

# Only remove Debian's unmodified, package-owned default site symlink.
oniondesk_remove_default=no
if [[ -e $oniondesk_default || -L $oniondesk_default ]]; then
    [[ -L $oniondesk_default && $(readlink -f -- "$oniondesk_default") == /etc/nginx/sites-available/default ]] || {
        printf '%s\n' 'Активный default не является штатной ссылкой Debian; исправьте его вручную.' >&2; exit 1;
    }
    oniondesk_packaged_hash=$(dpkg-query -W -f='${Conffiles}\n' nginx-common |
        awk '$1 == "/etc/nginx/sites-available/default" { print $2 }')
    oniondesk_actual_hash=$(md5sum /etc/nginx/sites-available/default | awk '{print $1}')
    [[ -n $oniondesk_packaged_hash && $oniondesk_actual_hash == "$oniondesk_packaged_hash" ]] || {
        printf '%s\n' 'Штатный default был изменён; он не удалён. Сначала проверьте его вручную.' >&2; exit 1;
    }
    oniondesk_remove_default=yes
fi

if getent passwd oniondesk-auth >/dev/null; then
    [[ $(getent passwd oniondesk-auth | cut -d: -f7) == /usr/sbin/nologin ]] || {
        printf '%s\n' 'Пользователь oniondesk-auth уже существует с другим назначением.' >&2; exit 1;
    }
else
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oniondesk-auth
fi
install -d -o root -g root -m 0755 /opt/oniondesk "$oniondesk_destination" /etc/oniondesk /var/lib/oniondesk
install -d -o oniondesk-auth -g oniondesk-auth -m 0700 /var/lib/oniondesk/auth
for oniondesk_file in auth.py login.html menu.html check-nginx-listeners.py build-nginx-config.py; do
    if [[ $oniondesk_source != "$oniondesk_destination" ]]; then
        install -o root -g root -m 0644 "$oniondesk_source/$oniondesk_file" "$oniondesk_destination/$oniondesk_file"
    else
        chown root:root "$oniondesk_destination/$oniondesk_file"
        chmod 0644 "$oniondesk_destination/$oniondesk_file"
    fi
done
# No password, OTP secret or enrollment URI is written to stdout/stderr.
python3 "$oniondesk_destination/auth.py" init --config-dir /etc/oniondesk --origin "http://$oniondesk_host"
chown root:root /etc/oniondesk/credentials.json /etc/oniondesk/auth.json
chmod 0600 /etc/oniondesk/credentials.json /etc/oniondesk/auth.json
install -o root -g root -m 0644 "$oniondesk_source/oniondesk-auth.service" /etc/systemd/system/oniondesk-auth.service

oniondesk_temp=$(mktemp -d /run/oniondesk-auth-install.XXXXXXXX)
oniondesk_had_site=no
oniondesk_had_link=no
oniondesk_default_removed=no
oniondesk_validated=no
[[ -f $oniondesk_site ]] && { cp -p -- "$oniondesk_site" "$oniondesk_temp/site.previous"; oniondesk_had_site=yes; }
[[ -L $oniondesk_enabled ]] && oniondesk_had_link=yes

oniondesk_cleanup() {
    local oniondesk_status=$?
    if [[ $oniondesk_validated != yes ]]; then
        if [[ $oniondesk_had_site == yes ]]; then
            cp -p -- "$oniondesk_temp/site.previous" "$oniondesk_site"
        else
            rm -f -- "$oniondesk_site"
        fi
        [[ $oniondesk_had_link == yes ]] || rm -f -- "$oniondesk_enabled"
        if [[ $oniondesk_default_removed == yes ]]; then
            ln -s /etc/nginx/sites-available/default "$oniondesk_default"
        fi
        printf '%s\n' 'Проверка не пройдена. Службы не запущены/не перезагружены; изменения сайта Nginx отменены.' >&2
    fi
    rm -rf -- "$oniondesk_temp"
    return "$oniondesk_status"
}
trap oniondesk_cleanup EXIT

python3 "$oniondesk_destination/build-nginx-config.py" "$oniondesk_host" \
    "$oniondesk_source/nginx.conf.in" /usr/share/novnc/vnc.html "$oniondesk_temp/site.new"
install -o root -g root -m 0644 "$oniondesk_temp/site.new" "$oniondesk_site"
[[ $oniondesk_had_link == yes ]] || ln -s "$oniondesk_site" "$oniondesk_enabled"
if [[ $oniondesk_remove_default == yes ]]; then
    rm -- "$oniondesk_default"
    oniondesk_default_removed=yes
    printf '%s\n' 'Отключена только неизменённая штатная ссылка sites-enabled/default из пакета Debian.'
fi

# Both checks must pass before enabling/restarting auth. The host installer
# owns nginx mask/unmask/start/reload and repeats nginx -t before starting it.
nginx -t
nginx -T > "$oniondesk_temp/nginx.expanded"
python3 "$oniondesk_destination/check-nginx-listeners.py" "$oniondesk_temp/nginx.expanded"
oniondesk_validated=yes
systemctl daemon-reload
systemctl enable oniondesk-auth.service
systemctl restart oniondesk-auth.service
systemctl is-active --quiet oniondesk-auth.service
python3 - "$oniondesk_host" <<'PY'
import http.client
import sys
import time

for attempt in range(10):
    connection = http.client.HTTPConnection('127.0.0.1', 18081, timeout=2)
    try:
        connection.request('GET', '/login', headers={'Host': sys.argv[1]})
        response = connection.getresponse()
        response.read()
        if response.status == 200:
            break
    except (OSError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    time.sleep(0.2)
else:
    raise SystemExit('Служба входа не отвечает. Nginx не запускайте; проверьте journalctl -u oniondesk-auth.')
PY
printf '%s\n' 'Защищённый вход установлен. Данные входа доступны только root через control.sh credentials.'
