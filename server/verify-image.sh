#!/bin/bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FINGERPRINT=916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
SHA512=84b30da63af4750159006cdf1b5fbf6ab06c3a7ada697428f3b3b125286d85c33b11ee443464c119824aa7f4316e9a84c4a42eb1a50b5570b4105028099ffbe9
[[ $# == 4 ]] || { printf 'Usage: verify-image.sh ARCHIVE SIGNATURE KEY WORKDIR\n' >&2; exit 2; }
archive=$1 signature=$2 key=$3 workdir=$4
[[ -f $archive && -f $signature && -f $key ]] || { printf 'Нет архива, подписи или ключа.\n' >&2; exit 1; }
actual=$(sha512sum -- "$archive")
[[ ${actual%% *} == "$SHA512" ]] || { printf 'SHA-512 не совпадает с закреплённым выпуском Whonix.\n' >&2; exit 1; }
mkdir -m 0700 -- "$workdir/gpg"
gpg --batch --no-options --homedir "$workdir/gpg" --import "$key" >/dev/null 2>&1
actual_fingerprint=$(gpg --batch --no-options --homedir "$workdir/gpg" --with-colons --fingerprint "$FINGERPRINT" | awk -F: '$1 == "fpr" {print $10; exit}')
[[ $actual_fingerprint == "$FINGERPRINT" ]] || { printf 'Неверный fingerprint Whonix.\n' >&2; exit 1; }
gpg --batch --no-options --homedir "$workdir/gpg" --export "$FINGERPRINT" > "$workdir/whonix.gpg"
gpgv --status-fd 1 --keyring "$workdir/whonix.gpg" "$signature" "$archive" > "$workdir/signature.status"
python3 -B "$SCRIPT_DIR/image_tools.py" verify-status < "$workdir/signature.status"
printf 'Подпись и SHA-512 выпуска Whonix 18.2.1.9 проверены.\n'

