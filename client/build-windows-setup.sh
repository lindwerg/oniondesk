#!/bin/sh
# Run inside the isolated Linux Windows builder after the frozen application build.
set -eu
: "${APP_DIR:?Set APP_DIR to the frozen Windows OnionDesk directory}"
: "${GPG_DIR:?Set GPG_DIR to the verified native GnuPG runtime}"
: "${LICENSE_DIR:?Set LICENSE_DIR to component license files}"
: "${DATA_DIR:?Set DATA_DIR to the full source-pinned OnionDesk-Data directory}"
: "${SETUP_WORK:?Set SETUP_WORK to a new owned build directory}"
: "${OUTPUT_EXE:?Set OUTPUT_EXE to the resulting Windows installer}"
client_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$SETUP_WORK"
python3 "$client_dir/build-windows-data.py" --data "$DATA_DIR" --output "$SETUP_WORK" \
  --extra-tree "$APP_DIR" --extra-tree "$GPG_DIR" --extra-tree "$LICENSE_DIR"
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Werror -municode -mwindows \
  -I"$SETUP_WORK" "$client_dir/build-windows-data-check.c" -ladvapi32 -lshell32 \
  -o "$SETUP_WORK/OnionDesk-Data-Check.exe"
makensis -V3 "-DAPP_DIR=$APP_DIR" "-DGPG_DIR=$GPG_DIR" "-DLICENSE_DIR=$LICENSE_DIR" \
  "-DDATA_INCLUDE=$SETUP_WORK/oniondesk-data-files.nsh" \
  "-DDATA_VERIFIER=$SETUP_WORK/OnionDesk-Data-Check.exe" "-DOUTPUT_EXE=$OUTPUT_EXE" \
  "$client_dir/build-windows.nsi"
