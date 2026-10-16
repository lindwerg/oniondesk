#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Установите Python 3.10 или новее с https://www.python.org/downloads/'
  exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Нужен Python 3.10 или новее"'
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
exec .venv/bin/python start_app.py
