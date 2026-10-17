#!/usr/bin/env python3
"""Selected test browser: pass a launch URL privately to the headed UI driver."""
import os
from pathlib import Path
import re
import sys


def main():
    if len(sys.argv) != 2 or not re.fullmatch(
        r"http://127\.0\.0\.1:[0-9]{1,5}/#[A-Za-z0-9_-]{32,128}", sys.argv[1]
    ):
        return 2
    target = Path(os.environ["ONIONDESK_CI_BROWSER_REQUEST"])
    root = Path(os.environ["ONIONDESK_CI_OWNED_ROOT"])
    if target.parent != root or root.is_symlink() or not (root / ".owner").is_file():
        return 2
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(sys.argv[1])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError):
        raise SystemExit(2)
