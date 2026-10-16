#!/usr/bin/env python3
"""Reject any non-loopback TCP listener in nginx -T output."""
import ipaddress
from pathlib import Path
import shlex
import sys


def check(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars="{};")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    tokens = list(lexer)
    listeners = 0
    for index, token in enumerate(tokens):
        if token != "listen":
            continue
        listeners += 1
        address = tokens[index + 1] if index + 1 < len(tokens) else ""
        if address.startswith("unix:"):
            continue
        if address.startswith("["):
            host = address[1:address.find("]")]
        else:
            host = address.split(":", 1)[0]
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError("Active nginx configuration has a non-loopback listener")
    if listeners == 0:
        raise ValueError("No nginx listeners found")


if __name__ == "__main__":
    try:
        check(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (ValueError, OSError, IndexError):
        print("Nginx содержит внешний или непроверенный listen. Чужие конфиги не удалены; установка остановлена.",
              file=sys.stderr)
        raise SystemExit(1) from None
