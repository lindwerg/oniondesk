#!/usr/bin/env python3
"""Render onion nginx config with hashes of the installed noVNC inline modules."""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re


class InlineScripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.current = None
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script" and "src" not in dict(attrs):
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            self.scripts.append("".join(self.current))
            self.current = None


def render(hostname, template, novnc_html):
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", hostname):
        raise ValueError("Expected a Tor v3 hostname")
    parser = InlineScripts()
    parser.feed(novnc_html.replace("\r\n", "\n").replace("\r", "\n"))
    parser.close()
    if parser.current is not None:
        raise ValueError("Unclosed script in installed noVNC page")
    hashes = sorted({"'sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii") + "'"
                     for script in parser.scripts if script.strip()})
    return template.replace("__ONION_HOST__", hostname).replace("__NOVNC_SCRIPT_HASHES__", " ".join(hashes))


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("hostname")
    argument_parser.add_argument("template", type=Path)
    argument_parser.add_argument("novnc_html", type=Path)
    argument_parser.add_argument("output", type=Path)
    arguments = argument_parser.parse_args()
    try:
        arguments.output.write_text(render(arguments.hostname, arguments.template.read_text(encoding="utf-8"),
                                           arguments.novnc_html.read_text(encoding="utf-8")), encoding="utf-8")
    except (ValueError, OSError):
        raise SystemExit("Не удалось проверить стартовые модули noVNC; конфигурация не создана.") from None
