#!/usr/bin/env python3
"""Read-only compatibility checks. No installations, sockets, or files are created."""
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import sys


def os_fields(text):
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            tokens = shlex.split(value)
            result[key] = tokens[0] if tokens else ""
    return result


def evaluate(facts):
    return [
        ("Debian 13 amd64", facts["id"] == "debian" and facts["version"] == "13" and facts["arch"] == "x86_64"),
        ("KVM: /dev/kvm, доступ чтения и записи", facts["kvm"]),
        ("Не менее 4 доступных CPU", facts["cpus"] >= 4),
        # An 8 GiB VM normally reports slightly less usable memory to Linux.
        ("8 GiB RAM (не менее 7.5 GiB доступно Linux)", facts["memory"] >= 7.5 * 1024**3),
        ("50 GiB свободно на разделе /var/lib", facts["free"] >= 50 * 1024**3),
        ("Системный пакетный менеджер apt-get", facts["apt"]),
    ]


def collect():
    release = Path("/etc/os-release")
    fields = os_fields(release.read_text()) if release.exists() else {}
    memory_file = Path("/proc/meminfo")
    memory = 0
    if memory_file.exists():
        for line in memory_file.read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = int(line.split()[1]) * 1024
                break
    kvm = Path("/dev/kvm")
    writable_kvm = kvm.exists() and stat.S_ISCHR(kvm.stat().st_mode) and os.access(kvm, os.R_OK | os.W_OK)
    available_cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 0
    disk_path = "/var/lib" if Path("/var/lib").is_dir() else "/"
    return {
        "id": fields.get("ID", ""), "version": fields.get("VERSION_ID", ""),
        "arch": platform.machine(), "memory": memory, "cpus": available_cpus,
        "kvm": writable_kvm, "free": shutil.disk_usage(disk_path).free,
        "apt": shutil.which("apt-get") is not None,
    }


def main():
    facts = collect()
    results = evaluate(facts)
    for title, passed in results:
        print(f"{'OK' if passed else 'НЕТ'}: {title}")
    print("Проверка не изменяет систему. Debian 12 этим выпуском установщика не поддерживается.")
    if not facts["kvm"] and os.geteuid() != 0:
        print("Для проверки прав на KVM можно повторить: sudo bash server/install.sh --check")
    if "--json" in sys.argv:
        print(json.dumps(facts))
    return 0 if all(passed for _, passed in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

