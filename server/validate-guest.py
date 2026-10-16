#!/usr/bin/env python3
"""Certify the narrow maintenance contract before writing any guest files."""
import argparse
import subprocess
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def validate_domain(text, role):
    """Validate libvirt's normalized installed XML, including a live domain.

    Libvirt adds UUIDs, PCI addresses, aliases and runtime IDs. Those additions
    are permitted; extra network/device backends and QEMU XML namespaces are not.
    """
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(role in {"gateway", "workstation"}, "Неизвестная роль VM.")
    require("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "DTD/entities в VM запрещены.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError("Невозможно проверить XML VM.") from error
    require(root.tag == "domain" and root.get("type") == "kvm" and set(root.attrib) <= {"type", "id"}, "Ожидается KVM domain без расширений.")
    require(all(isinstance(node.tag, str) and "{" not in node.tag for node in root.iter()), "XML namespaces VM запрещены.")
    allowed_root = {"name", "uuid", "description", "genid", "memory", "currentMemory", "memoryBacking", "vcpu", "cpu", "os", "features", "clock", "on_poweroff", "on_reboot", "on_crash", "pm", "devices", "resource", "seclabel"}
    require(all(node.tag in allowed_root for node in root), "Неизвестное расширение domain.")
    require(len(root.findall("name")) == 1 and root.findtext("name") == f"oniondesk-{role}", "Неожиданное имя VM.")
    require(len(root.findall("devices")) == 1, "Ожидался один devices.")
    devices = root.find("devices")
    allowed_devices = {"emulator", "disk", "interface", "controller", "serial", "console", "channel", "graphics", "video", "sound", "audio", "input", "watchdog", "memballoon", "rng"}
    require(all(node.tag in allowed_devices for node in devices), "Неожиданное устройство VM.")
    require(root.find("os") is not None and all(node.tag in {"type", "boot", "bootmenu"} for node in root.find("os")), "Прямой kernel/loader или неизвестный способ загрузки запрещён.")
    emulators = devices.findall("emulator")
    require(len(emulators) <= 1 and all(node.text == "/usr/bin/qemu-system-x86_64" for node in emulators), "Неожиданный QEMU emulator.")
    disks = devices.findall("disk")
    require(len(disks) == 1 and disks[0].get("type") == "file" and disks[0].get("device") == "disk", "Ожидался один file disk VM.")
    disk = disks[0]
    require(len(disk.findall("source")) == 1 and disk.find("source").get("file") == f"/var/lib/libvirt/images/oniondesk/{role}.qcow2", "Неожиданный диск VM.")
    require(set(disk.find("source").attrib) <= {"file", "index"}, "Неизвестный disk source.")
    backing = disk.find("backingStore")
    require(backing is None or (not list(backing) and not backing.attrib), "Внешний backing disk запрещён.")
    interfaces = devices.findall("interface")
    require(len(interfaces) == (2 if role == "gateway" else 1), "Неверное число NIC: Workstation не должна иметь внешний адаптер.")
    for index, interface in enumerate(interfaces):
        external = role == "gateway" and index == 0
        require(interface.attrib == {"type": "user" if external else "udp"}, "Неверный тип NIC.")
        permitted = {"model", "mac", "alias", "address", "target", "backend" if external else "source"}
        require(all(child.tag in permitted for child in interface), "Неожиданный backend/forwarding NIC.")
        require(len(interface.findall("model")) == 1 and interface.find("model").attrib == {"type": "virtio"}, "NIC должна быть virtio.")
        if external:
            require(len(interface.findall("backend")) == 1 and interface.find("backend").attrib == {"type": "passt"}, "Внешний GW backend должен оставаться passt.")
        else:
            remote, local = ("5577", "6688") if role == "gateway" else ("6688", "5577")
            sources = interface.findall("source")
            require(len(sources) == 1 and sources[0].attrib == {"address": "127.0.0.1", "port": remote}, "Неверный внутренний UDP endpoint.")
            require(len(list(sources[0])) == 1 and sources[0][0].tag == "local" and sources[0][0].attrib == {"address": "127.0.0.1", "port": local}, "Внутренний UDP bind должен оставаться loopback.")
    graphics = devices.findall("graphics")
    port = "5901" if role == "gateway" else "5902"
    require(len(graphics) == 1 and graphics[0].attrib == {"type": "vnc", "port": port, "autoport": "no", "listen": "127.0.0.1"}, "VNC должен слушать только установленный loopback port.")
    require(len(list(graphics[0])) == 1 and graphics[0][0].tag == "listen" and graphics[0][0].attrib == {"type": "address", "address": "127.0.0.1"}, "Неожиданная настройка VNC listen.")
    channels = devices.findall("channel")
    require(len(channels) == int(role == "workstation"), "Неожиданный канал VM.")
    if channels:
        require(channels[0].get("type") == "unix" and len(channels[0].findall("target")) == 1 and channels[0].find("target").get("type") == "virtio" and channels[0].find("target").get("name") == "org.qemu.guest_agent.0", "Неожиданный guest-agent channel.")
        require(all(node.tag in {"source", "target", "alias", "address"} for node in channels[0]), "Неизвестный guest-agent backend.")


def validate_contract(role, passwd, grub, target, boot_script, marker):
    accounts = {line.split(":", 1)[0] for line in passwd.splitlines() if ":" in line}
    if not {"user", "sysmaint"} <= accounts:
        raise ValueError("В образе отсутствуют ожидаемые user/sysmaint accounts.")
    if not marker:
        raise ValueError("Не найден официальный role marker Whonix.")
    if "boot-role=sysmaint" not in grub or "systemd.unit=sysmaint-boot.target" not in grub:
        raise ValueError("Не подтверждён SYSMAINT boot entry; GRUB изменяться не будет.")
    if "boot-role=sysmaint" not in boot_script or "sysmaint" not in boot_script:
        raise ValueError("Не подтверждён механизм user-sysmaint-split.")
    if "sysmaint" not in target or "network" not in target or "tor@default.service" not in target:
        raise ValueError("Не подтверждён maintenance target с сетью/Tor.")
    if role not in {"gateway", "workstation"}:
        raise ValueError("Неизвестная роль.")


def read_guest(disk, command, path):
    return subprocess.run(["guestfish", "--ro", "--format=qcow2", "-a", disk, "-i", command, path], check=True, text=True, stdout=subprocess.PIPE).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk", required=True)
    parser.add_argument("--role", required=True, choices=["gateway", "workstation"])
    args = parser.parse_args()
    if not Path(args.disk).is_file():
        raise ValueError("Нет диска гостевой VM.")
    marker_path = "/usr/share/anon-gw-base-files/gateway" if args.role == "gateway" else "/usr/share/anon-ws-base-files/workstation"
    validate_contract(args.role,
                      read_guest(args.disk, "cat", "/etc/passwd"),
                      read_guest(args.disk, "cat", "/boot/grub/grub.cfg"),
                      read_guest(args.disk, "cat", "/usr/lib/systemd/system/sysmaint-boot.target"),
                      read_guest(args.disk, "cat", "/usr/libexec/user-sysmaint-split/sysmaint-boot"),
                      read_guest(args.disk, "is-file", marker_path).strip() == "true")
    print(f"Подтверждён контракт {args.role}: sysmaint boot + split; bootloader не меняется.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Проверка гостя остановлена: {error}", file=sys.stderr)
        raise SystemExit(1)

