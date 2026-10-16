#!/usr/bin/env python3
"""Strict transformation of the two pinned, verified upstream domain XML files."""
import argparse
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

FINGERPRINT = "916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA"
DOMAIN_CHILDREN = {"name", "description", "genid", "memory", "currentMemory", "memoryBacking", "vcpu", "cpu", "os", "features", "clock", "on_poweroff", "on_reboot", "on_crash", "pm", "devices"}
DEVICE_CHILDREN = {"disk", "interface", "controller", "serial", "console", "channel", "graphics", "video", "sound", "memballoon", "rng"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_status(text):
    valid = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[:2] == ["[GNUPG:]", "VALIDSIG"]:
            valid.append(parts[2] == FINGERPRINT or (len(parts) >= 12 and parts[11] == FINGERPRINT))
    require(len(valid) == 1 and valid[0], "Подпись не принадлежит закреплённому ключу Whonix.")


def transform(text, role, disk_path):
    require(role in {"gateway", "workstation"}, "Неизвестная роль.")
    require("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "DTD и XML entities запрещены.")
    root = ET.fromstring(text)
    require(root.tag == "domain" and root.attrib == {"type": "kvm"}, "Неподдерживаемый domain/XML namespace.")
    require(all(node.tag in DOMAIN_CHILDREN for node in root), "Неизвестный элемент domain.")
    require(len(root.findall("devices")) == 1, "Ожидался один devices.")
    name = root.find("name")
    expected = "Whonix-Gateway" if role == "gateway" else "Whonix-Workstation"
    require(name is not None and name.text == expected, "Неожиданное имя исходной VM.")
    devices = root.find("devices")
    require(all(node.tag in DEVICE_CHILDREN for node in devices), "Неизвестное устройство; автоматическое изменение остановлено.")
    disks = devices.findall("disk")
    require(len(disks) == 1, "Ожидался ровно один диск.")
    disk = disks[0]
    require(disk.attrib == {"type": "volume", "device": "disk"}, "Неожиданный тип диска.")
    source = disk.find("source")
    require(source is not None and source.attrib == {"pool": "default", "volume": f"{expected}.qcow2"}, "Неожиданный upstream disk source.")
    require(Path(disk_path).is_absolute() and Path(disk_path).parent == Path("/var/lib/libvirt/images/oniondesk"), "Диск должен находиться в собственном каталоге libvirt.")
    interfaces = devices.findall("interface")
    require(len(interfaces) == (2 if role == "gateway" else 1), "Неверное число сетевых интерфейсов.")
    if role == "gateway":
        external = interfaces[0]
        require(external.attrib == {"type": "user"}, "GW external должен быть user/passt.")
        require(external.find("backend") is not None and external.find("backend").attrib == {"type": "passt"}, "Неожиданный внешний backend.")
        require(external.find("source") is None and external.find("portForward") is None, "Внешнее перенаправление портов запрещено.")
    internal = interfaces[-1]
    require(internal.attrib == {"type": "udp"}, "Внутренняя сеть должна оставаться UDP.")
    target_port, local_port = ("5577", "6688") if role == "gateway" else ("6688", "5577")
    net_source = internal.find("source")
    require(net_source is not None and net_source.attrib == {"address": "127.0.0.1", "port": target_port}, "Неожиданный UDP endpoint.")
    local = net_source.find("local")
    require(local is not None and local.attrib == {"address": "127.0.0.1", "port": local_port}, "Неожиданный local UDP endpoint.")
    for interface in interfaces:
        require(interface.find("model") is not None and interface.find("model").attrib == {"type": "virtio"}, "Неожиданный NIC model.")
        permitted = {"backend", "model"} if interface is interfaces[0] and role == "gateway" else {"source", "model"}
        require(all(child.tag in permitted for child in interface), "Неизвестный элемент сетевого интерфейса.")
    graphics = devices.findall("graphics")
    require(len(graphics) == 1 and graphics[0].get("type") == "spice", "Ожидался один SPICE display.")
    channels = devices.findall("channel")
    require(len(channels) == 1 and channels[0].get("type") == "spicevmc", "Ожидался исходный SPICE channel.")
    devices.remove(channels[0])
    devices.remove(graphics[0])
    display = ET.SubElement(devices, "graphics", type="vnc", port="5901" if role == "gateway" else "5902", autoport="no", listen="127.0.0.1")
    ET.SubElement(display, "listen", type="address", address="127.0.0.1")
    if role == "workstation":
        channel = ET.SubElement(devices, "channel", type="unix")
        ET.SubElement(channel, "target", type="virtio", name="org.qemu.guest_agent.0")
    vcpu = root.find("vcpu")
    require(vcpu is not None, "Не найден vcpu.")
    vcpu.attrib.pop("cpuset", None)
    name.text = f"oniondesk-{role}"
    disk.set("type", "file")
    source.attrib.clear()
    source.set("file", disk_path)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["transform", "verify-status"])
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--role", choices=["gateway", "workstation"])
    parser.add_argument("--disk")
    args = parser.parse_args()
    if args.action == "verify-status":
        verify_status(sys.stdin.read())
    else:
        require(all([args.input, args.output, args.role, args.disk]), "Недостаточно аргументов transform.")
        Path(args.output).write_text(transform(Path(args.input).read_text(), args.role, args.disk))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, ET.ParseError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        raise SystemExit(1)

