FROM debian:13-slim@sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483
ENV container=docker DEBIAN_FRONTEND=noninteractive LIBGUESTFS_BACKEND=direct
# A container has no /boot kernel by default; the genuine Debian kernel is
# required by the libguestfs appliance used by the unchanged installer.
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus python3 python3-pil ca-certificates curl \
      iproute2 linux-image-amd64 qemu-system-x86 qemu-system-gui qemu-utils \
      libvirt-daemon-system libvirt-clients passt chromium chromium-driver \
      python3-selenium && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /usr/sbin/policy-rc.d && \
    systemctl set-default multi-user.target
COPY boot.sh /ci/boot.sh
COPY container.py /ci/container.py
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/bash", "/ci/boot.sh"]
