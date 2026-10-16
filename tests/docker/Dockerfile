FROM debian:13-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d
RUN apt-get update && apt-get -y --no-install-recommends install \
    qemu-system-x86 qemu-system-gui qemu-utils libvirt-daemon-system libvirt-clients \
    passt libguestfs-tools libxml2-utils python3 python3-venv python3-requests \
    python3-paramiko python3-socks python3-websockets curl ca-certificates gnupg \
    xz-utils tor nginx novnc websockify iproute2 openssl shellcheck chromium \
    mat2 zenity python3-pil python3-docx python3-reportlab libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv --system-site-packages /opt/testenv \
    && /opt/testenv/bin/pip install --no-cache-dir playwright==1.58.0
RUN apt-get update && apt-get -y --no-install-recommends install "linux-image-$(dpkg --print-architecture)" \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get -y --no-install-recommends install gpgv \
    && rm -rf /var/lib/apt/lists/*
RUN /opt/testenv/bin/pip install --no-cache-dir paramiko==5.0.0 'requests[socks]==2.34.2'
LABEL oniondesk-test="true"
WORKDIR /workspace
