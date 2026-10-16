#!/bin/sh
# Developer-only: builds a Linux program; end users open the packaged executable.
set -eu
client_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
kit_root=$(CDPATH='' cd -- "$client_dir/.." && pwd)
arch=${1:-x86_64}
case "$arch" in
    x86_64) docker_arch=amd64 ;;
    aarch64) docker_arch=arm64 ;;
    *) printf '%s\n' 'Architecture must be x86_64 or aarch64.' >&2; exit 2 ;;
esac
# This is a trusted developer override. Keep build intermediates outside the
# checkout by default and let build-linux.py enforce its ownership marker.
build_root=${ONIONDESK_BUILD_ROOT:-"${kit_root}-build/linux"}
mkdir -p "$build_root"
build_root=$(CDPATH='' cd -- "$build_root" && pwd -P)
work_dir="$build_root/$arch"
if [ -L "$work_dir" ]; then
    printf '%s\n' 'Build work directory must not be a symlink.' >&2
    exit 2
fi
mkdir -p "$work_dir"
image="oniondesk-linux-builder:$arch"
docker build --platform "linux/$docker_arch" --tag "$image" \
    --file "$client_dir/build-linux.Dockerfile" \
    "$client_dir"
docker run --rm --platform "linux/$docker_arch" \
    --name "oniondesk-linux-build-$arch" \
    --mount "type=bind,src=$kit_root,dst=/workspace" \
    --mount "type=bind,src=$work_dir,dst=/buildwork" \
    "$image" --architecture "$arch" \
    --work /buildwork
