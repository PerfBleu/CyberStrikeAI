#!/bin/sh
# 切换到清华 Debian 源。构建早期尚无 ca-certificates，须用 http（勿用 https）。
set -eu

DEBIAN_SUITE="${DEBIAN_SUITE:-trixie}"

write_sources_list() {
  cat >/etc/apt/sources.list <<EOF
deb http://mirrors.tuna.tsinghua.edu.cn/debian ${DEBIAN_SUITE} main contrib non-free non-free-firmware
deb http://mirrors.tuna.tsinghua.edu.cn/debian ${DEBIAN_SUITE}-updates main contrib non-free non-free-firmware
deb http://mirrors.tuna.tsinghua.edu.cn/debian-security ${DEBIAN_SUITE}-security main contrib non-free non-free-firmware
EOF
}

rm -f /etc/apt/sources.list.d/debian.sources
: >/etc/apt/sources.list
write_sources_list
