# shellcheck shell=bash
# 国内镜像：Debian 使用清华。

setup_debian_tuna_apt() {
  local suite="${DEBIAN_SUITE:-trixie}"
  rm -f /etc/apt/sources.list.d/debian.sources
  : >/etc/apt/sources.list
  cat >/etc/apt/sources.list <<EOF
deb http://mirrors.tuna.tsinghua.edu.cn/debian ${suite} main contrib non-free non-free-firmware
deb http://mirrors.tuna.tsinghua.edu.cn/debian ${suite}-updates main contrib non-free non-free-firmware
deb http://mirrors.tuna.tsinghua.edu.cn/debian-security ${suite}-security main contrib non-free non-free-firmware
EOF
}
