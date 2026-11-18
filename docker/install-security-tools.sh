#!/usr/bin/env bash
# 仅通过 apt、venv pip、go install 安装工具（不拉 GitHub Release / 不 gem / 不 git clone）
set -euo pipefail

INSTALL_APT="${INSTALL_APT:-1}"
INSTALL_PIP="${INSTALL_PIP:-1}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"

# shellcheck source=/opt/cyberstrike/mirrors.sh
source /opt/cyberstrike/mirrors.sh

log() { printf '[install-security-tools] %s\n' "$*"; }

setup_debian_tuna_apt
log "已切换 Debian 软件源为清华镜像"

if [[ "${INSTALL_APT}" == "1" ]]; then
  log "安装 Debian 软件包…"
  apt-get update
  while IFS= read -r pkg || [[ -n "${pkg}" ]]; do
    pkg="$(echo "${pkg}" | xargs)"
    [[ -z "${pkg}" ]] && continue
    apt-get install -y --no-install-recommends "${pkg}" || log "跳过不可用/失败的 apt 包: ${pkg}"
  done < <(grep -v '^[[:space:]]*#' /opt/cyberstrike/apt-security-packages.txt | grep -v '^[[:space:]]*$')
  apt-get clean
  rm -rf /var/lib/apt/lists/*
fi

if [[ "${INSTALL_PIP}" == "1" && -x /opt/venv/bin/pip ]]; then
  log "通过 venv pip 安装 Python 安全工具…"
  /opt/venv/bin/pip install --no-cache-dir -i "${PIP_INDEX_URL}" -r /opt/cyberstrike/requirements-security-tools.txt || \
    log "部分 pip 包安装失败，见上方日志"
fi

log "校验部分关键命令…"
for cmd in nmap sqlmap ffuf subfinder nuclei; do
  if command -v "${cmd}" >/dev/null 2>&1; then
    log "  OK: ${cmd}"
  else
    log "  缺失: ${cmd}（可在宿主机安装或扩展 apt/go-tools/pip 列表）"
  fi
done

log "完成"
