#!/bin/sh
set -eu

APP_ROOT=/opt/cyberstrike
CONFIG=/data/config.yaml

mkdir -p /data/tmp/workspace /data/log /data/chat_uploads
ln -sfn /data/chat_uploads "${APP_ROOT}/chat_uploads"
ln -sfn /data/tmp "${APP_ROOT}/tmp"

if [ ! -f "$CONFIG" ]; then
  cp "${APP_ROOT}/config.example.yaml" "$CONFIG"
  sed -i \
    -e 's/^  tls_enabled: true/  tls_enabled: false/' \
    -e 's/^  tls_auto_self_sign: true/  tls_auto_self_sign: false/' \
    -e 's/^  enabled: false # 是否启用 MCP 服务器（http模式）/  enabled: true # 是否启用 MCP 服务器（http模式）/' \
    -e 's|^  host: 127.0.0.1 # MCP |  host: 0.0.0.0 # MCP |' \
    -e 's/^  allow_global_access: false/  allow_global_access: true/' \
    -e 's|^  path: data/conversations.db|  path: /data/conversations.db|' \
    -e 's|^  knowledge_db_path: data/knowledge.db|  knowledge_db_path: /data/knowledge.db|' \
    -e 's|^  tools_dir: tools |  tools_dir: /opt/cyberstrike/tools |' \
    -e 's|^skills_dir: skills |skills_dir: /opt/cyberstrike/skills |' \
    -e 's|^agents_dir: agents|agents_dir: /opt/cyberstrike/agents|' \
    -e 's|^roles_dir: roles |roles_dir: /opt/cyberstrike/roles |' \
    -e 's|^  base_path: knowledge_base |  base_path: /opt/cyberstrike/knowledge_base |' \
    -e 's|^  diagnostic_dir: log |  diagnostic_dir: /data/log |' \
    -e 's|^  workspace_root_dir: ""|  workspace_root_dir: /data/tmp/workspace|' \
    "$CONFIG"

  if [ -n "${CYBERSTRIKE_MCP_TOKEN:-}" ]; then
    case "$CYBERSTRIKE_MCP_TOKEN" in
      *[!A-Za-z0-9._-]*)
        echo "CYBERSTRIKE_MCP_TOKEN 只能包含字母、数字、点、下划线和连字符" >&2
        exit 1
        ;;
    esac
    sed -i "s|^  auth_header_value: \"\"|  auth_header_value: \"${CYBERSTRIKE_MCP_TOKEN}\"|" "$CONFIG"
  fi
  chmod 600 "$CONFIG"
fi

cd "$APP_ROOT"
exec "$APP_ROOT/cyberstrike-ai" -config "$CONFIG" --http
