#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TASK_SUPPORT_ROOT=${WECHAT_VOICE_TOOLS_DIR:-"${HOME}/Library/Application Support/WeChatVoiceMP4/tools"}
DIRECT_PYTHON="$TASK_SUPPORT_ROOT/python/bin/python"

if [[ ! -x "$DIRECT_PYTHON" ]]; then
  print -u2 "直连依赖尚未安装。请先运行：$PROJECT_ROOT/scripts/setup_direct_tools.sh"
  exit 2
fi

exec "$DIRECT_PYTHON" "$PROJECT_ROOT/direct_vault/direct_voice_vault.py" "$@"
