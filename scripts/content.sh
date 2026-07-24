#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TASK_SUPPORT_ROOT=${WECHAT_LOCAL_EXPORT_TOOLS_DIR:-"${HOME}/Library/Application Support/WeChatLocalExport/tools"}
CONTENT_PYTHON="$TASK_SUPPORT_ROOT/python/bin/python"

if [[ ! -x "$CONTENT_PYTHON" ]]; then
  print -u2 "统一导出依赖尚未安装。请先运行：$PROJECT_ROOT/scripts/setup_content_tools.sh"
  exit 2
fi

exec "$CONTENT_PYTHON" -m content_vault.cli "$@"
