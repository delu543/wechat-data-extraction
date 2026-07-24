#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TASK_SUPPORT_ROOT=${WECHAT_VOICE_TOOLS_DIR:-"${HOME}/Library/Application Support/WeChatVoiceMP4/tools"}
DIRECT_PYTHON="$TASK_SUPPORT_ROOT/python/bin/python"
OUTPUT_DIR="$PROJECT_ROOT/outputs"
STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE=${1:-"$OUTPUT_DIR/direct-self-test-$STAMP.mp4"}

if [[ ! -x "$DIRECT_PYTHON" ]]; then
  print -u2 "直连依赖尚未安装。请先运行：$PROJECT_ROOT/scripts/setup_direct_tools.sh"
  exit 2
fi

mkdir -p "$OUTPUT_DIR"
"$PROJECT_ROOT/scripts/build.sh"
exec "$DIRECT_PYTHON" "$PROJECT_ROOT/direct_vault/direct_self_test.py" \
  --swift-bin "$PROJECT_ROOT/.build/release/wechat-voice-mp4" \
  --output "$OUTPUT_FILE"
