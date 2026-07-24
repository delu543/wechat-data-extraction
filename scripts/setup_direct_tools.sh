#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TASK_SUPPORT_ROOT=${WECHAT_VOICE_TOOLS_DIR:-"${HOME}/Library/Application Support/WeChatVoiceMP4/tools"}
VENV_ROOT="$TASK_SUPPORT_ROOT/python"

mkdir -p "$TASK_SUPPORT_ROOT"
chmod 700 "$TASK_SUPPORT_ROOT"

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else "需要 Python 3.9 或更高版本")'
python3 -m venv "$VENV_ROOT"

PIP_CACHE_DIR="$TASK_SUPPORT_ROOT/pip-cache" \
  "$VENV_ROOT/bin/python" -m pip install \
  "pilk==0.2.4" \
  "zstandard==0.23.0"

"$VENV_ROOT/bin/python" -c 'import pilk, zstandard; print("Direct voice dependencies: OK")'
print "Direct Python: $VENV_ROOT/bin/python"
print "Next: $PROJECT_ROOT/scripts/direct.sh doctor --vault-dir /path/to/decrypted/current"
