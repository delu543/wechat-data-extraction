#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TASK_SUPPORT_ROOT=${WECHAT_LOCAL_EXPORT_TOOLS_DIR:-"${HOME}/Library/Application Support/WeChatLocalExport/tools"}
VENV_ROOT="$TASK_SUPPORT_ROOT/python"

mkdir -p "$TASK_SUPPORT_ROOT"
chmod 700 "$TASK_SUPPORT_ROOT"

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else "需要 Python 3.9 或更高版本")'
python3 -m venv "$VENV_ROOT"

PIP_CACHE_DIR="$TASK_SUPPORT_ROOT/pip-cache" \
  "$VENV_ROOT/bin/python" -m pip install \
  "pilk==0.2.4" \
  "imageio-ffmpeg==0.6.0" \
  "pycryptodome==3.23.0" \
  "zstandard==0.23.0"

PYTHONPATH="$PROJECT_ROOT" "$VENV_ROOT/bin/python" -c \
  'import Crypto, imageio_ffmpeg, pilk, zstandard; import content_vault.cli; print("WeChat local export dependencies: OK")'
print "Content Python: $VENV_ROOT/bin/python"
print "Next: $PROJECT_ROOT/scripts/content.sh doctor --vault-dir /path/to/decrypted/current"
