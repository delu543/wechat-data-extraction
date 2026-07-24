#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
cd "$PROJECT_ROOT"
exec "$PROJECT_ROOT/.build/release/wechat-voice-mp4" "$@"
