#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
cd "$PROJECT_ROOT"
MODULE_ROOT="$PROJECT_ROOT/work/release-module-cache"
mkdir -p "$MODULE_ROOT/clang" "$MODULE_ROOT/swiftpm"
CLANG_MODULE_CACHE_PATH="$MODULE_ROOT/clang" \
  SWIFTPM_MODULECACHE_OVERRIDE="$MODULE_ROOT/swiftpm" \
  swift build -c release --disable-sandbox -j 1 -Xswiftc -disable-batch-mode
print "Built: $PROJECT_ROOT/.build/release/wechat-voice-mp4"
