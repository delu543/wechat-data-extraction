#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wechat-voice-mp4-test.XXXXXX")
trap 'rm -rf -- "$TEST_DIR"' EXIT

cd "$PROJECT_ROOT"
mkdir -p "$TEST_DIR/clang-module-cache" "$TEST_DIR/swiftpm-module-cache" "$TEST_DIR/pycache"
PYTHONPYCACHEPREFIX="$TEST_DIR/pycache" \
  /usr/bin/python3 -W error::ResourceWarning \
  -m unittest -v direct_vault.tests.test_direct_voice_vault
zsh -n "$PROJECT_ROOT/scripts/direct.sh" "$PROJECT_ROOT/scripts/setup_direct_tools.sh"
CLANG_MODULE_CACHE_PATH="$TEST_DIR/clang-module-cache" \
  SWIFTPM_MODULECACHE_OVERRIDE="$TEST_DIR/swiftpm-module-cache" \
  swift build --disable-sandbox -j 1 -Xswiftc -disable-batch-mode
"$PROJECT_ROOT/.build/debug/wechat-voice-mp4" verify-core
"$PROJECT_ROOT/.build/debug/wechat-voice-mp4" self-test --output "$TEST_DIR/media-pipeline.mp4"
"$PROJECT_ROOT/scripts/verify_no_keyboard.sh"
