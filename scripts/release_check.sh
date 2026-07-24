#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
TEMP_ROOT=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/wechat-release-check.XXXXXXXX")

cleanup() {
  case "$TEMP_ROOT" in
    */wechat-release-check.*)
      [[ ! -L "$TEMP_ROOT" && -d "$TEMP_ROOT" ]] && /bin/rm -rf -- "$TEMP_ROOT"
      ;;
  esac
}
trap cleanup EXIT

RUNTIME_PYTHON="$HOME/Library/Application Support/WeChatLocalExport/tools/python/bin/python"
[[ -x "$RUNTIME_PYTHON" ]] || {
  print -u2 "Run ./scripts/codex_bootstrap.sh install before the full release check"
  exit 2
}

cd "$PROJECT_ROOT"
/usr/bin/python3 scripts/validate_public_repo.py
"$RUNTIME_PYTHON" portable_skill/scripts/validate_package.py
PYTHONPYCACHEPREFIX="$TEMP_ROOT/pycache" \
  "$RUNTIME_PYTHON" -m unittest discover -s direct_vault/tests -p 'test_*.py'
PYTHONPYCACHEPREFIX="$TEMP_ROOT/pycache" \
  "$RUNTIME_PYTHON" -m unittest discover -s content_vault/tests -p 'test_*.py'
PYTHONPYCACHEPREFIX="$TEMP_ROOT/pycache" \
  "$RUNTIME_PYTHON" -m unittest discover -s live_tools/tests -p 'test_*.py'
PYTHONPYCACHEPREFIX="$TEMP_ROOT/pycache" \
  "$RUNTIME_PYTHON" -m unittest portable_skill.tests.test_package
"$PROJECT_ROOT/scripts/tests/test_codex_bootstrap.sh"
"$PROJECT_ROOT/scripts/build.sh"
"$PROJECT_ROOT/.build/release/wechat-voice-mp4" verify-core
"$PROJECT_ROOT/.build/release/wechat-voice-mp4" self-test \
  --output "$TEMP_ROOT/media-self-test.mp4"
"$PROJECT_ROOT/scripts/verify_no_keyboard.sh"
print "Release check: OK"
