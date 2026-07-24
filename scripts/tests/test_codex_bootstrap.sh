#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h:h}
TEST_ROOT=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/wechat-bootstrap-test.XXXXXXXX")

cleanup() {
  case "$TEST_ROOT" in
    */wechat-bootstrap-test.*)
      [[ ! -L "$TEST_ROOT" && -d "$TEST_ROOT" ]] && /bin/rm -rf -- "$TEST_ROOT"
      ;;
  esac
}
trap cleanup EXIT

TEST_HOME="$TEST_ROOT/home"
/bin/mkdir -p "$TEST_HOME"

HOME="$TEST_HOME" "$PROJECT_ROOT/scripts/codex_bootstrap.sh" \
  install --skip-dependencies --skip-build >/dev/null

for skill in wechat-local-export wechat-local-export-setup; do
  link="$TEST_HOME/.agents/skills/$skill"
  [[ -L "$link" ]] || {
    print -u2 "Missing installed Skill link"
    exit 2
  }
done

# The same checkout is idempotent.
HOME="$TEST_HOME" "$PROJECT_ROOT/scripts/codex_bootstrap.sh" \
  install --skip-dependencies --skip-build >/dev/null

sentinel="$TEST_HOME/Library/Application Support/WeChatLocalExport/private-data-sentinel"
/usr/bin/touch "$sentinel"
HOME="$TEST_HOME" "$PROJECT_ROOT/scripts/codex_bootstrap.sh" uninstall >/dev/null

[[ -f "$sentinel" ]] || {
  print -u2 "Uninstall removed private data"
  exit 2
}
[[ ! -e "$TEST_HOME/.agents/skills/wechat-local-export" ]] || exit 2
[[ ! -e "$TEST_HOME/.agents/skills/wechat-local-export-setup" ]] || exit 2

print "Codex bootstrap tests: OK"
