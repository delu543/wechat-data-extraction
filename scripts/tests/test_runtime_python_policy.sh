#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h:h}
TEST_ROOT=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/wechat-python-policy-test.XXXXXXXX")
source "$PROJECT_ROOT/scripts/runtime_python_policy.sh"

cleanup() {
  case "$TEST_ROOT" in
    */wechat-python-policy-test.*)
      [[ ! -L "$TEST_ROOT" && -d "$TEST_ROOT" ]] && /bin/rm -rf -- "$TEST_ROOT"
      ;;
  esac
}
trap cleanup EXIT

TOOL_CACHE="$TEST_ROOT/hostedtoolcache"
PYTHON_BIN="$TOOL_CACHE/Python/current/bin/python3"
/bin/mkdir -p "${PYTHON_BIN:h}"
/usr/bin/touch "$PYTHON_BIN"
/bin/chmod 775 "$PYTHON_BIN"
CURRENT_UID=$(/usr/bin/id -u)

if wechat_allow_github_hosted_python \
  "$PYTHON_BIN" "$PYTHON_BIN" "$CURRENT_UID" "$CURRENT_UID"; then
  print -u2 "Group-writable custom Python was accepted without the hosted-runner gate"
  exit 2
fi

CI=true \
GITHUB_ACTIONS=true \
RUNNER_ENVIRONMENT=github-hosted \
RUNNER_OS=macOS \
RUNNER_TOOL_CACHE="$TOOL_CACHE" \
WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
  wechat_allow_github_hosted_python \
    "$PYTHON_BIN" "$PYTHON_BIN" "$CURRENT_UID" "$CURRENT_UID"

if CI=true \
  GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=self-hosted \
  RUNNER_OS=macOS \
  RUNNER_TOOL_CACHE="$TOOL_CACHE" \
  WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
    wechat_allow_github_hosted_python \
      "$PYTHON_BIN" "$PYTHON_BIN" "$CURRENT_UID" "$CURRENT_UID"; then
  print -u2 "A self-hosted runner was accepted by the hosted-runner exception"
  exit 2
fi

if CI=true \
  GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=github-hosted \
  RUNNER_OS=macOS \
  RUNNER_TOOL_CACHE="$TEST_ROOT/different-cache" \
  WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
    wechat_allow_github_hosted_python \
      "$PYTHON_BIN" "$PYTHON_BIN" "$CURRENT_UID" "$CURRENT_UID"; then
  print -u2 "Hosted-runner Python outside the declared tool cache was accepted"
  exit 2
fi

if CI=true \
  GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=github-hosted \
  RUNNER_OS=macOS \
  RUNNER_TOOL_CACHE="$TOOL_CACHE" \
  WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
    wechat_allow_github_hosted_python \
      "$PYTHON_BIN" "$PYTHON_BIN" "777" "$CURRENT_UID"; then
  print -u2 "Hosted-runner Python owned by another user was accepted"
  exit 2
fi

CI=true \
GITHUB_ACTIONS=true \
RUNNER_ENVIRONMENT=github-hosted \
RUNNER_OS=macOS \
RUNNER_TOOL_CACHE="$TOOL_CACHE" \
WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
  wechat_allow_github_hosted_python \
    "$PYTHON_BIN" \
    "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11" \
    "0" \
    "$CURRENT_UID"

if CI=true \
  GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=github-hosted \
  RUNNER_OS=macOS \
  RUNNER_TOOL_CACHE="$TOOL_CACHE" \
  WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON=1 \
    wechat_allow_github_hosted_python \
      "$PYTHON_BIN" "/tmp/untrusted-python" "0" "$CURRENT_UID"; then
  print -u2 "A hosted-runner shim resolving outside trusted roots was accepted"
  exit 2
fi

WECHAT_LOCAL_EXPORT_ALLOW_UNVERIFIED_PYTHON=1 \
WECHAT_LOCAL_EXPORT_PYTHON=/usr/bin/python3 \
  "$PROJECT_ROOT/scripts/setup_runtime_tools.sh" --validate-python-only \
  >"$TEST_ROOT/system.out"
/usr/bin/grep -q "Runtime Python policy: OK" "$TEST_ROOT/system.out"

print "Runtime Python policy tests: OK"
