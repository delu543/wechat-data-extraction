#!/bin/zsh
set -euo pipefail
umask 077

PROJECT_ROOT=${0:A:h:h}
REQUIREMENTS="$PROJECT_ROOT/scripts/requirements-runtime.txt"
BUILD_REQUIREMENTS="$PROJECT_ROOT/scripts/requirements-build.txt"
SUPPORT_ROOT="$HOME/Library/Application Support/WeChatLocalExport"
TOOLS_ROOT="$SUPPORT_ROOT/tools"
RUNTIMES_ROOT="$TOOLS_ROOT/runtimes"
LOCK_HASH=$(/bin/cat "$BUILD_REQUIREMENTS" "$REQUIREMENTS" | \
  /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')
CURRENT_RUNTIME="$TOOLS_ROOT/python"
CURRENT_UID=$(/usr/bin/id -u)
STAGE=""

fail() {
  print -u2 -- "$1"
  exit 2
}

PYTHON_BIN=/usr/bin/python3
if [[ -n "${WECHAT_LOCAL_EXPORT_PYTHON:-}" ]]; then
  [[ "${WECHAT_LOCAL_EXPORT_ALLOW_UNVERIFIED_PYTHON:-}" == "1" ]] || \
    fail "A custom Python requires the explicit development opt-in"
  [[ "$WECHAT_LOCAL_EXPORT_PYTHON" == /* ]] || fail "Custom Python must be absolute"
  PYTHON_BIN=${WECHAT_LOCAL_EXPORT_PYTHON:A}
  [[ -f "$PYTHON_BIN" && ! -L "$PYTHON_BIN" && -x "$PYTHON_BIN" ]] || \
    fail "Custom Python is not a regular executable"
  python_owner=$(/usr/bin/stat -f '%u' "$PYTHON_BIN")
  [[ "$python_owner" == "$CURRENT_UID" || "$python_owner" == "0" ]] || \
    fail "Custom Python has an unexpected owner"
  python_mode=$(/usr/bin/stat -f '%Lp' "$PYTHON_BIN")
  (( (8#$python_mode & 8#022) == 0 )) || fail "Custom Python is writable by another user"
fi
PYTHON_TAG=$("$PYTHON_BIN" -c \
  'import platform,sys; print(f"cp{sys.version_info.major}{sys.version_info.minor}-{platform.machine()}")')
RUNTIME_ROOT="$RUNTIMES_ROOT/runtime-${LOCK_HASH[1,16]}-$PYTHON_TAG"

assert_private_directory() {
  local path=$1
  [[ -d "$path" && ! -L "$path" ]] || fail "Unsafe private runtime directory"
  [[ "$(/usr/bin/stat -f '%u' "$path")" == "$CURRENT_UID" ]] || \
    fail "Runtime directory is not owned by the current user"
  [[ "$(/usr/bin/stat -f '%Lp' "$path")" == "700" ]] || \
    fail "Runtime directory must have mode 0700"
}

cleanup() {
  [[ -n "$STAGE" ]] || return 0
  case "$STAGE" in
    "$RUNTIMES_ROOT"/.install.*)
      [[ -d "$STAGE" && ! -L "$STAGE" ]] && /bin/rm -rf -- "$STAGE"
      ;;
  esac
}
trap cleanup EXIT

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || fail "Runtime supports macOS only"
[[ -n "${HOME:-}" && "$HOME" == /* && "$HOME" != "/" ]] || fail "Unsafe HOME"
[[ "$CURRENT_UID" != "0" ]] || fail "Do not install as root"
[[ -f "$REQUIREMENTS" && ! -L "$REQUIREMENTS" ]] || fail "Runtime lock is missing"
[[ -f "$BUILD_REQUIREMENTS" && ! -L "$BUILD_REQUIREMENTS" ]] || \
  fail "Build lock is missing"
"$PYTHON_BIN" - <<'PY'
import platform
import sys

supported = platform.python_implementation() == "CPython" and (3, 9) <= sys.version_info[:2] < (3, 14)
raise SystemExit(0 if supported else "Standard CPython 3.9 through 3.13 is required")
PY
/usr/bin/xcrun --find clang >/dev/null 2>&1 || \
  fail "Apple Command Line Tools are required to build the pinned pilk package"

/bin/mkdir -p "$HOME/Library/Application Support"
for path in "$SUPPORT_ROOT" "$TOOLS_ROOT" "$RUNTIMES_ROOT"; do
  if [[ -e "$path" || -L "$path" ]]; then
    assert_private_directory "$path"
  else
    /bin/mkdir "$path"
    /bin/chmod 700 "$path"
  fi
done

if [[ ! -d "$RUNTIME_ROOT" ]]; then
  STAGE=$(/usr/bin/mktemp -d "$RUNTIMES_ROOT/.install.XXXXXXXX")
  assert_private_directory "$STAGE"
  "$PYTHON_BIN" -m venv "$STAGE/python"
  "$STAGE/python/bin/python" -m pip \
    --isolated \
    --disable-pip-version-check \
    install \
    --index-url https://pypi.org/simple \
    --require-hashes \
    --only-binary=:all: \
    --no-deps \
    --no-cache-dir \
    --no-compile \
    --requirement "$BUILD_REQUIREMENTS"
  "$STAGE/python/bin/python" -m pip \
    --isolated \
    --disable-pip-version-check \
    install \
    --index-url https://pypi.org/simple \
    --require-hashes \
    --no-deps \
    --no-cache-dir \
    --no-compile \
    --no-build-isolation \
    --requirement "$REQUIREMENTS"
  "$STAGE/python/bin/python" - <<'PY'
import Crypto
import imageio_ffmpeg
import pilk
import zstandard
PY
  "$PYTHON_BIN" - "$STAGE/python" "$RUNTIME_ROOT" <<'PY'
import ctypes
import errno
import os
import sys

source = os.fsencode(sys.argv[1])
destination = os.fsencode(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
rename_exclusive = libc.renamex_np
rename_exclusive.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rename_exclusive.restype = ctypes.c_int
if rename_exclusive(source, destination, 0x00000004) != 0:
    error = ctypes.get_errno()
    if error != errno.EEXIST:
        raise SystemExit("Atomic runtime installation failed: " + os.strerror(error))
PY
  /bin/rmdir "$STAGE"
  STAGE=""
fi

if [[ -e "$CURRENT_RUNTIME" && ! -L "$CURRENT_RUNTIME" ]]; then
  fail "Existing legacy runtime is not replaced automatically"
fi
temporary="$TOOLS_ROOT/.python.$$.tmp"
/bin/ln -s "$RUNTIME_ROOT" "$temporary"
"$PYTHON_BIN" - "$temporary" "$CURRENT_RUNTIME" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
print "Runtime dependencies: OK"
