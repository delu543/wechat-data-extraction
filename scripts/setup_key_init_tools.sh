#!/bin/zsh
set -euo pipefail
umask 077

PROJECT_ROOT=${0:A:h:h}
REQUIREMENTS_PATH="$PROJECT_ROOT/scripts/requirements-key-init.txt"
PRODUCT_SUPPORT_ROOT="${HOME}/Library/Application Support/WeChatLocalExport"
TASK_SUPPORT_ROOT="$PRODUCT_SUPPORT_ROOT/key-init-tools"
VENV_ROOT="$TASK_SUPPORT_ROOT/python"
CURRENT_UID=$(/usr/bin/id -u)
STAGE_ROOT=""

fail() {
  print -u2 -- "$1"
  exit 2
}

path_mode() {
  /usr/bin/stat -f '%Lp' "$1"
}

path_owner() {
  /usr/bin/stat -f '%u' "$1"
}

assert_safe_ancestor() {
  local path=$1
  local mode
  [[ -e "$path" ]] || fail "Required support-directory ancestor is missing"
  [[ ! -L "$path" ]] || fail "Refusing a symbolic-link support-directory ancestor"
  [[ -d "$path" ]] || fail "Support-directory ancestor is not a directory"
  [[ "$(path_owner "$path")" == "$CURRENT_UID" ]] || \
    fail "Support-directory ancestor is not owned by the current user"
  mode=$(path_mode "$path")
  (( (8#$mode & 8#022) == 0 )) || \
    fail "Support-directory ancestor is writable by another user"
}

assert_private_root() {
  local path=$1
  [[ -e "$path" ]] || fail "Private support directory is missing"
  [[ ! -L "$path" ]] || fail "Refusing a symbolic-link private support directory"
  [[ -d "$path" ]] || fail "Private support path is not a directory"
  [[ "$(path_owner "$path")" == "$CURRENT_UID" ]] || \
    fail "Private support directory is not owned by the current user"
  [[ "$(path_mode "$path")" == "700" ]] || \
    fail "Private support directory must have mode 0700"
}

cleanup_stage() {
  local stage=${STAGE_ROOT:-}
  [[ -n "$stage" ]] || return 0
  case "$stage" in
    "$TASK_SUPPORT_ROOT"/.python.install.*) ;;
    *)
      print -u2 "Refusing to clean an unexpected installer staging path"
      return 1
      ;;
  esac
  if [[ -e "$stage" || -L "$stage" ]]; then
    [[ ! -L "$stage" && -d "$stage" ]] || {
      print -u2 "Refusing to clean a non-directory installer staging path"
      return 1
    }
    [[ "$(path_owner "$stage")" == "$CURRENT_UID" ]] || {
      print -u2 "Refusing to clean installer staging owned by another user"
      return 1
    }
    /bin/rm -rf -- "$stage"
  fi
}
trap cleanup_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[[ -n "${HOME:-}" && "$HOME" == /* && "$HOME" != "/" ]] || \
  fail "HOME must be an absolute non-root path"
[[ -f "$REQUIREMENTS_PATH" && ! -L "$REQUIREMENTS_PATH" ]] || \
  fail "Pinned key-initializer requirements are missing or unsafe"

# Existing ancestors may be readable, but none may be symlinks, foreign-owned,
# or writable by group/other. The two product-private directories are stricter.
assert_safe_ancestor "$HOME"
assert_safe_ancestor "$HOME/Library"
assert_safe_ancestor "$HOME/Library/Application Support"

if [[ -e "$PRODUCT_SUPPORT_ROOT" || -L "$PRODUCT_SUPPORT_ROOT" ]]; then
  assert_safe_ancestor "$PRODUCT_SUPPORT_ROOT"
else
  /bin/mkdir "$PRODUCT_SUPPORT_ROOT"
  /bin/chmod 700 "$PRODUCT_SUPPORT_ROOT"
fi

if [[ -e "$TASK_SUPPORT_ROOT" || -L "$TASK_SUPPORT_ROOT" ]]; then
  assert_private_root "$TASK_SUPPORT_ROOT"
else
  /bin/mkdir "$TASK_SUPPORT_ROOT"
  /bin/chmod 700 "$TASK_SUPPORT_ROOT"
fi
assert_private_root "$TASK_SUPPORT_ROOT"

if [[ -e "$VENV_ROOT" || -L "$VENV_ROOT" ]]; then
  fail "Key-initializer environment already exists; refusing to overwrite it"
fi

/usr/bin/python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else "需要 Python 3.9 或更高版本")'
[[ "$(/usr/bin/python3 -c 'import platform; print(platform.python_implementation())')" == "CPython" ]] || \
  fail "Only standard CPython is supported by the pinned macOS wheels"

STAGE_ROOT=$(/usr/bin/mktemp -d "$TASK_SUPPORT_ROOT/.python.install.XXXXXXXX")
assert_private_root "$STAGE_ROOT"
STAGE_VENV="$STAGE_ROOT/python"
/usr/bin/python3 -m venv "$STAGE_VENV"

"$STAGE_VENV/bin/python" -m pip \
  --isolated \
  --disable-pip-version-check \
  install \
  --index-url https://pypi.org/simple \
  --require-hashes \
  --only-binary=:all: \
  --no-deps \
  --no-cache-dir \
  --no-compile \
  --requirement "$REQUIREMENTS_PATH"

PYTHONPATH="$PROJECT_ROOT" "$STAGE_VENV/bin/python" -c \
  'from live_tools.wechat_key_init import dependency_status; status=dependency_status(); raise SystemExit(0 if all(status.values()) else status)'

# renamex_np(RENAME_EXCL) is an atomic, same-filesystem, no-clobber rename on
# macOS. Unlike `mv -n source existing-directory`, it cannot accidentally nest
# the staged environment inside a destination that appeared concurrently.
/usr/bin/python3 - "$STAGE_VENV" "$VENV_ROOT" <<'PY'
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
RENAME_EXCL = 0x00000004

if rename_exclusive(source, destination, RENAME_EXCL) != 0:
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise SystemExit(
            "Key-initializer environment appeared concurrently; nothing was overwritten"
        )
    raise SystemExit("Atomic key-initializer installation failed: " + os.strerror(error))
PY
[[ ! -e "$STAGE_VENV" && ! -L "$STAGE_VENV" ]] || \
  fail "Atomic key-initializer environment installation did not consume staging"
[[ -d "$VENV_ROOT" && ! -L "$VENV_ROOT" ]] || \
  fail "Atomic key-initializer environment installation failed"
/bin/rmdir "$STAGE_ROOT"
STAGE_ROOT=""

print "Key initializer Python: $VENV_ROOT/bin/python"
print "Next: run the read-only setup-doctor before requesting capture consent"
