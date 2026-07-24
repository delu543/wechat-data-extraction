#!/bin/zsh
set -euo pipefail
umask 077

SOURCE_ROOT=${0:A:h:h}
ACTION=${1:-install}
[[ $# -gt 0 ]] && shift
SKIP_DEPENDENCIES=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-dependencies) SKIP_DEPENDENCIES=true ;;
    --skip-build) SKIP_BUILD=true ;;
    *)
      print -u2 "Unknown bootstrap option"
      exit 2
      ;;
  esac
  shift
done

fail() {
  print -u2 -- "$1"
  exit 2
}

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || fail "This project supports macOS only"
[[ -n "${HOME:-}" && "$HOME" == /* && "$HOME" != "/" ]] || \
  fail "HOME must be an absolute non-root path"
[[ "$(/usr/bin/id -u)" != "0" ]] || fail "Do not run this installer as root"
[[ -f "$SOURCE_ROOT/portable_skill/.codex-plugin/plugin.json" ]] || \
  fail "Run the installer from a complete project checkout"

SUPPORT_ROOT="$HOME/Library/Application Support/WeChatLocalExport"
TOOLS_ROOT="$SUPPORT_ROOT/tools"
RUNTIME_PYTHON="$TOOLS_ROOT/python/bin/python"
APP_ROOT="$SUPPORT_ROOT/app"
RELEASES_ROOT="$APP_ROOT/releases"
CURRENT_LINK="$APP_ROOT/current"
INSTALL_STATE="$APP_ROOT/install.json"
SKILLS_ROOT="$HOME/.agents/skills"
EXPORT_LINK="$SKILLS_ROOT/wechat-local-export"
SETUP_LINK="$SKILLS_ROOT/wechat-local-export-setup"
VERSION=$(/usr/bin/python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' \
  "$SOURCE_ROOT/portable_skill/.codex-plugin/plugin.json")
SOURCE_HASH=$(/usr/bin/python3 - "$SOURCE_ROOT" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

root = Path(sys.argv[1])
included = [
    root / name
    for name in (
        ".agents",
        ".github",
        ".gitignore",
        "AGENTS.md",
        "Package.swift",
        "PRIVACY.md",
        "README.md",
        "SECURITY.md",
        "Sources",
        "THIRD_PARTY_NOTICES.md",
        "content_vault",
        "direct_vault",
        "docs",
        "live_tools",
        "portable_skill",
        "scripts",
    )
]
excluded_parts = {".build", ".codex", ".git", "__pycache__", "outputs", "tasks", "work"}
digest = sha256()
files: list[Path] = []
for entry in included:
    if entry.is_file():
        files.append(entry)
    elif entry.is_dir():
        files.extend(path for path in entry.rglob("*") if path.is_file())
for path in sorted(files, key=lambda value: value.relative_to(root).as_posix()):
    relative = path.relative_to(root)
    if any(part in excluded_parts for part in relative.parts):
        continue
    digest.update(relative.as_posix().encode("utf-8"))
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")
print(digest.hexdigest())
PY
)
RELEASE_ID="$VERSION-${SOURCE_HASH[1,16]}"
if $SKIP_BUILD; then
  RELEASE_ID="$RELEASE_ID.unbuilt"
fi
RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_ID"
INSTALLED_EXPORT_SOURCE="$CURRENT_LINK/portable_skill/skills/wechat-local-export"
INSTALLED_SETUP_SOURCE="$CURRENT_LINK/portable_skill/skills/wechat-local-export-setup"
INSTALLED_SWIFT_BINARY="$CURRENT_LINK/.build/release/wechat-voice-mp4"
RELEASE_STAGE=""

cleanup_release_stage() {
  [[ -n "$RELEASE_STAGE" ]] || return 0
  case "$RELEASE_STAGE" in
    "$RELEASES_ROOT"/.install.*)
      [[ -d "$RELEASE_STAGE" && ! -L "$RELEASE_STAGE" ]] && \
        /bin/rm -rf -- "$RELEASE_STAGE"
      ;;
  esac
}
trap cleanup_release_stage EXIT

assert_owned_directory() {
  local path=$1
  [[ -d "$path" && ! -L "$path" ]] || fail "Unsafe installer directory"
  [[ "$(/usr/bin/stat -f '%u' "$path")" == "$(/usr/bin/id -u)" ]] || \
    fail "Installer directory is not owned by the current user"
}

ensure_private_directory() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    assert_owned_directory "$path"
    [[ "$(/usr/bin/stat -f '%Lp' "$path")" == "700" ]] || \
      fail "Private installer directory must have mode 0700"
  else
    /bin/mkdir "$path"
    /bin/chmod 700 "$path"
  fi
}

prepare_roots() {
  /bin/mkdir -p "$HOME/Library/Application Support"
  ensure_private_directory "$SUPPORT_ROOT"
  ensure_private_directory "$APP_ROOT"
  ensure_private_directory "$RELEASES_ROOT"
  /bin/mkdir -p "$SKILLS_ROOT"
  assert_owned_directory "$SKILLS_ROOT"
}

runtime_ready() {
  [[ -x "$RUNTIME_PYTHON" ]] || return 1
  "$RUNTIME_PYTHON" - <<'PY' >/dev/null 2>&1
from importlib.metadata import version
expected = {
    "pilk": "0.2.4",
    "imageio-ffmpeg": "0.6.0",
    "pycryptodome": "3.23.0",
    "zstandard": "0.23.0",
}
raise SystemExit(0 if all(version(name) == wanted for name, wanted in expected.items()) else 1)
PY
}

link_points_to() {
  local link_path=$1
  local source_path=$2
  [[ -L "$link_path" ]] || return 1
  [[ "$(/usr/bin/readlink "$link_path")" == "$source_path" ]]
}

skills_ready() {
  link_points_to "$EXPORT_LINK" "$INSTALLED_EXPORT_SOURCE" &&
    link_points_to "$SETUP_LINK" "$INSTALLED_SETUP_SOURCE"
}

swift_ready() {
  [[ -x "$INSTALLED_SWIFT_BINARY" ]] || return 1
  "$INSTALLED_SWIFT_BINARY" verify-core >/dev/null 2>&1
}

source_package_ready() {
  /usr/bin/python3 "$SOURCE_ROOT/portable_skill/scripts/validate_package.py" >/dev/null 2>&1 &&
    /usr/bin/python3 "$SOURCE_ROOT/scripts/validate_public_repo.py" >/dev/null 2>&1
}

installed_package_ready() {
  [[ -L "$CURRENT_LINK" ]] || return 1
  /usr/bin/python3 "$CURRENT_LINK/portable_skill/scripts/validate_package.py" >/dev/null 2>&1 &&
    /usr/bin/python3 "$CURRENT_LINK/scripts/validate_public_repo.py" >/dev/null 2>&1
}

doctor() {
  local runtime=false
  local skills=false
  local swift=false
  local package=false
  runtime_ready && runtime=true
  skills_ready && skills=true
  swift_ready && swift=true
  installed_package_ready && package=true
  if $runtime && $skills && $swift && $package; then
    print "status=ready"
    print "runtime=ready"
    print "skills=ready"
    print "swift_helper=ready"
    print "account_setup=not_checked"
    return 0
  fi
  print "status=needs_install"
  print "runtime=$runtime"
  print "skills=$skills"
  print "swift_helper=$swift"
  print "package=$package"
  print "account_setup=not_checked"
  return 2
}

copy_release_source() {
  local destination=$1
  /bin/mkdir "$destination"
  for name in \
    .agents .github .gitignore AGENTS.md Package.swift PRIVACY.md README.md SECURITY.md \
    Sources THIRD_PARTY_NOTICES.md \
    content_vault direct_vault docs live_tools portable_skill scripts; do
    [[ -e "$SOURCE_ROOT/$name" && ! -L "$SOURCE_ROOT/$name" ]] || \
      fail "Release source is incomplete or contains an unsafe link"
    /usr/bin/rsync -a \
      --exclude '.DS_Store' \
      --exclude '__pycache__' \
      --exclude '*.pyc' \
      "$SOURCE_ROOT/$name" "$destination/"
  done
}

publish_release() {
  [[ -e "$RELEASE_ROOT" || -L "$RELEASE_ROOT" ]] && return 0
  RELEASE_STAGE=$(/usr/bin/mktemp -d "$RELEASES_ROOT/.install.XXXXXXXX")
  local staged_source="$RELEASE_STAGE/source"
  copy_release_source "$staged_source"
  /usr/bin/python3 "$staged_source/portable_skill/scripts/validate_package.py" >/dev/null
  /usr/bin/python3 "$staged_source/scripts/validate_public_repo.py" >/dev/null

  if ! $SKIP_BUILD; then
    /usr/bin/xcrun --find swift >/dev/null 2>&1 || \
      fail "Apple Command Line Tools with Swift are required"
    "$staged_source/scripts/build.sh"
    "$staged_source/.build/release/wechat-voice-mp4" verify-core >/dev/null
    "$staged_source/scripts/verify_no_keyboard.sh"
  fi

  /usr/bin/python3 - "$staged_source" "$RELEASE_ROOT" <<'PY'
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
        raise SystemExit("Atomic release installation failed: " + os.strerror(error))
PY
  [[ -d "$RELEASE_ROOT" && ! -L "$RELEASE_ROOT" ]] || \
    fail "Release publication failed"
  /bin/rmdir "$RELEASE_STAGE"
  RELEASE_STAGE=""
}

switch_current_release() {
  if [[ -e "$CURRENT_LINK" && ! -L "$CURRENT_LINK" ]]; then
    fail "Refusing to replace a non-link current installation"
  fi
  local temporary="$APP_ROOT/.current.$$.tmp"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || fail "Unsafe current-link staging path"
  /bin/ln -s "$RELEASE_ROOT" "$temporary"
  /usr/bin/python3 - "$temporary" "$CURRENT_LINK" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
}

install_skill_link() {
  local source_path=$1
  local link_path=$2
  [[ -d "$source_path" ]] || fail "Installed Skill source is missing"
  if [[ -e "$link_path" || -L "$link_path" ]]; then
    link_points_to "$link_path" "$source_path" || \
      fail "A different Skill already occupies the installation path"
    return 0
  fi
  /bin/ln -s "$source_path" "$link_path"
}

write_install_state() {
  VERSION_VALUE="$VERSION" SOURCE_HASH_VALUE="$SOURCE_HASH" \
    RELEASE_ROOT_VALUE="$RELEASE_ROOT" INSTALL_STATE_VALUE="$INSTALL_STATE" \
    /usr/bin/python3 - <<'PY'
import json
import os
from pathlib import Path

destination = Path(os.environ["INSTALL_STATE_VALUE"])
temporary = destination.with_name(".install.json.tmp")
temporary.write_text(
    json.dumps(
        {
            "schema_version": 1,
            "project": "微信数据提取项目",
            "release_root": os.environ["RELEASE_ROOT_VALUE"],
            "source_hash": os.environ["SOURCE_HASH_VALUE"],
            "version": os.environ["VERSION_VALUE"],
            "owns_private_data": False,
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
temporary.chmod(0o600)
temporary.replace(destination)
PY
}

install_project() {
  source_package_ready || fail "Project validation failed before installation"
  prepare_roots

  if ! $SKIP_DEPENDENCIES && ! runtime_ready; then
    "$SOURCE_ROOT/scripts/setup_runtime_tools.sh"
  fi
  $SKIP_DEPENDENCIES || runtime_ready || fail "Runtime dependency verification failed"

  publish_release
  switch_current_release
  install_skill_link "$INSTALLED_EXPORT_SOURCE" "$EXPORT_LINK"
  install_skill_link "$INSTALLED_SETUP_SOURCE" "$SETUP_LINK"
  write_install_state

  if $SKIP_DEPENDENCIES || $SKIP_BUILD; then
    print "status=installed_with_development_skips"
    return 0
  fi
  doctor
}

remove_owned_link() {
  local link_path=$1
  local source_path=$2
  if [[ -L "$link_path" ]]; then
    link_points_to "$link_path" "$source_path" || \
      fail "Refusing to remove a Skill link owned by another installation"
    /bin/rm -- "$link_path"
  elif [[ -e "$link_path" ]]; then
    fail "Refusing to remove a non-link Skill installation"
  fi
}

uninstall_project() {
  remove_owned_link "$EXPORT_LINK" "$INSTALLED_EXPORT_SOURCE"
  remove_owned_link "$SETUP_LINK" "$INSTALLED_SETUP_SOURCE"
  if [[ -L "$CURRENT_LINK" ]]; then
    current_target=$(/usr/bin/readlink "$CURRENT_LINK")
    case "$current_target" in
      "$RELEASES_ROOT"/*) ;;
      *) fail "Refusing to remove another installed release link" ;;
    esac
    /bin/rm -- "$CURRENT_LINK"
  elif [[ -e "$CURRENT_LINK" ]]; then
    fail "Refusing to remove a non-link current installation"
  fi
  if [[ -f "$INSTALL_STATE" && ! -L "$INSTALL_STATE" ]]; then
    /bin/rm -- "$INSTALL_STATE"
  fi
  print "status=skills_removed"
  print "private_data=retained"
  print "runtime=retained"
  print "release_copy=retained"
}

case "$ACTION" in
  doctor) doctor ;;
  install) install_project ;;
  uninstall) uninstall_project ;;
  *)
    print -u2 "Usage: ./scripts/codex_bootstrap.sh [doctor|install|uninstall]"
    exit 2
    ;;
esac
