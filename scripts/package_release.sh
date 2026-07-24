#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
PACKAGE_VERSION=${1:-0.2.0-dev.8}
MANIFEST_VERSION=$(/usr/bin/python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' \
  "$PROJECT_ROOT/portable_skill/.codex-plugin/plugin.json")
if [[ "$PACKAGE_VERSION" != "$MANIFEST_VERSION" ]]; then
  print -u2 "Package version does not match Plugin manifest"
  exit 2
fi
OUTPUT_ROOT="$PROJECT_ROOT/outputs"
PLUGIN_ARCHIVE="$OUTPUT_ROOT/wechat-local-export-plugin-$PACKAGE_VERSION.zip"
SOURCE_ARCHIVE="$OUTPUT_ROOT/wechat-local-export-source-kit-$PACKAGE_VERSION.zip"
PACKAGE_STAGE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wechat-local-export-package.XXXXXX")

cleanup_stage() {
  case "$PACKAGE_STAGE_ROOT" in
    */wechat-local-export-package.*)
      if [[ -d "$PACKAGE_STAGE_ROOT" && ! -L "$PACKAGE_STAGE_ROOT" ]]; then
        rm -rf -- "$PACKAGE_STAGE_ROOT"
      fi
      ;;
    *)
      print -u2 "Refusing to clean unexpected staging path"
      ;;
  esac
}
trap cleanup_stage EXIT

if [[ -e "$PLUGIN_ARCHIVE" || -e "$SOURCE_ARCHIVE" ]]; then
  print -u2 "Release archive already exists; refusing to overwrite"
  exit 2
fi

mkdir -p "$OUTPUT_ROOT"
PLUGIN_STAGE="$PACKAGE_STAGE_ROOT/wechat-local-export-plugin-$PACKAGE_VERSION"
SOURCE_STAGE="$PACKAGE_STAGE_ROOT/wechat-local-export-source-kit-$PACKAGE_VERSION"
mkdir -p "$PLUGIN_STAGE" "$SOURCE_STAGE"

copy_tree() {
  local source_path=$1
  local destination_parent=$2
  /usr/bin/rsync -a \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.DS_Store' \
    "$source_path" "$destination_parent/"
}

copy_tree "$PROJECT_ROOT/portable_skill/.codex-plugin" "$PLUGIN_STAGE"
copy_tree "$PROJECT_ROOT/portable_skill/.agents" "$PLUGIN_STAGE"
copy_tree "$PROJECT_ROOT/portable_skill/skills" "$PLUGIN_STAGE"
copy_tree "$PROJECT_ROOT/portable_skill/scripts" "$PLUGIN_STAGE"
copy_tree "$PROJECT_ROOT/portable_skill/tests" "$PLUGIN_STAGE"
for name in INSTALL.md PRIVACY.md SECURITY.md; do
  /bin/cp "$PROJECT_ROOT/portable_skill/$name" "$PLUGIN_STAGE/$name"
done
/bin/cp "$PROJECT_ROOT/THIRD_PARTY_NOTICES.md" "$PLUGIN_STAGE/THIRD_PARTY_NOTICES.md"

for name in README.md AGENTS.md PRIVACY.md SECURITY.md Package.swift THIRD_PARTY_NOTICES.md .gitignore; do
  /bin/cp "$PROJECT_ROOT/$name" "$SOURCE_STAGE/$name"
done
for name in Sources content_vault direct_vault live_tools scripts docs portable_skill .agents; do
  copy_tree "$PROJECT_ROOT/$name" "$SOURCE_STAGE"
done

validate_stage() {
  local stage_path=$1
  local unsafe_links
  unsafe_links=$(find "$stage_path" -type l -print)
  if [[ -n "$unsafe_links" ]]; then
    print -u2 "Staging contains symbolic links"
    print -u2 "$unsafe_links"
    exit 2
  fi
  local sensitive_files
  sensitive_files=$(find "$stage_path" -type f \( \
    -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.sqlite*' \
    -o -name '*.silk' -o -name '*.pcm' -o -name '*.m4a' -o -name '*.mp3' \
    -o -name '*.mp4' -o -name '*.mov' -o -name '*.zip' -o -name '*.whl' \
    -o -name '*.pem' -o -name '*.key' -o -name '*.p12' \
    -o -name '*.dylib' -o -name '*.so' \
    -o -name '*.jsonl' -o -name '*.log' -o -name '*.pid' \
  \) -print)
  if [[ -n "$sensitive_files" ]]; then
    print -u2 "Staging contains prohibited data artifacts"
    print -u2 "$sensitive_files"
    exit 2
  fi
  local privacy_matches
  privacy_matches=$(rg -l --hidden \
    '/(Users|home)/[^/]+/|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' \
    "$stage_path" || true)
  if [[ -n "$privacy_matches" ]]; then
    print -u2 "Staging contains a private path, key block, or real-task fingerprint"
    print -u2 "$privacy_matches"
    exit 2
  fi
  xattr -cr "$stage_path"
}

validate_stage "$PLUGIN_STAGE"
validate_stage "$SOURCE_STAGE"

(
  cd "$PACKAGE_STAGE_ROOT"
  COPYFILE_DISABLE=1 /usr/bin/zip -X -q -r "$PLUGIN_ARCHIVE" "${PLUGIN_STAGE:t}"
  COPYFILE_DISABLE=1 /usr/bin/zip -X -q -r "$SOURCE_ARCHIVE" "${SOURCE_STAGE:t}"
)

/usr/bin/unzip -tq "$PLUGIN_ARCHIVE"
/usr/bin/unzip -tq "$SOURCE_ARCHIVE"

VERIFY_ROOT="$PACKAGE_STAGE_ROOT/verify"
mkdir -p "$VERIFY_ROOT"
/usr/bin/unzip -q "$SOURCE_ARCHIVE" -d "$VERIFY_ROOT"
/usr/bin/python3 \
  "$VERIFY_ROOT/${SOURCE_STAGE:t}/portable_skill/scripts/validate_package.py" >/dev/null

print "$PLUGIN_ARCHIVE"
print "$SOURCE_ARCHIVE"
