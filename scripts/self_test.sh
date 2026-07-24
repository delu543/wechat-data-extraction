#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
OUTPUT_DIR="$PROJECT_ROOT/outputs"
mkdir -p "$OUTPUT_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE=${1:-"$OUTPUT_DIR/self-test-$STAMP.mp4"}

"$PROJECT_ROOT/scripts/build.sh"
"$PROJECT_ROOT/.build/release/wechat-voice-mp4" self-test --output "$OUTPUT_FILE"
print "Verified MP4: $OUTPUT_FILE"
