#!/bin/zsh
set -euo pipefail

PROJECT_ROOT=${0:A:h:h}
BINARY="$PROJECT_ROOT/.build/release/wechat-voice-mp4"
FORBIDDEN='CGEventCreateKeyboardEvent|CGEventKeyboardSetUnicodeString|AXUIElementSetAttributeValue|AXUIElementPostKeyboardEvent|NSPasteboard|CGEventTapCreate'

"$PROJECT_ROOT/scripts/build.sh"

if /usr/bin/grep -R -n -E "$FORBIDDEN" "$PROJECT_ROOT/Sources"; then
  print -u2 "Forbidden input API referenced in source"
  exit 1
fi

if nm -u "$BINARY" | /usr/bin/grep -E "$FORBIDDEN"; then
  print -u2 "Forbidden input symbol found"
  exit 1
fi

print "Forbidden keyboard/paste/event-tap symbols: none"
