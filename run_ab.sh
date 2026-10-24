#!/usr/bin/env bash
# Node2Shell trigger A/B: same payload, vulnerable vs patched Brotli decoder.
#
#   ./run_ab.sh <payload.br> [watchdog seconds]
#
# The prober feeds the payload as one chunk, drains NEEDS_MORE_OUTPUT, then adds
# exactly the number of attacker bytes needed to push a byte past the 8-byte
# internal input buffer, and prints an explicit verdict per build.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD="${1:?usage: run_ab.sh <payload.br> [watchdog seconds]}"
WD="${2:-900}"

for v in 1.2.0 1.2.1; do
  echo "=============================================================="
  echo "decoder brotli $v   payload $(basename "$PAYLOAD")   ($(stat -c%s "$PAYLOAD" 2>/dev/null || stat -f%z "$PAYLOAD") bytes)"
  echo "--------------------------------------------------------------"
  "$HERE/asan/harness-$v" --watchdog "$WD" "$PAYLOAD" 2>/dev/null \
    | grep -vE "^  offsetof|^  sizeof|^state_layout|^  input byte index|^phase1 call=[0-9]+ result=3"
  echo
done
