#!/usr/bin/env bash
# Build the instrumented decoder harness for both Brotli versions.
#   harness-<ver>        release semantics (BROTLI_DCHECK compiled out)
#   harness-<ver>-debug  -DBROTLI_DEBUG: the vendor's own assertions live
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CC="${CC:-cc}"
CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer -Wall"

for t in 1.2.0 1.2.1; do
  src_dir="brotli-$t/c"
  [ -d "$src_dir" ] || { echo "missing $src_dir (download the sources first)" >&2; exit 1; }
  # shellcheck disable=SC2086
  "$CC" $CFLAGS -I "$src_dir/include" -I "$src_dir/dec" -I "$src_dir/common" \
      harness.c "$src_dir"/dec/*.c "$src_dir"/common/*.c -o "harness-$t"
  # shellcheck disable=SC2086
  "$CC" $CFLAGS -DBROTLI_DEBUG -I "$src_dir/include" -I "$src_dir/dec" -I "$src_dir/common" \
      harness.c "$src_dir"/dec/*.c "$src_dir"/common/*.c -o "harness-$t-debug"
  echo "built harness-$t harness-$t-debug"
done
