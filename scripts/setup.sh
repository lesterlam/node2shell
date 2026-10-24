#!/usr/bin/env bash
# Fetch the decoders under test and build the harnesses.
#
# The Brotli tarballs are pinned by sha256 because the GitHub release assets publish no SHASUMS
# file; the Node.js tarballs are verified against the release's own SHASUMS256.txt.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

BROTLI_120_SHA=816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec
BROTLI_121_SHA=98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f
NODE_VERSIONS="${NODE_VERSIONS:-}"

fetch() {   # url dest [sha256]
  local url="$1" dest="$2" want="${3:-}"
  [ -f "$dest" ] && { echo "have $dest"; return 0; }
  echo "fetch $url"
  curl -fsSL -o "$dest" "$url"
  if [ -n "$want" ]; then
    echo "$want  $dest" | sha256sum -c -
  fi
}

mkdir -p asan runtimes

# ---- decoders under test -------------------------------------------------
fetch "https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz" \
      "asan/brotli-v1.2.0.tar.gz" "$BROTLI_120_SHA"
fetch "https://github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz" \
      "asan/brotli-v1.2.1.tar.gz" "$BROTLI_121_SHA"
for v in 1.2.0 1.2.1; do
  [ -d "asan/brotli-$v" ] || tar -xzf "asan/brotli-v$v.tar.gz" -C asan \
      --one-top-level="brotli-$v" --strip-components=1
done

# ---- optional: Node.js runtimes for a runtime-level A/B ------------------
for v in $NODE_VERSIONS; do
  fetch "https://nodejs.org/dist/v$v/SHASUMS256.txt" "runtimes/SHASUMS256-v$v.txt"
  tarball="node-v$v-linux-x64.tar.xz"
  fetch "https://nodejs.org/dist/v$v/$tarball" "runtimes/$tarball"
  ( cd runtimes && grep " $tarball\$" "SHASUMS256-v$v.txt" | sha256sum -c - )
  tar -xJf "runtimes/$tarball" -C runtimes
  "runtimes/node-v$v-linux-x64/bin/node" -v
done

# ---- harnesses -----------------------------------------------------------
./asan/build.sh
echo
echo "next: payload/gen_payload.py --variant cmd-drain --tail 24 --out payload/payloads/cmd-drain-t24.br"
echo "      ./run_ab.sh payload/payloads/cmd-drain-t24.br 900"
