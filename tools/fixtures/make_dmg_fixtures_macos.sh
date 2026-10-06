#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Apple DMG (UDIF) fixtures, converted by hdiutil on macOS from the same raw
# GPT disk the virtual-disk fixtures use (recovered from the fixed-VHD fixture,
# which is that raw disk plus a footer). Variants: UDRO (raw blocks), UDZO
# (zlib), UDBZ (bzip2), UDCO (ADC), ULMO (lzma); lzfse waits for a decoder. Existing
# outputs are kept (hdiutil output is not reproducible). Oracle: the raw
# disk's SHA-256 and size.
set -eu
OUT=${1:-tests/fixtures/dmg}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

python3 "$HERE/sparsify.py" unpack "$HERE/../../tests/fixtures/vdisk/vhd_fixed.sparse" "$WORK/disk.vhd"
RAWSIZE=$(awk -F= '/^raw_size=/ {print $2}' "$HERE/../../tests/fixtures/vdisk/vhd_fixed.oracle.txt")
SHA=$(awk -F= '/^sha256=/ {print $2}' "$HERE/../../tests/fixtures/vdisk/vhd_fixed.oracle.txt")
head -c "$RAWSIZE" "$WORK/disk.vhd" > "$WORK/disk.img"
echo "raw $RAWSIZE bytes sha256 $SHA"

make_one() { # name format
  local name=$1 fmt=$2
  if [ -f "$OUT/$name.sparse" ]; then echo "$name: exists, kept (hdiutil output is not reproducible)"; return; fi
  hdiutil convert "$WORK/disk.img" -format "$fmt" -o "$WORK/$name" -ov >/dev/null
  python3 "$HERE/sparsify.py" pack "$WORK/$name.dmg" "$OUT/$name.sparse"
  printf 'format=%s\nraw_size=%s\nsha256=%s\n' "$fmt" "$RAWSIZE" "$SHA" > "$OUT/$name.oracle.txt"
  echo "$name ($fmt): $(stat -f %z "$WORK/$name.dmg") -> $(stat -f %z "$OUT/$name.sparse") bytes"
}

make_one dmg_udro UDRO
make_one dmg_udzo UDZO
make_one dmg_udbz UDBZ
make_one dmg_udco UDCO
make_one dmg_ulmo ULMO
