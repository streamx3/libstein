#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# EWF / E01 (Expert Witness, EnCase) fixtures acquired by libewf's ewfacquire
# from a raw GPT disk (FAT12 + ext2 partitions): EnCase 6 best compression in
# one segment, EnCase 6 uncompressed split into 2 MiB segments, and EnCase 5.
# Oracle: the raw disk's SHA-256 and size, ewfacquire's MD5/SHA-1, and the
# segment count. Each segment is packed separately as <name>.<ext>.sparse.
set -eu
OUT=${1:-tests/fixtures/ewf}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

RAW="$WORK/disk.raw"
truncate -s 24M "$RAW"
sgdisk -o -n 1:2048:+4M -t 1:0700 -c 1:fatpart -n 2:0:+12M -t 2:8300 -c 2:extpart "$RAW" >/dev/null
P1="$WORK/p1.img"; truncate -s 4M "$P1"; mkfs.vfat -F 12 -n FATPART "$P1" >/dev/null
P2="$WORK/p2.img"; truncate -s 12M "$P2"; mkfs.ext2 -q -b 1024 -L inside_ewf "$P2"
echo "ext2 file inside an E01 image" > "$WORK/hello.txt"
debugfs -w -R "write $WORK/hello.txt hello.txt" "$P2" >/dev/null 2>&1
P2START=$(sgdisk -i 2 "$RAW" | awk '/First sector/ {print $3}')
dd if="$P1" of="$RAW" bs=512 seek=2048 conv=notrunc status=none
dd if="$P2" of="$RAW" bs=512 seek="$P2START" conv=notrunc status=none
python3 - "$RAW" <<'PY'
import sys, hashlib
p = sys.argv[1]
with open(p, "r+b") as f:
    for off in (5 * 1024 * 1024 + 123, 7 * 1024 * 1024 - 1, 9 * 1024 * 1024 + 4095, 23 * 1024 * 1024 + 511):
        f.seek(off); f.write(hashlib.sha256(str(off).encode()).digest() * 8)
    # A run of incompressible data so compressed chunks of every kind appear.
    f.seek(15 * 1024 * 1024); f.write(hashlib.sha256(b"noise").digest() * 8192)   # 256 KiB
PY
SHA=$(sha256sum "$RAW" | cut -d' ' -f1)
RAWSIZE=$(stat -c %s "$RAW")

make_one() { # name ewfacquire-args...
  local name=$1; shift
  local dir="$WORK/$name"; mkdir -p "$dir"
  ewfacquire -u -t "$dir/$name" -C case1 -D "libstein fixture" -E ev1 -e stein -N note -m fixed -M physical -d sha1 "$@" "$RAW" >/dev/null 2>&1
  local md5 sha1 count=0
  md5=$(ewfinfo "$dir/$name.E01" | awk '/MD5:/ {print $2}')
  sha1=$(ewfinfo "$dir/$name.E01" | awk '/SHA1:/ {print $2}')
  for seg in "$dir"/"$name".E??; do
    python3 "$HERE/sparsify.py" pack "$seg" "$OUT/$(basename "$seg").sparse"
    count=$((count + 1))
  done
  printf 'raw_size=%s\nsha256=%s\nmd5=%s\nsha1=%s\nsegments=%s\n' "$RAWSIZE" "$SHA" "$md5" "$sha1" "$count" > "$OUT/$name.oracle.txt"
  echo "$name: $count segment(s), $(du -sb "$dir" | cut -f1) bytes raw EWF"
}

make_one ewf6_best  -f encase6 -c best -b 64 -g 64
make_one ewf6_split -f encase6 -c none -b 128 -S 2MiB
make_one ewf5       -f encase5 -c fast -b 32
