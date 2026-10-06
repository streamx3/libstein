#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# exFAT fixtures for the in-process reader. There is no kernel exfat driver
# in the build container, so the files are written through exfat-fuse on a
# loop device (root); the oracle is `find` + sha256 over the FUSE mount and
# fsck.exfat confirms the volume is clean. Covers contiguous (NoFatChain)
# and fragmented files, Unicode and 255-character names, a 300-entry
# directory, empty files, nested directories and two cluster sizes.
set -eu
OUT=${1:-tests/fixtures/exfatfs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

fill() { # mountpoint
  local m=$1
  python3 - "$m" <<'PY'
import os, sys
m = sys.argv[1]
def w(path, data):
    p = os.path.join(m, path); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "wb").write(data)
rng = int.from_bytes(b"stein", "big")
def prng(n):
    global rng
    out = bytearray()
    while len(out) < n:
        rng = (rng * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out += rng.to_bytes(8, "little")
    return bytes(out[:n])
w("hello.txt", b"hello from libstein\n")
w("big.bin", prng(300 * 1024 + 123))               # contiguous: NoFatChain set, no FAT entries
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/upper.txt", b"case test\n")
w("dir/" + "n" * 255, b"longest name\n")           # exFAT name limit
w("dir/ünïcödé 日本語.txt", b"unicode\n")
# Fragmented file: punch holes in the heap, then write something larger than any hole.
for i in range(6):
    w("hole_%d.bin" % i, prng(32 * 1024))
for i in (0, 2, 4):
    os.remove(os.path.join(m, "hole_%d.bin" % i))
w("frag.bin", prng(200 * 1024 + 7))
os.makedirs(os.path.join(m, "many"))
for i in range(300):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        os.utime(os.path.join(root, n), (1704164645, 1704164645))   # 2024-01-02 03:04:05 UTC
PY
  sync
}

oracle() { # mountpoint oraclefile
  local m=$1 o=$2
  ( cd "$m" && find . -mindepth 1 \( -type f -o -type d \) -printf '%y %s %P\n' | sort ) > "$o"
  ( cd "$m" && find . -type f -printf '%P\n' | sort | while read -r f; do printf 'sha256 %s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done ) >> "$o"
}

make_one() { # name size mkfs-args...
  local name=$1 size=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  mkfs.exfat -q "$@" "$img"
  local dev; dev=$(losetup -f --show "$img")
  local mnt="$WORK/mnt_$name"; mkdir -p "$mnt"
  mount.exfat-fuse "$dev" "$mnt"
  fill "$mnt"
  oracle "$mnt" "$OUT/$name.oracle.txt"
  fusermount3 -u "$mnt"
  sleep 0.5
  losetup -d "$dev"
  fsck.exfat -n "$img" | tail -1
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one exfat     64M -c 4K  -L rd_exfat
make_one exfat_32k 64M -c 32K -L rdexfat32
