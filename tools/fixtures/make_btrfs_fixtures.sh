#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# btrfs fixtures for the in-process reader. mkfs.btrfs --rootdir populates
# the filesystem from a directory without a kernel driver: inline and
# regular extents, directories large enough for several leaves, symlinks,
# hard links, Unicode and 255-byte names. `btrfs check` confirms the image;
# the oracle is the source tree. Variants: default profile with 16 KiB
# nodes, mixed block groups with 4 KiB nodes, and (with mkfs.btrfs 6.14+,
# MKFS_BTRFS=/path overrides the binary) zlib, lzo and zstd compression.
set -eu
OUT=${1:-tests/fixtures/btrfsfs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
SRC="$WORK/src"
mkdir -p "$SRC"

python3 - "$SRC" <<'PY'
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
w("hello.txt", b"hello from libstein " * 9 + b"\n")   # inline extent (compressible)
w("compressible.txt", (b"the quick brown fox jumps over the lazy dog; " * 7 + b"\n") * 1000)   # several 128 KiB extents, highly compressible
w("mixed.bin", b"".join(bytes([i & 0xFF]) * 300 + prng(60) for i in range(600)))   # compresses moderately
w("big.bin", prng(200 * 1024 + 123))                  # regular extents (more than one 128 KiB extent)
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/upper.txt", b"case test\n")
w("dir/" + "n" * 255, b"longest name\n")
w("dir/ünïcödé 日本語.txt", b"unicode\n")
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(1024 * 1024); f.write(b"after a hole\n"); f.seek(3 * 1024 * 1024); f.write(b"end\n")
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
os.makedirs(os.path.join(m, "many"))
for i in range(400):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))
PY

MKFS=${MKFS_BTRFS:-mkfs.btrfs}
CHECK=${BTRFS_TOOL:-btrfs}
make_one() { # name size mkfs-args...
  local name=$1 size=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  "$MKFS" -q -f --rootdir "$SRC" -L "rd_$name" "$@" "$img" >/dev/null
  "$CHECK" check --readonly "$img" >/dev/null 2>&1 || { echo "btrfs check reports problems in $name"; exit 1; }
  python3 "$HERE/oracle.py" "$SRC" > "$OUT/$name.oracle.txt"
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes, $(grep -c . "$OUT/$name.oracle.txt") oracle lines"
}

make_one btrfs       128M
make_one btrfs_mixed 128M -M --nodesize 4096
if "$MKFS" --help 2>&1 | grep -q -- '--compress'; then
  make_one btrfs_zlib 128M --compress zlib:3
  make_one btrfs_lzo  128M --compress lzo
  make_one btrfs_zstd 128M --compress zstd:3
else
  echo "note: $MKFS has no --compress (needs btrfs-progs 6.14+); compressed variants not regenerated"
fi
