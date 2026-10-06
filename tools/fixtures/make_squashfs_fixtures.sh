#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SquashFS fixtures for the in-process reader: mksquashfs from a source tree
# with every compressor (gzip, lzo, xz, lz4, zstd, lzma), one image with
# uncompressed inodes/data/fragments (-noI -noD -noF), one that forces
# fragments for everything (-always-use-fragments) and one with the xz x86
# BCJ filter (mksquashfs keeps the filter only where it shrinks a block, which
# this tree never triggers; a filtered block would be refused). The oracle is
# the source tree.
set -eu
OUT=${1:-tests/fixtures/squashfs}
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
w("hello.txt", b"hello from libstein\n")
w("big.bin", prng(2 * 131072 + 123))                                            # two full blocks plus a fragment tail
w("compressible.txt", (b"the quick brown fox jumps over the lazy dog; " * 7 + b"\n") * 1000)
w("exact.bin", prng(131072))                                                     # one whole block, no fragment
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
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
python3 "$HERE/oracle.py" "$SRC" > "$OUT/squashfs.oracle.txt"

make_one() { # name mksquashfs-args...
  local name=$1; shift
  local img="$WORK/$name.img"
  mksquashfs "$SRC" "$img" -quiet -no-progress -noappend -all-root -no-xattrs -mkfs-time 1704164645 "$@" >/dev/null
  rm -rf "$WORK/check" && unsquashfs -quiet -no-progress -d "$WORK/check" "$img" >/dev/null 2>&1 || { echo "unsquashfs cannot read $name"; exit 1; }
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$img") -> $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one squashfs_gzip  -comp gzip
make_one squashfs_lzo   -comp lzo
make_one squashfs_xz    -comp xz
make_one squashfs_lz4   -comp lz4 -Xhc
make_one squashfs_zstd  -comp zstd
make_one squashfs_lzma  -comp lzma
make_one squashfs_plain -comp gzip -noI -noD -noF -noId
make_one squashfs_frags -comp zstd -always-use-fragments -b 65536
make_one squashfs_bcj   -comp xz -Xbcj x86
