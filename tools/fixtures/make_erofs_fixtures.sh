#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# EROFS fixtures for the in-process reader, built with mkfs.erofs from one
# source tree: uncompressed (flat plain/inline, chunk-based), lz4 with the
# default compact indexes, lz4 with legacy full indexes, lz4hc with big
# physical clusters, ztailpacking, fragments plus dedupe, lzma and deflate.
# fsck.erofs checks every image; the oracle is the source tree.
set -eu
OUT=${1:-tests/fixtures/erofs}
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
w("big.bin", prng(2 * 65536 + 123))                                     # incompressible: plain lclusters
w("compressible.txt", (b"the quick brown fox jumps over the lazy dog; " * 7 + b"\n") * 1000)
w("mixed.bin", b"".join(bytes([i & 0xFF]) * 300 + prng(60) for i in range(600)))   # compresses moderately
w("exact.bin", prng(4096 * 3))                                          # whole blocks, no inline tail
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/" + "n" * 200, b"long name\n")                                     # mkfs.erofs 1.7.1 rejects 255-character names
w("dir/ünïcödé 日本語.txt", b"unicode\n")
w("dup1.txt", b"duplicate content " * 3000)                              # dedupe candidates
w("dup2.txt", b"duplicate content " * 3000)
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(256 * 1024); f.write(b"after a hole\n"); f.seek(768 * 1024); f.write(b"end\n")
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
python3 "$HERE/oracle.py" "$SRC" > "$OUT/erofs.oracle.txt"

make_one() { # name mkfs-args...
  local name=$1; shift
  local img="$WORK/$name.img"
  # Chunk-based files cannot inline (keep the image small without the 400-file directory), and
  # mkfs.erofs 1.7.1 writes a sparse file as all-hole chunks in this mode, so it is left out too.
  [ "$name" = erofs_chunked ] && python3 "$HERE/oracle.py" "$SRC" --skip many sparse.bin > "$OUT/$name.oracle.txt"
  local label="rd_${name#erofs_}"; label=${label:0:16}   # the label holds 16 bytes
  mkfs.erofs -T 1704164645 -U 0f0e0d0c-0b0a-0908-0706-050403020100 -L "$label" "$@" "$img" "$SRC" >/dev/null 2>&1
  fsck.erofs "$img" >/dev/null 2>&1 || { echo "fsck.erofs reports problems in $name"; exit 1; }
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$img") -> $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one erofs_plain
make_one erofs_chunked      --chunksize=16384 --exclude-path=many --exclude-path=sparse.bin
make_one erofs_lz4          -zlz4
make_one erofs_lz4_legacy   -zlz4 -Elegacy-compress
make_one erofs_lz4hc_bigpcl -zlz4hc,12 -C65536
make_one erofs_lz4_ztail    -zlz4 -Eztailpacking
make_one erofs_lz4_frag     -zlz4 -Efragments,dedupe -C16384
make_one erofs_lzma         -zlzma
make_one erofs_deflate      -zdeflate
