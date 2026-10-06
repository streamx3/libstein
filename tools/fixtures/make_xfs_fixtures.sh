#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# XFS fixtures for the in-process reader. mkfs.xfs populates the filesystem
# from a protofile (no kernel driver needed): regular files, directories of
# every on-disk form (shortform, block, leaf, node), symlinks (inline), Unicode and 255-byte names. The oracle is the source tree;
# xfs_repair -n confirms the image is consistent. Two variants: v5 defaults
# (crc, ftype, bigtime, nrext64 as the installed mkfs.xfs chooses) and a
# 1 KiB-block filesystem with 8 KiB directory blocks.
set -eu
OUT=${1:-tests/fixtures/xfsfs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
SRC="$WORK/src"
mkdir -p "$SRC"

python3 - "$SRC" "$WORK/proto" <<'PY'
import os, sys
m, proto = sys.argv[1], sys.argv[2]
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
w("big.bin", prng(200 * 1024 + 123))
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/upper.txt", b"case test\n")
w("dir/" + "n" * 255, b"longest name\n")
w("dir/ünïcödé_日本語.txt", b"unicode\n")
os.makedirs(os.path.join(m, "many"))
for i in range(300):                       # leaf-form directory (several data blocks)
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
os.makedirs(os.path.join(m, "huge"))
for i in range(700):                       # node-form directory (leaf entries spill over a block)
    w("huge/e%04d" % i, b"")
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
# No remote (out-of-inode) symlink: mkfs.xfs's protofile writer produces a bad symlink header for those.

# Protofile: see mkfs.xfs(8). Entries: name, type/perm/flags, uid, gid, [source|target].
lines = ["/", "0 0", "d--755 0 0"]
def emit(dirpath, indent):
    for name in sorted(os.listdir(dirpath)):
        p = os.path.join(dirpath, name)
        if os.path.islink(p):
            lines.append("%s%s l--777 0 0 %s" % (indent, name, os.readlink(p)))
        elif os.path.isdir(p):
            lines.append("%s%s d--755 0 0" % (indent, name))
            emit(p, indent + " ")
            lines.append("%s$" % indent)
        else:
            lines.append("%s%s ---644 0 0 %s" % (indent, name, p))
emit(m, "")
lines.append("$")
open(proto, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY

make_one() { # name size mkfs-args...
  local name=$1 size=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  mkfs.xfs -q -f -p "$WORK/proto" -L "rd_$name" "$@" "$img" >/dev/null
  xfs_repair -n "$img" >/dev/null 2>&1 || { echo "xfs_repair reports problems in $name"; exit 1; }
  python3 "$HERE/oracle.py" "$SRC" > "$OUT/$name.oracle.txt"
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes, $(grep -c . "$OUT/$name.oracle.txt") oracle lines; $(xfs_db -r -c 'version' "$img" | head -c 160)"
}

make_one xfs     300M
make_one xfs_1k  300M -b size=1024 -n size=8192
