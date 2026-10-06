#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# F2FS fixtures for the in-process reader, built with mkfs.f2fs and populated
# offline with sload.f2fs (no mount needed) from one source tree: the default
# feature set (inline data and dentries, a file deep enough for indirect
# nodes), the extra-attribute set with inode checksums, creation times and
# casefolding, and compressed images where the f2fs-tools build supports an
# algorithm (Ubuntu's 1.16 supports none; set F2FS_TOOLS to the sbin
# directory of a build with lz4/zstd). fsck.f2fs checks every image; the
# oracle is the source tree.
set -eu
OUT=${1:-tests/fixtures/f2fs}
if [ -n "${F2FS_TOOLS:-}" ]; then PATH="$F2FS_TOOLS:$PATH"; fi
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
w("big.bin", prng(200 * 1024 + 123))
w("compressible.txt", (b"the quick brown fox jumps over the lazy dog; " * 7 + b"\n") * 1000)
w("mixed.bin", b"".join(bytes([i & 0xFF]) * 300 + prng(60) for i in range(600)))
w("indirect.bin", b"".join(b"indirect block %07d\n" % i for i in range(13 * 1024 * 1024 // 22)) + b"tail")   # past the inode's 923 slots and both direct nodes; repetitive so git stores it small
w("exact.bin", prng(4096 * 3))
w("tiny.txt", b"x")                                                      # inline data
w("inline3k.txt", prng(3000))                                            # inline data near the limit
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/" + "n" * 255, b"longest name\n")
w("dir/ünïcödé 日本語.txt", b"unicode\n")
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(256 * 1024); f.write(b"after a hole\n"); f.seek(768 * 1024); f.write(b"end\n")
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
os.makedirs(os.path.join(m, "many"))
for i in range(400):                                                     # several dentry blocks, hashed levels
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
os.makedirs(os.path.join(m, "few"))
for i in range(3):                                                       # fits an inline dentry
    w("few/f%d.txt" % i, ("few %d\n" % i).encode())
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))
PY
python3 "$HERE/oracle.py" "$SRC" > "$OUT/f2fs.oracle.txt"

make_one() { # name size mkfs-args -- sload-args
  local name=$1 size=$2; shift 2
  local mkfs=() sload=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do mkfs+=("$1"); shift; done
  if [ $# -gt 0 ]; then shift; fi
  sload=("$@")
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  mkfs.f2fs -q -f -l "$name" -T 1704164645 "${mkfs[@]}" "$img" >/dev/null
  # sload.f2fs 1.16 exits 1 after a complete load on extra_attr images; fsck decides.
  sload.f2fs -f "$SRC" -T 1704164645 "${sload[@]}" "$img" >/dev/null 2>&1 || true
  fsck.f2fs "$img" 2>&1 | grep -q "\[FSCK\] other corrupted bugs *\[Ok..\]" || { echo "fsck.f2fs rejects $name"; fsck.f2fs "$img" | tail -20; exit 1; }
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one f2fs_plain 256M
# Not flexible_inline_xattr: sload.f2fs 1.16 fills the inode's address slots as if the inline xattr
# area were absent and then records i_inline_xattr_size = 50, so a kernel (or this reader) would
# misplace blocks 867.. of a large file. Not lost_found either: with it sload leaves the SIT bitmap
# inconsistent for fsck.
make_one f2fs_extra 256M -O extra_attr,inode_checksum,inode_crtime,sb_checksum,casefold -C utf8
supports() { # compression algorithm: does this sload.f2fs accept it?
  local probe="$WORK/probe_$1.img"
  truncate -s 64M "$probe" && mkfs.f2fs -q -f -O extra_attr,compression "$probe" >/dev/null 2>&1
  mkdir -p "$WORK/empty"
  ! sload.f2fs -f "$WORK/empty" -c -a "$1" "$probe" 2>&1 | grep -qi "unknown compression\|not supported"
}
# f2fs-tools 1.16 compresses with lz4 and lzo when built against liblz4/liblzo2 (Ubuntu's package is
# not; build it from `apt-get source f2fs-tools` and point F2FS_TOOLS at its sbin). lzo-rle and
# zstd need a newer f2fs-tools.
for algo in lz4 lzo zstd; do
  if supports "$algo"; then make_one "f2fs_$algo" 256M -O extra_attr,compression -- -c -a "$algo" -L 3; else echo "f2fs_$algo: skipped, sload.f2fs lacks $algo"; fi
done
