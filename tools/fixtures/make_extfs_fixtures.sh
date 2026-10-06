#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ext2/ext4 fixtures for the in-process reader: deterministic files written
# through a kernel mount (root), with sha256 of every file and the directory
# listing recorded as oracles. Covers extents vs indirect blocks, holes,
# symlinks, hard links, long names, a directory with many entries (htree),
# inline data and the 4 KiB / 1 KiB block sizes.
set -eu
OUT=${1:-tests/fixtures/extfs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

fill() { # mountpoint
  local m=$1
  python3 - "$m" <<'PY'
import os, sys, hashlib
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
w("big.bin", prng(300 * 1024 + 123))               # extents / double indirect at 1 KiB blocks
w("medium.bin", prng(70 * 1024))                   # beyond 12 direct blocks at 4K, single indirect at 1K
w("tiny.txt", b"x")                                 # inline-data candidate on ext4
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/" + "n" * 200 + ".txt", b"long name\n")
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(1024 * 1024); f.write(b"after a hole\n"); f.seek(5 * 1024 * 1024); f.write(b"end\n")
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
os.makedirs(os.path.join(m, "many"))
for i in range(300):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
PY
  sync
}

oracle() { # mountpoint oraclefile
  local m=$1 o=$2
  ( cd "$m" && find . -mindepth 1 \( -type f -o -type l -o -type d \) -printf '%y %s %P\n' | sort ) > "$o"
  ( cd "$m" && find . -type f -printf '%P\n' | sort | while read -r f; do printf 'sha256 %s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done ) >> "$o"
  ( cd "$m" && find . -type l -printf 'link %P -> %l\n' | sort ) >> "$o"
}

make_one() { # name size mkfs...
  local name=$1 size=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  "$@" "$img" >/dev/null 2>&1
  local dev; dev=$(losetup -f --show "$img")
  local mnt="$WORK/mnt_$name"; mkdir -p "$mnt"
  mount "$dev" "$mnt"
  fill "$mnt"
  oracle "$mnt" "$OUT/$name.oracle.txt"
  umount "$mnt"
  losetup -d "$dev"
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one ext4   64M mkfs.ext4 -q -b 4096 -O inline_data,dir_index,extent,64bit,metadata_csum -L reader_ext4
make_one ext2   32M mkfs.ext2 -q -b 1024 -L reader_ext2
make_one ext3   32M mkfs.ext3 -q -b 2048 -L reader_ext3
