#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# NTFS fixture for the in-process reader: mkfs.ntfs + a kernel/ntfs-3g mount
# (root), deterministic content, oracle of every entry, sha256 and link.
set -eu
OUT=${1:-tests/fixtures/ntfsfs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
img="$WORK/ntfs.img"
truncate -s 64M "$img"
mkfs.ntfs -q -F -c 4096 -L reader_ntfs "$img" >/dev/null
dev=$(losetup -f --show "$img")
mnt="$WORK/mnt"; mkdir -p "$mnt"
mount "$dev" "$mnt"
python3 - "$mnt" <<'PY'
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
w("hello.txt", b"hello from libstein\n")                 # resident $DATA
w("big.bin", prng(300 * 1024 + 123))                    # non-resident, several runs likely
w("medium.bin", prng(70 * 1024))
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/" + "n" * 200 + ".txt", b"long name\n")
w("dir/unicode-éü中文.txt", b"unicode name\n")
w("dir/UPPER.TXT", b"case\n")
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(1024 * 1024); f.write(b"after a hole\n"); f.seek(5 * 1024 * 1024); f.write(b"end\n")
os.makedirs(os.path.join(m, "many"))
for i in range(300):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())   # index allocation (B-tree) directory
try:
    os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
except OSError:
    pass
try:
    os.symlink("hello.txt", os.path.join(m, "link_short"))
except OSError:
    pass
PY
sync
( cd "$mnt" && find . -mindepth 1 \( -type f -o -type l -o -type d \) -not -path './System Volume Information*' -printf '%y %s %P\n' | sort ) > "$OUT/ntfs.oracle.txt"
( cd "$mnt" && find . -type f -not -path './System Volume Information*' -printf '%P\n' | sort | while read -r f; do printf 'sha256 %s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done ) >> "$OUT/ntfs.oracle.txt"
( cd "$mnt" && find . -type l -printf 'link %P -> %l\n' | sort ) >> "$OUT/ntfs.oracle.txt"
umount "$mnt"
losetup -d "$dev"
# $LogFile is 0xFF-filled: zero it to keep the fixture small (read-only tests never touch it).
python3 - "$img" <<'PY'
import sys
p = sys.argv[1]
d = bytearray(open(p, "rb").read())
start = d.find(b"\xff" * 65536)
if start >= 0:
    end = start
    while end < len(d) and d[end] == 0xFF: end += 1
    d[start:end] = bytes(end - start)
    open(p, "wb").write(d)
PY
python3 "$HERE/sparsify.py" pack "$img" "$OUT/ntfs.sparse"
echo "ntfs: $(stat -c %s "$OUT/ntfs.sparse") bytes"
