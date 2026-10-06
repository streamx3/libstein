#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# APFS fixtures for the in-process reader. Needs macOS (hdiutil creates an
# APFS container in a raw UDRW image; the native driver populates it). Run by
# .github/workflows/fixtures-macos.yml; the output is committed under
# tests/fixtures/apfs. Variants: case-insensitive (the default, hashed
# directory keys) and case-sensitive. Content mirrors the HFS+ generator plus
# a file with an extended attribute. The oracle is the mounted tree.
set -eu
OUT=${1:-tests/fixtures/apfs}
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
w("big.bin", prng(200 * 1024 + 123))
w("compressible.txt", (b"the quick brown fox jumps over the lazy dog; " * 7 + b"\n") * 1000)
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/upper.txt", b"case test\n")
w("dir/" + "n" * 255, b"longest name\n")
w("dir/ünïcödé 日本語.txt", b"unicode\n")
w("Case.txt", b"capital\n")
try:
    w("case.txt", b"lower\n")          # second file when case-sensitive, overwrite otherwise
except OSError:
    pass
for i in range(6):
    w("hole_%d.bin" % i, prng(32 * 1024))
for i in (0, 2, 4):
    os.remove(os.path.join(m, "hole_%d.bin" % i))
w("frag.bin", prng(150 * 1024 + 7))
with open(os.path.join(m, "sparse.bin"), "wb") as f:
    f.seek(1024 * 1024); f.write(b"after a hole\n"); f.seek(3 * 1024 * 1024); f.write(b"end\n")
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "dir/hardlink2.txt"))
os.makedirs(os.path.join(m, "many"))
for i in range(300):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
w("xattr.txt", b"has an xattr\n")
os.setxattr(os.path.join(m, "xattr.txt"), "user.stein", b"xattr value")
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))   # 2024-01-02 03:04:05 UTC
PY
  sync
}

make_one() { # name fs-type label
  local name=$1 fstype=$2 label=$3
  local img="$WORK/$name"
  hdiutil create -size 64m -fs "$fstype" -volname "$label" -layout NONE -ov "$img" >/dev/null
  local mnt="$WORK/mnt_$name"; mkdir -p "$mnt"
  hdiutil attach -nobrowse -noverify -noautofsck -mountpoint "$mnt" "$img.dmg" >/dev/null
  touch "$mnt/.metadata_never_index"
  mkdir -p "$mnt/.fseventsd" && touch "$mnt/.fseventsd/no_log"
  fill "$mnt"
  sync
  python3 "$HERE/oracle.py" "$mnt" --skip .fseventsd .metadata_never_index > "$OUT/$name.oracle.txt"
  hdiutil detach "$mnt" >/dev/null
  python3 "$HERE/sparsify.py" pack "$img.dmg" "$OUT/$name.sparse"
  echo "$name: $(stat -f %z "$OUT/$name.sparse") bytes, $(grep -c . "$OUT/$name.oracle.txt") oracle lines"
}

make_one apfs  "APFS"                rd_apfs
make_one apfsx "Case-sensitive APFS" rd_apfsx
