#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# APFS fixtures for the in-process reader. Needs macOS (hdiutil creates an
# APFS container in a raw UDRW image; the native driver populates it). Run by
# .github/workflows/fixtures-macos.yml; the output is committed under
# tests/fixtures/apfs. Variants: case-insensitive (the default, hashed
# directory keys) and case-sensitive, plus `apfs_snap`: a container with two
# volumes, the first carrying a snapshot taken before further changes
# (fs_snapshot_create needs root; the runner has passwordless sudo) and
# transparently compressed files (ditto --hfsCompression: decmpfs zlib in the
# xattr and in the resource fork; afsctool adds lzvn and lzfse when brew has
# it), the second a small tree. Oracles: the mounted trees, the first volume's
# pre-snapshot tree as apfs_snap.snapshot.oracle.txt, the second volume as
# apfs_snap.second.oracle.txt.
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
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))   # 2024-01-02 03:04:05 UTC
PY
  xattr -w user.stein "xattr value" "$m/xattr.txt"
  sync
}

make_one() { # name fs-type label
  local name=$1 fstype=$2 label=$3
  if [ -e "$OUT/$name.sparse" ]; then echo "$name: exists, kept (delete it to rebuild)"; return; fi
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

# --- apfs_snap: two volumes, a snapshot, compressed files ---------------------
make_snap() {
  local name=apfs_snap img="$WORK/$name"
  if [ -e "$OUT/$name.sparse" ]; then echo "$name: exists, kept (delete it to rebuild)"; return; fi
  hdiutil create -size 96m -fs APFS -volname rd_snap -layout NONE -ov "$img" >/dev/null
  local mnt="$WORK/mnt_$name"; mkdir -p "$mnt"
  hdiutil attach -nobrowse -noverify -noautofsck -mountpoint "$mnt" "$img.dmg" >/dev/null
  touch "$mnt/.metadata_never_index"
  mkdir -p "$mnt/.fseventsd" && touch "$mnt/.fseventsd/no_log"
  fill "$mnt"
  sync
  # The state the snapshot must preserve.
  python3 "$HERE/oracle.py" "$mnt" --skip .fseventsd .metadata_never_index > "$OUT/$name.snapshot.oracle.txt"
  cat > "$WORK/mksnap.c" <<'C'
#include <fcntl.h>
#include <stdio.h>
#include <sys/snapshot.h>
int main(int argc, char** argv) {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    if (fs_snapshot_create(fd, argv[2], 0) != 0) { perror("fs_snapshot_create"); return 1; }
    return 0;
}
C
  cc -o "$WORK/mksnap" "$WORK/mksnap.c"
  sudo "$WORK/mksnap" "$mnt" stein-snap
  # Changes after the snapshot: a deletion, a rewrite, a growth, new files.
  rm "$mnt/tiny.txt"
  printf 'rewritten after the snapshot\n' > "$mnt/dir/upper.txt"
  printf 'appended after the snapshot\n' >> "$mnt/hello.txt"
  python3 - "$mnt" <<'PY'
import os, sys
m = sys.argv[1]
text = (b"compressible text for decmpfs; " * 4 + b"\n")
open(os.path.join(m, "src_small.txt"), "wb").write(text * 20)            # ~2.5 KiB: fits the xattr
open(os.path.join(m, "src_large.txt"), "wb").write(text * 3000)          # ~380 KiB: resource fork, several 64 KiB blocks
open(os.path.join(m, "src_mixed.bin"), "wb").write(text * 600 + os.urandom(70000) + text * 600)   # a block that does not compress
open(os.path.join(m, "after_snapshot.txt"), "wb").write(b"only in the live volume\n")
PY
  for f in src_small.txt src_large.txt src_mixed.bin; do
    ditto --hfsCompression "$mnt/$f" "$mnt/zlib_${f}"       # decmpfs types 3 (xattr) and 4 (resource fork)
  done
  if command -v afsctool >/dev/null 2>&1 || brew install afsctool >/dev/null 2>&1; then
    for algo in LZVN LZFSE; do
      for f in src_small.txt src_large.txt; do
        cp "$mnt/$f" "$mnt/$(echo $algo | tr A-Z a-z)_${f}" && afsctool -c -T "$algo" "$mnt/$(echo $algo | tr A-Z a-z)_${f}" >/dev/null 2>&1 || true
      done
    done
  fi
  # An extended attribute large enough to live in its own data stream rather than the record.
  python3 -c "print('v' * 6000, end='')" > "$WORK/bigxattr"
  xattr -w user.big "$(cat "$WORK/bigxattr")" "$mnt/xattr.txt"
  ls -lO@ "$mnt" | sed -n '1,40p' || true
  sync
  python3 "$HERE/oracle.py" "$mnt" --skip .fseventsd .metadata_never_index > "$OUT/$name.oracle.txt"
  # Second volume in the same container.
  local container
  container=$(diskutil apfs list -plist | python3 -c '
import plistlib, sys
mnt = sys.argv[1]
d = plistlib.load(sys.stdin.buffer)
for c in d["Containers"]:
    for v in c["Volumes"]:
        if v.get("MountPoint") == mnt:
            print(c["ContainerReference"])
' "$mnt")
  echo "container: $container"
  diskutil apfs listSnapshots "$mnt" || true
  diskutil apfs addVolume "$container" APFS rd_second -nomount >/dev/null
  local second
  second=$(diskutil apfs list -plist "$container" | python3 -c '
import plistlib, sys
d = plistlib.load(sys.stdin.buffer)
for c in d["Containers"]:
    for v in c["Volumes"]:
        if v.get("Name") == "rd_second":
            print(v["DeviceIdentifier"])
')
  local mnt2="$WORK/mnt_second"; mkdir -p "$mnt2"
  diskutil mount -mountPoint "$mnt2" "$second" >/dev/null
  touch "$mnt2/.metadata_never_index"
  mkdir -p "$mnt2/.fseventsd" && touch "$mnt2/.fseventsd/no_log"
  printf 'second volume\n' > "$mnt2/second.txt"
  mkdir -p "$mnt2/sub" && printf 'nested in the second volume\n' > "$mnt2/sub/nested.txt"
  sync
  python3 "$HERE/oracle.py" "$mnt2" --skip .fseventsd .metadata_never_index > "$OUT/$name.second.oracle.txt"
  diskutil unmount "$mnt2" >/dev/null
  hdiutil detach "$mnt" >/dev/null
  python3 "$HERE/sparsify.py" pack "$img.dmg" "$OUT/$name.sparse"
  echo "$name: $(stat -f %z "$OUT/$name.sparse") bytes, $(grep -c . "$OUT/$name.oracle.txt") live / $(grep -c . "$OUT/$name.snapshot.oracle.txt") snapshot / $(grep -c . "$OUT/$name.second.oracle.txt") second oracle lines"
}

make_snap
