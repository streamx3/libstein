#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Allocation-map fixtures: small filesystems with a few files, kept whole as
# .sparse (free space is zero and therefore omitted), plus the free-space
# figure the native tool reports as an oracle. Needs root for loop mounts;
# without a mountable kernel driver the fixture is an empty filesystem.
set -eu
OUT=${1:-tests/fixtures/alloc}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

fill() { # mountpoint
  head -c 65536 /dev/urandom > "$1/random.bin"
  seq 1 5000 > "$1/numbers.txt"
  mkdir -p "$1/sub/dir"
  (yes "libstein allocation map fixture" || true) | head -c 65536 > "$1/sub/dir/pattern.txt"
  printf 'small\n' > "$1/sub/small.txt"
  sync
}

make_one() { # name size mkfs-command... (image path appended)
  local name=$1 size=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s "$size" "$img"
  "$@" "$img" >/dev/null 2>&1
  local dev; dev=$(losetup -f --show "$img")
  local mnt="$WORK/mnt_$name"; mkdir -p "$mnt"
  if mount "$dev" "$mnt" 2>/dev/null; then
    fill "$mnt"
    umount "$mnt"
    echo "mounted=yes" > "$OUT/$name.oracle.txt"
  else
    echo "mounted=no" > "$OUT/$name.oracle.txt"
  fi
  losetup -d "$dev"
  case $name in
    ext*)   echo "free_bytes=$(( $(dumpe2fs -h "$img" 2>/dev/null | awk -F: '/^Free blocks/{gsub(/ /,"",$2);print $2}') * $(dumpe2fs -h "$img" 2>/dev/null | awk -F: '/^Block size/{gsub(/ /,"",$2);print $2}') ))" >> "$OUT/$name.oracle.txt" ;;
    fat*)   fsck.fat -n "$img" 2>/dev/null | awk '/clusters/{print "clusters=" $(NF-1)}' >> "$OUT/$name.oracle.txt" || true ;;
    ntfs)   echo "free_clusters=$(ntfsinfo -m -f "$img" 2>/dev/null | awk -F: '/Free Clusters/{gsub(/[ \t]/,"",$2);print $2}')" >> "$OUT/$name.oracle.txt" ;;
  esac
  if [ "$name" = ntfs ]; then
    # $LogFile is 2 MiB of 0xFF: irrelevant for L0/L1 tests and expensive to store. Zero it.
    python3 - "$img" <<'PY'
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
run = b"\xff" * 65536
start = data.find(run)
if start >= 0:
    end = start
    while end < len(data) and data[end] == 0xFF:
        end += 1
    data[start:end] = bytes(end - start)
    open(p, "wb").write(data)
PY
  fi
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes"
}

make_one ext4    64M mkfs.ext4 -q -L alloc_ext4
make_one ext2    32M mkfs.ext2 -q -b 1024 -L alloc_ext2
make_one fat16   32M mkfs.vfat -F 16 -n ALLOCFAT16
make_one fat32   64M mkfs.vfat -F 32 -n ALLOCFAT32
make_one exfat   64M mkfs.exfat -L allocexfat
make_one ntfs    16M mkfs.ntfs -Q -F -c 4096 -L alloc_ntfs
make_one hfsplus 64M mkfs.hfsplus -v allochfs
