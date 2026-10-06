#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Virtual-disk container fixtures (qcow2, VHD, VHDX, VMDK, VDI) built with
# qemu-img from one raw disk: GPT with a FAT12 and an ext2 partition carrying
# known files. The oracle is the raw disk's SHA-256 plus qemu-img's own view
# of each container (format, virtual size, cluster size); the reader must
# reproduce the raw bytes exactly through every container.
set -eu
OUT=${1:-tests/fixtures/vdisk}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

RAW="$WORK/disk.raw"
truncate -s 24M "$RAW"
sgdisk -o -n 1:2048:+4M -t 1:0700 -c 1:fatpart -n 2:0:+12M -t 2:8300 -c 2:extpart "$RAW" >/dev/null
# Partition 1: FAT12 at sector 2048 (4 MiB); partition 2: ext2 right after it (12 MiB).
P1="$WORK/p1.img"; truncate -s 4M "$P1"; mkfs.vfat -F 12 -n FATPART "$P1" >/dev/null
echo "fat file inside a virtual disk" > "$WORK/f.txt"
mcopy -i "$P1" "$WORK/f.txt" ::/f.txt 2>/dev/null || true
P2="$WORK/p2.img"; truncate -s 12M "$P2"; mkfs.ext2 -q -b 1024 -L inside_vdisk "$P2"
echo "ext2 file inside a virtual disk" > "$WORK/hello.txt"
debugfs -w -R "write $WORK/hello.txt hello.txt" "$P2" >/dev/null 2>&1
P2START=$(sgdisk -i 2 "$RAW" | awk '/First sector/ {print $3}')
dd if="$P1" of="$RAW" bs=512 seek=2048 conv=notrunc status=none
dd if="$P2" of="$RAW" bs=512 seek="$P2START" conv=notrunc status=none
# Scatter some non-zero bytes so block/cluster boundaries at odd places matter.
python3 - "$RAW" <<'PY'
import sys, hashlib
p = sys.argv[1]
with open(p, "r+b") as f:
    for off in (5 * 1024 * 1024 + 123, 7 * 1024 * 1024 - 1, 9 * 1024 * 1024 + 4095, 23 * 1024 * 1024 + 511):
        f.seek(off); f.write(hashlib.sha256(str(off).encode()).digest() * 8)
PY
SHA=$(sha256sum "$RAW" | cut -d' ' -f1)
RAWSIZE=$(stat -c %s "$RAW")
echo "raw sha256 $SHA size $RAWSIZE"

make_one() { # name format [qemu-img convert options...]
  local name=$1 fmt=$2; shift 2
  local img="$WORK/$name.img"
  qemu-img convert -f raw -O "$fmt" "$@" "$RAW" "$img"
  python3 - "$img" "$OUT/$name.oracle.txt" "$SHA" "$fmt" "$RAWSIZE" <<'PY'
import json, subprocess, sys
img, out, sha, fmt, rawsize = sys.argv[1:6]
info = json.loads(subprocess.run(["qemu-img", "info", "--output=json", img], check=True, capture_output=True).stdout)
lines = ["format=%s" % info["format"], "virtual_size=%d" % info["virtual-size"], "raw_size=%s" % rawsize, "sha256=%s" % sha]
if "cluster-size" in info: lines.append("cluster_size=%d" % info["cluster-size"])
fs = info.get("format-specific", {}).get("data", {})
for k in ("compat", "compression-type", "create-type"):
    if k in fs: lines.append("%s=%s" % (k.replace("-", "_"), fs[k]))
open(out, "w").write("\n".join(lines) + "\n")
PY
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$img") -> $(stat -c %s "$OUT/$name.sparse") bytes ($(tr '\n' ' ' < "$OUT/$name.oracle.txt"))"
}

make_one qcow2            qcow2
make_one qcow2_compressed qcow2 -c
make_one qcow2_v2         qcow2 -o compat=0.10
make_one qcow2_64k        qcow2 -o cluster_size=4096
make_one qcow2_zstd       qcow2 -c -o compression_type=zstd
make_one vhd_dynamic      vpc
make_one vhd_fixed        vpc   -o subformat=fixed
make_one vhdx             vhdx
make_one vmdk_sparse      vmdk
make_one vmdk_stream      vmdk  -o subformat=streamOptimized
make_one vdi              vdi
