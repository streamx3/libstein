#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# LVM2 fixtures: PVs on loop devices, one VG, linear and striped LVs created
# without activation (no device-mapper needed). Filesystems are written into
# the LVs through loop devices at the extent offsets LVM reports, so the
# tests can check our mapping against lvm's own view (lvs / vgcfgbackup).
set -eu
OUT=${1:-tests/fixtures/lvm}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
export LVM_SYSTEM_DIR="$WORK/lvm"
mkdir -p "$LVM_SYSTEM_DIR"
cat > "$LVM_SYSTEM_DIR/lvm.conf" <<CONF
devices { scan = [ "/dev" ] filter = [ "a|^/dev/loop|", "r|.*|" ] obtain_device_list_from_udev = 0 }
global { use_lvmetad = 0 locking_type = 1 }
activation { udev_sync = 0 udev_rules = 0 }
CONF

truncate -s 32M "$WORK/pv0.img"
truncate -s 32M "$WORK/pv1.img"
L0=$(losetup -f --show "$WORK/pv0.img")
L1=$(losetup -f --show "$WORK/pv1.img")
cleanup() { losetup -d "$L0" "$L1" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

pvcreate -q --driverloaded n --config 'devices{scan=["/dev"]}' "$L0" "$L1" >/dev/null
vgcreate -q --driverloaded n -s 1M stein_vg "$L0" "$L1" >/dev/null
# Linear LV on pv0, striped LV across both, a second linear LV made of two segments (fragmented).
lvcreate -q --driverloaded n -an -y -L 8M -n linear stein_vg "$L0" >/dev/null
lvcreate -q --driverloaded n -an -y -L 8M -i 2 -I 64 -n striped stein_vg "$L0" "$L1" >/dev/null
lvcreate -q --driverloaded n -an -y -L 4M -n frag stein_vg "$L0" >/dev/null
lvcreate -q --driverloaded n -an -y -L 2M -n filler stein_vg "$L0" >/dev/null
lvextend -q --driverloaded n -y -L +4M stein_vg/frag "$L0" >/dev/null   # second segment after the filler

# Where things are, as lvm sees it.
lvs --driverloaded n --noheadings --units b -o lv_name,lv_size,seg_start_pe,seg_size_pe,seg_pe_ranges,stripes,stripe_size stein_vg > "$OUT/lvs.txt"
vgcfgbackup --driverloaded n -f "$OUT/vgcfg.txt" stein_vg >/dev/null
pvs --driverloaded n --noheadings --units b -o pv_name,pv_uuid,pe_start,pv_pe_count "$L0" "$L1" > "$OUT/pvs.txt"

# Write filesystems into the LVs: linear and frag via their PE ranges (frag: write only into its first segment's
# head so the fs fits? no: mkfs needs the whole LV -> assemble a plain image and copy per segment).
pe_start=$(pvs --driverloaded n --noheadings --units b -o pe_start "$L0" | tr -dc '0-9')   # bytes
mkfs_into() { # lvname label -> writes an ext2 of the LV size via the segment list
  local lv=$1 label=$2
  local size; size=$(lvs --driverloaded n --noheadings --units b -o lv_size "stein_vg/$lv" | tr -dc '0-9')
  truncate -s "$size" "$WORK/$lv.plain"
  mkfs.ext2 -q -b 4096 -L "$label" "$WORK/$lv.plain"
  python3 - "$WORK/$lv.plain" "$lv" "$WORK/pv0.img" "$WORK/pv1.img" "$L0" "$L1" <<'PY'
import sys, subprocess, re
plain, lv, pv0, pv1, l0, l1 = sys.argv[1:7]
data = open(plain, "rb").read()
# segment table: start_pe size_pe pe_ranges stripes stripe_size
out = subprocess.run(["lvs", "--driverloaded", "n", "--noheadings", "--units", "b", "-o", "seg_start_pe,seg_size_pe,seg_pe_ranges,stripes,stripe_size", f"stein_vg/{lv}"], capture_output=True, text=True, check=True).stdout
pe_size = 1 << 20
pe_start = {}
for line in subprocess.run(["pvs", "--driverloaded", "n", "--noheadings", "--units", "b", "-o", "pv_name,pe_start"], capture_output=True, text=True, check=True).stdout.splitlines():
    name, start = line.split()
    pe_start[name] = int(re.sub(r"\D", "", start))
files = {l0: open(pv0, "r+b"), l1: open(pv1, "r+b")}
for line in out.splitlines():
    f = line.split()
    start_pe, size_pe, ranges, stripes, stripe_size = int(f[0]), int(f[1]), f[2:-2], int(f[-2]), f[-1]
    ss = int(re.sub(r"\D", "", stripe_size)) if stripes > 1 else 0
    seg = data[start_pe * pe_size:(start_pe + size_pe) * pe_size]
    if stripes == 1:
        dev, rng = ranges[0].split(":")
        a = int(rng.split("-")[0])
        files[dev].seek(pe_start[dev] + a * pe_size); files[dev].write(seg)
    else:
        # chunks of stripe_size round-robin over the stripes; each stripe holds size_pe/stripes extents
        per = size_pe // stripes
        targets = []
        for r in ranges:
            dev, rng = r.split(":")
            targets.append((dev, int(rng.split("-")[0])))
        for i in range(0, len(seg), ss):
            chunk = seg[i:i+ss]
            n = i // ss
            dev, a = targets[n % stripes]
            off = pe_start[dev] + a * pe_size + (n // stripes) * ss
            files[dev].seek(off); files[dev].write(chunk)
PY
}
# The loop devices see the files' contents; sync the writes we made to the backing files first.
losetup -d "$L0" "$L1"
trap 'rm -rf "$WORK"' EXIT
# Re-attach is not needed for mkfs_into (it writes the backing files directly), but lvs needs the devices.
L0=$(losetup -f --show "$WORK/pv0.img"); L1=$(losetup -f --show "$WORK/pv1.img")
trap cleanup EXIT
mkfs_into linear lv_linear
mkfs_into striped lv_striped
mkfs_into frag lv_frag
losetup -d "$L0" "$L1"
trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/sparsify.py" pack "$WORK/pv0.img" "$OUT/pv0.sparse"
python3 "$HERE/sparsify.py" pack "$WORK/pv1.img" "$OUT/pv1.sparse"
echo "pv0: $(stat -c %s "$OUT/pv0.sparse") bytes, pv1: $(stat -c %s "$OUT/pv1.sparse") bytes"
