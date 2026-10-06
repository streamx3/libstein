#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Generates partition-table fixtures with the reference tools (sgdisk, sfdisk,
# mmls) and stores them as .sparse files plus the tools' own textual output as
# oracles. Re-run when the tools or the scenarios change; commit the results.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/../../tests/fixtures/pt"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

pack() { python3 "$here/sparsify.py" pack "$1" "$out/$2.sparse" ${3:+--sector-size "$3"}; }
oracle() { # name cmd...
  local name=$1; shift
  "$@" > "$out/$name" 2>&1 || true
}

# --- gpt_basic: 16 MiB, three partitions, names, attributes -----------------
img=$work/gpt_basic.img; truncate -s 16M "$img"
sgdisk -o "$img" >/dev/null
sgdisk -n 1:2048:+2M  -t 1:ef00 -c 1:"EFI System"  "$img" >/dev/null
sgdisk -n 2:0:+4M     -t 2:8300 -c 2:"Linux data"  -A 2:set:2 "$img" >/dev/null
sgdisk -n 3:0:0       -t 3:0700 -c 3:"Data"        -A 3:set:63 "$img" >/dev/null
sgdisk -U 11111111-2222-3333-4444-555555555555 "$img" >/dev/null
sgdisk -u 1:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE "$img" >/dev/null
pack "$img" gpt_basic
oracle gpt_basic.sgdisk-p.txt sgdisk -p "$img"
oracle gpt_basic.sgdisk-v.txt sgdisk -v "$img"
oracle gpt_basic.sfdisk.json  sfdisk --json "$img"
oracle gpt_basic.mmls.txt     mmls "$img"

# --- gpt_broken_primary: primary header zeroed --------------------------------
cp "$img" "$work/gpt_broken_primary.img"
dd if=/dev/zero of="$work/gpt_broken_primary.img" bs=512 seek=1 count=1 conv=notrunc status=none
pack "$work/gpt_broken_primary.img" gpt_broken_primary
oracle gpt_broken_primary.sgdisk-v.txt sgdisk -v "$work/gpt_broken_primary.img"

# --- gpt_broken_backup: backup header + entries zeroed ------------------------
cp "$img" "$work/gpt_broken_backup.img"
dd if=/dev/zero of="$work/gpt_broken_backup.img" bs=512 seek=$((32768-33)) count=33 conv=notrunc status=none
pack "$work/gpt_broken_backup.img" gpt_broken_backup
oracle gpt_broken_backup.sgdisk-v.txt sgdisk -v "$work/gpt_broken_backup.img"

# --- gpt_grown: disk grew after the table was written -------------------------
cp "$img" "$work/gpt_grown.img"; truncate -s 24M "$work/gpt_grown.img"
pack "$work/gpt_grown.img" gpt_grown
oracle gpt_grown.sgdisk-v.txt sgdisk -v "$work/gpt_grown.img"

# --- gpt_both_broken: both headers zeroed, protective MBR remains -------------
cp "$img" "$work/gpt_both_broken.img"
dd if=/dev/zero of="$work/gpt_both_broken.img" bs=512 seek=1 count=1 conv=notrunc status=none
dd if=/dev/zero of="$work/gpt_both_broken.img" bs=512 seek=$((32768-1)) count=1 conv=notrunc status=none
pack "$work/gpt_both_broken.img" gpt_both_broken

# --- mbr_basic: 2 primaries + extended with 2 logicals ------------------------
img=$work/mbr_basic.img; truncate -s 16M "$img"
sfdisk "$img" >/dev/null <<'SF'
label: dos
label-id: 0xdeadbeef
unit: sectors
1 : start=2048,  size=4096,  type=83, bootable
2 : start=6144,  size=4096,  type=0c
3 : start=10240, size=22528, type=05
5 : start=12288, size=4096,  type=83
6 : start=18432, size=8192,  type=07
SF
pack "$img" mbr_basic
oracle mbr_basic.sfdisk-d.txt  sfdisk -d "$img"
oracle mbr_basic.sfdisk.json   sfdisk --json "$img"
oracle mbr_basic.mmls.txt      mmls "$img"

# --- mbr_empty: valid signature, no entries ----------------------------------
img=$work/mbr_empty.img; truncate -s 4M "$img"
sfdisk "$img" >/dev/null <<'SF'
label: dos
SF
pack "$img" mbr_empty

# --- fat_whole: a filesystem on the whole device, no table --------------------
img=$work/fat_whole.img; truncate -s 4M "$img"
mkfs.vfat -F 12 -n "WHOLEDISK" "$img" >/dev/null
pack "$img" fat_whole

# --- gpt_4k: 4096-byte sectors (needs a loop device; skipped if unavailable) --
if [ "$(id -u)" = 0 ] && command -v losetup >/dev/null; then
  img=$work/gpt_4k.img; truncate -s 32M "$img"
  if dev=$(losetup --find --show --sector-size 4096 "$img" 2>/dev/null); then
    sgdisk -o "$dev" >/dev/null
    sgdisk -n 1:0:+8M -t 1:8300 -c 1:"Linux 4Kn" "$dev" >/dev/null
    oracle gpt_4k.sgdisk-p.txt sgdisk -p "$dev"
    losetup -d "$dev"
    pack "$img" gpt_4k 4096
  else
    echo "note: losetup --sector-size unavailable; gpt_4k skipped" >&2
  fi
fi

ls -la "$out"
