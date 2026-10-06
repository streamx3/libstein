#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Generates filesystem fixtures with the reference mkfs tools and records
# `blkid -p -o export` for each as the oracle. Images are sparse; only the
# non-zero chunks are stored (tools/fixtures/sparsify.py). Needs root for the
# loop-device cases (LVM PV, md member); those are skipped otherwise.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/../../tests/fixtures/fs"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

pack()   { python3 "$here/sparsify.py" pack "$1" "$out/$2.sparse" ${3:+--sector-size "$3"}; }
oracle() { blkid -p -o export "$1" > "$out/$2.blkid.txt" 2>&1 || true; }
have()   { command -v "$1" >/dev/null 2>&1; }
img()    { local p="$work/$1.img"; rm -f "$p"; truncate -s "$2" "$p"; echo "$p"; }
done_()  { pack "$1" "$2" ${3:-}; oracle "$1" "$2"; echo "ok   $2"; }
skip()   { echo "skip $1 ($2)"; }

U=0123abcd-4567-89ef-0123-456789abcdef

# ext2/3/4 --------------------------------------------------------------------
if have mkfs.ext4; then
  i=$(img ext4 64M); mkfs.ext4 -q -F -L STEIN_EXT4 -U $U "$i" && done_ "$i" ext4
  i=$(img ext2 16M); mkfs.ext2 -q -F -L STEIN_EXT2 -U $U "$i" && done_ "$i" ext2
  i=$(img ext3 32M); mkfs.ext3 -q -F -L STEIN_EXT3 -U $U "$i" && done_ "$i" ext3
  i=$(img ext4_dirty 32M); mkfs.ext4 -q -F -L DIRTY "$i" && python3 - "$i" <<'PY' && done_ "$i" ext4_dirty
import sys,struct
p=sys.argv[1]; f=open(p,'r+b'); f.seek(1024+0x3A); st=struct.unpack('<H',f.read(2))[0]
f.seek(1024+0x3A); f.write(struct.pack('<H', st & ~1))   # clear EXT2_VALID_FS -> "not cleanly unmounted"
PY
else skip ext "no mkfs.ext4"; fi
# FAT / exFAT -----------------------------------------------------------------
if have mkfs.vfat; then
  i=$(img fat12 4M);  mkfs.vfat -F 12 -n STEIN_FAT12 -i 12345678 "$i" >/dev/null && done_ "$i" fat12
  i=$(img fat16 32M); mkfs.vfat -F 16 -n STEIN_FAT16 -i 1234ABCD "$i" >/dev/null && done_ "$i" fat16
  i=$(img fat32 64M); mkfs.vfat -F 32 -n STEIN_FAT32 -i DEADBEEF "$i" >/dev/null && done_ "$i" fat32
fi
if have mkfs.exfat; then i=$(img exfat 64M); mkfs.exfat -L STEIN_EXFAT "$i" >/dev/null && done_ "$i" exfat; fi
# NTFS ------------------------------------------------------------------------
# $LogFile is 0xFF-filled (2 MiB); keep boot sector, MFT region and the backup boot sector only.
if have mkfs.ntfs; then i=$(img ntfs 64M); mkfs.ntfs -Q -F -q -L STEIN_NTFS "$i" >/dev/null 2>&1 && python3 "$here/trim.py" "$i" 0:1M -512:end && done_ "$i" ntfs; fi
# Apple -----------------------------------------------------------------------
if have mkfs.hfsplus; then i=$(img hfsplus 64M); mkfs.hfsplus -v STEIN_HFSP "$i" >/dev/null && done_ "$i" hfsplus
  i=$(img hfsx 64M); mkfs.hfsplus -s -v STEIN_HFSX "$i" >/dev/null && done_ "$i" hfsx; fi
if have hformat; then i=$(img hfs 16M); hformat -l STEIN_HFS "$i" >/dev/null 2>&1 && done_ "$i" hfs; fi
# Linux native ----------------------------------------------------------------
if have mkfs.xfs;   then i=$(img xfs 300M);   mkfs.xfs -q -f -L STEIN_XFS -m uuid=$U "$i" && done_ "$i" xfs; fi
if have mkfs.btrfs; then i=$(img btrfs 128M); mkfs.btrfs -q -f -L STEIN_BTRFS -U $U "$i" && done_ "$i" btrfs; fi
if have mkfs.f2fs;  then i=$(img f2fs 64M);   mkfs.f2fs -q -f -l STEIN_F2FS -U $U "$i" >/dev/null 2>&1 && done_ "$i" f2fs; fi
if have mkfs.jfs;   then i=$(img jfs 32M);    mkfs.jfs -q -L STEIN_JFS "$i" >/dev/null && python3 "$here/trim.py" "$i" 0:256K && done_ "$i" jfs; fi
if have mkfs.reiserfs; then i=$(img reiserfs 40M); mkfs.reiserfs -q -f -f -l STEIN_REISER -u $U "$i" >/dev/null 2>&1 && done_ "$i" reiserfs; fi
if have mkfs.nilfs2; then i=$(img nilfs2 160M); mkfs.nilfs2 -q -f -L STEIN_NILFS "$i" >/dev/null 2>&1 && done_ "$i" nilfs2; fi
if have mkfs.minix; then i=$(img minix 16M);  mkfs.minix -3 "$i" >/dev/null && done_ "$i" minix; fi
if have mkswap;     then i=$(img swap 16M);   mkswap -q -L STEIN_SWAP -U $U "$i" >/dev/null && done_ "$i" swap; fi
if have mkfs.erofs; then mkdir -p "$work/tree"; echo hello > "$work/tree/hello.txt"; i="$work/erofs.img"; rm -f "$i"
  mkfs.erofs -L STEIN_EROFS -U $U "$i" "$work/tree" >/dev/null 2>&1 && done_ "$i" erofs; fi
if have mksquashfs; then mkdir -p "$work/tree"; echo hello > "$work/tree/hello.txt"; i="$work/squashfs.img"; rm -f "$i"
  mksquashfs "$work/tree" "$i" -no-progress -quiet >/dev/null 2>&1 && done_ "$i" squashfs; fi
if have mkfs.ocfs2; then i=$(img ocfs2 64M); mkfs.ocfs2 -q -F -L STEIN_OCFS2 -b 4K -C 4K "$i" >/dev/null 2>&1 && done_ "$i" ocfs2; fi
if have bcachefs;   then i=$(img bcachefs 64M); bcachefs format -q -L STEIN_BCFS -U $U "$i" >/dev/null 2>&1 && done_ "$i" bcachefs; fi
# Optical ---------------------------------------------------------------------
if have genisoimage; then mkdir -p "$work/tree"; echo hello > "$work/tree/hello.txt"; i="$work/iso9660.img"; rm -f "$i"
  genisoimage -quiet -V STEIN_ISO -J -R -o "$i" "$work/tree" 2>/dev/null && done_ "$i" iso9660; fi
if have mkudffs; then i=$(img udf 32M); mkudffs --utf8 --label=STEIN_UDF --media-type=hd --udfrev=0x201 "$i" >/dev/null 2>&1 && done_ "$i" udf; fi
# Containers / volume managers ------------------------------------------------
if have cryptsetup; then
  echo -n "stein" > "$work/key"
  # Keyslot areas are random data (megabytes); L0 only needs the headers, so keep those.
  i=$(img luks1 32M); cryptsetup -q luksFormat --type luks1 --pbkdf-force-iterations 1000 "$i" "$work/key" && python3 "$here/trim.py" "$i" 0:4K && done_ "$i" luks1
  i=$(img luks2 32M); cryptsetup -q luksFormat --type luks2 --label STEIN_LUKS2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$i" "$work/key" && python3 "$here/trim.py" "$i" 0:32K && done_ "$i" luks2
fi
if [ "$(id -u)" = 0 ] && have losetup; then
  if have pvcreate; then i=$(img lvm_pv 64M); dev=$(losetup --find --show "$i") && pvcreate -q --norestorefile -u 1ZaNjo-cfIz-0B2C-xXt1-zZ3j-5555-aaaaaa "$dev" >/dev/null 2>&1; losetup -d "$dev"; done_ "$i" lvm_pv; fi
fi
# md RAID member: synthesised (mdadm cannot create arrays inside containers); blkid validates it.
i=$(img md_member 32M); python3 "$here/make_md_member.py" "$i" 0123abcd456789ef0123456789abcdef steintest && done_ "$i" md_member
ls "$out" | wc -l
