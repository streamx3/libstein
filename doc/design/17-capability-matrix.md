# Capability matrix (target state; updated as modules land)

Legend — levels from `design/12-class-hierarchies.md` §3:
L0 detect/geometry/label/uuid · L1 used-block map · L2 offline metadata edit
(label/uuid/resize/check/create) · L3 in-process read · L4 in-process write.
`v1/v2/v3` = milestone in `20-roadmap.md`; `x` = via optional
`stein_backend_exec` only; `–` = not planned.

## Filesystems

| FS | L0 | L1 | L2 label/uuid | L2 resize | L2 check | L2 create | L3 | L4 |
|---|---|---|---|---|---|---|---|---|
| ext2/3/4 | v1 | v1 | v1 | v2 (x in v1) | v2 (x in v1) | v1 | v1 | v2 |
| FAT12/16/32 | v1 | v1 | v1 | v2 (FAT32 only, cluster-count rules) | v1 (FreeBSD fsck_msdosfs port) | v1 | v1 | v1 |
| exFAT | v1 | v1 | v1 | v2 | v2 | v1 | v1 | v1 |
| NTFS | v1 | v1 | v1 | v3 (x in v1) | – (x) | v2 (x in v1) | v1 | v3 |
| HFS+ / HFSX | v1 | v1 | v1 | v3 | – | v2 | v2 | v3 |
| HFS (classic) | v1 | – | v1 | – | – | – | – | – |
| APFS (container + volumes) | v1 | v2 | v1 (name) | – | – | – | v2 | – |
| XFS | v1 | v2 | v1 | x (grow) | x | x | v2 | – |
| btrfs | v1 | v2 | v1 | x | x | x | v2 | – |
| F2FS, JFS, nilfs2, bcachefs, reiser*, minix, ocfs2 | v1 | – | v1 (read) | x | x | x | – | – |
| UDF | v1 | – | v1 | – | – | x | v1 | – |
| ISO9660 | v1 | v1 (used = everything) | v1 | – | – | – | v1 | – |
| swap (linux, freebsd) | v1 | v1 (nothing used) | v1 | v1 (recreate) | – | v1 | – | – |
| ReFS, ZFS, UFS | v1 | – | v1 (label) | – | – | – | – | – |
| BitLocker (as content marker) | v1 | → container | | | | | | |

## Partition tables

| Table | read | diagnostics | write/edit | repair | notes |
|---|---|---|---|---|---|
| GPT (+ protective/hybrid MBR) | v1 | v1 (CRCs, header pairs, overlaps, out-of-bounds, backup location) | v1 | v1 (rebuild primary from backup and vice versa, fix CRCs, relocate backup, fix PMBR) | basis: FreeBSD `g_part_gpt.c` + UEFI 2.10 §5 |
| MBR + EBR | v1 | v1 (overlap, CHS/LBA mismatch, extended chains) | v1 | v1 (rewrite EBR chain) | FreeBSD `g_part_mbr.c`/`g_part_ebr.c` |
| APM (+ DDM block0) | v1 | v1 | v2 | v2 | FreeBSD `g_part_apm.c`; required explicitly by R4 |
| BSD disklabel (+ nested in MBR) | v1 | v1 | v2 | – | FreeBSD `g_part_bsd.c` |
| Windows LDM (dynamic disks) | v1 | v1 | – | – | FreeBSD `g_part_ldm.c`; volumes via `stein_volume` |
| Sun VTOC, SGI/DVH, Amiga RDB, PC98, AIX, Atari | v2 | v2 | v3 | – | specs + libparted as reference-only; libparted/libblkid list is the completeness bar |
| none (whole-device fs) | v1 | v1 | v1 | – | |

## Containers and volume managers

| Thing | detect | open/read | write/create | notes |
|---|---|---|---|---|
| LUKS1 | v1 | v1 | v2 (format, keyslots) | PBKDF2, AF-splitter, aes-xts-plain64 first; other cipher specs v2 |
| LUKS2 | v1 | v1 (argon2id/pbkdf2, xts; integrity → refuse) | v2 | JSON metadata, two header copies |
| TrueCrypt/VeraCrypt | v1 (by trial decrypt) | v2 (basis: tc-play, BSD-2; cascades, hidden, PIM) | v3 | system-encryption volumes v3 |
| BitLocker | v1 | v2 (password / recovery key / BEK; AES-CBC+Elephant, AES-XTS) | – | libbde docs as spec |
| FileVault2 / CoreStorage | v1 | v3 | – | |
| plain dm-crypt | v1 (parameters supplied) | v1 | v1 | |
| LVM2 | v1 | v1 (linear, striped), v2 (mirror read, thin detect) | v3 (pvcreate/vgcreate/lvcreate in-process) | own text-metadata parser |
| mdraid 0.9/1.x | v1 | v2 (linear/0/1/10 read) | – | |
| APFS container | v1 | v2 | – | |

## Images

| Format | read | write | mount via `ImageDevice` | notes |
|---|---|---|---|---|
| raw / split raw | v1 | v1 | v1 | |
| `.stein` | v1 | v1 | v1 | see `14-imaging.md` |
| E01/EWF | v2 | v2 | v2 | |
| VHD (fixed/dynamic) | v2 | v2 | v2 | fixed VHD = raw + footer → native Windows attach |
| VHDX | v2 | v3 | v2 | |
| qcow2 | v2 | v3 | v2 | |
| VMDK | v2 | – | v2 | |
| DMG/UDIF | v2 | – | v2 | zlib/bzip2/ADC/lzfse |
| partclone/Clonezilla | v3 | – | v3 | |
