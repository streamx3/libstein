# Capability matrix (target state; updated as modules land)

Legend — levels from `design/12-class-hierarchies.md` §3:
L0 detect/geometry/label/uuid · L1 used-block map · L2 offline metadata edit
(label/uuid/resize/check/create) · L3 in-process read · L4 in-process write.
`v1/v2/v3` = milestone in `20-roadmap.md`; `x` = via optional
`stein_backend_exec` only; `–` = not planned.

## Filesystems

| FS | L0 | L1 | L2 label/uuid | L2 resize | L2 check | L2 create | L3 | L4 |
|---|---|---|---|---|---|---|---|---|
| ext2/3/4 | **done** (reader: extents, indirect, inline, htree, symlinks) | **done** (allocation map; used-only imaging) | v1 | v2 (x in v1) | v2 (x in v1) | v1 | v1 | v2 |
| FAT12/16/32 | **done** | **done** (allocation map; used-only imaging) | v1 | v2 (FAT32 only, cluster-count rules) | v1 (FreeBSD fsck_msdosfs port) | v1 | v1 | v1 |
| exFAT | **done** | **done** (allocation map; used-only imaging) | v1 | v2 | v2 | v1 | v1 | v1 |
| NTFS | **done** | **done** (allocation map; used-only imaging) | v1 | v3 (x in v1) | – (x) | v2 (x in v1) | v1 | v3 |
| HFS+ / HFSX | **done** | **done** (allocation map; used-only imaging) | v1 | v3 | – | v2 | v2 | v3 |
| HFS (classic) | **done** (incl. wrapper) | – | v1 | – | – | – | – | – |
| APFS (container + volumes) | **done** (container) | v2 | v1 (name) | – | – | – | v2 | – |
| XFS | **done** | v2 | v1 | x (grow) | x | x | v2 | – |
| btrfs | **done** | v2 | v1 | x | x | x | v2 | – |
| F2FS, JFS, nilfs2, bcachefs, reiser*, minix, ocfs2 | **done** (+erofs, squashfs) | – | v1 (read) | x | x | x | – | – |
| UDF | **done** | – | v1 | – | – | x | v1 | – |
| ISO9660 | **done** (+Joliet) | v1 (used = everything) | v1 | – | – | – | v1 | – |
| swap (linux, freebsd) | **done** (linux) | v1 (nothing used) | v1 | v1 (recreate) | – | v1 | – | – |
| ReFS, ZFS, UFS | **done** (detect; ZFS name/guid) | – | v1 (label) | – | – | – | – | – |
| BitLocker (as content marker) | **done** | → container | | | | | | |

## Partition tables

| Table | read | diagnostics | write/edit | repair | notes |
|---|---|---|---|---|---|
| GPT (+ protective/hybrid MBR) | **done** | **done** (CRCs, header pairs, overlaps, out-of-bounds, backup location, hybrid) | **done** | **done** (rebuild either copy, fix CRCs, relocate backup, fix PMBR) | own code from UEFI 2.10 §5; byte-identical with sgdisk |
| MBR + EBR | **done** | **done** (overlap, chain loops/breaks, logical outside extended, protective leftovers) | **done** | v1 (rewrite EBR chain) | own code; byte-identical with sfdisk |
| APM (+ DDM block0) | v1 | v1 | v2 | v2 | FreeBSD `g_part_apm.c`; required explicitly by R4 |
| BSD disklabel (+ nested in MBR) | v1 | v1 | v2 | – | FreeBSD `g_part_bsd.c` |
| Windows LDM (dynamic disks) | v1 | v1 | – | – | FreeBSD `g_part_ldm.c`; volumes via `stein_volume` |
| Sun VTOC, SGI/DVH, Amiga RDB, PC98, AIX, Atari | v2 | v2 | v3 | – | specs + libparted as reference-only; libparted/libblkid list is the completeness bar |
| none (whole-device fs) | **done** | **done** | n/a | – | |

## Containers and volume managers

| Thing | detect | open/read | write/create | notes |
|---|---|---|---|---|
| LUKS1 | **done** | v1 | v2 (format, keyslots) | PBKDF2, AF-splitter, aes-xts-plain64 first; other cipher specs v2 |
| LUKS2 | **done** | v1 (argon2id/pbkdf2, xts; integrity → refuse) | v2 | JSON metadata, two header copies |
| TrueCrypt/VeraCrypt | v1 (by trial decrypt) | v2 (basis: tc-play, BSD-2; cascades, hidden, PIM) | v3 | system-encryption volumes v3 |
| BitLocker | v1 | v2 (password / recovery key / BEK; AES-CBC+Elephant, AES-XTS) | – | libbde docs as spec |
| FileVault2 / CoreStorage | v1 | v3 | – | |
| plain dm-crypt | v1 (parameters supplied) | v1 | v1 | |
| LVM2 | **done** (PV, VG name) | **done** (linear/striped/multi-segment LVs as devices) | v3 (pvcreate/vgcreate/lvcreate in-process) | own text-metadata parser |
| mdraid 0.9/1.x | **done** | v2 (linear/0/1/10 read) | – | |
| APFS container | v1 | v2 | – | |

## Images

| Format | read | write | mount via `ImageDevice` | notes |
|---|---|---|---|---|
| raw / split raw | **done** (raw) | **done** (raw) | **done** (raw) | split raw: v1 |
| `.stein` | **done** | **done** | **done** | spec in `doc/spec/stein-image-v1.md`; encryption/zstd later |
| E01/EWF | v2 | v2 | v2 | |
| VHD (fixed/dynamic) | v2 | v2 | v2 | fixed VHD = raw + footer → native Windows attach |
| VHDX | v2 | v3 | v2 | |
| qcow2 | v2 | v3 | v2 | |
| VMDK | v2 | – | v2 | |
| DMG/UDIF | v2 | – | v2 | zlib/bzip2/ADC/lzfse |
| partclone/Clonezilla | v3 | – | v3 | |

## Mount backends (stein_mount)

| Backend | read-only mount | writable mount | notes |
|---|---|---|---|
| Linux libfuse3 | **done** (`stein mount`, any `fs::Reader`: partitions inside images, LUKS, LVM) | v2 (needs fs writers) | optional at configure time (`pkg-config fuse3`) |
| macOS NFS loopback / macFUSE | v1 | v2 | kext-less default per design doc 15 |
| Windows WinFsp / Dokany | v1 | v2 | |

## Operations (stein_ops, M1)

| Operation | Status | Notes |
|---|---|---|
| CreateTable GPT/MBR/APM | **done** | zeroes old signatures first; preview on overlay |
| Add/Delete/Update partition | **done** | bounds/overlap validation from `PartitionTable`; optional signature wipe |
| RepairTable | **done** | GPT copies rebuild/relocate |
| WipeSignatures | **done** | regions from the probe tree |
| Resize/move partition (data) | planned | M3 |
| CreateImage/RestoreImage as operations | planned | currently direct functions in `stein_image` |
