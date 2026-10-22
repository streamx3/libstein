# Capability matrix (target state; updated as modules land)

Legend — levels from `design/12-class-hierarchies.md` §3:
L0 detect/geometry/label/uuid · L1 used-block map · L2 offline metadata edit
(label/uuid/resize/check/create) · L3 in-process read · L4 in-process write.
`v1/v2/v3` = milestone in `20-roadmap.md`; `x` = via optional
`stein_backend_exec` only; `–` = not planned.

## Filesystems

| FS | L0 | L1 | L2 label/uuid | L2 resize | L2 check | L2 create | L3 | L4 |
|---|---|---|---|---|---|---|---|---|
| ext2/3/4 | **done** | **done** (allocation map; used-only imaging) | v1 | v2 (x in v1) | v2 (x in v1) | v1 | **done** (reader: extents, indirect, inline, htree, symlinks) | v2 |
| FAT12/16/32 | **done** (boot sector described whole; BPB/FSInfo sanity, FAT[0]/FAT[1] media and clean/hard-error bits, hidden_sectors vs partition start; FAT32 backup boot/FSInfo and mirrored FAT copies compared, `repair()` rewrites the backup boot sector from the live one, an FSInfo copy with wrong signatures from the intact one and a FAT copy whose head fails fsck.fat's media-byte / end-of-chain test from the sound copy; a backup FSInfo that merely lags is Info, not repairable) | **done** (allocation map from the active FAT per ext_flags; used-only imaging) | v1 | v2 (FAT32 only, cluster-count rules) | v1 (FreeBSD fsck_msdosfs port) | v1 | **done** (reader: LFN, chains, active FAT) | v1 |
| exFAT | **done** (boot regions with checksums and backup, `repair()` restores or reseals them; geometry/truncation checks; used space counted from bitmaps up to 8 MiB; TexFAT second FAT compared, not repaired) | **done** (allocation map from the live bitmap per volume_flags; used-only imaging) | v1 | v2 | v2 | v1 | **done** (reader: NoFatChain, up-case table, live FAT per volume_flags) | v1 |
| NTFS | **done** | **done** (allocation map; used-only imaging) | v1 | v3 (x in v1) | – (x) | v2 (x in v1) | **done** (reader: MFT, INDX, reparse links) | v3 |
| HFS+ / HFSX | **done** | **done** (allocation map; used-only imaging) | v1 | v3 | – | v2 | **done** (reader: B-trees, overflow extents, hard links, HFSX case) | v3 |
| HFS (classic) | **done** (incl. wrapper) | – | v1 | – | – | – | – | – |
| APFS (container + volumes) | **done** (container) | v2 | v1 (name) | – | – | – | **done** (reader: latest checkpoint, container/volume object maps, any volume by name or slot, snapshots via the snapshot superblock and xid-bounded omap lookups, fs tree inodes/dirs/extents/symlinks, xattrs embedded or in data streams, decmpfs zlib/lzvn/lzfse files; unencrypted only) | – |
| XFS | **done** | v2 | v1 | x (grow) | x | x | **done** (reader: v4/v5 inodes, extents and bmbt forks, sf/block/leaf/node dirs) | – |
| btrfs | **done** | v2 | v1 | x | x | x | **done** (reader: chunk map, fs/subvolume trees, inline/regular extents, zlib/lzo/zstd compression) | – |
| SquashFS | **done** | – | – | – | – | – | **done** (reader: 4.0, gzip/lzo/xz/lz4/zstd/lzma, fragments, sparse blocks, basic and extended inodes) | – |
| EROFS | **done** | – | – | – | – | – | **done** (reader: flat/inline/chunk-based data, compressed data with full and compact indexes, big pclusters, tail packing, fragments, dedupe; lz4/lzma/deflate/zstd) | – |
| F2FS | **done** | – | v2 | x | x | x | **done** (reader: checkpoint selection, NAT + journal, inline data/dentries, direct/indirect/double-indirect nodes, extra attributes, casefold, lz4/lzo compressed clusters; encrypted files refused) | – |
| JFS, nilfs2, bcachefs, reiser*, minix, ocfs2 | **done** | – | v1 (read) | x | x | x | – | – |
| UDF | **done** | – | v1 | – | – | x | **done** (reader: physical/sparable/metadata maps, FE/EFE, inline/short/long ADs, symlinks; VAT v2) | – |
| ISO9660 | **done** (+Joliet) | v1 (used = everything) | v1 | – | – | – | **done** (reader: Rock Ridge names/links/relocation, Joliet, plain) | – |
| swap (linux, freebsd) | **done** (linux) | v1 (nothing used) | v1 | v1 (recreate) | – | v1 | – | – |
| ReFS, ZFS, UFS | **done** (detect; ZFS name/guid) | – | v1 (label) | – | – | – | – | – |
| BitLocker (as content marker) | **done** | → container | | | | | | |

## Partition tables

| Table | read | diagnostics | write/edit | repair | notes |
|---|---|---|---|---|---|
| GPT (+ protective/hybrid MBR) | **done** | **done** (CRCs, header pairs, overlaps, out-of-bounds, backup location, PMBR extent, hybrid entries mirrored by GPT entries) | **done** | **done** (rebuild either copy, fix CRCs, relocate backup, fix PMBR; a hybrid MBR is left alone) | own code from UEFI 2.10 §5; byte-identical with sgdisk; v4 GUIDs from `crypto::randomBytes` |
| MBR + EBR | **done** | **done** (overlap, chain loops/breaks, lost logicals, links outside the extended partition, logical outside extended, protective leftovers, status/CHS/stale entries) | **done** | **done** (rewrite EBR chain; orphaned-EBR recovery on the 1 MiB grid and, right behind the break, the 63-sector grid within 64 MiB of reads, a hit believed only with a recognised filesystem of the entry's size behind it; a lost logical rebuilt from the filesystem behind its EBR, else the chain is not closed over it; a wiped head EBR told from an empty container by what lies behind it; normalise entries; refuses to empty a chain it could not read) | own code; byte-identical with sfdisk |
| APM (+ DDM block0) | v1 | v1 | v2 | v2 | FreeBSD `g_part_apm.c`; required explicitly by R4 |
| BSD disklabel (+ nested in MBR) | v1 | v1 | v2 | – | FreeBSD `g_part_bsd.c` |
| Windows LDM (dynamic disks) | v1 | v1 | – | – | FreeBSD `g_part_ldm.c`; volumes via `stein_volume` |
| Sun VTOC, SGI/DVH, Amiga RDB, PC98, AIX, Atari | v2 | v2 | v3 | – | specs + libparted as reference-only; libparted/libblkid list is the completeness bar |
| none (whole-device fs) | **done** | **done** | n/a | – | |

## Containers and volume managers

| Thing | detect | open/read | write/create | notes |
|---|---|---|---|---|
| LUKS1 | **done** | **done** (PBKDF2 over sha1/sha256/sha512/ripemd160/whirlpool, AF-splitter, aes/serpent/twofish/camellia xts-plain64, detached header) | v2 (format, keyslots) | cbc-essiv, plain64be and `capi:` refused by name; `Luks::open(header, data)` for `--header` / `luksHeaderBackup` |
| LUKS2 | **done** | **done** (argon2i/argon2id on lane threads with a memory cap and a cancel hook, pbkdf2; slots by priority, tokens read, unusable slots skipped with a reason; both header copies with checksum and seqid; 512/4096-byte sectors; detached header; dm-integrity, reencryption or mandatory requirements, several or non-crypt segments and unknown flags → refused with the reason) | v2 | JSON numbers parsed defensively; read-only payloads behind `CachedDevice`; the probe keeps an unlocked-key cache by UUID (`probe::Options::masterKeys` / `onUnlocked` / `cancelled`) |
| TrueCrypt/VeraCrypt | **done** (by trial decrypt with a passphrase) | **done** (every cipher and cascade of VeraCrypt 1.26 and TrueCrypt 7 in XTS; PBKDF2 over all six PRFs with PIM; normal, hidden, backup headers) | v3 | system-encryption volumes v3 |
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
| E01/EWF | **done** (EnCase 5/6 v1 format, segments, deflate chunks, stored MD5/SHA-1) | v2 | **done** | EWF2 (EnCase 7), smart, logical evidence v2 |
| VHD (fixed/dynamic) | **done** | v2 | **done** | differencing v2; fixed VHD = raw + footer → native Windows attach |
| VHDX | **done** (dynamic; log must be clean) | v3 | **done** | differencing v2 |
| qcow2 | **done** (v2/v3, deflate- and zstd-compressed clusters) | v3 | **done** | backing files, subclusters v2 |
| VMDK | **done** (sparse, stream-optimized, multi-extent descriptors) | – | **done** | snapshot chains v2 |
| DMG/UDIF | **done** (UDRO raw, UDZO zlib, UDBZ bzip2, UDCO ADC, ULMO lzma/xz, ULFO lzfse; ignored/zero blocks) | – | **done** | segmented and encrypted images v2 |
| VDI | **done** (dynamic/fixed) | – | **done** | undo/differencing v2 |
| partclone/Clonezilla | v3 | – | v3 | |

## Mount backends (stein_mount)

| Backend | read-only mount | writable mount | notes |
|---|---|---|---|
| Linux libfuse3 | **done** (`stein mount`, any `fs::Reader`: partitions inside images, LUKS, LVM) | v2 (needs fs writers) | optional at configure time (`pkg-config fuse3`) |
| macOS NFS loopback | **done** (own NFSv3 server on 127.0.0.1 + `mount_nfs`, export named after the volume via `NfsServerOptions::exportPath`, `Mount::run()` returns on an external unmount through a getfsstat poll and the client's UMNT; `stein attach` hands a decoded disk to macOS's own drivers via hdiutil) | v2 | no kext, no dependency; FSKit later for packaged apps |
| Windows WinFsp | **done** (same libfuse3-API source over WinFsp's fuse3 layer, delay-loaded; drive letter or absent directory as mount point; CI mounts and reads the ext4 fixture through it) | v2 | WinFsp is optional at configure time and at run time (clear `Unsupported` when not installed); Dokany not pursued |

## Operations (stein_ops, M1)

| Operation | Status | Notes |
|---|---|---|
| CreateTable GPT/MBR/APM | **done** | zeroes old signatures first; preview on overlay |
| Add/Delete/Update partition | **done** | bounds/overlap validation from `PartitionTable`; optional signature wipe |
| RepairTable | **done** | any table with repairable diagnostics: GPT copies rebuild/relocate and PMBR, MBR EBR chain rewrite and orphan recovery |
| WipeSignatures | **done** | regions from the probe tree |
| Filesystem repair (FAT backup boot/FSInfo/FAT copies, exFAT boot regions) | **done**, not an operation | `fs::FileSystem::repair()`, called directly by `stein repair` and the app |
| ConvertTable MBR ↔ GPT | not scheduled | no code, no milestone; `13-operations.md` §3 |
| Resize/move partition (data) | planned | M3 |
| CreateImage/RestoreImage as operations | planned | currently direct functions in `stein_image` |
