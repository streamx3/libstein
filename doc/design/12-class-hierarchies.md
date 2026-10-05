# Class hierarchies: partition tables, filesystems, containers, volumes

Companion to `10-architecture.md` (what the libraries are) and
`11-cpp-interfaces.md` (how abilities are expressed). This file lists the
concrete classes, what each one must know about its on-disk format, and the
gotchas that decide the interface shape.

## 1. Block devices (`stein_block`, `stein_platform`)

```
BlockDevice (abstract)
├── MemoryDevice            tests, simulation
├── FileDevice              regular file via injected FileIo (portable)
├── SliceDevice             [offset, length) window on a parent; used for Partition, nested tables
├── CachedDevice            LRU sector cache decorator
├── ReadOnlyDevice          decorator that fails writes (safe default for probing)
├── ConcatDevice            N devices back-to-back (split images, LVM linear)
├── StripedDevice           RAID0 / LVM striped
├── MirrorDevice            RAID1 read (first good copy)
├── platform::PlatformDisk  Linux /dev/sdX | macOS /dev/rdiskN | Windows \\.\PhysicalDriveN
├── image::ImageDevice      backed by an ImageFormat::Reader
├── container::DecryptedDevice   XTS/CBC transform over a parent (LUKS, VeraCrypt, BitLocker)
└── volume::LogicalVolumeDevice  LVM LV / md array mapping over PVs/members
```

`BlockDevice` interface (minimal, everything else is a capability):

```cpp
class BlockDevice {
public:
    virtual ~BlockDevice() = default;
    virtual DeviceIdentity identity() const = 0;            // stable id, human name, path (may be empty)
    virtual Geometry       geometry() const = 0;            // size bytes, logical & physical sector size, optimal io, alignment offset
    virtual Flags          flags() const = 0;               // ReadOnly, Removable, Rotational, Virtual, Partition, Image...
    virtual Expected<size_t> readAt (uint64_t off, std::span<std::byte> dst) = 0;
    virtual Expected<size_t> writeAt(uint64_t off, std::span<const std::byte> src) = 0;
    virtual Expected<void>   flush() = 0;
    virtual Expected<void>   discard(uint64_t off, uint64_t len) { return Error::Unsupported; } // TRIM/zero
    virtual std::shared_ptr<BlockDevice> parent() const { return nullptr; }
    virtual Expected<std::vector<Extent>> extentsOnParent() const; // for Slice/LV: physical map (used by imaging/move)
};
```

Gotchas captured:
- `readAt` must handle partial reads at end-of-device and unaligned requests
  (`PlatformDisk` on Windows/`O_DIRECT` requires sector alignment → the
  platform class does read-modify-write/bounce buffering, the core never does).
- Identity must survive reboots and port changes: serial + WWN + model + size;
  for partitions: GPT GUID / MBR disk-id+index; for images: file hash of header.

## 2. Partition tables (`stein_pt`)

```
PartitionTable (abstract)
├── MbrPartitionTable     DOS MBR, 4 primaries, EBR chain for logicals, disk signature,
│                         CHS vs LBA, protective-MBR detection, hybrid MBR awareness,
│                         bootable flag, type 0x05/0x0F/0x85 extended, 0xEE GPT protective
├── GptPartitionTable     primary+backup headers, CRC32 of header & array, up to 128+ entries,
│                         attributes (bit 0 platform required, 2 legacy BIOS bootable, 60-63 vendor:
│                         MS read-only/hidden/no-automount, Chrome OS priorities), partition names UTF-16LE,
│                         Repairer: rebuild primary from backup / backup from primary, fix CRCs, relocate backup
│                         to end after disk grow, fix "alternate LBA" and "last usable LBA"
├── ApmPartitionTable     Block0 (Driver Descriptor Map, sbSig 'ER', sbBlkSize), partition map entries
│                         (pmSig 'PM'), partition map describes itself (Apple_partition_map), types as strings
│                         (Apple_HFS, Apple_UFS, Apple_Free, Apple_Boot, Apple_Driver43...), 512 vs 2048 block size,
│                         pmPartStatus flags; Editor must keep map entry 1 = map itself and keep entries contiguous
├── BsdDisklabel          at sector 1 (or 0 on some archs), magic 0x82564557, 8/16 slices, may live inside an
│                         MBR partition (type 0xA5/0xA6/0xA9) → nested table
├── SunVtoc               sun label at sector 0, checksum XOR, 8 slices, cylinder units
├── SgiDvhLabel           SGI volume header, magic 0x0BE5A941, 16 partitions, volume directory
├── AmigaRdb              Rigid Disk Block 'RDSK' searched in first 16 blocks, linked list of 'PART' blocks, checksums
├── Pc98Table             NEC PC-98, 16 entries at offset 0x200, CHS-based, magic 0x55AA + sanity rules
├── AixLabel              AIX IPL record magic 0xC9C2D4C1 (detect/label only)
├── AtariTable            AHDI root sector (detect; libparted lists it)
└── NoPartitionTable      whole-device content ("loop" in libparted terms); may still host a filesystem
```

Base interface:

```cpp
class PartitionTable {
public:
    virtual TableType type() const = 0;
    virtual TableHealth health() const = 0;          // Ok, PrimaryCorrupt, BackupCorrupt, BothCorrupt, CrcMismatch, Overlapping, OutOfBounds...
    virtual std::span<const Partition> partitions() const = 0;   // sorted by start; logicals carry parent index
    virtual std::vector<FreeRegion> freeRegions(const AlignmentPolicy&) const = 0;
    virtual Limits limits() const = 0;               // max primaries, max total, min/max partition size, supports names/uuids/flags
    virtual Editor*   editor()   { return nullptr; } // produces a modified COPY; nothing hits disk until write()
    virtual Repairer* repairer() { return nullptr; }
    virtual Expected<void> write(BlockDevice&, WriteOptions) = 0;  // ordered, verified
    virtual Expected<Bytes> serialize(std::span<std::byte>) const = 0; // for snapshots in image metadata
    static  Expected<std::unique_ptr<PartitionTable>> read(BlockDevice&, ReadOptions); // via registry: tries all, returns best match with health
};
```

Format-specific rules that shape the interface:
- GPT read must succeed with a corrupt primary (use backup) and must *report*
  that it did (`health()`), so UIs can offer "repair". This is R6.
- GPT and protective/hybrid MBR are one logical table with two physical
  parts; `GptPartitionTable` owns the PMBR and writes it.
- A `Partition` is `{index, start, length (sectors), type (PartitionType: scheme + code/GUID/string), flags, name, uuid, nestedTable?}`.
  `PartitionType` is a sum type; the registry maps to semantic roles
  (`Role::EfiSystem`, `Role::LinuxFilesystem`, `Role::WindowsBasicData`,
  `Role::AppleApfs`, `Role::Swap`, `Role::LvmPv`, `Role::LuksData`, …) so the
  UI can show "EFI System Partition" regardless of scheme.
- MBR CHS fields: compute for compatibility, never trust for geometry.
- APM entries are 1-based and the map's own entry must come first; the Editor
  enforces this invariant.

## 3. Filesystems (`stein_fs`)

```
FileSystem (abstract; capability objects per 11-cpp-interfaces.md)
├── ext::ExtFamily              shared superblock @1024, group descriptors, feature flags
│   ├── Ext2FileSystem
│   ├── Ext3FileSystem          (ext2 + has_journal)
│   └── Ext4FileSystem          (extents, 64bit, metadata_csum, flex_bg, inline data, encryption flag detect)
├── fat::FatFamily              BPB parsing, FAT12/16/32 width rules, long names (VFAT), dirty bit
│   ├── Fat12FileSystem
│   ├── Fat16FileSystem
│   └── Fat32FileSystem         FSInfo sector, backup boot sector @6
├── ExFatFileSystem             boot region (main+backup), FAT, allocation bitmap, up-case table, checksum sector
├── NtfsFileSystem              boot sector, $MFT, $Bitmap, $Volume (label, flags: dirty), $LogFile state, resident/non-resident attrs, compression/sparse, $UsnJrnl awareness; resize = move clusters + $Bitmap/$BadClus edit (hard; v2)
├── RefsFileSystem              detect + label (format is undocumented; read via reverse-engineered specs later)
├── hfs::HfsFamily              volume header @1024, allocation file, B-trees (catalog/extents/attributes)
│   ├── HfsFileSystem           classic (MDB), wrapper detection
│   └── HfsPlusFileSystem       HFS+ / HFSX (case-sensitive flag), journal (HFSJ) detection
├── ApfsContainer -> see stein_volume (container) ; ApfsVolume : FileSystem (detect/label/read later; encrypted volumes via FileVault later)
├── BtrfsFileSystem             superblock @64 KiB (+ copies @64 MiB, 256 GiB), csum, chunk tree → device extents (needed for used-block maps and multi-device detection)
├── XfsFileSystem               superblock @0 per AG, v4/v5 (CRC), AG free-space B-trees for used maps
├── F2fsFileSystem              superblock @1 KiB (2 copies), checkpoints
├── JfsFileSystem               superblock @32 KiB
├── ReiserFsFileSystem, Reiser4FileSystem   detect/label/uuid only
├── Nilfs2FileSystem            superblock @1 KiB + backup at end
├── BcachefsFileSystem          superblock @4 KiB; detect/label/uuid
├── UdfFileSystem               VRS (BEA01/NSR02/NSR03/TEA01) @32 KiB, AVDP @256, label
├── Iso9660FileSystem           PVD @32 KiB, Joliet SVD, Rock Ridge; read-only by nature (L3 is cheap and valuable for images)
├── MinixFileSystem             v1/v2/v3 superblock @1 KiB
├── SwapSpace                   swap v1 signature @ pagesize-10, label, uuid (treated as a FileSystem for uniformity)
├── ZfsPool                     vdev labels (4 per device: 2 front, 2 back), detect/name only
├── Lvm2Pv, MdMember, LuksHeader, VeraCryptHeader, BitLockerVolume   ← thin "content markers" whose real class lives in stein_volume / stein_container; FsRegistry delegates
└── UnknownContent / Empty
```

Implementation *levels* per filesystem (tracked in a capability matrix,
`design/17-capability-matrix.md`):

| Level | Meaning | Interface pieces |
|---|---|---|
| L0 | detect, geometry, label, uuid, dirty/clean state, version/features | `FileSystem` base methods |
| L1 | used-block bitmap (for fs-aware imaging and intelligent copy) | `UsedBlockMap` capability |
| L2 | metadata editing offline: set label, set uuid, resize (grow/shrink), check (verify consistency), create (mkfs) | `Labeler`, `Uuider`, `Resizer`, `Checker`, `Creator` |
| L3 | in-process read: directory listing, stat, file read, xattrs where cheap | `Reader` (a VFS-like interface: `open`, `readdir`, `stat`, `read`, `readlink`) |
| L4 | in-process write: create/delete/rename/write/truncate, journaling-correct or journal-replay-then-write | `Writer` |

L3/L4 are the "userspace driver" of R7 and are described in `15-userspace-fs.md`.

Common `FileSystem` machinery (base-class helpers, not virtual):
- `Superblock` parsing is done on a `SliceDevice` so the same code works on
  partitions, LVs, decrypted containers and images.
- A `FsSignature` table (magic, offset, size, optional validator) drives the
  registry's cheap first pass (what `libblkid` does), then the matched class
  does a full parse.
- Every module ships golden fixtures (tiny sparse images made with the real
  tools) and property tests (parse → serialize → parse).

## 4. Containers (`stein_container`)

```
Container (abstract)  — "something that yields a BlockDevice after a key"
├── Luks1Container     binary header, 8 key slots, AF-splitter, PBKDF2, cipher spec strings ("aes-xts-plain64")
├── Luks2Container     binary header + JSON metadata (two copies with seqid), argon2id/pbkdf2, keyslots/segments/digests/tokens, label/subsystem, 4 KiB sectors option, dm-integrity awareness (detect only; refuse to open when integrity is set, v1)
├── VeraCryptContainer TrueCrypt/VeraCrypt header @0 (+ hidden @65536, + backup at end − 128 KiB), PKCS5-based header decryption trial over all cipher/hash combos and PIM, cascades (AES-Twofish-Serpent…), XTS; system-encryption and partition modes
├── BitLockerContainer FVE metadata (3 copies), detect + volume label; unlock (recovery password / FVEK) later
├── PlainContainer     dm-crypt "plain": user-supplied cipher/hash/offset; useful for legacy & tests
└── CoreStorageContainer / FileVault2 (detect; unlock later)
```

`Container::Unlocker` takes a `Credential` variant (passphrase, keyfile(s),
recovery key, raw key) and returns a `std::shared_ptr<BlockDevice>`
(`DecryptedDevice`). Key material is held in a `SecureBuffer` (locked,
zeroed on free). Everything is in-process; no device-mapper required. On
Linux an *optional* platform path can hand the same volume to dm-crypt for
native mounting.

## 5. Volume managers (`stein_volume`)

```
VolumeGroup (abstract)
├── Lvm2VolumeGroup     PV label @ sector 1 ("LABELONE"), metadata area with text-format VG description
│                       (parse the mini-language: vg { lv { segment { type = "striped"|"mirror"|"thin"|... } } }),
│                       assemble LVs over 1..N PVs → LogicalVolumeDevice (linear, striped; mirror read; thin → detect only v1)
├── MdRaidArray         superblock 0.90 (end of device) and 1.0/1.1/1.2 (various offsets), levels linear/0/1/4/5/6/10; v1: detect + read linear/0/1
├── LdmDiskGroup        Windows dynamic disks: private header @ end, TOC, VMDB/VBLK records; detect + list volumes
├── ApfsContainer       NXSB superblock, checkpoint descriptor area, object map, list volumes (APSB) with names/roles/encryption flags
└── CoreStorageGroup    detect
```

A `VolumeGroup::Enumerator` yields `LogicalVolume`s; each is a
`BlockDevice` and goes back into the probe recursion.

## 6. Images (`stein_image`) — see `14-imaging.md`

```
ImageFormat (abstract) → RawImage, SplitRawImage, SteinImage, EwfImage, Qcow2Image, VhdImage, VhdxImage, VmdkImage, DmgImage
ImageDevice : BlockDevice
CopyEngine, UsedBlockMap, BadSectorMap, Verifier
```

## 7. Probe tree (`stein_probe`)

```cpp
struct Node {
    std::shared_ptr<BlockDevice> device;        // the region this node describes
    Content content;                             // variant<Empty, Unknown, FileSystem*, Container*, VolumePv, PartitionTable*>
    std::vector<Node> children;                  // partitions, unlocked containers' contents, LVs...
    std::vector<Diagnostic> diagnostics;         // "backup GPT header is corrupt", "fs extends past partition end"
};
Expected<Node> probe(std::shared_ptr<BlockDevice>, ProbeOptions);   // non-destructive, bounded reads
```

Diagnostics are the raw material for the UI's "this disk has problems, here
is what I can do about it" view, which neither Disk Utility nor GNOME Disks
provide in a structured way.
