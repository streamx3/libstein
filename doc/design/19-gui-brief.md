# GUI brief: what libstein can do today, for designing the desktop app

Purpose: a single, precise description of the library's current
capabilities, the objects it exposes and the operations it performs, so a
GUI can be designed against it without reading code. Everything here is
implemented and covered by tests on Linux, macOS and Windows unless marked
*planned*. Numbers and names are the real ones from the public headers.

The library has no UI of its own. The CLI `stein` exists as a thin shell over
the same calls the GUI would make; each screen below names the CLI command
that already does the same thing, so behaviour can be tried before pixels
exist.

## 1. Who uses it and for what

Three audiences, one library:

1. **The one-button user** (the dr_stein case). Owns one or two machines,
   wants "back up this disk to that drive" and "put it back" with as few
   decisions as possible, a clear progress bar, and a trustworthy verdict
   ("restored and verified"). Never sees sector numbers.
2. **The power user / technician.** Wants to see what is on a disk or in an
   image (partition table, filesystems, containers, health), fix a broken
   GPT, pull files out of an image without mounting anything, test a
   suspicious USB stick, convert between image formats.
3. **The forensic / recovery user.** Opens E01, qcow2, DMG, VeraCrypt or LUKS
   images read-only, browses foreign filesystems, extracts evidence, verifies
   hashes. Needs everything read-only by default and every destructive action
   gated.

Design principle inherited from the library: **read-only until explicitly
not.** Every object opens read-only; writes go through an operation stack
that previews on an overlay and applies in one pass; destructive operations
are flagged as such by the library, not guessed by the UI.

## 2. The objects a GUI shows

### 2.1 Disks (platform layer)

`platform::DiskInfo`, one per physical or virtual disk the OS knows about
(`stein list`):

| Field | Example | Notes |
|---|---|---|
| `osPath` | `/dev/sda`, `/dev/rdisk2`, `\\.\PhysicalDrive0` | what to open |
| `kernelName` | `sda`, `nvme0n1`, `loop3`, `disk2` | short label |
| `geometry` | 500107862016 bytes, 512-byte logical, 4096 physical sectors | size and sector sizes |
| `bus` | `Nvme`, `Usb`, `Sd`, `Ata`, `Scsi`, `Loop`, `Virtual`, `Md`, `DeviceMapper` | icon / grouping |
| `model`, `vendor`, `serial`, `firmware`, `wwn` | "Samsung SSD 980", "S64ANX0R123", ... | identity line |
| `removable`, `rotational`, `readOnly`, `isVirtual` | flags | removable → "safe to pick as backup target" |
| `backingFile` | `/home/me/disk.img` | loop devices only |
| `identity()` | stable string from the most durable fields | what profiles store to find "the same disk" again |

Also per disk: current mounts (`MountInfo`: source, target, fsType,
options, readOnly), whether the process is elevated (`isElevated()`), and
the platform's ability to unmount a volume, re-read the partition table and
attach an image file as a block device (Linux loop, macOS hdiutil).
Per-OS differences are in the README's per-OS table; the GUI should treat
"not available on this OS" as a disabled control with a tooltip, never a
missing feature.

### 2.2 The topology tree (probe)

`probe::probe(device)` returns one `probe::Node` tree for a disk or an
image. This is the central object of every "what is on this disk" screen
(`stein probe`):

```
Device  "disk" 500 GB
├─ table GPT (diagnostics: OK)
├─ Partition 1  "EFI System" 512 MiB    content: FAT32 "EFI" uuid 1A2B-3C4D clean
├─ Partition 2  "Linux filesystem" 400 GB   content: LUKS2 → Decrypted → LVM2 PV → Volume "root": ext4 "fedora" 61% used
├─ Free 2 MiB
└─ Partition 3  ... content: NTFS "Data" (dirty: not cleanly unmounted)
```

Node fields: `kind` (Device, Partition, Free, Metadata, Decrypted, Volume),
`name`, `region` (byte offset and length on the root device), `partition`
(the table entry, see 2.3), `table` (a partition table at this node),
`content` (a filesystem or container, see 2.4), `children`, `notes`
(severity Ok/Info/Warning/Error, stable `code`, message). Containers that
need a passphrase (LUKS, VeraCrypt) stay closed until one is supplied; the
probe accepts a list of passphrases and descends into whatever they open.

### 2.3 Partition tables and partitions

`pt::PartitionTable` for GPT, MBR (+EBR chains) and APM:

- `partitions()`: index (1-based slot), `firstLba`, `lastLba`, `type`
  (GUID or MBR byte, with a human name and an sgdisk-style code such as
  `EF00`, `8300`), `name` (GPT/APM), `uuid` (GPT), `attributes` (GPT bits,
  MBR bootable), `isExtended`/`isLogical` (MBR).
- `diagnostics()`: list of `{severity, code, message, region?, repairable}`;
  codes are stable strings like `gpt.primary_header`, `gpt.backup_location`,
  `mbr.overlap`. `health()` is the worst severity. `repair()` fixes every
  diagnostic flagged repairable (rebuild a lost header copy, fix CRCs, move
  the backup to the disk's end, fix the protective MBR).
- `limits()`: max partitions, name support, UUID support, logical support,
  name length. Use it to enable or disable fields in a "new partition" form.
- Free regions, first/last usable LBA, metadata regions (for a byte map).
- `describe()`: a hexinator-style tree of every metadata structure with
  field values, offsets and validity (`stein inspect --doc`). This is the
  "show me the bytes" expert view; it exists for every format the library
  parses, filesystems included.

### 2.4 Filesystems and containers

`fs::FileSystem::info()` for the 35 recognised formats (`FsType`), with:
`type`, `version`, `label`, `uuid`, `blockSize`, `totalBytes`, `usedBytes`
(when the superblock says), `clean` (cleanly unmounted or not),
`features` (strings worth showing), `extra` (one-liner, e.g. the LUKS
cipher spec), plus diagnostics (`Validity` + code + message) and
`capabilities()`:

| Capability | Meaning for the UI |
|---|---|
| `Identify`, `Label`, `Uuid` | the basics every detector provides |
| `UsedBlocks` | used-block map exists → "skip free space" is possible when imaging (ext2/3/4, FAT, exFAT, NTFS, HFS+) |
| `Read` | files can be browsed and copied out in-process (12 filesystems, see README matrix) |
| `SetLabel`, `SetUuid`, `Grow`, `Shrink`, `Check`, `Create`, `Write` | *planned*; never set today, so a GUI should hide or disable the related controls |

Containers appear as content nodes too: LUKS1/2 (`stein luks info`: key
slots, cipher, PBKDF), VeraCrypt/TrueCrypt (found only by trial decryption
with a passphrase, so the UI needs an "this may be a hidden encrypted
volume, try a passphrase" affordance for unrecognised space), LVM2 physical
volumes (volume group name, logical volumes with sizes), mdraid members,
BitLocker (detected, not opened).

### 2.5 Files inside a filesystem (the viewer)

`fs::Reader` for the readable filesystems, reached from a `FileSystem`
with `openReader()`:

- `root()`, `lookup(dir, name)`, `readdir(dir)` → entries `{name, inode,
  type}`; `stat(inode)` → `{type, size, mode, nlink, uid, gid, atime,
  mtime, ctime, crtime, allocatedBytes}`; `read(file, offset, buffer)`;
  `readlink(symlink)`; `caseSensitive()`.
- `fs::resolvePath(reader, "/etc/fstab")` for path entry, with symlink
  following and `..` handling.
- `fs::copyTree(reader, inode, hostPath, options, progress)` copies a
  file or a whole directory tree out to the host: files, directories,
  symlinks (recreated where the host allows), modification times preserved,
  per-entry warnings for what could not be copied, byte-level progress,
  cancellable between entries. **This is the drag-out primitive**: the viewer
  hands over the dragged inode and the drop folder.
- Lazy: nothing is read until a directory is expanded or a file opened, so a
  viewer can show a 2 TB image instantly.

The viewer is read-only by design (no `Write` capability exists yet). What
it can show: the directory tree, per-entry size/dates/mode, a preview
(bytes are available for any text/hex/image preview), a hash on demand.
What it cannot do yet: edit, rename, delete, change permissions, show
extended attributes (`xattr` reading is not exposed), show NTFS compressed
or encrypted files, APFS compressed files, or encrypted APFS volumes.

The same reader is what `stein mount` exposes to the OS (FUSE on Linux,
WinFsp on Windows, the NFS loopback on macOS), so a "Mount" button is a
second way to reach the same content; the viewer never needs it.

### 2.6 Images

Any image is a disk: `image::openImage(path)` gives a block device for
`.stein`, raw (`.img`, dd, GNOME Disks), split raw, qcow2, VHD, VHDX,
VMDK, VDI, E01/EWF and DMG, and everything in 2.2–2.5 then works on it.
`image::detectVdiskFormat(path)` tells the format; `image::openVdisk`
returns `VdiskInfo` (format, variant, virtual size, cluster size,
compressed, stored MD5/SHA-1 for E01, member files for split sets, notes).

The library's own format, `.stein`, adds (`image::imageInfo`): format
version (major.minor, with the writer's libstein version), UUID, source
name and identity, source size and sector size, chunk size, compression,
chunks stored / total (zero chunks are implicit), bytes on disk, segment
files (split images), completeness (a crash while writing leaves a
recoverable, flagged-incomplete image), the recorded topology tree of the
source, SHA-256 of the whole source, encryption state (ChaCha20-Poly1305;
key slots with passphrases, Argon2id by default; locked images still show
their structure and verify their stored CRCs). Format versioning follows
the ext4 model: a newer major is refused with a clear message, unknown
"incompatible" feature bits are refused and named, unknown read-only or
compatible bits are tolerated.

## 3. The operations a GUI runs

All long operations take a `Progress` (phase name, done/total in a unit,
rate, ETA, ~10 updates per second, cancel token) and fill a `Report` (a
tree of titled steps with status Pending/Running/Success/Warning/Error,
key/value details, free-text lines, durations). A GUI gets a progress bar
and a collapsible log for free.

### 3.1 Inspect and verify (read-only)

- Probe a disk or image → the tree of 2.2 (`stein probe`).
- Inspect metadata structures field by field (`stein inspect --doc`).
- Verify a partition table → exit health plus diagnostics (`stein verify`).
- Verify an image: level 1 structure (milliseconds), 2 stored checksums
  (reads the file, no decompression), 3 full content incl. SHA-256
  (`stein image verify --level N`).
- Surface scan of a device: read everything, list unreadable regions, no
  writes (`stein media scan`).

### 3.2 Partition table editing (metadata writes, previewed)

`ops::OperationStack` on a device: push operations (`CreateTable
GPT|MBR|APM`, `AddPartition`, `DeletePartition`, `UpdatePartition`
type/name/bounds, `RepairTable`, `WipeSignatures`), each validated against
the current topology; the stack keeps a **preview tree** computed on an
in-memory overlay (so the UI can show the resulting layout before anything
is written), the list of pending entries with their job titles and a
`destructive` flag, the changed byte ranges; `apply()` writes everything in
one pass and re-probes; `pop()`/`clear()` undo. Byte-identical with sgdisk
and sfdisk output. (`stein pt create|add|rm|set|wipe`, `stein repair`,
all with `--dry-run`.)

### 3.3 Imaging

- **Create** (`image::createImage`): source device → `.stein` with options
  chunk size, compression (LZ4 or none), split size, bad-sector policy
  (fail or zero-fill and count), used-blocks-only (free space of
  filesystems with a `UsedBlocks` map becomes implicit zero chunks),
  passphrase + KDF parameters, source name/identity, notes. Result: files
  written, UUID, bytes read/stored, zero chunks, unreadable sectors,
  per-filesystem allocation notes, SHA-256. Raw output (`--format raw` or a
  `.img` name) does a plain dd-style copy instead.
- **Restore** (`image::restoreImage`): image → device, with verify-first,
  write or skip zero chunks (discard where supported), allow a smaller
  target (writes what fits, reported). Result: bytes, chunks, "target is
  larger/smaller" flags. Raw and any readable container restore through the
  same device-to-device copy.
- **Keys**: list, add and remove passphrase slots of an encrypted image
  (`stein image keys`).
- **Attach / mount / serve**: hand an image to the OS (loop, hdiutil), mount a
  reader (FUSE, WinFsp, NFS loopback), or serve it to any NFS client
  (`stein mount|attach|serve`).

### 3.4 One-button profiles (dr_stein)

`app::Profile` (JSON file): name, description, **target selector** (serial,
WWN, model, size with tolerance, osPath as last resort, removable/virtual
allowed), **image spec** (path, compression, chunk size, split size,
used-only, encrypt, KDF), **policy** (lock target to identity, require
elevation, allow smaller target, verify before restore level
None/Structure/Checksums/Full, verify after restore and after backup,
re-read partition table, repair the GPT backup after restoring to a larger
disk, unmount the target first or refuse while mounted). Scenarios:
`status` (is the disk present, does the image exist, is it complete, when
was it made, does it fit), `backup`, `restore`, `verify`, each with
`dryRun`, returning a `Report` and typed results. (`stein app init|status|
backup|restore|verify`.)

This is the screen for audience 1: one profile = one card with the disk's
identity, the image's state and three big buttons.

### 3.5 Media tests

`ops::surfaceScan` (read-only) and `ops::capacityTest` (**destructive**:
writes a pattern across the device, reads it back, detects fake-flash by
the address where data stops matching and by wrap-around, estimates real
capacity, measures write/read MiB/s, optionally quick mode every Nth chunk,
restores zeros afterwards unless asked to keep the pattern).
(`stein media scan|test --force`.)

## 4. Platform notes the UI must respect

- **Privileges.** Reading raw disks needs root/Administrator on every OS;
  images in files do not. `isElevated()` tells which. Profiles can require
  elevation up front. A privilege broker (elevate once, keep working) is
  *planned*; today the whole process runs elevated or not.
- **Busy volumes.** Writing to a disk with mounted volumes is refused or
  the volumes are unmounted first, per policy. Windows locks and dismounts
  volumes through the exclusive open.
- **Mount backends.** Linux FUSE needs libfuse3 and `/dev/fuse`; Windows
  needs WinFsp installed (the binary runs without it and reports
  `Unsupported`); macOS needs nothing. `Mount::available()` answers.
- **Hot-plug.** No device change notifications yet (*planned*); a GUI
  should offer a refresh and re-enumerate before any destructive step.
- **SMART / health.** Not implemented (*planned*).

## 5. Error model

Every call returns a value or an `Error` with a category (`NotFound`,
`Permission`, `Unsupported`, `InvalidArgument`, `OutOfRange`,
`InvalidFormat`, `Integrity`, `Io`, `Busy`, `Internal`) and a sentence
meant for people ("`/dev/sdb2` is LUKS-encrypted; pass a passphrase",
"stein image format 2.x cannot be read by this version"). Messages are
complete sentences without codes; the category decides the UI treatment
(Permission → offer elevation; Unsupported → explain and disable; Busy →
offer unmount; Integrity → red, never silent).

## 6. Suggested screens (derived, not prescriptive)

1. **Disks and images**: a list of `DiskInfo` cards plus "open image file";
   selecting one shows its topology tree.
2. **Topology**: tree + byte-proportional bar; health badges from
   diagnostics; "Repair" when anything is repairable; expert toggle for the
   metadata tree.
3. **Viewer**: two-pane file browser over any readable content node, with
   drag-out (copyTree), preview, hash, "mount instead" and "copy all".
4. **Image**: create/restore wizard with the options of 3.3, live progress,
   final report; info and verify for an existing image; key management.
5. **Profiles**: cards for dr_stein-style one-button backup/restore.
6. **Tools**: surface scan, fake-flash test (behind a destructive-action
   confirmation that repeats the device identity), partition table editor
   with preview and apply.

Everything in these screens maps to a call that exists today except where
marked *planned*.
