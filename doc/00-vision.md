# libstein — Vision and Requirements

*Status: living document. Captured from the project owner's brief on 2026-10-05.
Everything in later design documents must trace back to a line here.*

## 1. What we are building

A **chain of pure C++ libraries** (CMake, no Qt, no GTK/glib) for managing
block devices, partition tables, filesystems, encrypted containers, volume
managers and disk images — portable across **Linux, macOS and Windows** — on top
of which several very different front-ends can be built:

1. Platform-native "power-user" GUIs (one per OS) that are better than
   Disk Utility (macOS), GNOME Disks (Linux) and `diskmgmt.msc` (Windows).
2. "One-button" user-oriented apps in the spirit of
   [dr_stein](https://github.com/streamx3/dr_stein): pre-configured,
   metadata-driven, e.g. "restore this machine's Windows partition" with a
   single click.
3. Command-line tools and scripting bindings (a natural by-product of a clean
   library API; also what the test-suite drives).

## 2. Why the existing tools are not enough

| Tool | Good | Bad |
|---|---|---|
| Apple Disk Utility | Polished, old, reliable | Apple keeps *removing* features; closed; macOS-only |
| GNOME Disks | Best of the three, has imaging, SMART, benchmarks, loop mounting | Linux-only; tied to GTK/glib and UDisks2/D-Bus; now adding Rust to the mix; maintainers reject "comfort" features (split images, compressed images, mounting filesystems inside images) even when proposed |
| KDE Partition Manager / kpmcore | Real C++ class hierarchy; appears to handle a damaged GPT better than GNOME Disks | Qt/KDE-Frameworks-bound; Linux-only; everything shells out to external binaries. **Survey finding:** kpmcore has no GPT header code at all; the "restore primary from backup" behaviour the owner observed is libfdisk's implicit fallback under `sfdisk` (see `research/02-kpmcore-partitionmanager.md` §5). Nobody in this list does it explicitly except `gdisk`/`sgdisk` |
| GParted | Old, battle-tested, libparted-based | Shells out to external binaries for almost everything; GTK-bound; Linux-only |
| `diskmgmt.msc` | Ships with Windows | Practically unusable for anything beyond trivial |

The common failure: **none of them are portable, and none of them own the
on-disk logic.** They are all thin UIs over an OS-specific stack
(UDisks2/libblockdev, libparted, or dozens of `mkfs.*`/`fsck.*` binaries).

## 3. Hard requirements (v1 design scope)

- **R1. Pure C++** (C++20), standard library only in the core. No Qt, no glib,
  no GTK, no Boost in public headers.
- **R2. Cross-platform core.** Linux, macOS, Windows. Platform specifics are
  isolated in one "platform" library behind abstract interfaces.
- **R3. Modular, inheritance-based design.** Every "kind of thing" has an
  abstract base: `PartitionTable` → `GptPartitionTable`, `MbrPartitionTable`,
  `ApmPartitionTable`, …; `FileSystem` → `Ext4FileSystem`, `NtfsFileSystem`, …;
  likewise for block devices, encrypted containers, volume managers, image
  formats, operations and jobs.
- **R4. Breadth of formats, at least in design, from day one:**
  - Partition tables: everything the Linux tools support (MBR/DOS incl. EBR
    logical partitions, GPT, BSD disklabel, Sun, SGI/DVH, Amiga RDB, PC98,
    AIX, Mac/APM, "loop"/unpartitioned) **plus Apple Partition Map** explicitly.
  - Filesystems: everything GParted/kpmcore list (ext2/3/4, btrfs, xfs, f2fs,
    jfs, reiserfs, reiser4, nilfs2, bcachefs, FAT12/16/32, exFAT, NTFS, ReFS
    (detect), HFS, HFS+, APFS (detect at least), UDF, ISO9660, minix, swap,
    LVM2 PV, LUKS, bitlocker (detect), zfs (detect), …).
  - Containers / volume managers: **LUKS1/LUKS2** and **LVM2** are first-class
    targets; **VeraCrypt** compatibility is a stated long-term goal; mdraid,
    BitLocker, FileVault/CoreStorage, APFS containers, Windows dynamic disks
    (LDM) are to be at least recognisable.
- **R5. Disk imaging that GNOME Disks refuses to do:** create/restore raw
  images, **split images into pieces**, **compress** them, checksum them,
  describe them with metadata, and **mount filesystems from inside image
  files** on any OS.
- **R6. GPT robustness:** read and repair from the backup header, verify CRCs,
  relocate backup header after disk resize, detect hybrid/protective MBR
  mismatches — explicitly, with diagnostics, the way `gdisk`'s recovery menu
  does; none of the three GUI tools surveyed does this themselves.
- **R7. Userspace filesystem access.** Long-term: *read and write* foreign
  filesystems in-process (e.g. open an ext4-inside-LUKS partition on Windows
  or macOS and write to it). Design the `FileSystem` interface so that a
  full userspace driver fits in it from the first attempt; detection-only and
  read-only implementations are just lower capability levels of the same
  interface.
- **R8. No reliance on external binaries in the core.** Shelling out to
  `mkfs.xxx`/`fsck.xxx` is allowed only as an *optional, clearly separated
  backend* (so that early versions can be useful on Linux), never as the
  architecture. GPL tools may be used by the **test-suite as oracles**.
- **R9. Licensing.** The project is MIT. We may link LGPL libraries
  dynamically, absorb BSD/MIT/Apache/ISC code with attribution, and only
  *read* GPL code for ideas. See `research/05-library-ecosystem.md`.
- **R10. Operations are planned, previewed and then applied** (the
  kpmcore/GParted "pending operations" model), with progress reporting,
  structured reports and — where physically possible — undo.
- **R11. Privilege separation.** Raw device access needs root/Administrator on
  every OS; the design must support an unprivileged UI driving a privileged
  helper, without the UI library knowing which.
- **R12. User-oriented apps must stay trivial.** A dr_stein-style app is a
  configuration file (device selector, image location, checksum, policy) plus
  three buttons; the library must make that a ~200-line program.

## 4. Non-goals (for now)

- Replacing the OS kernel drivers for *booting* or for everyday mounting on
  the native OS. Native mounting goes through the OS; our userspace drivers
  are for *foreign* filesystems and *images*.
- A plugin ABI stable across versions. Plugins are compile-time modules first.
- Reimplementing RAID resync, btrfs balance, zfs scrub, etc. Those are
  "recognise, mount via OS, hand off" at most.

## 5. Open questions (to be resolved in design docs)

- OQ1. Single library vs. a chain: decided in `design/10-architecture.md`
  (chain; see the dependency DAG there).
- OQ2. "Interfaces" in C++: abstract base classes with virtual inheritance vs.
  capability objects vs. concepts — argued in `design/11-cpp-interfaces.md`.
- OQ3. Which third-party libraries to *link* in v1 (if any) vs. write ourselves
  — `research/05-library-ecosystem.md`.
- OQ4. Image container format: adopt an existing one (EWF/E01, qcow2, VHDX)
  or define our own (`design/14-imaging.md`).
- OQ5. The mounting story per OS (FUSE / WinFsp / local NFS-SMB bridge) —
  `design/15-userspace-fs.md`.
