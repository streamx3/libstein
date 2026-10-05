# Reference survey: GParted

Surveyed: `gparted 1.8.1-git` (NEWS top entry 2026-03-17). `src/*.cc +
include/*.h` = 33,568 lines; `src/GParted_Core.cc` alone is 4,730 lines.
Paths are relative to the gparted checkout.

## 1. License

- `COPYING` is GPLv2; `README` states **GPLv2+** for all files unless noted.
  Every header carries the GPLv2+ boilerplate (`src/GParted_Core.cc:1-16`,
  `src/CopyBlocks.cc:1-6`, `include/BlockSpecial.h:1-5`).
- `COPYING-DOCS` = GFDL 1.2 (manual). `lib/gtest/` = vendored GoogleTest
  1.16.0, BSD-3-Clause.
- **Consequence:** nothing can be copied into libstein. libparted itself is
  GPLv3+ (parted ≥ 3.0), a further constraint if we ever linked it.

## 2. Build system and dependencies

Autotools (autoconf 2.50+, automake, libtool, gettext), **C++14**. Single
binary `gpartedbin`; `gparted.in` is a shell wrapper handling privilege
escalation (pkexec/gksudo/kdesudo/xdg-su/run0).

| Dependency | Use |
|---|---|
| libuuid | `Utils::generate_uuid()` only |
| **libparted ≥ 3.2** + **libparted-fs-resize** | all partition-table work; FAT/HFS resize |
| gthread-2.0, **glibmm-2.4 ≥ 2.32**, **gtkmm-3.0 ≥ 3.18** | everything |
| polkit | runtime policy |

Options: `--enable-libparted-dmraid`, `--enable-xhost-root`.

**GTK vs pure logic split: there is none.** `tests/Makefile.am:27-72`
defines a de-facto "core" object set (BlockSpecial, CopyBlocks, DMRaid,
Device, FS_Info, FileSystem, GParted_Core, LUKS_Info, LVM2_Info, Mount_Info,
Operation*, Partition*, PasswordRAMStore, PipeCapture, Proc_Partitions_Info,
ProgressBar, SupportedFileSystems, SWRaid_Info, Utils, VGDevice + 19 fs
classes), but even that is contaminated:
- `include/Utils.h` includes `<gtkmm/label.h>`, `<gdkmm/pixbuf.h>`.
- `include/Operation.h` carries a `Gdk::Pixbuf` icon.
- `OperationDetail.cc`, `CopyBlocks.cc`, `Utils.cc`, `GParted_Core.cc` drive
  sub-threads by **nested `Gtk::Main::run()`/`quit()`** and `g_idle_add` —
  the glib main loop is the synchronisation primitive for process spawning
  and block copying.
- `Glib::ustring`, `Glib::spawn_async_with_pipes`, `sigc::signal`,
  gettext'd strings in result trees everywhere.

Genuinely GUI-free (still glibmm-typed): `BlockSpecial`,
`Proc_Partitions_Info`, `Mount_Info`, `LUKS_Info`, `SWRaid_Info`,
`LVM2_Info`, `BCache_Info`, `PasswordRAMStore`, `Partition`,
`PartitionVector`, `PartitionLUKS`, `Device`, `VGDevice`, `ProgressBar`,
`SupportedFileSystems`.

## 3. Directory layout

```
include/   66 headers, one per class
src/       66 .cc + main.cc; GUI (Win_GParted, Dialog_*, DrawingAreaVisualDisk, TreeView_Detail…) mixed with core
lib/gtest/ vendored GoogleTest
tests/     8 gtest programs; test_SupportedFileSystems (665 lines) is parameterised per FSType,
           creates sparse image files / loop devices and runs the REAL mkfs/fsck tools
data/ help/ po/ m4/
```

## 4. Class design

### 4.1 Data model
- `include/Partition.h` — header comment: "Partition isn't really a
  partition. It's more like a geometry, a continuous part of the disk."
  Mostly public fields: `device_path, partition_number, type
  (PRIMARY/LOGICAL/EXTENDED/UNALLOCATED/UNPARTITIONED), status
  (REAL/NEW/COPY), alignment (CYLINDER/MEBIBYTE/STRICT), fstype, uuid, name,
  sector_start, sector_end, sectors_used/unused/unallocated,
  inside_extended, busy, fs_readonly, logicals, sector_size, fs_block_size`;
  private `path, m_flags, mountpoints, filesystem_label, messages`.
- `include/PartitionVector.h` — owning `std::vector<Partition*>` wrapper
  allowing polymorphic `PartitionLUKS` elements.
- `include/PartitionLUKS.h` — `PartitionLUKS : Partition` holding an inner
  `Partition m_encrypted` plus `m_header_size`; aggregates usage.
- `include/Device.h` — `partitions, length, heads/sectors/cylinders, model,
  serial_number, disktype, sector_size, max_prims, readonly`.
- `include/VGDevice.h` — `VGDevice : Device` (LVM VG shown as a disk, LVs as
  partitions, read-only), built by `LVM2_Info::make_vgdevice()`.
- `include/Utils.h` — `enum FSType` (45 values; 22 "fully supported" +
  "other recognised": APFS, ATARAID, BCACHE, BITLOCKER, GRUB2_CORE_IMG,
  ISO9660, JBD, LINUX_SWRAID, LINUX_SWSUSPEND, LVM2_THINPOOL, REFS, UFS, ZFS).

### 4.2 GParted_Core
God-object façade (`src/GParted_Core.cc`): `set_devices()` (probe thread),
`apply_operation_to_disk(Operation*)` (`:392-516`, a `switch(m_type)` that
first `calibrate_partition()`s to re-sync with libparted reality, then
chains step functions with `&&`), `set_disklabel`, `toggle_flag`,
`get_disklabeltypes()`, static `get_filesystem_object(FSType)`.
`SupportedFileSystems` holds one `FileSystem` instance per type —
`ext2(FS_EXT2)`, `ext2(FS_EXT3)`, `ext2(FS_EXT4)`, `fat16(FS_FAT16)`,
`fat16(FS_FAT32)` (same class, parameterised).

### 4.3 Operation hierarchy
```
Operation (abstract): m_type, m_device (clone w/o partitions), m_partition_original/new,
                      m_description, m_icon, OperationDetail m_operation_detail
                      apply_to_visual(PartitionVector&)=0, create_description()=0, merge_operations()=0
   ├── OperationCreate         (merges later Format/Resize on STAT_NEW)
   ├── OperationDelete         (never merged)
   ├── OperationResizeMove     (merges chains on same partition)  ← one op; GParted_Core::resize_move()
   │                           decomposes recursively into shrink→move or move→grow with a temp ALIGN_STRICT partition
   ├── OperationFormat
   ├── OperationCopy           (+ m_partition_copied; never merges)
   ├── OperationCheck          (idempotent merge)
   ├── OperationLabelFileSystem / OperationNamePartition / OperationChangeUUID (field-level merge)
```
Pending model: `Win_GParted` keeps `OperationVector`; `merge_operation()`
walks backwards to the last op touching the same path. Visual preview =
re-run `apply_to_visual()` over a cloned `PartitionVector`.

### 4.4 FileSystem hierarchy (`include/FileSystem.h`)
```
FileSystem (abstract)
  virtual FS get_filesystem_support()=0; FS_Limits get_filesystem_limits(const Partition&)
  is_busy, set_used_sectors, read_label/read_uuid, write_label/write_uuid,
  create, resize(new, OD&, fill), move, copy, check_repair, remove, get_custom_text
  protected: mk_temp_dir/rm_temp_dir, FS_Limits m_fs_limits
   └── bcachefs btrfs exfat ext2(2|3|4) f2fs fat16(16|32) hfs hfsplus jfs linux_swap luks
       lvm2_pv minix nilfs2 ntfs reiser4 reiserfs udf xfs   (19 classes, 22 types)
```
Defaults return false/no-op; derived classes override only what the tool
set supports. Progress callbacks parse tool stdout/stderr.

## 5. The `FS` capability model (`include/FileSystem.h:45-85`) — key design to compare

```cpp
struct FS_Limits { Byte_Value min_size = 0, max_size = 0; };   // 0 => no limit
struct FS {
    enum Support { NONE = 0, GPARTED = 1, LIBPARTED = 2, EXTERNAL = 3 };
    FSType fstype;
    Support busy, read, read_label, write_label, read_uuid, write_uuid,
            create, create_with_label, grow, shrink, move, check, copy, remove,
            online_read, online_grow, online_shrink, online_write_label;
};
```
The value is both a **boolean capability and a dispatch selector**:
`GParted_Core` switches on it (`is_busy()` `:1782`, `set_used_sectors()`
`:1838`, `resize_filesystem_implement()` `:3179`, `move_filesystem()`
`:2522`, `copy_filesystem()`): `GPARTED` = internal (block copy, statvfs,
mount table), `LIBPARTED` = `ped_file_system_*`, `EXTERNAL` = the fs class's
tool wrapper. Capability probing happens **once at startup** via
`find_program_in_path`, sometimes running `tool --help`/`--version` and
regex-matching (`btrfstune -u`, `e2image -o`, `tune.exfat` serial support,
`xfs_io label`, `fatlabel ≤ 4.1` bug, `mkfs.exfat -V` must be exfatprogs),
plus `/proc/filesystems`+`modprobe` and kernel-version checks for online
resize. Dependency rules are procedural (shrink needs read; move/copy need
check; btrfs/jfs/xfs/nilfs2 grow needs mount+kernel driver).
`FS_Limits`: btrfs min 256 MiB, ext2/3 max ~16 TiB, FAT16 16 MiB–4 GiB,
FAT32 33 MiB–2 TiB, HFS max 2 GiB, NTFS min 2 MiB, XFS min 300 MiB, …

## 6. Where the work happens — CONFIRMED: shell-out for essentially everything

Only FAT16/32 and HFS/HFS+ resize (and HFS usage) go through libparted.
Everything else is `OperationDetail::execute_command()`
(`src/OperationDetail.cc:338-432`) / `Utils::execute_command()`:
`Glib::spawn_async_with_pipes` + `PipeCapture`, child in its own process
group so cancel = `kill(-pid, SIGINT)`.

| FS | usage | label r/w | uuid r/w | create | grow / shrink | check | copy/move |
|---|---|---|---|---|---|---|---|
| bcachefs | `bcachefs fs usage` (online) | `bcachefs show-super` / mount-based | show-super / – | `bcachefs format -L` | `bcachefs device resize` / – | `bcachefs fsck` | GPARTED |
| btrfs | `btrfs inspect-internal dump-super`, `filesystem show` | `btrfs filesystem label` | dump-super / `btrfstune -u` | `mkfs.btrfs -L` | mount + `btrfs filesystem resize` + umount | `btrfs check` | GPARTED |
| exfat | `dump.exfat` | `tune.exfat -l/-L` | `tune.exfat -i/-I` | `mkfs.exfat -L` | – | `fsck.exfat -y` | GPARTED |
| ext2/3/4 | `dumpe2fs -h`, `resize2fs -P` | `e2label` | `tune2fs -l` / `-U random` | `mkfs.ext{2,3,4} -F -L` | `resize2fs -p [-b]` | `e2fsck -f -y -v -C 0` | `e2image -ra -p` else GPARTED |
| f2fs | `dump.f2fs` | blkid | blkid | `mkfs.f2fs -l` | `resize.f2fs` / – | `fsck.f2fs -f -a` + mount cycle | GPARTED |
| fat16/32 | `minfo` | `fatlabel` / `mlabel` | `mdir` / `mlabel -s -n` | `mkfs.fat -F16/32` | **LIBPARTED** | `fsck.fat -a -w` | GPARTED |
| hfs / hfsplus | **LIBPARTED** | blkid / – | – | `hformat` / `mkfs.hfsplus` | – / **LIBPARTED** | `hfsck` / `fsck.hfsplus` | GPARTED |
| jfs | `jfs_debugfs` | `jfs_tune -l/-L` | `jfs_tune -U` | `mkfs.jfs -q -L` | mount `-o remount,resize` / – | `jfs_fsck -f` | GPARTED |
| linux_swap | fixed | `swaplabel` | `swaplabel -U` | `mkswap` | recreate | – | no-op |
| luks | dm table | – | blkid | – | `cryptsetup resize` (passphrase on stdin) | – | GPARTED (while open) |
| lvm2_pv | `lvm pvs` | – | – | `lvm pvcreate -M 2` | `lvm pvresize` | `lvm pvck` | – |
| minix | – | – | – | `mkfs.minix -3` | – | `fsck.minix` | GPARTED |
| nilfs2 | `nilfs-tune -l` | `nilfs-tune -L` | `-U` | `mkfs.nilfs2 -L` | mount + `nilfs-resize` | – | GPARTED |
| ntfs | `ntfsinfo --mft` | `ntfslabel` | `ntfslabel --new-serial` | `mkntfs -Q -F -L` | `ntfsresize --force` (run twice: `--no-action` then real) | `ntfsresize -i -f` | `ntfsclone` / GPARTED |
| reiser4 | `debugfs.reiser4` | same / – | same / – | `mkfs.reiser4` | – | `fsck.reiser4` | GPARTED |
| reiserfs | `debugreiserfs` | `reiserfstune --label` | `-u random` | `mkreiserfs` | `echo y | resize_reiserfs` (exit 0 **or 1** ok) | `reiserfsck` | GPARTED |
| udf | `udfinfo` | `udflabel` | `udflabel --uuid=random` | `mkudffs --media-type=hd --udfrev=0x201` | – | – | GPARTED |
| xfs | `xfs_db -r -c 'sb 0'` | `xfs_db label` / `xfs_admin -L`, online `xfs_io label` | `xfs_admin -U` | `mkfs.xfs -f -L` | mount + `xfs_growfs` / – | `xfs_repair` | `mkfs.xfs -m uuid=` + `xfsdump | xfsrestore` |

GUI-layer shell-outs: `mount`, `umount`, `swapon/off`, `lvm vgchange`,
`cryptsetup luksOpen/luksClose`.

**Through libparted** (49 distinct `ped_*` symbols): device enumeration and
geometry; table read (`ped_disk_new`, `ped_disk_next_partition`, flags
enumeration); table write (`ped_disk_new_fresh`, `ped_partition_new` +
`ped_disk_add_partition` with constraints, `ped_disk_set_partition_geom`,
`ped_partition_set_system(fs_type)` to set the type id — **UDF/exFAT mapped
to the "ntfs" id, default "ext2"=0x83; arbitrary GUIDs cannot be set**),
`commit_to_dev` + `commit_to_os` + `udevadm settle`; fs resize for FAT/HFS
(`libparted-fs-resize`); raw I/O (`ped_device_read/write`,
`ped_geometry_write`); a custom exception handler marshalled to the GTK
thread.

## 7. Partition table types

`get_disklabeltypes()` (`:619-627`) iterates `ped_disk_type_get_next()` —
whatever the linked libparted registers: `aix, amiga, bsd, dvh, gpt, loop,
mac, msdos, pc98, sun` (+ `atari` since parted 3.3). Default `msdos` below
2 TiB else `gpt`. Partition naming only for GPT (36 UTF-16 code points);
naming on amiga/dvh/mac/pc98 deliberately disabled due to libparted bugs.
Flags are libparted's enum, not raw attribute bits.

## 8. In-process logic worth noting

- **Signature table** `detect_filesystem_internal()` (`:1314-1410`): LUKS
  (`"LUKS\xBA\xBE"`@0), BitLocker (`"-FVE-FS-"`@3), GRUB2 core.img, APFS
  (`"NXSB"`@32), LVM2 PV (`"LABELONE"`@512 + `"LVM2"`@536), NILFS2
  (`"\x34\x34"`@1030), Reiser4 (`"ReIsEr4"`@65536), Btrfs (`"_BHRfS_M"`@65600).
  Used as 4th-priority fallback after mdadm/dmraid caches, blkid, libparted.
- **Signature erase** `erase_filesystem_signatures()` (`:4105-4366`): zeroes
  0..512 KiB, btrfs mirror superblocks at 64 MiB / 256 GiB / 1 PiB, Promise
  FastTrack at −3087 sectors, bcachefs backup SB at −1 MiB (bucket-rounded),
  and −512 KiB..end (covers md 0.90/1.0, nilfs2 secondary SB, ZFS L2/L3).
  Unit-tested.
- **NTFS boot-sector fix-up** `update_bootsector()` (`:4368`): after a move,
  rewrite the 32-bit "hidden sectors" at offset 0x1C.
- `FS_Info` (blkid once for all paths, lazy labels), `Proc_Partitions_Info`
  (`/proc/partitions` + whole-disk name heuristics), `BlockSpecial`
  (identity by major:minor, so `/dev/sda1` == `/dev/disk/by-id/…`),
  `Mount_Info` (`getmntent`, `/proc/swaps`), `LUKS_Info` (`dmsetup table`),
  `SWRaid_Info` (`mdadm --examine --scan`, `/proc/mdstat`), `LVM2_Info`
  (`lvm pvs/vgs/lvs` CSV), `DMRaid`, `BCache_Info` (sysfs).
- `PasswordRAMStore`: 4 KiB `mmap`+`mlock`ed page of passphrases keyed by
  LUKS UUID, wiped on erase, piped to `cryptsetup` on stdin, never argv.
- `PipeCapture`: `\r`-aware line discipline so tool progress bars are
  captured incrementally.

## 9. Copy/move engine — `src/CopyBlocks.cc`, `GParted_Core::copy_blocks()` (`:3430-3546`)

1. **Benchmark phase**: copies successive 16 MiB chunks with block sizes 1,
   2, 4, 8, 16 MiB, timing each; picks the fastest. Benchmarked chunks count
   as real progress.
2. **Bulk phase** with the optimal block size.
3. **Direction**: if `dst_start > src_start` (overlapping right-move) the
   copy runs **backwards** (negated `blocksize`/`done`, offsets start at the
   end, pre-decrement). A leading partial block is copied first.
4. **Sector-size heterogeneity**: separate `num_blocks_src/dst`; reads via
   `ped_device_read`, writes via `ped_device_write`; single buffer.
5. Progress every 0.5 s via `g_idle_add`; completion posts `Gtk::Main::quit()`.
6. Cancel honoured only when `cancel_safe` or forced; checked per block.
7. **Rollback for moves** (`move()` `:2435`): first *widen* the table entry
   to old ∪ new, then `move_filesystem()`; on failure
   `rollback_move_filesystem()` (`:3548`) copies back the `total_done` bytes
   in reverse and restores the entry; then narrow and `update_bootsector()`.
   Every move/resize is bracketed by `check_repair_filesystem()` before and
   `maximize_filesystem()` after.
8. Target resolution: partitions are copied through the whole-disk node at
   `sector_start` (buffer-cache coherency matters).

Limitations: no sparse/zero detection, no used-block awareness (except via
`e2image`/`ntfsclone`/`xfsdump`), no checksum, no resume, no O_DIRECT,
16 MiB block cap.

## 10. Progress / OperationDetail

`OperationDetail` is a **tree node** (`m_sub_details`), with Pango-markup
description, status `{NONE, EXECUTE, SUCCESS, ERROR, INFO, WARNING}`, timing
on status transitions, a tree path ("0:3:1"), and a `no_more_children`
guard. Three signals: `signal_update` (child→parent, live tree view),
`signal_capture_errors` (attach libparted exception text), `signal_cancel`
(tree-wide broadcast; cancel-safe vs force). `execute_command()` adds a
bold-italic child with the command line and two monospace children bound to
stdout/stderr, with `EXEC_PROGRESS_STDOUT/STDERR/TIMED` flags for progress
parsing. `ProgressBar` is a **single global**; ETA after 5 s, linear rate.
Unit test: `tests/test_OperationDetail.cc` (508 lines).

## 11. Gaps relative to libstein goals

1. **Everything is shell-out**; behaviour depends on tool versions (many
   version-sniffing hacks). No in-process superblock parsing beyond the
   8-signature table and the NTFS hidden-sectors poke.
2. **libparted hard dependency** (GPLv3+, Linux/BSD-centric, GPT backup
   header limits, cannot set arbitrary type GUIDs, naming bugs).
3. **Linux-only** by construction (`/proc/*`, `/sys/block`, `getmntent`,
   `udevadm settle`, device-mapper, `modprobe`).
4. **GTK/glib-bound core**: nested main loop as blocking primitive; global
   singletons; gettext in result trees; not a library.
5. **No imaging**, no compression, no checksums, no resume, no table
   backup/restore.
6. **Encryption**: LUKS only via `cryptsetup`; BitLocker is signature-only.
7. No undo/transaction log (rollback only for the move step).
8. No storage-backend abstraction: `open()/read()` here, `ped_device_read`
   there, `std::ofstream` elsewhere.

## 12. Assessment: ideas worth re-implementing (never copying)

**Keep / adapt**
1. **Capability struct with a "how" enum per operation** (`FS::Support`).
   Generalise: per-fs × per-operation → `{Unsupported, Native,
   ExternalTool, Online}` plus a provider object, with declarative
   dependency rules, queryable at run time so a feature matrix falls out.
   Keep `FS_Limits` and the `online_*` variants.
2. The **minimal `FileSystem` virtual surface** and the pattern where one
   class serves sibling types via a constructor parameter.
3. **Operations as mergeable, previewable commands** with `calibrate`
   before each apply step; the `resize_move()` decomposition and the
   widen→copy→rollback→narrow move algorithm are the reference algorithms.
4. **`OperationDetail` result tree** (status, timing, tree path, live
   update, cancel-safe vs force). Redo with an observer and a thread-safe
   sink instead of GTK main-loop re-entry.
5. **`BlockSpecial`-style identity** (device number, not path).
6. **Detection priority chain** and the signature + signature-erase range
   tables — reuse the *data* (offsets/magics), which is format fact, not code.
7. **CopyBlocks ideas**: adaptive block size, reverse copy, separate sector
   sizes, partial-block-first, rollback bookkeeping. Build on an abstract
   `BlockDevice`, add bitmaps, sparse detection, checksums, resume.
8. **`PartitionLUKS` composition** generalises to "partition + optional
   inner content" for any container (LUKS, BitLocker, LVM PV, md member).
9. **`VGDevice : Device`** shows that "a device is anything with a linear
   address space and children".
10. **PasswordRAMStore** — replicate as `SecureBuffer`.
11. **PipeCapture**'s line discipline and the `tool --help` sniffing — only
    for the optional external-tool backend.
12. The parameterised integration-test shape of `test_SupportedFileSystems`.

**Do not inherit:** libparted as the partition engine; nested main-loop
blocking; global singleton caches; glib strings/gettext in library data;
tool-version regex sniffing as the primary mechanism; the `Utils` grab-bag.
