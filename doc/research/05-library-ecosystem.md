# libstein — Survey of the Existing Library Ecosystem and License Compatibility

Scope: libraries and codebases that a pure-C++ (no Qt/glib), MIT-licensed, cross-platform
(Linux/macOS/Windows) disk/partition/filesystem/image library could (a) link against,
(b) borrow code from, or (c) use only as a reference. The central question is license
compatibility with an MIT project.

Verification budget: 25 WebFetch calls were spent. Claims marked `[verified: URL]` were
checked against that URL during this survey; `[unverified]` means from memory / training
data and should be re-checked before relying on it. One host (elm-chan.org, FatFs home)
is blocked by the egress proxy; FatFs was verified through a GitHub mirror instead.

Conventions used in verdicts:

| Verdict | Meaning |
|---|---|
| **link** | OK to link (dynamically at least) from an MIT binary without changing libstein's license. |
| **borrow** | License allows copying code into libstein (with attribution/notice retained). |
| **reference** | Read the code to learn the on-disk format / algorithms; do not copy; never link. Use at most in the test suite as an oracle. |
| **avoid** | Not useful, dead, or legally awkward even as a reference. |

Working license rules assumed throughout (confirm with counsel for anything shipped):

- MIT/BSD-1/2/3/ISC/0BSD/zlib/CC0/public domain/Boost: may copy into libstein, keeping notices.
- Apache-2.0: may copy/link; must keep NOTICE and license text; patent clause is an asset. (Apache-2.0 code combined into an MIT project is fine; the result is effectively "MIT + Apache-2 portions".)
- LGPL-2.1 / LGPL-3: may link **dynamically**; static linking is permitted only if you ship object files / relinkable form so the user can replace the LGPL part (LGPL §4(d)/§6). Copying LGPL code into libstein would make that file LGPL — i.e. **do not copy**.
- GPL-2 / GPL-3: cannot be linked or copied without the combined work becoming GPL. Reference only; shelling out to a GPL *executable* as a separate process is fine (both for tests and, if desired, for optional runtime features).
- CPL-1.0 / IPL-1.0 (Sleuth Kit): weak copyleft per-file, patent-retaliation clause, **incompatible with GPL** but not with MIT; linking is OK, copying brings the file under CPL. Treat like LGPL for practical purposes.
- APSL-2.0 (Apple): file-level copyleft; FSF considers it free but GPL-incompatible. Modified APSL files must be published under APSL. Treat as "reference / link only".
- TrueCrypt License 3.0: not OSI-approved, Debian/FSF consider it non-free. Reference only.
- WinFsp's GPLv3+FLOSS exception: special case, see §E.

---

## A. Partition tables

### A.1 libparted (GNU parted)
- What: the parted engine: label types msdos, gpt, mac (APM), bsd, sun, dvh (SGI), pc98, loop, aix, amiga; also contains filesystem *probing* and (legacy) resizers. C.
- License: GPL-3.0-or-later. [unverified] (parted switched to GPL-3 in 2007; README/COPYING in git.savannah.gnu.org/parted.)
- Platforms: Linux, with historical ports (GNU/Hurd, BeOS); not usable on Windows/macOS in practice.
- In-process: yes (library), but ties into Linux `BLKRRPART`/device-mapper.
- Verdict: **reference only**. Its `libparted/labels/*.c` are the most complete single collection of label parsers (including Sun, SGI/dvh, pc98, aix, amiga) and are good for understanding edge cases, but the code cannot be copied. `parted -s -m print` is a good **test oracle** (machine-parseable output).

### A.2 libfdisk (util-linux)
- What: library behind fdisk/sfdisk/cfdisk; labels: dos (MBR+EBR), gpt, sun, sgi, bsd. Has "script" format (sfdisk dumps) which is an excellent interchange/test format. C.
- License: LGPL-2.1-or-later. [verified: https://github.com/util-linux/util-linux/blob/master/libfdisk/COPYING] — "either version 2.1 of the License, or (at your option) any later version".
- Note the top-level util-linux README.licensing lists a mix (GPL-2+, LGPL-2.1+, BSD, MIT, Public Domain) and says the default for unmarked code is GPL-2.0-or-later [verified: https://github.com/util-linux/util-linux/blob/master/README.licensing] — so individual files must be checked before any borrowing. The *library* directories (libfdisk, libblkid, libmount, libuuid, libsmartcols) each carry their own LGPL/BSD COPYING.
- Platforms: Linux (uses `/sys`, `BLKRRPART`, `ioctl`), not portable.
- In-process: yes.
- Verdict: **reference**; **link** optional on Linux only, which contradicts the "same code on all platforms" goal, so practically reference. Use `sfdisk --dump` / `sfdisk --json` as **test oracle** and the sfdisk script format as a test-fixture format.

### A.3 libblkid (util-linux)
- What: superblock/partition-table probing (recognises ~70 filesystems, RAID metadata, LUKS, LVM PV headers, and partition tables incl. mac, atari, minix, solaris x86, ultrix, unixware); reports UUID/LABEL/TYPE/VERSION. C.
- License: LGPL-2.1-or-later. [unverified] (libblkid/COPYING; consistent with the README.licensing mix above.)
- Platforms: Linux-centric but the *probing* code (`libblkid/src/superblocks/*.c`, `libblkid/src/partitions/*.c`) is almost pure byte-parsing. Not copyable (LGPL).
- Verdict: **reference** (best catalogue of magic numbers/offsets for *every* superblock format; each `superblocks/xxx.c` is a 100-line spec of what to read); **test oracle** via `blkid -p -o export`. Do **not** copy tables verbatim; re-derive from the format specs (the facts — magic bytes and offsets — are not copyrightable, but the file structure/comments are).

### A.4 gptfdisk (gdisk/sgdisk/cgdisk)
- What: C++ GPT editor; classes `GPTData`, `GPTPart`, `MBRData`, `BasicMBRData`, `DiskIO` (with per-OS backends `diskio-unix.cc`, `diskio-windows.cc`). Supports: load GPT from backup (`sgdisk -r`, gdisk recovery menu `b`/`c`/`d`/`e`), convert MBR→GPT, hybrid MBR, GPT→MBR, verify, partition type GUID table (`parttypes.cc`), alignment logic. Builds on Linux, macOS, Windows (MinGW), FreeBSD.
- License: GPL-2.0-or-later. [unverified] (COPYING in https://sourceforge.net/projects/gptfdisk/ and the GitHub mirror; headers say "GPL version 2 or (at your option) any later version".)
- In-process: yes (it's a program, but the classes are library-like).
- Verdict: **reference only** — and the single most relevant *architectural* reference, because it is cross-platform C++ with the exact abstraction (per-OS `DiskIO`) libstein needs. Do not copy `parttypes.cc` (the GUID→name table is a curated creative list; derive your own from the UEFI spec / Wikipedia / systemd's Discoverable Partitions Spec, which are open). Use `sgdisk -p`, `sgdisk -v`, `sgdisk -b` (backup) as **test oracle**, and `sgdisk -r`'s recovery behaviour as a behavioural spec for our own "rebuild primary from backup" feature.

### A.5 FreeBSD `sys/geom/part` + `libgeom` + `gpart`
- What: in-kernel GEOM partition classes. Directory listing today: `g_part_apm.c` (Apple Partition Map), `g_part_bsd.c` (disklabel), `g_part_bsd64.c`, `g_part_ebr.c` (extended MBR), `g_part_gpt.c`, `g_part_ldm.c` (Windows LDM dynamic disks!), `g_part_mbr.c`. [verified: https://github.com/freebsd/freebsd-src/tree/main/sys/geom/part] — `g_part_vtoc8.c` (Sun/Solaris VTOC) is no longer in `main` (removed with sparc64 in FreeBSD 13; still in `stable/12` history) [unverified]. Each scheme is a self-contained probe/read/write/add/delete/resize/modify implementation on top of a 512-byte sector reader, ~1000 lines per scheme.
- License: BSD-2-Clause. [verified: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/geom/part/g_part_apm.c] — "SPDX-License-Identifier: BSD-2-Clause, Copyright (c) 2006-2008 Marcel Moolenaar". Other scheme files are expected BSD-2 as well, but **check each file's SPDX line** (g_part_ldm.c is by Andrey Elsukov, BSD-2 [unverified]).
- Platforms: kernel code, uses `malloc(M_GEOM)`, `g_read_data`, `sbuf`, `uuid` helpers; easily portable to userspace C/C++ with a shim (the actual format logic is plain struct marshalling).
- Verdict: **borrow**. This is the best BSD-licensed source for **writing** (not just parsing) APM, BSD disklabel, EBR, GPT, LDM and MBR. Keep the FreeBSD copyright notice in each derived file. `libgeom` (userland, BSD-2) and `sbin/geom/class/part/geom_part.c` show the userland API pattern.

### A.6 NetBSD
- What: `sys/sys/disklabel*.h`, `sys/dev/dkwedge/dkwedge_{apple,bsdlabel,gpt,mbr,rdb}.c` (wedge discovery for APM, BSD label, GPT, MBR, Amiga RDB), `sbin/gpt` (userland GPT editor, originally FreeBSD's `gpt(8)`, BSD-2), `sbin/fdisk`, `sbin/disklabel`. C.
- License: BSD-2/BSD-3 (NetBSD standard). [unverified]
- Verdict: **borrow** (second source for GPT/APM/MBR/RDB and the only BSD source for Amiga RDB). `sbin/gpt/gpt.c` + `gpt_*.c` is a complete userland GPT create/add/remove/resize/recover implementation in portable C — a good complement to FreeBSD's kernel version.

### A.7 Apple diskdev_cmds / IOKit partition schemes
- What: `diskdev_cmds` (fsck_hfs, newfs_hfs, fdisk, pdisk) and the IOKit `IOApplePartitionScheme`, `IOGUIDPartitionScheme`, `IOFDiskPartitionScheme` classes in xnu/IOStorageFamily. C/C++.
- License: APSL-2.0. [unverified]
- Verdict: **reference** (APSL is file-copyleft and GPL-incompatible; copying obliges publishing those files under APSL — legally possible alongside MIT but messy). Mainly useful for the exact APM semantics Apple expects (`Apple_partition_map`, `Apple_Free`, `Apple_Boot`, driver descriptor block) and HFS+ details.

### A.8 Windows: `IOCTL_DISK_GET_DRIVE_LAYOUT_EX`, LDM, libldm
- Windows API: `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` / `IOCTL_DISK_SET_DRIVE_LAYOUT_EX`, `IOCTL_DISK_CREATE_DISK`, `IOCTL_DISK_UPDATE_PROPERTIES` give OS-level MBR/GPT views; no license issue (platform API). They do **not** expose LDM internals; dynamic disks appear as one `PARTITION_LDM_DATA` MBR partition or GPT partitions of type `LDM Metadata`/`LDM Data`. Storage Spaces are entirely opaque (no public on-disk spec).
- **libldm / ldmtool**: library + tool for Windows dynamic disks (LDM), by Matthew Booth; reads the LDM database (VBLK records: Disk, Volume, Component, Partition) and creates device-mapper devices. License: library LGPL-3, tool GPL-3 (README says the project is under GPL-3 and LGPL-3). [verified: https://github.com/mdbooth/libldm — "dual-licensed under GPL-3.0 and LGPL-3.0"]. Depends on **GLib/GObject** and libdevmapper [unverified] — so it violates the no-glib constraint anyway.
- Verdict: libldm **reference**; FreeBSD `g_part_ldm.c` (BSD-2) is the **borrow** source for LDM parsing. `ldmtool show` is a Linux-side **test oracle**. For *writing* LDM there is no open implementation; treat LDM as read-only forever (Microsoft itself deprecated dynamic disks in favour of Storage Spaces).

### A.9 Summary of label coverage by source

| Scheme | BSD-licensed source available | GPL/LGPL reference | Spec |
|---|---|---|---|
| MBR + EBR | FreeBSD g_part_mbr/ebr, NetBSD fdisk | libfdisk dos, gptfdisk MBRData | de-facto; UEFI spec §5.2 |
| GPT | FreeBSD g_part_gpt, NetBSD sbin/gpt | libfdisk gpt, gptfdisk | UEFI spec §5.3 |
| APM | FreeBSD g_part_apm, NetBSD dkwedge_apple | libparted mac.c, libblkid mac.c | Apple Inside Macintosh: Devices; IOApplePartitionScheme.h (APSL) |
| BSD disklabel | FreeBSD g_part_bsd/bsd64, NetBSD disklabel | libfdisk bsd, libparted bsd.c | `<sys/disklabel.h>` |
| Sun VTOC (sun) | FreeBSD stable/12 g_part_vtoc8 (BSD) | libfdisk sun, libparted sun.c | illumos `sys/vtoc.h` (CDDL — reference only) |
| SGI/IRIX (dvh) | none known | libfdisk sgi, libparted dvh.c | Linux `include/uapi/linux/sgi...` (GPL-2 w/ syscall note) |
| LDM (Win dynamic) | FreeBSD g_part_ldm | libldm, ntfs-3g `ldm.c` (Linux kernel `fs/partitions/ldm.c`, GPL) | none public; linux-ntfs project docs |
| Amiga RDB | NetBSD dkwedge_rdb | libparted amiga.c | AmigaOS RDB spec |
| pc98, aix, atari, minix, ultrix, unixware, solaris-x86 | — | libparted / libblkid partitions/ | Legacy; reference only |

---

## B. Filesystems (userspace parsers / drivers)

### B.1 ext2/3/4

**e2fsprogs libext2fs**
- What: the canonical in-process ext2/3/4 library (read/write: inodes, extents, htree dirs, xattrs, journal replay via `libext2fs`+`e2fsck -p`, block allocation, `ext2fs_file_*` API). Used by e2fsck/mke2fs/debugfs/resize2fs and by Android's `e2fsdroid`, `fuse2fs` (full r/w FUSE driver inside e2fsprogs). C.
- License: lib/ext2fs, lib/e2p, lib/et, lib/ss: **LGPL-2.0** (the *lib* dirs say "GNU Library General Public License, version 2"); lib/uuid and lib/blkid (legacy copies): BSD-3; e2fsck/mke2fs/etc. tools: GPL-2. [unverified] (e2fsprogs `NOTICE`/`COPYING` and `lib/ext2fs/COPYING.LIB`.)
- Platforms: Linux, *BSD, macOS (builds natively, Homebrew `e2fsprogs`), Windows via Cygwin/MSYS2 and historically via `ext2fsd`-unrelated MinGW port; Android. Portable I/O manager abstraction (`unix_io`, `test_io`, `undo_io`, `windows_io` existed in older trees [unverified]).
- In-process: yes.
- Verdict: **link (dynamically)** for ext4 r/w in v1 — it is the only mature r/w ext4 implementation with a liberal-enough license. Wrap behind an abstract `IFileSystem` interface so it can be swapped for a native implementation later. Keep `fuse2fs` as the model of how to build an r/w driver on it. Do not copy its code.

**lwext4**
- What: embedded ext2/3/4 r/w library (extents, journal, htree, xattr, 64bit, metadata_csum read). C, platform-agnostic block-device callback interface — exactly the shape libstein wants.
- License: BSD-3-Clause **except** `ext4_xattr.c` and `ext4_extents.c` which are GPLv2, which "makes whole lwext4 GPLv2 licensed" unless those files are removed. [verified: https://github.com/gkostka/lwext4]
- Verdict: **borrow with surgery** — the BSD-3 files (superblock, block groups, inode, bitmap allocators, dir, htree, journal, mkfs) are reusable; **extents and xattr must be rewritten from the ext4 on-disk spec** (kernel `Documentation/filesystems/ext4/` is GPL-2 text, but the format facts are not copyrightable; use the ext4 wiki). Keep a file-by-file license audit in-tree. Also moderately maintained (forks in Zephyr/RT-Thread), so expect to own the code.

**fuse-ext2, ext4fuse**
- fuse-ext2: FUSE driver on top of libext2fs; GPL-2 [unverified]; macOS/Linux. **reference/avoid** (fuse2fs supersedes it).
- ext4fuse: read-only ext4 FUSE driver, own parser, GPL-2 [unverified]. **reference only**.

### B.2 NTFS
- **ntfs-3g / libntfs-3g**: full r/w NTFS, in-process library (`libntfs-3g`) plus FUSE driver; also handles LDM (`ldm.c`) and has `ntfsprogs` (mkntfs, ntfsfix, ntfsresize, ntfsclone — the latter is the model for used-block imaging). Linux, macOS (via macFUSE), Windows (Tuxera commercial; open MinGW builds exist). License: **GPL-2.0-or-later** (library and tools). [unverified] **Reference only**; `ntfsinfo`, `ntfscat`, `ntfsls` as **test oracle**.
- **libfsntfs (libyal)**: read-only NTFS 3.0/3.1 incl. LZNT1 compression and WOF-compressed data; no encrypted (EFS) support. License LGPL-3.0-or-later; status **experimental**; autotools + Windows PowerShell builds. [verified: https://github.com/libyal/libfsntfs] **link** candidate for read-only NTFS.
- Windows kernel `ntfs.sys` (platform, closed) — on Windows the native fs is available anyway via the OS; libstein needs its own parser only for *images* and *offline* access.
- Reference docs: Richard Russon's "NTFS Documentation" (linux-ntfs project, GPL-2 docs — read for facts), Microsoft's `[MS-FSA]` and Open Specifications (no license needed for implementing).

### B.3 FAT12/16/32 and exFAT
- **FatFs (ChaN)**: embedded FAT12/16/32 + exFAT read/write, LFN, `f_mkfs`, `f_expand`, long-tested on billions of MCUs. C, no dependencies, block-callback I/O (`disk_read/disk_write/disk_ioctl`). Version R0.16, Copyright (C) 2025 ChaN; license is a one-condition BSD-style ("permitted provided ... Redistributions of source code must retain the above copyright notice, this condition and the following disclaimer") — i.e. **BSD-1-Clause**, MIT-compatible. [verified via mirror: https://github.com/abbrev/fatfs/blob/master/source/ff.h; elm-chan.org blocked by proxy]. Caveats: global/static state per volume (max 10 volumes, `FF_VOLUMES`), 8.3 + LFN with code pages, no Unicode normalisation, limited concurrent-access model, no fsck. **borrow / embed** — the obvious v1 FAT/exFAT engine; wrap each volume in its own `FATFS` object, compile with `FF_FS_REENTRANT` and `FF_FS_EXFAT=1`.
- **FreeBSD `sbin/newfs_msdos`, `sbin/fsck_msdosfs`, `sys/fs/msdosfs`**: BSD-licensed mkfs and fsck for FAT (fsck_msdosfs is the only BSD-licensed FAT checker; it is also what macOS's `fsck_msdos` derives from). [unverified] **borrow** for `mkfs.fat`/`fsck.fat`-equivalents.
- **NetBSD makefs msdos**: builds FAT images from a directory tree, userspace, BSD. [verified list: https://github.com/NetBSD/src/tree/trunk/usr.sbin/makefs — cd9660, chfs, ffs, msdos, udf, v7fs; **no exfat**]. **borrow**.
- **dosfstools** (mkfs.fat, fsck.fat, fatlabel): GPL-3 [unverified]. **test oracle only**.
- **mtools**: GPL-3 [unverified]. **test oracle only** (`mdir`, `mcopy` against images).
- **exfatprogs** (Samsung; mkfs.exfat, fsck.exfat, tune.exfat, dump.exfat): GPL-2 [unverified]. **test oracle**.
- **fuse-exfat / libexfat** (relan): GPL-2+ [unverified]. **reference**.
- **libfsfat (libyal)**: read-only FAT12/16/32 + exFAT, LGPL-3, experimental [unverified]. Alternative to FatFs for pure read-only use; FatFs is better.
- Spec: Microsoft published the exFAT specification (2019) under its Open Specification Promise; FAT: Microsoft "FAT32 File System Specification" (free download, patent concerns expired 2013-ish for LFN; exFAT patents are pledged for Linux/OIN only — note this for *write* support on non-Linux, though FatFs ships exFAT regardless). [unverified]

### B.4 XFS, Btrfs, F2FS
- **xfsprogs**: `libxfs` (userspace port of the kernel XFS code) GPL-2; `libhandle` LGPL-2.1 [unverified]. Linux-only build. **reference / test oracle** (`xfs_db`, `xfs_repair -n`, `xfs_io`). libyal **libfsxfs** (LGPL-3, experimental, read-only) [unverified] is the only liberal in-process XFS reader — **link** candidate later.
- **btrfs-progs**: GPL-2 (libbtrfs & libbtrfsutil LGPL-2.1 or LGPL-3? libbtrfsutil is LGPL-3.0+ [unverified]) — libbtrfsutil only *talks to the kernel*, it does not parse on-disk format. **reference / test oracle** (`btrfs inspect-internal dump-super`, `btrfs check`). No liberal btrfs reader exists; a read-only btrfs parser would be new work (format documented on btrfs wiki).
- **f2fs-tools**: tools GPL-2, `lib/libf2fs` LGPL-2.1 [unverified]; Linux/Android. **reference**.

### B.5 HFS+/APFS (Apple)
- **hfsprogs / diskdev_cmds (fsck_hfs, newfs_hfs)**: APSL-2.0 [unverified]. **reference** (and the OS's own tool on macOS). Debian's `hfsprogs` is a Linux port of the same APSL code.
- **hfsutils** (Robert Leslie; HFS classic only): GPL-2 [unverified]. **avoid** (HFS classic irrelevant).
- **libfshfs (libyal)**: read-only HFS/HFS+/HFSX incl. compression (decmpfs), LGPL-3, experimental [unverified]. **link** candidate.
- **apfs-fuse** (sgan81): read-only APFS incl. encryption and snapshots, C++, GPL-2 [unverified]; macOS/Linux. **reference**.
- **linux-apfs-rw** (kernel module) + **apfsprogs** (mkapfs, apfsck): GPL-2 [unverified]. **reference / test oracle** (apfsck is the only independent APFS checker).
- **libfsapfs (libyal)**: read-only APFS incl. encrypted containers (needs password/recovery key), LGPL-3, experimental [unverified]. **link** candidate. APFS write support exists nowhere outside Apple and linux-apfs-rw; treat as read-only.
- Spec: Apple published the "Apple File System Reference" (PDF, freely downloadable; no license to implement). HFS+: Apple TN1150.

### B.6 The Sleuth Kit (libtsk)
- What: in-process **read-only** forensic parsers: filesystems ext2/3/4, NTFS, FAT12/16/32, exFAT, HFS+, APFS (incl. encrypted pools), YAFFS2, ISO9660, UFS1/2, plus volume systems DOS/MBR, GPT, BSD disklabel, Sun VTOC, Mac APM, and image layers (raw, split raw, E01 via libewf, VHD via libvhdi, VMDK via libvmdk, AFF). C/C++ (`tsk/` is C with a C++ wrapper `tsk/auto`). Builds on Linux, macOS, Windows (Visual Studio solutions in-tree).
- License: core `tsk/` under **Common Public License 1.0** (adopted from TCT/TASK); `tsk/fs/lzvn.c` and `samples/*` BSD-3; `tsk/auto/guid.cpp` MIT; `case-uco`, `rejistry++` Apache-2; `tools/srchtools/srch_strings.c` GPL-2 (tool only); fiwalk public domain; Java datamodel Apache-2. [verified: https://github.com/sleuthkit/sleuthkit/blob/develop/licenses/README.md]. Historically some TCT-derived fs files (`ffs`, `ext2fs`) carried **IBM Public License 1.0** headers [unverified] — IPL and CPL are near-identical (CPL is IBM's successor); both are GPL-incompatible but MIT-linkable.
- CPL-1.0 obligations: distributing *modified* CPL source requires making it available under CPL; linking a separate MIT module with libtsk is explicitly permitted ("Contributions do not include additions to the Program which ... are not derivative works"). It also has a patent-retaliation clause.
- Verdict: **link (dynamic preferred)** as the broadest read-only fallback for things libstein doesn't implement natively (UFS, YAFFS2, ISO9660, APFS, HFS+), and **reference** for the volume-system code (`tsk/vs/*.c` is the most compact, portable set of MBR/GPT/BSD/Sun/APM parsers in existence — but CPL, so don't copy). `mmls`, `fsstat`, `fls`, `icat` are superb **test oracles**. Caveat: the Windows build uses MSVC-only project files, and TSK is forensic-oriented (slow for random access, no caching tuned for live use).

### B.7 libyal family (Joachim Metz)
- What: ~60 single-purpose C libraries, each with a stable C API, Python bindings, autotools + MSVC/PowerShell builds, fuzzing harnesses, and detailed reverse-engineered format documentation (`documentation/*.asciidoc` — the docs alone are a major asset, licensed GFDL/CC [unverified]). All read-only except libewf (r/w).
- Licenses: **LGPL-3.0-or-later** for all libraries (tools in each repo are GPL-3). [verified for libfsntfs, libewf, libluksde, libvslvm — see URLs above; others unverified but uniform across the family.]
- Status (per README "Status:" lines): libewf **experimental** [verified], libfsntfs **experimental** [verified], libluksde **experimental** [verified], libvslvm **experimental** [verified]. From memory (unverified): libbde alpha, libfvde alpha, libvmdk alpha, libqcow alpha, libvhdi alpha, libfsext/libfsapfs/libfshfs/libfsfat/libfsxfs experimental, libvsgpt/libvsmbr/libvsapm/libvsbsdl experimental. "Experimental" in Metz's usage means "API may change / incomplete", not "abandoned"; the repos receive regular releases (yyyymmdd versioning). Be aware that most are **single-maintainer**.
- Relevant members:
  - Filesystems: libfsext (ext2/3/4), libfsntfs, libfsfat, libfsapfs, libfshfs, libfsxfs, libfsrefs (ReFS).
  - Volume systems: libvsmbr, libvsgpt, libvsapm, libvsbsdl.
  - Encryption: libbde (BitLocker: AES-CBC/XTS, TPM-less keys: password, recovery password, BEK), libfvde (FileVault 2 CoreStorage), libluksde (**LUKS1 only, read-only**; AES/Blowfish/Serpent; PBKDF2-SHA1/224/256/512; no LUKS2, no argon2, no Twofish) [verified: https://github.com/libyal/libluksde].
  - Volume managers: libvslvm (LVM2 metadata parse → linear mapping; **no multi-PV, no multi-segment, no striping, no snapshots**) [verified: https://github.com/libyal/libvslvm].
  - Images: libewf (read/write EWF-S01/E01/Ex01; read L01/Lx01) [verified], libqcow (QCOW1/2/3 read), libvmdk (read), libvhdi (VHD/VHDX read), libphdi (Parallels), libmodi (Apple DMG/sparseimage/UDIF read), libodraw (CD/DVD raw+cue).
- Platforms: Linux, macOS, Windows (first-class: MSVC solutions, `.ps1` build scripts), *BSD.
- Verdict: **link (dynamically; each is a separate .so/.dll)**. They are the closest existing thing to libstein's "read-only in-process layer" — but LGPL-3 means libstein cannot *absorb* them. Recommended pattern: an optional backend module per libyal library behind libstein's own interfaces, so a pure-MIT build (without them) still works and a full build gains breadth. Their asciidoc **format docs are the best reference** for writing native parsers (BitLocker, FileVault, VHDX, DMG, APFS).

### B.8 Linux Kernel Library (lklfuse), rump kernels
- **LKL**: Linux kernel compiled as a library; `lklfuse` mounts any Linux fs in userspace via FUSE; "supported hosts for now are POSIX and Windows userspace applications" (Linux, FreeBSD, Windows via MSYS2/Cygwin/MinGW); **macOS not mentioned** [verified: https://github.com/lkl/linux]. License GPL-2 (it is the kernel). Lagging kernel versions historically; build is heavy. **Reference / optional external process** at most; linking is out. Interesting as a *second test oracle* on Linux and Windows (mount an ext4 image with lklfuse and compare directory listings) but mainstream `mount` on Linux is simpler.
- **NetBSD rump kernels**: BSD-licensed, run NetBSD fs drivers (ffs, msdos, ext2fs read-only-ish, cd9660, udf, ntfs read-only, hfs read-only, lfs, tmpfs, v7fs) in userspace via `rump_server`/`p2k`/`ukfs`. [unverified]. Historically built on Linux/*BSD/Windows (Cygwin). Upstream `rumpkernel/buildrump.sh` is lightly maintained since ~2016. **borrow** at file level is possible (BSD) but the drivers are entangled with NetBSD VFS; practical value: reference for `msdosfs`, `udf`, `cd9660`, `ext2fs` (NetBSD's `ufs/ext2fs` has write support for ext2 + extents read [unverified]).
- **NetBSD makefs**: creates ffs/cd9660/chfs/msdos/udf/v7fs images from a directory tree, no root, BSD; ported to FreeBSD (adds ZFS creation in FreeBSD 14!) [unverified: FreeBSD makefs -t zfs]. **borrow** — ideal basis for "create image with filesystem" features and for generating **test fixtures** without root.

### B.9 UDF, ISO9660
- **udftools** (mkudffs, udfinfo, wrudf): GPL-2 [unverified]. **test oracle**.
- **libudfread** (VideoLAN): read-only UDF 1.02–2.60 (Blu-ray oriented), LGPL-2.1 [unverified], portable C. **link**.
- **libcdio**: ISO9660 read (+ UDF partially), GPL-3 [unverified]. **reference / test oracle** (`iso-info`).
- **libisofs** (libburnia): ISO9660 r/w with Rock Ridge/Joliet/El Torito, GPL-2 [unverified]. **reference / test oracle** (`xorriso`).
- **cdrtools / mkisofs**: CDDL + GPL mix — **avoid**.
- Liberal ISO9660 readers: TSK (CPL), libarchive's `archive_read_support_format_iso9660.c` (BSD-2 — reads ISO images incl. Rock Ridge/Joliet/zisofs; **borrow**), NetBSD makefs cd9660 (BSD, write). 

### B.10 ZFS (noted for completeness)
- OpenZFS: CDDL-1.0 (GPL-incompatible; MIT-linkable but file-copyleft). libzpool runs the real code in userspace (`ztest`, `zdb`). **reference / optional dynamic link** far in the future. FreeBSD makefs `-t zfs` (BSD-2) can *create* pools.

---

## C. Encryption / volume managers

### C.1 LUKS
- **cryptsetup / libcryptsetup**: the reference. Library `libcryptsetup` is LGPL-2.1-or-later **with the "cryptsetup-OpenSSL-exception"**; tools and unmarked files GPL-2.0-or-later. [verified: https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/README.licensing — lists "LGPL-2.1-or-later WITH cryptsetup-OpenSSL-exception" among the licenses; default is GPL-2.0-or-later]. Linux-only: requires device-mapper (`dm-crypt`) for mapping; however its **header parsing, keyslot unlocking and KDF code (`lib/luks1`, `lib/luks2`, `lib/crypto_backend`) runs in userspace** and the library can `crypt_activate_by_passphrase` only on Linux. Also implements TrueCrypt/VeraCrypt, BitLocker (BITLK) and FileVault2 (FVAULT2) *header* formats (`lib/tcrypt`, `lib/bitlk`, `lib/fvault2`) — valuable **reference** for those formats too. Crypto backends: OpenSSL (default), gcrypt, nettle, kernel, mbedTLS? (OpenSSL/gcrypt/nettle/nss/kernel [unverified]).
- Verdict: **reference** (not linkable cross-platform; it is LGPL so linking on Linux would be legal but pointless without dm-crypt). `cryptsetup luksDump --dump-json-metadata` is the **test oracle** for header parsing; `cryptsetup open` + `dd` for payload decryption comparison.
- **Write our own LUKS1/LUKS2 in userspace** — feasible and the recommended approach:
  - LUKS1 spec (Fruhwirth, "LUKS On-Disk Format Specification 1.2.3") and LUKS2 spec ("LUKS2 On-Disk Format Specification", gitlab cryptsetup wiki) are public documents; the formats are simple: header + JSON area (LUKS2) + keyslots using AF-splitter (anti-forensic stripes, SHA-based diffusion) + PBKDF2 or argon2i/argon2id → key → payload cipher (overwhelmingly `aes-xts-plain64`, sometimes `aes-cbc-essiv:sha256`, serpent/twofish-xts for VeraCrypt converts). Integrity (`dm-integrity` authenticated) and online reencryption metadata can be detected-and-refused in v1.
  - **libargon2** (PHC reference): dual **CC0 / Apache-2.0** [verified: https://github.com/P-H-C/phc-winner-argon2]. **borrow / vendor**.
  - Crypto backend candidates (all MIT-compatible): **OpenSSL 3** (Apache-2.0; has AES-XTS, PBKDF2, EVP; ubiquitous; large), **libsodium** (ISC; **no AES-XTS, no PBKDF2** — unsuitable alone), **mbedTLS** (Apache-2.0 or GPL-2 dual; has AES-XTS via `MBEDTLS_CIPHER_MODE_XTS`, PBKDF2; small, easy static link), **Botan 3** (BSD-2; C++, has XTS, PBKDF2, Argon2 built in, Serpent/Twofish/Camellia — the most convenient single C++ dependency), **Crypto++** (Boost Software License; XTS, PBKDF2, Serpent, Twofish, Camellia, Whirlpool, RIPEMD-160, Streebog?), **wolfSSL** (GPL-2/commercial — avoid). Platform crypto (CNG on Windows, CommonCrypto on macOS) lack XTS/Serpent uniformly. **Recommendation: Botan (BSD-2) or mbedTLS (Apache-2.0)** as the primary backend behind a small `ICipher` interface; Botan covers VeraCrypt's exotic algorithms (Serpent, Twofish, Camellia, Kuznyechik, Whirlpool, Streebog, SHA-512, RIPEMD-160 — all present [unverified for Kuznyechik]).
- **libluksde** (libyal): LUKS1 read-only only, no LUKS2, LGPL-3, experimental [verified]. **reference** for structure; not enough for the goal.

### C.2 TrueCrypt / VeraCrypt
- **VeraCrypt**: "multi-licensed under Apache License 2.0 and the TrueCrypt License version 3.0"; third-party parts: zlib, libzip (BSD), LZMA SDK (public domain), "Disk Cryptography Services" LGPL-3 component. [verified: https://github.com/veracrypt/VeraCrypt/blob/master/License.txt]. Interpretation [unverified]: the Apache-2.0 grant covers IDRIX's own contributions; code inherited from TrueCrypt 7.1a remains under TrueCrypt License 3.0 (non-OSI, non-free per Debian/FSF: branding restrictions, mandatory source disclosure for modified versions, odd liability clauses). Core volume code (`Common/`, `Volume/`, crypto in `Crypto/`) is largely TrueCrypt-derived. Some `Crypto/` files have their own liberal licenses (e.g. Brian Gladman's AES/Twofish/Serpent are BSD-ish/public domain; `Whirlpool` public domain; `chacha`/`t1ha` MIT [unverified]).
- Verdict: **reference only** for volume format (header layout at offset 0/65536 (hidden)/backup at end, PBKDF iterations/PIM, salt, encrypted header with XTS, cascade ciphers, system encryption), plus per-file **borrow** only for third-party crypto primitives after checking each header. VeraCrypt itself (CLI `veracrypt --text`) is a fine **test oracle** on all three OSes.
- **tc-play (tcplay)**: BSD-2-Clause TrueCrypt + VeraCrypt implementation (create/modify/map volumes); Linux (libdevmapper) and DragonFly BSD (libdm); core of DragonFly. [verified: https://github.com/bwalex/tc-play]. Header parsing/decryption, PBKDF2 with the TrueCrypt hash set, keyfile handling, hidden volumes and the *format writer* are in portable C (`tcplay.c`, `hdr.c`, `crypto.c` with OpenSSL/gcrypt backends); only the final mapping uses device-mapper. **borrow** — this is the BSD-licensed foundation for VeraCrypt compatibility (replace the dm-crypt mapping with libstein's own XTS block layer).
- **zuluCrypt**: GPL-2+, Qt GUI [unverified]. **avoid**.
- cryptsetup `lib/tcrypt/tcrypt.c`: LGPL-2.1+ — **reference** (the most complete open VeraCrypt header unlocker: PIM, all hashes, cascades, system encryption).

### C.3 LVM2 / device-mapper
- **LVM2**: `libdevmapper`/`liblvm` LGPL-2.1, tools GPL-2 [unverified]; Linux-only (needs `dm-*` kernel targets). LVM2 on-disk metadata is a text format (`lvm2 "text format"`: PV label sector 1 (`LABELONE`), metadata area with a ring of text VG descriptors; segments: striped, mirror, raid*, thin-pool, thin, cache, snapshot). The **format is documented in lvm2's `doc/` and in libvslvm's asciidoc**; writing a userspace **reader** that maps a linear/striped LV to PV extents is modest work (needs: parse text metadata, resolve segments). Mirror/RAID/thin need DM-target semantics — reading `thin` requires parsing the thin-pool btree metadata (`thin-provisioning-tools` is GPL-3 — reference only).
- Verdict: LVM2 **reference / test oracle** (`pvs/vgs/lvs --reportformat json`, `vgcfgbackup` dumps the text metadata directly — ideal fixture generator). **Write own reader** for linear+striped in v1; libvslvm (LGPL-3) **link** optional but it is *less* capable than what a weekend of work yields (no multi-PV).

### C.4 RAID / Windows / Apple volume managers
- **mdadm**: GPL-2 [unverified]; md superblock formats 0.90/1.x and IMSM/DDF containers are documented in the kernel (`md_p.h`, GPL-2 with syscall exception… headers under `uapi` are usable for ABI). **reference**; a userspace RAID0/1/10/5 reader is simple (linux-ntfs-style); `mdadm --examine` **test oracle**. libblkid detects md superblocks.
- **dmraid** (fake-RAID: Intel IMSM, Promise, NVIDIA, …): GPL-2, unmaintained [unverified]. **reference**.
- **Windows Storage Spaces**: no public spec; **avoid** (detect and refuse). **LDM**: see A.8 (FreeBSD BSD-2 parser available).
- **Apple CoreStorage** (FileVault 2 on HFS+ era): libfvde (LGPL-3, alpha) + its asciidoc are the only open docs. **link/reference**. **APFS containers**: APFS Reference (public) + libfsapfs/apfs-fuse. Fusion drives (multi-device APFS) — rare; detect.
- **BitLocker**: libbde (LGPL-3; FVE metadata, AES-CBC+Elephant diffuser, AES-XTS 128/256, password/recovery/BEK/clear-key; no TPM) **link**; **dislocker** (GPL-2, FUSE) **reference/test oracle**; cryptsetup `lib/bitlk` **reference**. Format: no MS spec; libbde asciidoc is the de-facto one.
- **FileVault 2**: libfvde (LGPL-3) **link**; cryptsetup `lib/fvault2` **reference** (both need the EncryptedRoot.plist.wipekey from the Recovery partition for CoreStorage FV2; APFS-era FileVault is just encrypted APFS → libfsapfs).

---

## D. Disk imaging and image formats

### D.1 Imaging tools (reference / oracle)
- **dd/raw**: trivial; implement natively (with `O_DIRECT`/unbuffered I/O, sparse detection, progress, verify hashes).
- **partclone**: GPL-2 [unverified]; used-block-only imaging per fs by linking each fs's library (libext2fs, libntfs-3g, libxfs, btrfs-progs, FatFs? no — own FAT bitmap reader, libhfsp, …) into one image format (partclone header + bitmap + used blocks; optional checksums). **reference** for the *approach* and for its image format (document it, implement a reader for interop); **test oracle**. Note partclone proves the "fs library → used-block bitmap" pattern libstein wants, and libstein already needs per-fs block-bitmap parsing for that (ext4 block bitmaps, NTFS $Bitmap, FAT allocation table, exFAT allocation bitmap, HFS+ allocation file, APFS spaceman, XFS AG free-space btrees, btrfs extent tree).
- **Clonezilla**: GPL-2 scripts over partclone/partimage — **avoid** (not a library).
- **GNU ddrescue**: GPL-2+ (C++) [unverified]; its *mapfile* format (position/size/status table) is worth implementing for interop. **reference / test oracle**. (`ddrescue` behaviour — multi-pass, trimming, scraping — is the spec for a robust recovery copier.)
- **ntfsclone / e2image / xfs_metadump**: GPL-2 tools; e2image's QCOW2 output and raw "metadata-only" images are good fixtures. **test oracle**.

### D.2 Image formats
| Format | Owner/spec | Liberal reader/writer | Verdict |
|---|---|---|---|
| EWF (E01/Ex01/L01) | Expert Witness; reverse-engineered; libewf asciidoc | libewf (LGPL-3; r/w E01/S01/Ex01) [verified] | **link** (dyn.) — gives compression (zlib), segmentation (chopping into pieces), hashing, metadata for free; de-facto forensic standard. |
| QCOW2 | QEMU docs (`docs/interop/qcow2.rst`, GPL-2 doc, format is public) | libqcow (LGPL-3, read) ; qemu-img GPL-2 | Write own reader+writer (format is well-specified; moderate: L1/L2 tables, refcounts, zlib/zstd clusters, backing files, snapshots optional). qemu-img = **test oracle** (`qemu-img check/compare/convert`). |
| VHD (fixed/dynamic/differencing) | Microsoft "VHD Format Spec" (Open Specification Promise) | libvhdi (LGPL-3, read); Windows Virtual Disk API (platform) | Write own (very simple: footer + BAT + bitmap). Needed on Windows for `AttachVirtualDisk`. |
| VHDX | Microsoft [MS-VHDX] (Open Specification) | libvhdi (read), qemu (GPL-2) | Write own reader (log replay + BAT + metadata region: moderate); writer later. |
| VMDK (sparse, flat, stream-optimized) | VMware "Virtual Disk Format 5.0" (public PDF) | libvmdk (LGPL-3, read), qemu | Own reader for monolithicSparse/streamOptimized; writer later. |
| Apple DMG/UDIF | reverse-engineered (koly trailer, plist XML, blkx chunk table, bzip2/zlib/ADC/LZFSE) | libmodi (LGPL-3, read); libdmg-hfsplus (GPL-3) [unverified]; dmg2img (GPL-2) [unverified] | Own reader (koly/plist/blkx is small; ADC decompressor is tiny and public-domain re-implementations exist; LZFSE is Apple's **BSD-3** library `lzfse` — **borrow**); `hdiutil` = **test oracle** on macOS. Writer: UDZO (zlib) straightforward. |
| Parallels HDD | | libphdi | low priority |
| AFF4 | Apache-2.0 (libaff4, C++) [unverified] | — | **link/borrow** possible; niche. |
| partclone image | GPL-2 tool | — | implement reader (format documented in partclone source comments — facts only). |
| raw split (`.001`, `.aa`) | convention | — | native. |

### D.3 Compression / container libraries (all MIT-compatible)
- **zlib** (zlib license) / **zlib-ng** (zlib) / **libdeflate** (MIT; faster, no streaming): needed for E01, QCOW2, DMG UDZO, VHDX?no. **borrow/link**.
- **zstd** (BSD-3 + GPL-2 dual — use the BSD-3 grant) [unverified]: default for libstein's own image format; supports `--long`, seekable format (`contrib/seekable_format`, BSD-3) which is exactly what random-access mounting of a compressed image needs. **link/vendor**.
- **lz4** (lib BSD-2, CLI GPL-2) [unverified]: fast path; LZ4 frame format has block-independence option enabling seeking. **link/vendor**.
- **xz / liblzma** (public domain → 0BSD since 5.4? [unverified]; note the 2024 backdoor incident — pin versions): .xz has block index enabling seek. **link**.
- **bzip2** (BSD-4-like/"bzip2 license", MIT-compatible) [unverified]: needed only for DMG UDBZ and E01-bzip2 reads. **link**.
- **lzfse** (Apple, BSD-3) [unverified]: DMG ULFO. **vendor**.
- **libarchive** (BSD-2) [unverified]: tar/zip/7z/iso9660/cpio readers and writers; use for "image inside tar/zip" containers and as an ISO9660 **reader** (`archive_read_support_format_iso9660`). **link**.
- Hashing: use the crypto backend (Botan/mbedTLS/OpenSSL) or vendored BSD/MIT implementations (e.g. BLAKE3 reference is CC0/Apache-2; xxHash BSD-2).

---

## E. Userspace filesystem mounting frameworks

| Platform | Framework | License | Status / notes | Verdict |
|---|---|---|---|---|
| Linux | **libfuse 3** | LGPL-2.1 [unverified] | Standard; kernel `fuse` module in every distro; unprivileged mounts via `fusermount3` setuid; also `/dev/fuse` directly. | **link (dyn.)** |
| Linux | **NBD** (`nbd-client`/`nbdkit` plugin API) | nbd GPL-2 tools; nbdkit BSD-2 [unverified]; kernel `nbd` | Exposing an *image* as a block device (`/dev/nbdX`) so the kernel mounts it natively — the qemu-nbd pattern. The **NBD protocol** is public/simple; a userspace NBD server is ~500 lines. Also **ublk** (6.0+, `liburing`, MIT) for high-perf block devices. | **implement NBD server** (protocol, no license issue); optional ublk backend. |
| Linux | **loop device** + `LOOP_CONFIGURE` | kernel | For raw/sparse images: no server needed; direct-io, partition scanning (`LO_FLAGS_PARTSCAN`). | native |
| macOS | **macFUSE** | libfuse.dylib + macFUSE.framework open source (BSD-style? [unverified]); **kernel extension closed-source**; macOS 12–27; older 3.8.3 tree fully open. [verified: https://github.com/macfuse/macfuse] | Requires user to allow kext (System Settings, Reduced Security on Apple Silicon). Workable but UX-hostile. | **link (dyn.) optional** |
| macOS | **FUSE-T** | **Proprietary**: free for non-commercial use; commercial use requires a license from the FUSE-T authors; bundled libfuse is LGPL. [verified: https://github.com/macos-fuse-t/fuse-t/blob/main/License.txt]. Kext-less: launches an NFSv4/SMB3/FSKit server on localhost and mounts it. | License is a blocker for an MIT library that others will embed commercially. | **avoid as dependency**; copy the *idea*. |
| macOS | **FSKit** (macOS 15+) | Apple framework (Swift/ObjC) | Apple-blessed userspace fs; app extension model; Apple's own `msdos` FSKit module; restrictive but the future. Requires Swift/ObjC glue (allowed: platform layer, not Qt/GTK). | **reference now, target later** |
| macOS | **hdiutil attach / DiskImages framework** | platform | For raw/DMG/UDIF/sparsebundle images macOS mounts natively (`hdiutil attach -imagekey diskimage-class=CRawDiskImage`, `-nomount` to get `/dev/diskN` for libstein to parse). | native |
| macOS | **NFS/SMB loopback** | protocol | What FUSE-T does. A local NFSv3/v4 server (user-level, e.g. based on **libnfs** (LGPL-2.1) or own) mounted via `mount_nfs localhost`. Works on all three OSes (Windows has an NFS client in Pro/Enterprise only; SMB loopback is blocked on Windows by default for local server on 445 — use WebDAV there). | **portable fallback (implement)** |
| Windows | **WinFsp** | **GPLv3 with FLOSS exception**: permits linking with the WinFsp DLL and redistributing the unmodified installer if your program (a) is under a license satisfying the Free Software Definition 1.14 or Open Source Definition 1.9 (MIT qualifies), (b) includes the notice "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos" + repo link, (c) **is not linked or distributed with proprietary (non-FLOSS) software**. Commercial license available. [verified: https://github.com/winfsp/winfsp/blob/master/License.txt and README] | Mature, fast, signed kernel driver, FUSE-compatible API (`fuse.h` / `fuse3.h`) plus native API. The "not linked with proprietary software" condition means **downstream proprietary users of libstein cannot rely on this exception** — libstein must keep WinFsp an *optional, dynamically loaded* backend (`LoadLibrary("winfsp-x64.dll")`) with a clear notice, so an MIT core without WinFsp remains clean. | **link (dyn., optional, documented)** |
| Windows | **Dokany** | dokan2.dll, dokan2.sys, dokanfuse2.dll, dokannp2.dll, installer: **LGPL** (v3 [unverified version]); dokanctl.exe and samples (mirror, memfs): **MIT**. [verified: https://github.com/dokan-dev/dokany] | Also offers a FUSE-compatible wrapper. Slightly slower than WinFsp; signed driver; broadly used (e.g. by some commercial products). LGPL is the cleaner license story for an MIT lib. | **link (dyn.) — preferred Windows FUSE backend for license reasons** |
| Windows | **ProjFS** | platform (Win10 1809+) | Virtualised *projection* of a directory (designed for VFS-for-Git); hydration model, no block semantics, poor fit for a real fs, but needs no third-party driver. | **reference / optional** |
| Windows | **Virtual Disk API** (`AttachVirtualDisk`, VHD/VHDX/ISO) | platform | Native mount of VHD/VHDX/ISO images → `\\.\PhysicalDriveN`; so a "convert to VHDX then attach" path mounts any image with *Windows'* own NTFS/FAT/exFAT/ReFS drivers. Requires admin (or Hyper-V role). | native |
| Windows | **WebDAV loopback** (`\\localhost@port\DavWWWRoot`) | protocol | Windows' built-in Mini-Redirector mounts a local WebDAV server without drivers (no admin). Limited (file size cap registry, no block semantics). | **portable fallback** |
| all | **iSCSI / NBD loopback** | protocol | NBD for Linux; Windows has a built-in iSCSI initiator, macOS does not (3rd-party). | optional |

Note on FUSE on macOS without kexts: Apple's own direction is FSKit; any MIT lib should plan: Linux=libfuse, Windows=Dokany (LGPL) with WinFsp optional, macOS=macFUSE if present, else NFS-loopback fallback, with FSKit later.

---

## F. Platform block-device access APIs (own "platform layer")

All of this is OS API usage — no third-party license concerns. The libraries noted are for enumeration convenience only.

### F.1 Linux
- Device nodes: `/dev/sdX`, `/dev/nvmeXnY`, `/dev/mmcblkX`, `/dev/loopX`, `/dev/dm-X`, `/dev/mdX`; stable paths in `/dev/disk/by-id|by-path|by-uuid|by-partuuid`.
- ioctls: `BLKGETSIZE64` (bytes), `BLKSSZGET` (logical sector), `BLKPBSZGET` (physical), `BLKIOMIN/BLKIOOPT/BLKALIGNOFF`, `BLKRRPART` (re-read table; fails EBUSY if any partition mounted) → prefer `BLKPG` (`BLKPG_ADD_PARTITION/DEL/RESIZE`, as libfdisk/`partx` do, per-partition without full reread), `BLKDISCARD`, `BLKZEROOUT`, `BLKROGET`, `BLKFLSBUF`, `HDIO_GETGEO` (legacy CHS), `FIBMAP/FIEMAP` (file extents for images-in-files), `BLKREPORTZONE` (zoned).
- Loop: `/dev/loop-control` + `LOOP_CTL_GET_FREE`, `LOOP_CONFIGURE` (5.8+, sets file, offset, sizelimit, `LO_FLAGS_DIRECT_IO|PARTSCAN|READ_ONLY` atomically); fallback `LOOP_SET_FD`+`LOOP_SET_STATUS64`.
- Enumeration: sysfs `/sys/class/block/*` (`size`, `queue/logical_block_size`, `removable`, `ro`, `device/model`, `device/vendor`, `device/wwid`, `partition`, `start`, `holders/`, `slaves/`), `/proc/mounts`/`/proc/self/mountinfo`, `/proc/swaps`, `/proc/mdstat`. **libudev** (LGPL-2.1, part of systemd; also `eudev`) gives hotplug monitoring; optional dynamic link or **just read sysfs + netlink `NETLINK_KOBJECT_UEVENT`** directly (no dependency; ~200 lines). **UDisks2** (D-Bus, GPL-2 daemon; LGPL-2 client lib — but glib) **avoid**, reference for the helper-daemon design.
- Open flags: `O_EXCL` on a block device = fails if mounted/held (the kernel's "exclusive open" used by mkfs/fdisk); `O_DIRECT` requires aligned buffers (sector-size multiples); `O_SYNC`; `fsync` after writes; `posix_fadvise`.
- Privileges: raw access needs root or `disk` group (rw) — `CAP_SYS_RAWIO`/`CAP_SYS_ADMIN` for some ioctls.

### F.2 macOS
- Device nodes: `/dev/diskN` (buffered) vs `/dev/rdiskN` (raw, aligned I/O, much faster); slices `/dev/diskNsM`; APFS synthesized disks `diskN` with `physical store` relation.
- ioctls (`<sys/disk.h>`): `DKIOCGETBLOCKSIZE`, `DKIOCGETBLOCKCOUNT`, `DKIOCGETPHYSICALBLOCKSIZE`, `DKIOCISWRITABLE`, `DKIOCEJECT`, `DKIOCSYNCHRONIZECACHE`, `DKIOCUNMAP` (TRIM), `DKIOCGETMAXBLOCKCOUNTREAD`.
- Enumeration/metadata: **IOKit** (`IOServiceMatching("IOMedia")`, properties `BSD Name`, `Size`, `Preferred Block Size`, `Whole`, `Removable`, `Ejectable`, `Content` (partition type), `Leaf`), `IOStorageFamily` parents for model/serial. **DiskArbitration** (`DADiskCreateFromBSDName`, `DADiskCopyDescription`, `DADiskUnmount`, `DADiskClaim` to prevent auto-mount, `DARegisterDiskAppearedCallback`) — necessary because macOS auto-mounts anything recognisable; claim before writing partition tables. Partition table re-read: no `BLKRRPART`; the kernel re-probes on close of a writable whole-disk fd (IOMedia re-registration) — `diskutil` triggers this; `DKIOCSYNCHRONIZECACHE` then close.
- Images: `hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage image.img` → `/dev/diskN`; `hdiutil` handles DMG/sparsebundle/ISO/raw; `DiskImages2` private framework, so shell out to `hdiutil` (BSD tool, platform).
- Privileges: raw whole-disk open needs root or the `authopen` helper (`/usr/libexec/authopen -o <flags> /dev/rdiskN` passes back the fd over a Unix socket via `SCM_RIGHTS`; prompts via Authorization Services) — this is how non-root GUI tools get disk fds. SIP does not block `/dev/rdisk` for root, but mounting APFS boot volumes etc. is restricted. "Full Disk Access" TCC affects *filesystem* paths, not raw devices.

### F.3 Windows
- Device paths: `\\.\PhysicalDriveN` (whole disk), `\\.\C:` (volume), `\\?\Volume{GUID}`, `\\.\HarddiskVolumeN`, `\\.\CdRomN`.
- DeviceIoControl: `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_DISK_GET_LENGTH_INFO`, `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty` → vendor/model/serial/bus type; `StorageAccessAlignmentProperty` → physical sector; `StorageDeviceTrimProperty`; `StorageDeviceSeekPenaltyProperty` SSD/HDD), `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` / `SET_DRIVE_LAYOUT_EX` / `IOCTL_DISK_CREATE_DISK` / `IOCTL_DISK_DELETE_DRIVE_LAYOUT`, `IOCTL_DISK_UPDATE_PROPERTIES` (re-read table), `IOCTL_STORAGE_GET_DEVICE_NUMBER`, `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` (volume → disk offsets), `IOCTL_DISK_IS_WRITABLE`, `IOCTL_STORAGE_EJECT_MEDIA`, `IOCTL_SCSI_PASS_THROUGH_DIRECT`, `IOCTL_ATA_PASS_THROUGH`, `IOCTL_STORAGE_PROTOCOL_COMMAND` (NVMe). Writing to sectors covered by a mounted volume requires `FSCTL_LOCK_VOLUME` (+`FSCTL_DISMOUNT_VOLUME`) on each volume on the disk, otherwise Vista+ blocks writes to in-use regions (ERROR_ACCESS_DENIED even as admin); `IOCTL_DISK_SET_DISK_ATTRIBUTES` (offline/read-only), `IOCTL_DISK_GET_DISK_ATTRIBUTES`. Alignment: `FILE_FLAG_NO_BUFFERING` → sector-aligned buffers/offsets; `FILE_FLAG_WRITE_THROUGH`.
- Enumeration: **SetupAPI/CfgMgr32** (`SetupDiGetClassDevs(GUID_DEVINTERFACE_DISK)`, `SetupDiEnumDeviceInterfaces`), WMI (`Win32_DiskDrive`, `MSFT_Disk` in `root/Microsoft/Windows/Storage`) — COM, allowed but heavy; `FindFirstVolume`/`GetVolumePathNamesForVolumeName` for mounts; `WM_DEVICECHANGE`/`RegisterDeviceNotification` for hotplug.
- Images: **Virtual Disk API** (`virtdisk.dll`: `OpenVirtualDisk`, `AttachVirtualDisk`, `CreateVirtualDisk`; VHD/VHDX/ISO; needs admin, or Hyper-V Administrators). No native raw-image attach (convert raw→VHD by appending a 512-byte footer: trivial and lossless! Fixed VHD = raw + footer).
- Privileges: opening `\\.\PhysicalDriveN` for write needs Administrator (High IL); read access to physical drives also requires admin on modern Windows. UAC elevation = separate process (`ShellExecute` with `runas`), or a Windows Service / COM elevation moniker.

### F.4 SMART / drive health
- Linux: `SG_IO` ioctl with ATA PASS-THROUGH (16) CDB (`0x85`) carrying `SMART READ DATA (0xB0, feature 0xD0)` / `SMART READ LOG`; SAT translation for USB bridges (many don't support it); NVMe: `NVME_IOCTL_ADMIN_CMD` with `Get Log Page 0x02 (SMART/Health)`; `HDIO_DRIVE_CMD` legacy.
- macOS: IOKit `IOATASMARTInterface` (`SMARTReadData`, `SMARTReturnStatus`, via `IOCreatePlugInInterfaceForService` on `IOBlockStorageDevice` with `SMART Capable`); NVMe: `IONVMeSMARTInterface` (private-ish header `NVMeSMARTLibExternal.h`, used by smartmontools). USB/Thunderbolt enclosures generally not supported by Apple's drivers (no SAT).
- Windows: `SMART_RCV_DRIVE_DATA` / `SMART_GET_VERSION` ioctls (legacy ATA), `IOCTL_ATA_PASS_THROUGH`, `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProtocolSpecificProperty` (NVMe SMART log, Win10+), `IOCTL_SCSI_PASS_THROUGH`.
- **smartmontools**: GPL-2 [unverified] — the definitive **reference** for OS quirks (USB bridge SAT table `drivedb.h` — note `drivedb.h` is GPL too; don't copy), and **test oracle** (`smartctl -j` JSON output). **libatasmart** (Lennart Poettering; LGPL-2.1 [unverified]; Linux-only, ATA only, unmaintained) — **reference** for attribute decoding. Attribute tables (ID → name) are factual; ACS/NVMe specs are public (T13/NVMe Express) — implement natively.

---

## G. Privilege elevation

- **Linux**: polkit (`pkexec`, or D-Bus-activated helper authorized via `polkit` actions). Without D-Bus/glib: spawn `pkexec <helper>` (returns 126/127 on cancel), or `sudo -A`; `pkexec` requires the helper to be a system-installed binary with a `.policy` file for a nice prompt. Alternatives: setuid helper (discouraged), systemd `systemd-run --uid=0` via polkit. UDisks2 pattern: long-running root daemon on the system bus doing all block ops; clients unprivileged.
- **macOS**: `SMJobBless` (launchd privileged helper, code-signing requirements; deprecated since 13) → **`SMAppService.daemon`** (macOS 13+, helper daemons registered from the app bundle) with XPC; `AuthorizationExecuteWithPrivileges` deprecated since 10.7 (still works, discouraged); `authopen` (fd passing for device files — the lightweight answer for *reading/writing devices* without a daemon); `osascript -e 'do shell script ... with administrator privileges'` (hack). Apple's `DiskArbitration` performs unmount/eject without root for user-mounted volumes.
- **Windows**: UAC — elevated separate process (`ShellExecuteEx` verb `runas`, manifest `requireAdministrator`), or a Windows Service (installed once, talks over named pipes / RPC / COM with impersonation), or COM Elevation Moniker (`CoCreateInstanceAsAdmin`) for out-of-process elevated COM objects.
- **Pattern for libstein** (same as **kpmcore** (GPL-3, KAuth helper, Qt — reference only), **UDisks2**, GParted's `gparted` polkit wrapper, Etcher's `sudo-prompt`): unprivileged client library ↔ **privileged helper process** over a small message protocol (length-prefixed binary or JSON), with the helper exposing *only* coarse operations (open device by id → fd passing on Unix via `SCM_RIGHTS`; on Windows `DuplicateHandle` into the client process, or keep I/O in the helper). Keep the IPC transport platform-specific (Unix socket / named pipe) and the protocol shared.

---

## License Compatibility Matrix

Legend: Y = yes; D = dynamic link only (ship relinkable objects for static); N = no; T = test-suite/oracle use only (separate process). "Copy" means copying source into libstein under MIT (keeping notices).

| Library / code | License | Link dyn. | Link static | Copy code | Reference | Notes |
|---|---|---|---|---|---|---|
| FreeBSD sys/geom/part, libgeom, newfs_msdos, fsck_msdosfs, makefs | BSD-2/BSD-3 [verified g_part_apm.c] | Y | Y | **Y** | Y | Keep per-file copyright; check each SPDX line. |
| NetBSD sbin/gpt, dkwedge_*, makefs, rump fs | BSD-2/3 [unverified] | Y | Y | **Y** | Y | Some files carry 4-clause BSD / UCB (advertising clause removed 1999) — check. |
| FatFs R0.16 | BSD-1-Clause-style [verified mirror] | Y | Y | **Y** | Y | Keep ChaN notice. |
| lwext4 (BSD-3 files) | BSD-3 [verified] | Y | Y | **Y** | Y | **Exclude** ext4_xattr.c, ext4_extents.c (GPL-2). |
| tc-play | BSD-2 [verified] | Y | Y | **Y** | Y | Replace dm mapping. |
| libargon2 | CC0 / Apache-2 [verified] | Y | Y | **Y** | Y | |
| zlib, zstd, lz4, liblzma, bzip2, lzfse, libdeflate, libarchive | zlib / BSD-3 / BSD-2 / 0BSD-PD / bzip2 / BSD-3 / MIT / BSD-2 [unverified] | Y | Y | Y | Y | Standard. |
| Botan 3 / mbedTLS / OpenSSL 3 / Crypto++ | BSD-2 / Apache-2 / Apache-2 / Boost [unverified] | Y | Y | Y (Apache: keep NOTICE) | Y | libsodium (ISC) lacks XTS/PBKDF2. |
| libyal (libfs*, libvs*, libbde, libfvde, libluksde, libvslvm, libewf, libqcow, libvhdi, libvmdk, libmodi) | LGPL-3.0-or-later [verified 4 repos] | **Y** | D | N | Y (docs are excellent) | Optional backends; keep pure-MIT build. |
| libext2fs (e2fsprogs lib/) | LGPL-2.0 [unverified] | **Y** | D | N | Y | v1 ext4 r/w engine. |
| libfdisk, libblkid, libmount, libudev | LGPL-2.1+ [verified libfdisk] | Y (Linux only) | D | N | Y | Prefer own code for portability. |
| libcryptsetup | LGPL-2.1+ w/ OpenSSL exc. [verified listing] | Y (Linux only) | D | N | Y | Needs dm-crypt; reference for LUKS2/tcrypt/bitlk/fvault2 parsing. |
| LVM2 libdevmapper/liblvm | LGPL-2.1 [unverified] | Y (Linux) | D | N | Y | T: `vgcfgbackup`, `lvs --reportformat json`. |
| libudfread, libnfs | LGPL-2.1 [unverified] | Y | D | N | Y | |
| libfuse 3 | LGPL-2.1 [unverified] | Y | D | N | Y | Linux mount backend. |
| Dokany (dokan2.dll/.sys/dokanfuse2.dll) | LGPL [verified]; dokanctl & samples MIT [verified] | **Y** | D | samples: Y | Y | Preferred Windows backend. |
| WinFsp | GPL-3 + FLOSS exception [verified] | Y **only** when the whole distributed program is FLOSS and carries the notice; proprietary downstream users need a commercial license | N | N | Y | Keep optional & dynamically loaded. |
| macFUSE libfuse.dylib / framework | open source (license per LICENSE.txt, BSD-like [unverified]); kext closed [verified] | Y | ? | ? | Y | Optional backend. |
| FUSE-T | Proprietary, non-commercial free [verified] | N (for an MIT lib intended for commercial reuse) | N | N | Y (idea) | |
| The Sleuth Kit libtsk | CPL-1.0 (+IPL-1.0 files) [verified listing] | **Y** | D-ish (CPL §3 permits object-code distribution under own license if source of CPL parts offered) | N | Y | Breadth fallback; T: mmls/fsstat/fls. |
| OpenZFS libzpool | CDDL-1.0 [unverified] | Y | N (practically) | N | Y | Far future. |
| Apple diskdev_cmds, xnu, IOStorageFamily | APSL-2.0 [unverified] | Y (platform anyway) | N | N (file-copyleft) | Y | |
| lzfse (Apple) | BSD-3 [unverified] | Y | Y | Y | Y | |
| libparted | GPL-3+ [unverified] | N | N | N | Y | T: `parted -m`. |
| gptfdisk | GPL-2+ [unverified] | N | N | N | **Y (architecture)** | T: sgdisk. |
| libldm/ldmtool | LGPL-3 lib / GPL-3 tool [verified] | Y (glib dep → no) | N | N | Y | Use FreeBSD g_part_ldm instead. |
| ntfs-3g/ntfsprogs, dosfstools, mtools, exfatprogs, fuse-exfat, xfsprogs libxfs, btrfs-progs, f2fs-tools, apfs-fuse, linux-apfs-rw/apfsprogs, udftools, libcdio, libisofs, partclone, ddrescue, qemu-img, mdadm, dmraid, smartmontools, dislocker, lklfuse/LKL, cryptsetup tools, VeraCrypt (TrueCrypt-licensed parts), hfsutils, kpmcore, UDisks2, zuluCrypt, thin-provisioning-tools | GPL-2 / GPL-3 / TrueCrypt-3.0 [mostly unverified] | **N** | N | N | Y | **T** only (separate process in CI). |
| VeraCrypt Apache-2.0-marked contributions, bundled BSD/PD crypto files | Apache-2 / BSD / PD [verified mixed licensing; per-file unverified] | Y | Y | Y per file | Y | Audit every file header before borrowing. |
| Microsoft specs (FAT32, exFAT, VHD, [MS-VHDX], [MS-FSA]), UEFI spec, Apple APFS Reference, LUKS1/2 specs, VMware VMDK spec, NVMe/ACS specs | spec documents | — | — | — | Y | Implementing a published spec needs no code license; note exFAT patent pledge scope (OIN/Linux) [unverified]. |

---

## Recommended v1 stack

**Write ourselves (MIT), from specs, using BSD sources as a starting point:**
1. Platform layer: block-device open/enumerate/geometry/lock/reread/loop-or-attach on Linux (ioctl/sysfs/netlink), macOS (IOKit + DiskArbitration + `authopen` + `hdiutil`), Windows (DeviceIoControl + SetupAPI + Virtual Disk API). Privileged-helper + IPC pattern from day one.
2. Partition tables: MBR/EBR, GPT (incl. backup-header recovery, hybrid MBR detection, protective MBR), APM, BSD disklabel, LDM (read-only), Sun VTOC/SGI (read-only) — **derived from FreeBSD `sys/geom/part/*.c` and NetBSD `sbin/gpt` (BSD-2)**, validated against `sfdisk --json`, `sgdisk`, `parted -m`, `mmls`, `gpart show`, `diskutil list`, `diskpart` in CI.
3. Probing layer (what's in this partition?): own magic-number probes written from specs, cross-checked against `blkid -p` output in tests (never copy libblkid code).
4. FAT12/16/32/exFAT r/w: **vendor FatFs** (BSD-1) behind the fs interface; mkfs/fsck from **FreeBSD newfs_msdos/fsck_msdosfs** (BSD).
5. ext2/3/4: v1 **link libext2fs dynamically** (LGPL-2) for r/w; parallel track: native read-only ext4 built from **lwext4's BSD-3 files** + own extents/xattr implementation, later promoted to r/w and replacing libext2fs.
6. LUKS1/LUKS2 unlock + AES-XTS block layer: **own code** from the public specs + **libargon2** (CC0) + **Botan** (BSD-2) or **mbedTLS** (Apache-2) as crypto backend; VeraCrypt/TrueCrypt container support from **tc-play** (BSD-2) header code on the same block layer.
7. LVM2 linear/striped LV mapping: own text-metadata parser (small); md RAID0/1/10 superblock mapping: own.
8. Image layer: raw, split-raw, sparse; own QCOW2 reader/writer; own fixed/dynamic VHD (needed for Windows attach); VHDX reader; VMDK sparse reader; DMG (UDIF) reader with zlib/bzip2/ADC/**lzfse** (BSD-3). libstein-native image format = raw-chunks + **zstd seekable** (BSD-3) + per-chunk hashes + index, splittable at any chunk boundary; used-block-only mode fed by each fs backend's allocation bitmap (partclone pattern).
9. Mount layer: Linux = libfuse3 (LGPL, dyn) + NBD server (own) for block-level mounts; Windows = **Dokany** (LGPL, dyn) primary, WinFsp optional (FLOSS-exception documented), Virtual Disk API attach for VHD/VHDX; macOS = macFUSE if installed (dyn, optional), `hdiutil attach` for images, own NFS-loopback server as the kext-less fallback; FSKit later.
10. SMART: own ATA/NVMe pass-through on each OS; validate against `smartctl -j`.

**Link (dynamically, as optional backends with a pure-MIT core build):**
- libext2fs (LGPL-2.0), libfuse3 (LGPL-2.1), Dokany (LGPL), libewf (LGPL-3) for E01, selected libyal readers (libfsntfs, libfsapfs, libfshfs, libfsxfs, libbde, libfvde, libvhdi/libvmdk/libqcow until native readers land), libtsk (CPL) as "breadth" read-only fallback (UFS, YAFFS2, ISO9660), libudfread (LGPL-2.1), libarchive (BSD-2, can be static).

**Never link; test-oracle only (CI containers, separate processes):**
- util-linux (sfdisk/blkid/losetup), parted, gptfdisk, e2fsprogs tools, ntfs-3g/ntfsprogs, dosfstools, mtools, exfatprogs, xfsprogs, btrfs-progs, f2fs-tools, hfsprogs, apfsprogs/apfs-fuse, udftools, libcdio/xorriso, cryptsetup, lvm2, mdadm, VeraCrypt CLI, qemu-img, partclone, ddrescue, smartmontools, dislocker, ldmtool, lklfuse, and on the host OSes: `diskutil`/`hdiutil`/`fsck_*`, `diskpart`/`Get-Disk`/`chkdsk`.
- Fixture generation without root: NetBSD/FreeBSD **makefs** (BSD — can even be vendored), `mke2fs -d`, `mkfs.fat`, `mkfs.exfat`, `mkfs.ntfs -F`, `cryptsetup luksFormat` on loop files (Linux CI), `qemu-img create`, `hdiutil create` (macOS CI), `New-VHD` (Windows CI).

**Key license-risk reminders:**
- Keep a per-file `SPDX-License-Identifier` and a `THIRD_PARTY_NOTICES` file; CI lint that no GPL/LGPL/CPL/APSL file is compiled into the core target.
- lwext4: physically delete the two GPL files from the vendored copy.
- WinFsp: ship as a *plugin*, document the FLOSS exception's "not with proprietary software" condition; Dokany default.
- FUSE-T: do not depend on it.
- VeraCrypt: no code from TrueCrypt-licensed files; tc-play is the BSD path.
- Re-verify the `[unverified]` items (esp. e2fsprogs lib LGPL-2.0, libblkid LGPL-2.1+, Dokany LGPL version, macFUSE user-space license text, zstd/lz4/xz exact terms, exFAT patent position) before the first release.
