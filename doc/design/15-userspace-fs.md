# Userspace filesystem access and mounting (R7)

Goal: open an ext4 (or anything else we implement) living inside LUKS inside
LVM inside a GPT on a physical disk *or* inside a compressed split image, on
Windows or macOS or Linux, read it, and eventually write to it — without
kernel drivers for that filesystem.

## 1. Layering

```
stein_fs::FileSystem::Reader / ::Writer           (per-fs userspace driver, VFS-like interface)
            │
stein_mount::Vfs  (path resolution, handle table, caching, locking, case/normalisation policy)
            │
   ┌────────┼──────────────┬──────────────────┬──────────────────┐
libfuse3   Dokany        macFUSE          NFS/WebDAV loopback   NBD / block export
(Linux)    (Windows,     (macOS, optional, (portable fallback,   (expose a BlockDevice to the OS
           LGPL, default) kext)            no driver, own code)  so the native driver mounts it)
           WinFsp optional (GPL+FLOSS exception; documented)
```

Two very different ways to "mount" and both are offered:

- **File-level** (FUSE-style): our `Reader`/`Writer` serves files. Works for
  any fs we implement, including foreign ones the OS cannot read. This is
  the unique feature.
- **Block-level export** (NBD on Linux, VHD attach on Windows, `hdiutil`
  on macOS): we expose a `BlockDevice` (decrypted LUKS, LV, image chunk
  store…) and let the OS's own driver mount the filesystem. Fast, write-safe,
  but only for filesystems the OS already supports (ext4 on Windows: no;
  NTFS/FAT/exFAT on all three: yes; APFS on macOS: yes). Useful for
  "open this LUKS-encrypted NTFS image on Windows" with zero fs code.

## 2. The `Reader` / `Writer` interfaces (stein_fs)

```cpp
class Reader {                                   // L3
public:
    virtual Expected<Inode>        root() const = 0;
    virtual Expected<Inode>        lookup(const Inode& dir, std::string_view name) = 0;
    virtual Expected<Stat>         stat(const Inode&) = 0;
    virtual Expected<void>         readdir(const Inode& dir, DirCallback) = 0;      // streaming, cookie-based
    virtual Expected<size_t>       read(const Inode& file, uint64_t off, std::span<std::byte>) = 0;
    virtual Expected<std::string>  readlink(const Inode&) = 0;
    virtual Expected<std::vector<Extent>> extents(const Inode&) = 0;               // physical map (for recovery/imaging tools)
    virtual Expected<Xattrs>       xattrs(const Inode&) { return Error::Unsupported; }
    virtual FsFeatures             features() const = 0;                            // case-sensitivity, max name, hard links, sparse, timestamps resolution, ADS/forks
};

class Writer : public Reader {                   // L4
public:
    virtual Expected<Inode>  create(const Inode& dir, std::string_view name, const Stat& initial) = 0;
    virtual Expected<Inode>  mkdir(const Inode& dir, std::string_view name, const Stat& initial) = 0;
    virtual Expected<void>   unlink(const Inode& dir, std::string_view name) = 0;
    virtual Expected<void>   rmdir(const Inode& dir, std::string_view name) = 0;
    virtual Expected<void>   rename(const Inode& d1, std::string_view n1, const Inode& d2, std::string_view n2, RenameFlags) = 0;
    virtual Expected<size_t> write(const Inode& file, uint64_t off, std::span<const std::byte>) = 0;
    virtual Expected<void>   truncate(const Inode& file, uint64_t size) = 0;
    virtual Expected<void>   setattr(const Inode&, const StatChange&) = 0;
    virtual Expected<Inode>  symlink(const Inode& dir, std::string_view name, std::string_view target) = 0;
    virtual Expected<void>   link(const Inode& file, const Inode& dir, std::string_view name) = 0;
    virtual Expected<void>   fsync(const Inode&) = 0;
    virtual Expected<void>   sync() = 0;                                            // flush journal / metadata
};
```

Rules for a `Writer` implementation (these are what make "write foreign
filesystems from the first try" credible rather than reckless):

1. **Journal discipline.** ext3/4, NTFS, HFS+J, XFS, btrfs all have journals
   or logs. A `Writer` must either (a) replay a dirty journal before any
   write and then write *through* its own journal implementation, or (b)
   refuse to open a dirty volume for writing (`Error::NeedsReplay`). ext4
   v1: (a) for the jbd2 journal (replay + journaled metadata writes). NTFS
   v1: (b) — require clean shutdown flag, then write with `$LogFile` reset
   to a clean state the way ntfs-3g does. HFS+: (b) initially.
2. **Checksums must be maintained** (ext4 `metadata_csum`, XFS v5 CRCs,
   btrfs everything) or the kernel driver will reject the volume later.
   Each fs module lists which feature flags it can write under; unknown or
   unsupported incompat flags → open read-only and say why.
3. **Allocation policy** can be naive (first-fit, no locality) in v1; it
   must be *correct* (bitmaps, group counters, free-space trees updated).
4. **Round-trip tests** are mandatory: write with our `Writer`, mount with
   the kernel driver on Linux CI, fsck must be clean, contents must match;
   and the reverse. The GPL tools are the oracle here (R8).
5. **Case / normalisation** (NTFS case-insensitive with `$UpCase`, HFS+
   NFD normalisation, exFAT up-case table, ext4 `casefold`) is handled in
   the fs module, not in `stein_mount`, because it is a property of the
   on-disk format.

## 3. Per-filesystem plan

| FS | L3 read | L4 write | Source basis | Notes |
|---|---|---|---|---|
| FAT12/16/32, exFAT | v1 | v1 | vendor FatFs (BSD-1) wrapped per volume (`FF_FS_REENTRANT`, `FF_FS_EXFAT`); mkfs/fsck from FreeBSD `newfs_msdos`/`fsck_msdosfs` (BSD) | The cheapest full r/w win; validates the whole mount stack on all OSes early |
| ext2/3/4 | v1 (own, from lwext4's BSD-3 files + own extents/xattr/casefold) | v2 (own; jbd2 replay + journaled writes; `metadata_csum`, `64bit`, `flex_bg`, `extra_isize`, `inline_data`); optional libext2fs (LGPL, dynamic) backend in v1 for write | The headline feature ("ext4 on Windows") |
| NTFS | v1 (own; MFT, attribute lists, non-resident runs, compression, sparse, `$UpCase`, reparse points, ADS) | v3 (own; clean-volume-only initially) | ntfs-3g (GPL) is reference-only; libfsntfs docs are the spec | Second most valuable: NTFS on macOS r/w |
| HFS+ | v2 | v3 | Apple TN1150 (public spec) | Journaled volumes read-only until journal replay lands |
| APFS | **done** (read; unencrypted volumes, first volume of the container; FileVault later via libfvde docs) | — | Apple APFS Reference (public) | Containers, snapshots, encryption make write a far-future item |
| ISO9660/Joliet/RockRidge, UDF | v1 read | — | ECMA-119/167, UDF 2.60 (public) | Trivial, valuable for images |
| XFS | v2 read | — | public on-disk docs; v5 CRCs | |
| btrfs | v2 read (single device, no compression → with zstd/lzo/zlib in v3) | — | public wiki docs | |
| F2FS | **done** (read; fixtures from mkfs.f2fs + sload.f2fs, lz4/lzo compression) | — | kernel `f2fs_fs.h` (public) | fscrypt files refused; zstd/lzo-rle clusters need newer f2fs-tools to test |
| JFS, Reiser*, nilfs2, bcachefs, minix | detect/label only | — | | |
| ZFS | detect | — | | out of scope |

## 4. Mount backends

**Status:** the Linux libfuse3 backend exists (`stein_mount`, read-only, high-level API, single
thread, `stein mount`); the same source builds on Windows against WinFsp's fuse3-compatible
layer (delay-loaded, so the binary runs without WinFsp and reports `Unsupported`), and CI
mounts and reads the ext4 fixture through it. macOS mounts through the built-in NFSv3
loopback server (`stein_mount::NfsServer`, below) and the system's `mount_nfs`: no kext, no
third-party dependency. The `Vfs` layer below is not written yet — the backends talk to
`fs::Reader` directly with a path → inode cache.

- **Linux:** libfuse3 (LGPL, dynamic). Optional: our own NBD server + `nbd` kernel module for block export (`qemu-nbd` pattern), `ublk` later.
- **Windows:** **WinFsp** through its fuse3-compatible layer (done; GPLv3 with the FLOSS exception, loaded at run time only, so the MIT core never requires it). Dokany was the original default but WinFsp's fuse3 layer let the Linux backend run unchanged. Block export via Virtual Disk API only for VHD/VHDX.
- **macOS:** **own NFSv3 loopback server** (done) mounted with the stock `mount_nfs` on 127.0.0.1 with explicit `port`/`mountport`, so no portmapper, no kext, no admin rights and no third-party code (the FUSE-T idea, re-implemented, since FUSE-T itself is proprietary and macFUSE needs a kext the user must allow). Why not a "block device" API: macOS has no public way for a process to provide a block device (no NBD/ublk/loop-from-userspace); the only block-level path is `hdiutil attach` of a *file*, and a block device would only help for filesystems macOS already has drivers for. The NFS server covers that case too: `makeSingleFileReader` exports a decoded or decrypted disk as one file, and `hdiutil attach -imagekey diskimage-class=CRawDiskImage` on that file lets macOS mount HFS+/APFS/exFAT/FAT/NTFS(ro)/UDF/ISO inside a LUKS/VeraCrypt/LVM/qcow2/E01 container with its own drivers (`stein attach`). FSKit (macOS 15+, Apple's userspace filesystem API) remains the candidate for a native-feeling module later; it needs a signed app extension, so it belongs to a packaged app, not the CLI.
- **All:** the NFS loopback server runs on every platform (`stein serve`), so Linux and Windows can use it as a fallback when FUSE/WinFsp are absent (with the OS NFS client). WebDAV loopback is no longer planned.

`stein_mount::Vfs` sits between the backend and the fs module: path → inode resolution with a negative/positive dentry cache, open-handle table, page cache for reads with write-through, per-inode locking, and the policy for things backends need (Windows file IDs, macOS resource forks → ADS/xattr mapping).

## 5. Safety

- Writable mounts of a volume that the host OS has also mounted are refused (platform `VolumeControl` is consulted).
- Writable mounts require the fs module to declare `WriteSafety::Journaled` or `WriteSafety::CleanOnly`; `Experimental` modules mount read-only unless the caller opts in explicitly.
- Every writable mount session records a small "mounted by stein, dirty" marker in the image/sidecar (never in the fs itself) so an aborted session is detectable.
