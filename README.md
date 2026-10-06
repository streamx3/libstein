# libstein

Pure C++ libraries for block devices, partition tables, filesystems,
encrypted containers, volume managers and disk images — portable across
Linux, macOS and Windows, with no Qt, GTK or glib dependencies.

The goal is a foundation that can replace Disk Utility, GNOME Disks and
`diskmgmt.msc` with platform-native front-ends, *and* power one-button
user apps such as [dr_stein](https://github.com/streamx3/dr_stein) (image
and restore a machine with a couple of clicks). Long term: in-process
read/write access to foreign filesystems (open an ext4-inside-LUKS
partition on Windows or macOS), disk images that can be split, compressed,
verified and mounted anywhere, and proper GPT repair.

Status: milestone M1 in progress. Core types, block devices, the
manifest-driven structure layer, GPT/MBR partition tables with diagnostics
and repair, detection of 35 filesystem/container formats, the topology
probe, the Linux platform layer and the `.stein` imaging format are
implemented and tested; see
[`doc/reports/`](doc/reports/) for progress and [`doc/README.md`](doc/README.md)
for the design.

## Building

Requirements: CMake ≥ 3.25, a C++23 compiler (GCC 13+, Clang 17+, MSVC 2022
17.8+), Python ≥ 3.11 at build time (for the layout generator), Ninja
recommended, `ccache` used automatically when present.

```sh
cmake --preset debug      # or: release, ci, mono
cmake --build --preset debug
ctest --preset debug
./build/debug/tools/stein/stein list                      # disks (Linux)
./build/debug/tools/stein/stein probe /dev/sdb            # table, partitions, filesystems
./build/debug/tools/stein/stein inspect /dev/sdb --doc    # every header field, annotated
./build/debug/tools/stein/stein repair disk.img --dry-run # GPT: rebuild a lost copy
./build/debug/tools/stein/stein pt create disk.img gpt     # edits are simulated, shown, then applied
./build/debug/tools/stein/stein pt add disk.img --size 512M --type EF00 --name EFI --dry-run
./build/debug/tools/stein/stein image create /dev/sdb backup.stein --compress lz4 --used-only --passphrase ...   # encrypted, free space skipped
./build/debug/tools/stein/stein probe backup.stein        # an image is a disk; so is vm.qcow2 / .vhdx / .vmdk / .vdi / .vhd / evidence.E01 / mac.dmg
./build/debug/tools/stein/stein image restore backup.stein /dev/sdc
./build/debug/tools/stein/stein app init office.json /dev/sdb /backups/office.stein   # dr_stein-style profile
./build/debug/tools/stein/stein app status office.json && ./build/debug/tools/stein/stein app restore office.json
./build/debug/tools/stein/stein media test /dev/sdX --force    # fake-flash capacity test (destructive); `media scan` is read-only
./build/debug/tools/stein/stein ls backup.stein --part 2 /home              # browse ext4/NTFS/FAT/exFAT/HFS+/APFS/ISO/UDF/XFS/btrfs/squashfs/erofs inside an image, partition,
./build/debug/tools/stein/stein cp disk.img --passphrase ... --lv root /etc/fstab fstab   # LUKS container or LVM volume
./build/debug/tools/stein/stein luks info /dev/sdb2 && ./build/debug/tools/stein/stein lvm list /dev/sdb3
./build/debug/tools/stein/stein tcrypt unlock vault.hc --passphrase ... --pim 0   # VeraCrypt/TrueCrypt: header found by trial decryption
./build/debug/tools/stein/stein mount backup.stein /mnt/old --part 2     # Linux: FUSE mount of a partition inside an image
```

## Support matrix

Everything below runs in-process with no kernel drivers and the same code
on Linux, macOS and Windows; only the last table differs per OS. Legend:
**✓** done and covered by tests against the reference tools, **◐** partial
(see note), **–** not yet. "Mount" means exposing the in-process reader
to the OS (Linux: FUSE, Windows: WinFsp, macOS: built-in NFS loopback).

### Filesystems

| Filesystem | Detect, label, UUID | Used-block map | Read files | Mount | Write |
|---|---|---|---|---|---|
| ext2 / ext3 / ext4 | ✓ | ✓ | ✓ extents, indirect, inline data, htree, symlinks | ✓ | – |
| FAT12 / 16 / 32 | ✓ | ✓ | ✓ long names | ✓ | – |
| exFAT | ✓ | ✓ | ✓ NoFatChain, up-case table | ✓ | – |
| NTFS | ✓ | ✓ | ◐ MFT, attribute lists, sparse runs, reparse links; compressed and encrypted files refused | ✓ | – |
| HFS+ / HFSX | ✓ | ✓ | ✓ B-trees, overflow extents, hard links, case rules | ✓ | – |
| HFS (classic, incl. wrapper) | ✓ | – | – | – | – |
| APFS | ✓ container and volumes | – | ◐ first volume, unencrypted; decmpfs files refused | ✓ | – |
| XFS (v4, v5) | ✓ | – | ✓ extents, B-tree forks, all directory forms | ✓ | – |
| btrfs | ✓ | – | ✓ single/DUP/RAID0/1/10, subvolumes, zlib/lzo/zstd | ✓ | – |
| SquashFS 4 | ✓ | – | ✓ gzip/lzo/xz/lz4/zstd/lzma, fragments | ✓ | – |
| EROFS | ✓ | – | ✓ full and compact indexes, big pclusters, fragments, dedupe; lz4/lzma/deflate/zstd | ✓ | – |
| ISO 9660 | ✓ Joliet | – | ✓ Rock Ridge, Joliet, plain | ✓ | – |
| UDF 1.02–2.60 | ✓ | – | ✓ physical/sparable/metadata partitions; VAT – | ✓ | – |
| F2FS, JFS, NILFS2, bcachefs, OCFS2, ReiserFS, Reiser4, Minix, UFS | ✓ | – | – | – | – |
| ReFS, ZFS | ✓ (ZFS: name, GUID) | – | – | – | – |
| Linux swap, BitLocker marker | ✓ | – | n/a | n/a | – |

### Partition tables

| Table | Read and diagnose | Create / edit | Repair |
|---|---|---|---|
| GPT (+ protective and hybrid MBR) | ✓ CRCs, header pairs, overlaps, bounds, backup placement | ✓ byte-identical with sgdisk | ✓ rebuild either copy, fix CRCs, relocate backup, fix PMBR |
| MBR + EBR chains | ✓ overlaps, chain loops and breaks | ✓ byte-identical with sfdisk | ◐ (EBR chain rewrite planned) |
| Apple Partition Map | ✓ | ✓ | – |
| BSD disklabel, Windows LDM, Sun/SGI/Amiga/Atari/PC98 | – (planned) | – | – |

### Encrypted containers and volume managers

| Container | Detect | Open / read | Create / write |
|---|---|---|---|
| LUKS1 | ✓ | ✓ PBKDF2, AF-splitter, aes-xts-plain64 | – |
| LUKS2 | ✓ | ✓ Argon2id / PBKDF2 key slots, AES-XTS; integrity volumes refused | – |
| VeraCrypt / TrueCrypt | ✓ by trial decryption | ✓ AES-XTS; SHA-512, SHA-256, BLAKE2s-256, RIPEMD-160 with PIM; normal, hidden and backup headers; cascades and Whirlpool/Streebog – | – |
| BitLocker | ✓ | – | – |
| LVM2 | ✓ PV, VG | ✓ linear and striped logical volumes, multi-segment | – |
| mdraid 0.9 / 1.x | ✓ | – | – |

### Disk images

| Format | Open (probe, read, mount as a disk) | Create |
|---|---|---|
| raw, split raw | ✓ | ✓ |
| `.stein` (own format) | ✓ LZ4, split segments, used-block-only, ChaCha20-Poly1305 encryption with Argon2id key slots, verification | ✓ |
| E01 / EWF (EnCase 5/6) | ✓ segments, deflate chunks, stored MD5/SHA-1 | – |
| VHD (fixed, dynamic) | ✓ | – |
| VHDX (dynamic) | ✓ log must be clean | – |
| qcow2 v2 / v3 | ✓ deflate and zstd clusters; backing files and subclusters – | – |
| VMDK | ✓ sparse, stream-optimized, multi-extent descriptors | – |
| VDI | ✓ dynamic and fixed | – |
| DMG / UDIF | ✓ raw, zlib, bzip2, ADC, lzma, lzfse blocks | – |

Every compressor involved (deflate, bzip2, LZ4, LZO, xz/LZMA, zstd, lzfse,
ADC) is an own implementation checked against the reference tool.

### Per operating system

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| List disks with bus, model, serial, size | ✓ sysfs | ✓ IOKit | ✓ SetupAPI / IOCTL |
| Raw device access (read-only, exclusive read-write) | ✓ | ✓ | ✓ with volume lock and dismount |
| List, unmount mounts; re-read partition table | ✓ | ✓ diskutil | ◐ (volumes dismount through the exclusive open) |
| Attach an image as a block device for the OS | ✓ loop | ✓ hdiutil (raw) | – |
| Mount an in-process reader (foreign filesystems, partitions inside images, LUKS, LVM) | ✓ FUSE (libfuse3) | ✓ built-in NFS loopback + `mount_nfs` (no kext) | ✓ WinFsp |
| Hand a decoded/decrypted disk to the OS's own filesystem drivers | ◐ raw image files via loop (NBD for decoded disks planned) | ✓ NFS loopback + `hdiutil attach` (`stein attach`) | – |
| Media tests (fake-flash capacity, surface scan) | ✓ | ✓ | ✓ |
| Profile-driven one-button backup / restore | ✓ | ✓ | ✓ |

Fixtures under `tests/fixtures/` are regenerated with the scripts in
`tools/fixtures/` (partition tables, filesystems, LUKS, LVM, VeraCrypt,
virtual disks, E01, squashfs, EROFS; they need the matching mkfs,
cryptsetup, lvm, qemu-img, ewfacquire, mksquashfs and mkfs.erofs tools,
loop devices and root). HFS+, APFS and DMG fixtures come from
`.github/workflows/fixtures-macos.yml`, which runs hdiutil on macOS and
commits the results.

License: MIT.
