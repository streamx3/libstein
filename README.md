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
./build/debug/tools/stein/stein probe backup.stein        # an image is a disk; so is vm.qcow2 / .vhdx / .vmdk / .vdi / .vhd
./build/debug/tools/stein/stein image restore backup.stein /dev/sdc
./build/debug/tools/stein/stein app init office.json /dev/sdb /backups/office.stein   # dr_stein-style profile
./build/debug/tools/stein/stein app status office.json && ./build/debug/tools/stein/stein app restore office.json
./build/debug/tools/stein/stein media test /dev/sdX --force    # fake-flash capacity test (destructive); `media scan` is read-only
./build/debug/tools/stein/stein ls backup.stein --part 2 /home              # browse ext4/NTFS/FAT/exFAT/HFS+/ISO/XFS/btrfs inside an image, partition,
./build/debug/tools/stein/stein cp disk.img --passphrase ... --lv root /etc/fstab fstab   # LUKS container or LVM volume
./build/debug/tools/stein/stein luks info /dev/sdb2 && ./build/debug/tools/stein/stein lvm list /dev/sdb3
./build/debug/tools/stein/stein tcrypt unlock vault.hc --passphrase ... --pim 0   # VeraCrypt/TrueCrypt: header found by trial decryption
./build/debug/tools/stein/stein mount backup.stein /mnt/old --part 2     # Linux: FUSE mount of a partition inside an image
```

What works today (all in-process, no kernel drivers, Linux/macOS/Windows):
GPT/MBR/APM read, write and repair; 35 filesystems identified; allocation
maps for ext/FAT/exFAT/NTFS/HFS+ (used-block imaging); `.stein` images with
LZ4, split segments and ChaCha20-Poly1305 encryption (Argon2id key slots);
qcow2/VHD/VHDX/VMDK/VDI containers opened read-only;
LUKS1/2 unlock; VeraCrypt/TrueCrypt volumes (AES-XTS, SHA-512/SHA-256, hidden volumes); LVM2 linear/striped volumes; file readers for ext2/3/4,
NTFS, FAT, exFAT, HFS+, ISO 9660, XFS and btrfs, mountable through FUSE on Linux; profile-driven one-button
backup/restore; fake-flash and surface tests. See `doc/reports/` for the detailed status.

Fixtures under `tests/fixtures/` are regenerated with the scripts in
`tools/fixtures/` (partition tables, filesystems, LUKS, LVM; they need the
matching mkfs/cryptsetup/lvm tools, loop devices and root).

License: MIT.
