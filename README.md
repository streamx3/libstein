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
./build/debug/tools/stein/stein image create /dev/sdb backup.stein --compress lz4
./build/debug/tools/stein/stein probe backup.stein        # an image is a disk
./build/debug/tools/stein/stein image restore backup.stein /dev/sdc
```

Fixtures under `tests/fixtures/` are regenerated with
`tools/fixtures/make_pt_fixtures.sh` (needs sgdisk, sfdisk, mkfs.vfat; root
for the 4Kn loop-device case).

License: MIT.
