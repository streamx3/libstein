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

Status: research and design (milestone M0). Start with
[`doc/README.md`](doc/README.md).

License: MIT.
