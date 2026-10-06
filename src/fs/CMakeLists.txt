stein_add_module(fs
  SOURCES
    src/filesystem.cpp
    src/allocation_map.cpp
    src/reader.cpp
    src/fs_ext_reader.cpp
    src/fs_ntfs_reader.cpp
    src/fs_fat_reader.cpp
    src/fs_exfat_reader.cpp
    src/fs_hfsplus_reader.cpp
    src/fs_iso_reader.cpp
    src/fs_xfs_reader.cpp
    src/fs_btrfs_reader.cpp
    src/fs_squashfs_reader.cpp
    src/fs_apfs_reader.cpp
    src/fs_erofs_reader.cpp
    src/fs_f2fs_reader.cpp
    src/fs_udf_reader.cpp
    src/registry.cpp
    src/fs_ext.cpp
    src/fs_fat.cpp
    src/fs_ntfs.cpp
    src/fs_hfs.cpp
    src/fs_linux.cpp
    src/fs_optical_apple.cpp
    src/fs_containers.cpp
  PUBLIC_DEPS stein::core stein::block stein::layout)

stein_add_test(test_fs
  SOURCES ../core/tests/test_main.cpp tests/test_fs.cpp
  DEPS stein::fs)
