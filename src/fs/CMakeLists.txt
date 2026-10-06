stein_add_module(fs
  SOURCES
    src/filesystem.cpp
    src/allocation_map.cpp
    src/reader.cpp
    src/fs_ext_reader.cpp
    src/fs_ntfs_reader.cpp
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
