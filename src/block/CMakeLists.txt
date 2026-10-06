stein_add_module(block
  SOURCES
    src/block_device.cpp
    src/memory_device.cpp
    src/file_device.cpp
    src/slice_device.cpp
    src/sparse_file.cpp
    src/overlay_device.cpp
  PUBLIC_DEPS stein::core)

stein_add_test(test_block
  SOURCES ../core/tests/test_main.cpp tests/test_block.cpp
  DEPS stein::block)
