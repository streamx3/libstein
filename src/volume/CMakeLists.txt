stein_add_module(volume
  SOURCES
    src/lvm.cpp
  PUBLIC_DEPS stein::core stein::block stein::layout)

stein_add_test(test_volume
  SOURCES ../core/tests/test_main.cpp tests/test_volume.cpp
  DEPS stein::volume stein::fs)
