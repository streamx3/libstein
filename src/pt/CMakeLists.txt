stein_add_module(pt
  SOURCES
    src/partition_type.cpp
    src/partition_table.cpp
    src/gpt_table.cpp
    src/mbr_table.cpp
  PUBLIC_DEPS stein::core stein::block stein::layout)

stein_add_test(test_pt
  SOURCES ../core/tests/test_main.cpp tests/test_pt.cpp
  DEPS stein::pt)
