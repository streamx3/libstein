stein_add_module(core
  SOURCES
    src/error.cpp
    src/units.cpp
    src/guid.cpp
    src/crc32.cpp
    src/hash.cpp
    src/progress.cpp
    src/report.cpp
    src/strings.cpp
    src/log.cpp)

stein_add_test(test_core
  SOURCES tests/test_main.cpp tests/test_core.cpp
  DEPS stein::core)
