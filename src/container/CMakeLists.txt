stein_add_module(container
  SOURCES
    src/luks.cpp
    src/tcrypt.cpp
  PUBLIC_DEPS stein::core stein::block stein::layout)

stein_add_test(test_container
  SOURCES ../core/tests/test_main.cpp tests/test_container.cpp
  DEPS stein::container stein::fs)
