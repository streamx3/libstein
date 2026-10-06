stein_add_module(ops
  SOURCES
    src/operation.cpp
    src/stack.cpp
    src/media_test.cpp
  PUBLIC_DEPS stein::core stein::block stein::pt stein::probe stein::image)

stein_add_test(test_ops
  SOURCES ../core/tests/test_main.cpp tests/test_ops.cpp
  DEPS stein::ops)
