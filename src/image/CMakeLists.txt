stein_add_module(image
  SOURCES
    src/stein_format.cpp
    src/keys.cpp
    src/copy.cpp
    src/operations.cpp
  PUBLIC_DEPS stein::core stein::block stein::probe)

stein_add_test(test_image
  SOURCES ../core/tests/test_main.cpp tests/test_image.cpp
  DEPS stein::image)
