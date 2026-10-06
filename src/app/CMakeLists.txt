stein_add_module(app
  SOURCES
    src/profile.cpp
    src/scenario.cpp
  PUBLIC_DEPS stein::core stein::block stein::image stein::platform)

stein_add_test(test_app
  SOURCES ../core/tests/test_main.cpp tests/test_app.cpp
  DEPS stein::app stein::pt)
