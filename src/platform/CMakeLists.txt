set(STEIN_PLATFORM_SOURCES src/platform.cpp)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND STEIN_PLATFORM_SOURCES src/linux/platform_linux.cpp)
else()
  list(APPEND STEIN_PLATFORM_SOURCES src/generic/platform_generic.cpp)
endif()

stein_add_module(platform
  SOURCES ${STEIN_PLATFORM_SOURCES}
  PUBLIC_DEPS stein::core stein::block)

stein_add_test(test_platform
  SOURCES ../core/tests/test_main.cpp tests/test_platform.cpp
  DEPS stein::platform stein::probe)
