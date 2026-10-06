set(STEIN_PLATFORM_SOURCES src/platform.cpp src/aligned_device.cpp)
set(STEIN_PLATFORM_LIBS)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND STEIN_PLATFORM_SOURCES src/linux/platform_linux.cpp)
elseif(APPLE)
  list(APPEND STEIN_PLATFORM_SOURCES src/macos/platform_macos.cpp)
  list(APPEND STEIN_PLATFORM_LIBS "-framework IOKit" "-framework CoreFoundation")
elseif(WIN32)
  list(APPEND STEIN_PLATFORM_SOURCES src/windows/platform_windows.cpp)
  list(APPEND STEIN_PLATFORM_LIBS advapi32)
else()
  list(APPEND STEIN_PLATFORM_SOURCES src/generic/platform_generic.cpp)
endif()

stein_add_module(platform
  SOURCES ${STEIN_PLATFORM_SOURCES}
  PUBLIC_DEPS stein::core stein::block)
if(STEIN_PLATFORM_LIBS)
  target_link_libraries(stein_platform PRIVATE ${STEIN_PLATFORM_LIBS})
endif()

stein_add_test(test_platform
  SOURCES ../core/tests/test_main.cpp tests/test_platform.cpp
  DEPS stein::platform stein::probe)
