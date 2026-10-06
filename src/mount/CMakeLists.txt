# Mount backend: libfuse3 on Linux when present (dynamic link, LGPL; see DECISIONS D9).
set(STEIN_MOUNT_SOURCES src/mount_none.cpp)
set(STEIN_MOUNT_LIBS)
set(STEIN_HAVE_FUSE OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(FUSE3 QUIET IMPORTED_TARGET fuse3)
    if(FUSE3_FOUND)
      set(STEIN_MOUNT_SOURCES src/mount_fuse.cpp)
      set(STEIN_MOUNT_LIBS PkgConfig::FUSE3)
      set(STEIN_HAVE_FUSE ON)
    endif()
  endif()
endif()
message(STATUS "stein_mount: FUSE backend ${STEIN_HAVE_FUSE}")

stein_add_module(mount
  SOURCES ${STEIN_MOUNT_SOURCES}
  PUBLIC_DEPS stein::core stein::fs)
if(STEIN_MOUNT_LIBS)
  target_link_libraries(stein_mount PRIVATE ${STEIN_MOUNT_LIBS})
endif()
if(STEIN_HAVE_FUSE)
  target_compile_definitions(stein_mount PUBLIC STEIN_HAVE_FUSE=1)
endif()

stein_add_test(test_mount
  SOURCES ../core/tests/test_main.cpp tests/test_mount.cpp
  DEPS stein::mount stein::fs)
if(TARGET test_mount)
  # A FUSE request that is never answered blocks uninterruptibly; fail instead of hanging CI.
  set_tests_properties(test_mount PROPERTIES TIMEOUT 180)
endif()
