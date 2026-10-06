cmake_minimum_required(VERSION 3.25)
project(libstein VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)   # TODO(M2): proper export macros per module
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(STEIN_BUILD_TESTS    "Build unit tests"                               ON)
option(STEIN_BUILD_TOOLS    "Build the stein command-line tool"              ON)
option(STEIN_MONOLITHIC     "Link all modules into a single libstein"        OFF)
option(STEIN_WERROR         "Treat warnings as errors"                       OFF)
option(STEIN_SANITIZERS     "Enable ASan/UBSan in Debug builds"              OFF)
option(STEIN_FIXTURE_TOOLS  "Regenerate test fixtures with system tools when available" OFF)

include(SteinCompiler)
include(SteinModule)

if(STEIN_BUILD_TESTS)
  enable_testing()
  add_library(stein_doctest INTERFACE)
  target_compile_definitions(stein_doctest INTERFACE DOCTEST_CONFIG_DOUBLE_STRINGIFY)
  target_include_directories(stein_doctest INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/doctest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/include)
endif()

# ---------------------------------------------------------------------------
# Modules (dependency order; see doc/design/10-architecture.md)
# ---------------------------------------------------------------------------
foreach(mod core layout block pt fs probe platform image ops)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/${mod}/CMakeLists.txt)
    add_subdirectory(src/${mod})
  endif()
endforeach()

if(STEIN_BUILD_TOOLS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tools/stein/CMakeLists.txt)
  add_subdirectory(tools/stein)
endif()

stein_finalize_modules()
