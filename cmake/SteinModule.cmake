# stein_add_module(<name>
#     SOURCES <files...>
#     [PUBLIC_DEPS <stein modules or targets...>]
#     [PRIVATE_DEPS <targets...>])
#
# Creates target stein_<name> with alias stein::<name>. Public headers live in
# <module dir>/include and are exported to dependants. Each module is a shared
# library by default; with STEIN_MONOLITHIC=ON every module becomes an OBJECT
# library and stein_finalize_modules() links them into one shared `stein`.
#
# stein_add_test(<name> SOURCES <files...> DEPS <targets...>)
#   Builds a doctest executable and registers it with CTest.

function(stein_add_module name)
  cmake_parse_arguments(ARG "" "" "SOURCES;PUBLIC_DEPS;PRIVATE_DEPS" ${ARGN})
  set(target stein_${name})
  if(STEIN_MONOLITHIC)
    add_library(${target} OBJECT ${ARG_SOURCES})
    set_property(GLOBAL APPEND PROPERTY STEIN_MODULE_TARGETS ${target})
  else()
    add_library(${target} SHARED ${ARG_SOURCES})
    set_target_properties(${target} PROPERTIES
      VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR}
      OUTPUT_NAME stein_${name})
  endif()
  add_library(stein::${name} ALIAS ${target})
  target_include_directories(${target}
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(${target}
    PUBLIC  ${ARG_PUBLIC_DEPS}
    PRIVATE stein::compiler_flags ${ARG_PRIVATE_DEPS})
  target_compile_features(${target} PUBLIC cxx_std_23)
  set_target_properties(${target} PROPERTIES FOLDER "stein")
endfunction()

function(stein_finalize_modules)
  if(STEIN_MONOLITHIC)
    get_property(mods GLOBAL PROPERTY STEIN_MODULE_TARGETS)
    add_library(stein SHARED)
    target_link_libraries(stein PUBLIC ${mods})
    set_target_properties(stein PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
  endif()
endfunction()

function(stein_add_test name)
  if(NOT STEIN_BUILD_TESTS)
    return()
  endif()
  cmake_parse_arguments(ARG "" "" "SOURCES;DEPS" ${ARGN})
  add_executable(${name} ${ARG_SOURCES})
  target_link_libraries(${name} PRIVATE stein_doctest stein::compiler_flags ${ARG_DEPS})
  target_compile_definitions(${name} PRIVATE
    STEIN_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
    STEIN_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures")
  add_test(NAME ${name} COMMAND ${name})
  set_target_properties(${name} PROPERTIES FOLDER "stein/tests")
endfunction()
