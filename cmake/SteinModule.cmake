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
#
# Install/export: every module (or the monolithic `stein`) joins the
# `steinTargets` export set; headers go to <prefix>/include; the package
# config installed by stein_install_package() lets consumers write
# find_package(stein CONFIG) and link stein::<module>.

include(GNUInstallDirs)

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
  set_property(GLOBAL APPEND PROPERTY STEIN_MODULE_NAMES ${name})
  target_include_directories(${target}
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(${target}
    PUBLIC  ${ARG_PUBLIC_DEPS}
    PRIVATE stein::compiler_flags ${ARG_PRIVATE_DEPS})
  target_compile_features(${target} PUBLIC cxx_std_23)
  set_target_properties(${target} PROPERTIES FOLDER "stein" EXPORT_NAME ${name})
  # Public headers (and the generated ones, when the module has any).
  install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.hpp")
  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL FILES_MATCHING PATTERN "*.hpp")
  if(NOT STEIN_MONOLITHIC)
    install(TARGETS ${target} EXPORT steinTargets
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
endfunction()

function(stein_finalize_modules)
  if(STEIN_MONOLITHIC)
    get_property(mods GLOBAL PROPERTY STEIN_MODULE_TARGETS)
    add_library(stein SHARED)
    # The object libraries are private to the single library; their public usage requirements
    # (include directories, compile definitions such as STEIN_HAVE_FUSE) are copied onto it so the
    # exported target carries them without exporting the object libraries themselves.
    target_link_libraries(stein PRIVATE ${mods})
    foreach(mod ${mods})
      get_target_property(incs ${mod} INTERFACE_INCLUDE_DIRECTORIES)
      if(incs)
        target_include_directories(stein INTERFACE ${incs})
      endif()
      get_target_property(defs ${mod} INTERFACE_COMPILE_DEFINITIONS)
      if(defs)
        target_compile_definitions(stein INTERFACE ${defs})
      endif()
      get_target_property(libs ${mod} INTERFACE_LINK_LIBRARIES)
      if(libs)
        foreach(lib ${libs})
          if(NOT lib MATCHES "^stein::" AND NOT lib IN_LIST mods)
            target_link_libraries(stein INTERFACE ${lib})
          endif()
        endforeach()
      endif()
    endforeach()
    target_compile_features(stein INTERFACE cxx_std_23)
    set_target_properties(stein PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR} EXPORT_NAME stein)
    install(TARGETS stein EXPORT steinTargets
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
endfunction()

# The CMake package: steinTargets.cmake, steinConfig.cmake, steinConfigVersion.cmake under
# <prefix>/lib/cmake/stein. Call after every module is declared.
function(stein_install_package)
  include(CMakePackageConfigHelpers)
  get_property(STEIN_MODULE_NAMES GLOBAL PROPERTY STEIN_MODULE_NAMES)
  string(REPLACE ";" " " STEIN_MODULE_NAMES "${STEIN_MODULE_NAMES}")
  set(dest ${CMAKE_INSTALL_LIBDIR}/cmake/stein)
  install(EXPORT steinTargets NAMESPACE stein:: DESTINATION ${dest} FILE steinTargets.cmake)
  configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/steinConfig.cmake.in
    ${PROJECT_BINARY_DIR}/steinConfig.cmake INSTALL_DESTINATION ${dest})
  write_basic_package_version_file(${PROJECT_BINARY_DIR}/steinConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
  install(FILES ${PROJECT_BINARY_DIR}/steinConfig.cmake ${PROJECT_BINARY_DIR}/steinConfigVersion.cmake DESTINATION ${dest})
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
