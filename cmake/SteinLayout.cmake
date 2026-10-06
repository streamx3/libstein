# stein_add_layouts(<target> <manifest.layout.toml>...)
# Generates stein/layout/gen/<base>.hpp and <base>.cpp from each manifest at
# build time and adds them to <target>. Python 3.11+ (tomllib) is a build-time
# dependency only.
find_package(Python3 3.11 COMPONENTS Interpreter REQUIRED)

set(STEIN_LAYOUT_GEN "${PROJECT_SOURCE_DIR}/tools/layout_gen/layout_gen.py" CACHE INTERNAL "")

function(stein_add_layouts target)
  foreach(manifest ${ARGN})
    get_filename_component(base "${manifest}" NAME_WE)
    set(out_hpp "${CMAKE_CURRENT_BINARY_DIR}/include/stein/layout/gen/${base}.hpp")
    set(out_cpp "${CMAKE_CURRENT_BINARY_DIR}/gen/${base}.cpp")
    add_custom_command(
      OUTPUT "${out_hpp}" "${out_cpp}"
      COMMAND Python3::Interpreter "${STEIN_LAYOUT_GEN}" "${manifest}" --hpp "${out_hpp}" --cpp "${out_cpp}"
      DEPENDS "${manifest}" "${STEIN_LAYOUT_GEN}"
      COMMENT "layout_gen: ${base}"
      VERBATIM)
    target_sources(${target} PRIVATE "${out_cpp}" "${out_hpp}")
  endforeach()
  target_include_directories(${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)
endfunction()
