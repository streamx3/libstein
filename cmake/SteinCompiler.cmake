# Compiler settings shared by every stein target.

find_program(STEIN_CCACHE ccache)
if(STEIN_CCACHE AND NOT CMAKE_CXX_COMPILER_LAUNCHER)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${STEIN_CCACHE}" CACHE STRING "" FORCE)
  message(STATUS "stein: using ccache at ${STEIN_CCACHE}")
endif()

add_library(stein_compiler_flags INTERFACE)
add_library(stein::compiler_flags ALIAS stein_compiler_flags)

if(MSVC)
  target_compile_options(stein_compiler_flags INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  if(STEIN_WERROR)
    target_compile_options(stein_compiler_flags INTERFACE /WX)
  endif()
else()
  target_compile_options(stein_compiler_flags INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual
    -Wcast-align -Wformat=2 -Wimplicit-fallthrough)
  if(STEIN_WERROR)
    target_compile_options(stein_compiler_flags INTERFACE -Werror)
  endif()
  if(STEIN_SANITIZERS)
    target_compile_options(stein_compiler_flags INTERFACE
      $<$<CONFIG:Debug>:-fsanitize=address,undefined -fno-omit-frame-pointer>)
    target_link_options(stein_compiler_flags INTERFACE
      $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
  endif()
endif()
