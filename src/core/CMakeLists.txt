stein_add_module(core
  SOURCES
    src/error.cpp
    src/units.cpp
    src/guid.cpp
    src/cpu.cpp
    src/crc32.cpp
    src/crc32_hw.cpp
    src/hash.cpp
    src/sha256_hw.cpp
    src/progress.cpp
    src/report.cpp
    src/strings.cpp
    src/log.cpp
    src/json.cpp
    src/lz4.cpp
    src/crypto.cpp
    src/inflate.cpp
    src/bzip2.cpp
    src/aes.cpp
    src/aes_hw.cpp
    src/keys.cpp)

# The hardware kernels are compiled with their ISA extension enabled; they run
# only after cpuFeatures() confirms the CPU has it.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|i686")
    set_source_files_properties(src/crc32_hw.cpp PROPERTIES COMPILE_OPTIONS "-msse4.2")
    set_source_files_properties(src/sha256_hw.cpp PROPERTIES COMPILE_OPTIONS "-mssse3;-msse4.1;-msha")
    set_source_files_properties(src/aes_hw.cpp PROPERTIES COMPILE_OPTIONS "-msse2;-maes")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set_source_files_properties(src/crc32_hw.cpp PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crc")
    set_source_files_properties(src/sha256_hw.cpp PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
    set_source_files_properties(src/aes_hw.cpp PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
  endif()
endif()

if(WIN32)
  target_link_libraries(stein_core PRIVATE bcrypt)
endif()

stein_add_test(test_core
  SOURCES tests/test_main.cpp tests/test_core.cpp tests/test_json_lz4.cpp tests/test_crypto.cpp
  DEPS stein::core)
