// SPDX-License-Identifier: MIT
// Runtime CPU feature detection for the hashing fast paths. Everything has a
// portable fallback; STEIN_NO_SIMD=1 in the environment disables the
// hardware paths (tests use it to cross-check both).
#pragma once

#include <string>

namespace stein {

struct CpuFeatures {
    bool sse42 = false;      // x86: CRC32C instruction
    bool pclmul = false;     // x86: carry-less multiply
    bool shaNi = false;      // x86: SHA extensions (+ SSSE3/SSE4.1 required)
    bool armCrc = false;     // aarch64: CRC32 extension
    bool armSha2 = false;    // aarch64: SHA-256 extension
    bool disabled = false;   // STEIN_NO_SIMD set
    std::string summary() const;
};

const CpuFeatures& cpuFeatures();

} // namespace stein
