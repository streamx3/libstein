// SPDX-License-Identifier: MIT
// Hardware CRC32C. This file is compiled with the ISA extension enabled
// (-msse4.2 / -march=armv8-a+crc); callers check crc32cHardwareAvailable().
#include "hash_impl.hpp"
#include "stein/core/cpu.hpp"

#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define STEIN_CRC_X86 1
#include <nmmintrin.h>
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_MSC_VER)
#define STEIN_CRC_ARM 1
#include <arm_acle.h>
#endif

namespace stein::detail {

bool crc32cHardwareAvailable() {
#if defined(STEIN_CRC_X86)
    return cpuFeatures().sse42;
#elif defined(STEIN_CRC_ARM)
    return cpuFeatures().armCrc;
#else
    return false;
#endif
}

std::uint32_t crc32cHardware(std::uint32_t crc, std::span<const std::byte> data) {
#if defined(STEIN_CRC_X86) || defined(STEIN_CRC_ARM)
    const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    while (n && (reinterpret_cast<std::uintptr_t>(p) & 7)) {
#if defined(STEIN_CRC_X86)
        crc = _mm_crc32_u8(crc, *p++);
#else
        crc = __crc32cb(crc, *p++);
#endif
        --n;
    }
#if defined(STEIN_CRC_X86) && (defined(__x86_64__) || defined(_M_X64))
    std::uint64_t c64 = crc;
    while (n >= 8) {
        std::uint64_t v;
        std::memcpy(&v, p, 8);
        c64 = _mm_crc32_u64(c64, v);
        p += 8;
        n -= 8;
    }
    crc = static_cast<std::uint32_t>(c64);
#elif defined(STEIN_CRC_ARM)
    while (n >= 8) {
        std::uint64_t v;
        std::memcpy(&v, p, 8);
        crc = __crc32cd(crc, v);
        p += 8;
        n -= 8;
    }
#endif
    while (n--) {
#if defined(STEIN_CRC_X86)
        crc = _mm_crc32_u8(crc, *p++);
#else
        crc = __crc32cb(crc, *p++);
#endif
    }
    return crc;
#else
    return crc32cPortable(crc, data);
#endif
}

} // namespace stein::detail
