// SPDX-License-Identifier: MIT
#include "stein/core/cpu.hpp"

#include <cstdlib>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define STEIN_ARCH_X86 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#define STEIN_ARCH_ARM64 1
#if defined(__linux__)
#include <sys/auxv.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#endif

namespace stein {

namespace {

CpuFeatures detect() {
    CpuFeatures f;
    if (const char* e = std::getenv("STEIN_NO_SIMD"); e && *e && *e != '0') {
        f.disabled = true;
        return f;
    }
#if defined(STEIN_ARCH_X86)
    unsigned b = 0, c = 0;
#if defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 0);
    const unsigned maxLeaf = static_cast<unsigned>(regs[0]);
    if (maxLeaf >= 1) {
        __cpuid(regs, 1);
        c = static_cast<unsigned>(regs[2]);
    }
    bool ssse3 = (c >> 9) & 1, sse41 = (c >> 19) & 1;
    f.sse42 = (c >> 20) & 1;
    f.pclmul = (c >> 1) & 1;
    if (maxLeaf >= 7) {
        __cpuidex(regs, 7, 0);
        b = static_cast<unsigned>(regs[1]);
    }
#else
    unsigned a = 0, d = 0;
    const unsigned maxLeaf = __get_cpuid_max(0, nullptr);
    if (maxLeaf >= 1) __get_cpuid(1, &a, &b, &c, &d);
    bool ssse3 = (c >> 9) & 1, sse41 = (c >> 19) & 1;
    f.sse42 = (c >> 20) & 1;
    f.pclmul = (c >> 1) & 1;
    b = 0;
    if (maxLeaf >= 7) __get_cpuid_count(7, 0, &a, &b, &c, &d);
#endif
    f.shaNi = ((b >> 29) & 1) && ssse3 && sse41;
#elif defined(STEIN_ARCH_ARM64)
#if defined(__APPLE__)
    f.armCrc = true;    // every Apple Silicon / A-series chip since the A7 has both
    f.armSha2 = true;
#elif defined(__linux__)
    const unsigned long hw = getauxval(AT_HWCAP);
    f.armCrc = (hw & (1ul << 7)) != 0;    // HWCAP_CRC32
    f.armSha2 = (hw & (1ul << 6)) != 0;   // HWCAP_SHA2
#elif defined(_WIN32)
    f.armCrc = IsProcessorFeaturePresent(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) != 0;
    f.armSha2 = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#endif
#endif
    return f;
}

} // namespace

const CpuFeatures& cpuFeatures() {
    static const CpuFeatures f = detect();
    return f;
}

std::string CpuFeatures::summary() const {
    if (disabled) return "hardware paths disabled (STEIN_NO_SIMD)";
    std::string s;
    auto add = [&](bool on, const char* name) {
        if (on) s += (s.empty() ? "" : " ") + std::string(name);
    };
    add(sse42, "sse4.2");
    add(pclmul, "pclmul");
    add(shaNi, "sha-ni");
    add(armCrc, "arm-crc");
    add(armSha2, "arm-sha2");
    return s.empty() ? "portable only" : s;
}

} // namespace stein
