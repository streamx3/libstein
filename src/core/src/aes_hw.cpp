// SPDX-License-Identifier: MIT
// AES-NI (x86) and ARMv8 Crypto Extension kernels. Compiled with the ISA
// enabled; used only when cpuFeatures() reports support.
#include "aes_impl.hpp"
#include "stein/core/cpu.hpp"
#include "stein/core/endian.hpp"

#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#define STEIN_AES_X86 1
#include <immintrin.h>
#include <wmmintrin.h>
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_MSC_VER)
#define STEIN_AES_ARM 1
#include <arm_neon.h>
#endif

namespace stein::crypto::detail {

bool aesHardware() {
#if defined(STEIN_AES_X86)
    return cpuFeatures().aesni;
#elif defined(STEIN_AES_ARM)
    return cpuFeatures().armAes;
#else
    return false;
#endif
}

#if defined(STEIN_AES_X86)

namespace {
// Round keys are big-endian words in FIPS column order; as bytes in memory that is exactly the 16-byte round key.
inline __m128i roundKey(const std::uint32_t* rk, unsigned r) {
    std::uint8_t b[16];
    for (int i = 0; i < 4; ++i) storeBe32(reinterpret_cast<std::byte*>(b) + 4 * i, rk[4 * r + i]);
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(b));
}
} // namespace

void aesEncryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    __m128i s = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)), roundKey(rk, 0));
    for (unsigned r = 1; r < rounds; ++r) s = _mm_aesenc_si128(s, roundKey(rk, r));
    s = _mm_aesenclast_si128(s, roundKey(rk, rounds));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), s);
}

void aesDecryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    __m128i s = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)), roundKey(rk, rounds));
    for (unsigned r = rounds - 1; r > 0; --r) s = _mm_aesdec_si128(s, _mm_aesimc_si128(roundKey(rk, r)));
    s = _mm_aesdeclast_si128(s, roundKey(rk, 0));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), s);
}

#elif defined(STEIN_AES_ARM)

namespace {
inline uint8x16_t roundKey(const std::uint32_t* rk, unsigned r) {
    std::uint8_t b[16];
    for (int i = 0; i < 4; ++i) storeBe32(reinterpret_cast<std::byte*>(b) + 4 * i, rk[4 * r + i]);
    return vld1q_u8(b);
}
} // namespace

void aesEncryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    for (unsigned r = 0; r < rounds - 1; ++r) s = vaesmcq_u8(vaeseq_u8(s, roundKey(rk, r)));
    s = vaeseq_u8(s, roundKey(rk, rounds - 1));
    s = veorq_u8(s, roundKey(rk, rounds));
    vst1q_u8(out, s);
}

void aesDecryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    for (unsigned r = rounds; r > 1; --r) s = vaesimcq_u8(vaesdq_u8(s, roundKey(rk, r)));
    s = vaesdq_u8(s, roundKey(rk, 1));
    s = veorq_u8(s, roundKey(rk, 0));
    vst1q_u8(out, s);
}

#else

void aesEncryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) { aesEncryptPortable(rk, rounds, in, out); }
void aesDecryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) { aesDecryptPortable(rk, rounds, in, out); }

#endif

} // namespace stein::crypto::detail
