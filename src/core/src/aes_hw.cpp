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
inline __m128i key(const std::uint8_t* k, unsigned r) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(k + 16 * r)); }
} // namespace

void aesPrepareHardware(const std::uint32_t* rk, unsigned rounds, std::uint8_t* enc, std::uint8_t* dec) {
    // Round keys are big-endian words in FIPS column order; as bytes in memory that is exactly the 16-byte round key.
    for (unsigned i = 0; i < 4 * (rounds + 1); ++i) storeBe32(reinterpret_cast<std::byte*>(enc) + 4 * i, rk[i]);
    std::memcpy(dec, enc, 16);
    std::memcpy(dec + 16 * rounds, enc + 16 * rounds, 16);
    for (unsigned r = 1; r < rounds; ++r) _mm_storeu_si128(reinterpret_cast<__m128i*>(dec + 16 * r), _mm_aesimc_si128(key(enc, r)));
}

void aesEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    __m128i s = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)), key(enc, 0));
    for (unsigned r = 1; r < rounds; ++r) s = _mm_aesenc_si128(s, key(enc, r));
    s = _mm_aesenclast_si128(s, key(enc, rounds));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), s);
}

void aesDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    __m128i s = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)), key(dec, rounds));
    for (unsigned r = rounds - 1; r > 0; --r) s = _mm_aesdec_si128(s, key(dec, r));
    s = _mm_aesdeclast_si128(s, key(dec, 0));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), s);
}

#elif defined(STEIN_AES_ARM)

namespace {
inline uint8x16_t key(const std::uint8_t* k, unsigned r) { return vld1q_u8(k + 16 * r); }
} // namespace

void aesPrepareHardware(const std::uint32_t* rk, unsigned rounds, std::uint8_t* enc, std::uint8_t* dec) {
    for (unsigned i = 0; i < 4 * (rounds + 1); ++i) storeBe32(reinterpret_cast<std::byte*>(enc) + 4 * i, rk[i]);
    // Equivalent inverse cipher: AESD folds AddRoundKey before InvShiftRows/InvSubBytes, so the
    // middle-round keys must be InvMixColumns-transformed (first and last are used as is).
    std::memcpy(dec, enc, 16);
    std::memcpy(dec + 16 * rounds, enc + 16 * rounds, 16);
    for (unsigned r = 1; r < rounds; ++r) vst1q_u8(dec + 16 * r, vaesimcq_u8(key(enc, r)));
}

void aesEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    for (unsigned r = 0; r < rounds - 1; ++r) s = vaesmcq_u8(vaeseq_u8(s, key(enc, r)));
    s = vaeseq_u8(s, key(enc, rounds - 1));
    s = veorq_u8(s, key(enc, rounds));
    vst1q_u8(out, s);
}

void aesDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    s = vaesimcq_u8(vaesdq_u8(s, key(dec, rounds)));
    for (unsigned r = rounds - 1; r > 1; --r) s = vaesimcq_u8(vaesdq_u8(s, key(dec, r)));
    s = vaesdq_u8(s, key(dec, 1));
    s = veorq_u8(s, key(dec, 0));
    vst1q_u8(out, s);
}

#else

void aesPrepareHardware(const std::uint32_t*, unsigned, std::uint8_t*, std::uint8_t*) {}
void aesEncryptHardware(const std::uint8_t*, unsigned, const std::uint8_t in[16], std::uint8_t out[16]) { std::memcpy(out, in, 16); }
void aesDecryptHardware(const std::uint8_t*, unsigned, const std::uint8_t in[16], std::uint8_t out[16]) { std::memcpy(out, in, 16); }

#endif

} // namespace stein::crypto::detail
