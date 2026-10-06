// SPDX-License-Identifier: MIT
// SHA-256 compression with the x86 SHA extensions or the ARMv8 SHA-2
// extension. Compiled with the ISA enabled; callers check availability.
// Structure follows Intel's and ARM's reference sequences.
#include "hash_impl.hpp"
#include "stein/core/cpu.hpp"

#if defined(__x86_64__) || defined(_M_X64)
#define STEIN_SHA_X86 1
#include <immintrin.h>
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_MSC_VER)
#define STEIN_SHA_ARM 1
#include <arm_neon.h>
#endif

namespace stein::detail {

namespace {
alignas(16) constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
} // namespace

bool sha256HardwareAvailable() {
#if defined(STEIN_SHA_X86)
    return cpuFeatures().shaNi;
#elif defined(STEIN_SHA_ARM)
    return cpuFeatures().armSha2;
#else
    return false;
#endif
}

#if defined(STEIN_SHA_X86)

void sha256Hardware(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks) {
    const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bll, 0x0405060700010203ll);
    __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    tmp = _mm_shuffle_epi32(tmp, 0xB1);                   // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B);             // EFGH
    __m128i state0 = _mm_alignr_epi8(tmp, state1, 8);     // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);          // CDGH

    while (blocks--) {
        const __m128i save0 = state0, save1 = state1;
        __m128i m[4];
        for (int j = 0; j < 16; ++j) {
            __m128i msg;
            if (j < 4) {
                m[j] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16 * j)), mask);
            }
            msg = _mm_add_epi32(m[j & 3], _mm_load_si128(reinterpret_cast<const __m128i*>(&kK[4 * j])));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            if (j >= 3 && j <= 14) {
                // Message schedule for the block four rounds ahead.
                const __m128i t = _mm_alignr_epi8(m[j & 3], m[(j + 3) & 3], 4);
                m[(j + 1) & 3] = _mm_add_epi32(m[(j + 1) & 3], t);
                m[(j + 1) & 3] = _mm_sha256msg2_epu32(m[(j + 1) & 3], m[j & 3]);
            }
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            if (j >= 1 && j <= 12) m[(j + 3) & 3] = _mm_sha256msg1_epu32(m[(j + 3) & 3], m[j & 3]);
        }
        state0 = _mm_add_epi32(state0, save0);
        state1 = _mm_add_epi32(state1, save1);
        data += 64;
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B);                // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1);             // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);          // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8);             // HGFE
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), state0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), state1);
}

#elif defined(STEIN_SHA_ARM)

void sha256Hardware(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks) {
    uint32x4_t state0 = vld1q_u32(&state[0]);
    uint32x4_t state1 = vld1q_u32(&state[4]);
    while (blocks--) {
        const uint32x4_t save0 = state0, save1 = state1;
        uint32x4_t m[4];
        for (int i = 0; i < 4; ++i) m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16 * i)));
        uint32x4_t cur = vaddq_u32(m[0], vld1q_u32(&kK[0]));
        for (int j = 0; j < 16; ++j) {
            if (j <= 11) m[j & 3] = vsha256su0q_u32(m[j & 3], m[(j + 1) & 3]);
            const uint32x4_t t2 = state0;
            uint32x4_t next = cur;
            if (j < 15) next = vaddq_u32(m[(j + 1) & 3], vld1q_u32(&kK[4 * (j + 1)]));
            state0 = vsha256hq_u32(state0, state1, cur);
            state1 = vsha256h2q_u32(state1, t2, cur);
            if (j <= 11) m[j & 3] = vsha256su1q_u32(m[j & 3], m[(j + 2) & 3], m[(j + 3) & 3]);
            cur = next;
        }
        state0 = vaddq_u32(state0, save0);
        state1 = vaddq_u32(state1, save1);
        data += 64;
    }
    vst1q_u32(&state[0], state0);
    vst1q_u32(&state[4], state1);
}

#else

void sha256Hardware(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks) { sha256Portable(state, data, blocks); }

#endif

} // namespace stein::detail
