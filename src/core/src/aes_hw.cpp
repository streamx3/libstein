// SPDX-License-Identifier: MIT
// AES-NI (x86) and ARMv8 Crypto Extension kernels. Compiled with the ISA
// enabled; used only when cpuFeatures() reports support.
#include "aes_impl.hpp"
#include "stein/core/cpu.hpp"
#include "stein/core/endian.hpp"

#include <cstring>
#include <utility>

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

const char* aesHardwareName() {
    if (!aesHardware()) return "portable";
#if defined(STEIN_AES_X86)
    return "aes-ni";
#elif defined(STEIN_AES_ARM)
    return "arm-aes";
#else
    return "portable";
#endif
}

#if defined(STEIN_AES_X86) || defined(STEIN_AES_ARM)
namespace {
// The XTS kernels below are written over index packs so that every lane lives in its own
// register: a loop over a runtime index would keep the eight states in memory. Eight lanes
// match the AES unit's latency/throughput ratio on current x86 and Apple/ARM cores.
constexpr std::size_t kXtsLanes = 8;
using XtsLanes = std::make_index_sequence<kXtsLanes>;
using XtsLane = std::index_sequence<0>;

// Writes the tweaks of the next `n` blocks (16 bytes each) and advances `t` past them.
inline void nextTweaks(XtsTweak& t, std::uint8_t* out, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        xtsTweakStore(t, out + 16 * i);
        xtsTweakDouble(t);
    }
}
} // namespace
#endif

#if defined(STEIN_AES_X86)

namespace {
inline __m128i key(const std::uint8_t* k, unsigned r) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(k + 16 * r)); }
inline __m128i load(const std::uint8_t* p) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(p)); }
inline void store(std::uint8_t* p, __m128i v) { _mm_storeu_si128(reinterpret_cast<__m128i*>(p), v); }

template <std::size_t... I>
inline void xtsEncryptLanes(const std::uint8_t* enc, unsigned rounds, const std::uint8_t* tw, const std::uint8_t* in, std::uint8_t* out, std::index_sequence<I...>) {
    __m128i t[sizeof...(I)], s[sizeof...(I)];
    ((t[I] = load(tw + 16 * I)), ...);
    const __m128i k0 = key(enc, 0);
    ((s[I] = _mm_xor_si128(_mm_xor_si128(load(in + 16 * I), t[I]), k0)), ...);
    for (unsigned r = 1; r < rounds; ++r) {
        const __m128i k = key(enc, r);
        ((s[I] = _mm_aesenc_si128(s[I], k)), ...);
    }
    const __m128i kLast = key(enc, rounds);
    (store(out + 16 * I, _mm_xor_si128(_mm_aesenclast_si128(s[I], kLast), t[I])), ...);
}

template <std::size_t... I>
inline void xtsDecryptLanes(const std::uint8_t* dec, unsigned rounds, const std::uint8_t* tw, const std::uint8_t* in, std::uint8_t* out, std::index_sequence<I...>) {
    __m128i t[sizeof...(I)], s[sizeof...(I)];
    ((t[I] = load(tw + 16 * I)), ...);
    const __m128i k0 = key(dec, rounds);
    ((s[I] = _mm_xor_si128(_mm_xor_si128(load(in + 16 * I), t[I]), k0)), ...);
    for (unsigned r = rounds - 1; r > 0; --r) {
        const __m128i k = key(dec, r);
        ((s[I] = _mm_aesdec_si128(s[I], k)), ...);
    }
    const __m128i kLast = key(dec, 0);
    (store(out + 16 * I, _mm_xor_si128(_mm_aesdeclast_si128(s[I], kLast), t[I])), ...);
}
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

void aesXtsEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) {
    XtsTweak t = xtsTweakLoad(tweak);
    alignas(16) std::uint8_t tw[16 * kXtsLanes];
    for (; blocks >= kXtsLanes; blocks -= kXtsLanes, in += 16 * kXtsLanes, out += 16 * kXtsLanes) {
        nextTweaks(t, tw, kXtsLanes);
        xtsEncryptLanes(enc, rounds, tw, in, out, XtsLanes{});
    }
    for (; blocks > 0; --blocks, in += 16, out += 16) {
        nextTweaks(t, tw, 1);
        xtsEncryptLanes(enc, rounds, tw, in, out, XtsLane{});
    }
}

void aesXtsDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) {
    XtsTweak t = xtsTweakLoad(tweak);
    alignas(16) std::uint8_t tw[16 * kXtsLanes];
    for (; blocks >= kXtsLanes; blocks -= kXtsLanes, in += 16 * kXtsLanes, out += 16 * kXtsLanes) {
        nextTweaks(t, tw, kXtsLanes);
        xtsDecryptLanes(dec, rounds, tw, in, out, XtsLanes{});
    }
    for (; blocks > 0; --blocks, in += 16, out += 16) {
        nextTweaks(t, tw, 1);
        xtsDecryptLanes(dec, rounds, tw, in, out, XtsLane{});
    }
}

#elif defined(STEIN_AES_ARM)

namespace {
inline uint8x16_t key(const std::uint8_t* k, unsigned r) { return vld1q_u8(k + 16 * r); }
// Clang's arm_neon.h defines the intrinsics as statement-expression macros, and a parameter pack
// cannot expand inside those; these one-line functions give the fold expressions below something to call.
inline uint8x16_t load(const std::uint8_t* p) { return vld1q_u8(p); }
inline void store(std::uint8_t* p, uint8x16_t v) { vst1q_u8(p, v); }
inline uint8x16_t veor(uint8x16_t a, uint8x16_t b) { return veorq_u8(a, b); }
inline uint8x16_t aeseMc(uint8x16_t s, uint8x16_t k) { return vaesmcq_u8(vaeseq_u8(s, k)); }
inline uint8x16_t aese(uint8x16_t s, uint8x16_t k) { return vaeseq_u8(s, k); }
inline uint8x16_t aesdImc(uint8x16_t s, uint8x16_t k) { return vaesimcq_u8(vaesdq_u8(s, k)); }
inline uint8x16_t aesd(uint8x16_t s, uint8x16_t k) { return vaesdq_u8(s, k); }

// AESE/AESD fold AddRoundKey into the round, so the final round key is a plain XOR afterwards
// (see aesEncryptHardware / aesDecryptHardware below for the single-block shape).
template <std::size_t... I>
inline void xtsEncryptLanes(const std::uint8_t* enc, unsigned rounds, const std::uint8_t* tw, const std::uint8_t* in, std::uint8_t* out, std::index_sequence<I...>) {
    uint8x16_t t[sizeof...(I)], s[sizeof...(I)];
    ((t[I] = load(tw + 16 * I)), ...);
    ((s[I] = veor(load(in + 16 * I), t[I])), ...);
    for (unsigned r = 0; r < rounds - 1; ++r) {
        const uint8x16_t k = key(enc, r);
        ((s[I] = aeseMc(s[I], k)), ...);
    }
    const uint8x16_t kPen = key(enc, rounds - 1);
    ((s[I] = aese(s[I], kPen)), ...);
    const uint8x16_t kLast = key(enc, rounds);
    (store(out + 16 * I, veor(veor(s[I], kLast), t[I])), ...);
}

template <std::size_t... I>
inline void xtsDecryptLanes(const std::uint8_t* dec, unsigned rounds, const std::uint8_t* tw, const std::uint8_t* in, std::uint8_t* out, std::index_sequence<I...>) {
    uint8x16_t t[sizeof...(I)], s[sizeof...(I)];
    ((t[I] = load(tw + 16 * I)), ...);
    ((s[I] = veor(load(in + 16 * I), t[I])), ...);
    const uint8x16_t kFirst = key(dec, rounds);
    ((s[I] = aesdImc(s[I], kFirst)), ...);
    for (unsigned r = rounds - 1; r > 1; --r) {
        const uint8x16_t k = key(dec, r);
        ((s[I] = aesdImc(s[I], k)), ...);
    }
    const uint8x16_t kPen = key(dec, 1);
    ((s[I] = aesd(s[I], kPen)), ...);
    const uint8x16_t kLast = key(dec, 0);
    (store(out + 16 * I, veor(veor(s[I], kLast), t[I])), ...);
}
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

void aesXtsEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) {
    XtsTweak t = xtsTweakLoad(tweak);
    alignas(16) std::uint8_t tw[16 * kXtsLanes];
    for (; blocks >= kXtsLanes; blocks -= kXtsLanes, in += 16 * kXtsLanes, out += 16 * kXtsLanes) {
        nextTweaks(t, tw, kXtsLanes);
        xtsEncryptLanes(enc, rounds, tw, in, out, XtsLanes{});
    }
    for (; blocks > 0; --blocks, in += 16, out += 16) {
        nextTweaks(t, tw, 1);
        xtsEncryptLanes(enc, rounds, tw, in, out, XtsLane{});
    }
}

void aesXtsDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) {
    XtsTweak t = xtsTweakLoad(tweak);
    alignas(16) std::uint8_t tw[16 * kXtsLanes];
    for (; blocks >= kXtsLanes; blocks -= kXtsLanes, in += 16 * kXtsLanes, out += 16 * kXtsLanes) {
        nextTweaks(t, tw, kXtsLanes);
        xtsDecryptLanes(dec, rounds, tw, in, out, XtsLanes{});
    }
    for (; blocks > 0; --blocks, in += 16, out += 16) {
        nextTweaks(t, tw, 1);
        xtsDecryptLanes(dec, rounds, tw, in, out, XtsLane{});
    }
}

#else

// No hardware AES on this target: aesHardware() is false, so none of these is ever called.
void aesPrepareHardware(const std::uint32_t*, unsigned, std::uint8_t*, std::uint8_t*) {}
void aesEncryptHardware(const std::uint8_t*, unsigned, const std::uint8_t in[16], std::uint8_t out[16]) { std::memcpy(out, in, 16); }
void aesDecryptHardware(const std::uint8_t*, unsigned, const std::uint8_t in[16], std::uint8_t out[16]) { std::memcpy(out, in, 16); }
void aesXtsEncryptHardware(const std::uint8_t*, unsigned, const std::uint8_t[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) { std::memmove(out, in, 16 * blocks); }
void aesXtsDecryptHardware(const std::uint8_t*, unsigned, const std::uint8_t[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks) { std::memmove(out, in, 16 * blocks); }

#endif

} // namespace stein::crypto::detail
