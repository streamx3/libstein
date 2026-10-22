// SPDX-License-Identifier: MIT
#pragma once

#include "stein/core/endian.hpp"

#include <cstddef>
#include <cstdint>

namespace stein::crypto::detail {
// Portable kernels (aes.cpp) and hardware kernels (aes_hw.cpp) over an expanded encryption key schedule.
void aesEncryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
bool aesHardware();
// "aes-ni", "arm-aes", or "portable" when aesHardware() is false.
const char* aesHardwareName();
// The hardware kernels take the round keys as bytes, prepared once per key by aesPrepareHardware:
// `enc` is the schedule as 16-byte round keys, `dec` the equivalent-inverse-cipher schedule
// (InvMixColumns applied to the middle round keys), so a block costs no per-call key work.
void aesPrepareHardware(const std::uint32_t* rk, unsigned rounds, std::uint8_t* enc, std::uint8_t* dec);
void aesEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);

// The XTS tweak as two little-endian 64-bit words. Multiplying by alpha (x in GF(2^128) modulo
// x^128 + x^7 + x^2 + x + 1, IEEE 1619) is a 128-bit shift left with the carry folded back as 0x87;
// two words make that three integer operations instead of a byte loop.
struct XtsTweak {
    std::uint64_t lo = 0, hi = 0;
};
inline void xtsTweakDouble(XtsTweak& t) {
    const std::uint64_t carry = t.hi >> 63;
    t.hi = (t.hi << 1) | (t.lo >> 63);
    t.lo = (t.lo << 1) ^ (carry ? 0x87u : 0u);
}
inline XtsTweak xtsTweakLoad(const std::uint8_t b[16]) {
    const auto* p = reinterpret_cast<const std::byte*>(b);
    return XtsTweak{loadLe64(p), loadLe64(p + 8)};
}
inline void xtsTweakStore(const XtsTweak& t, std::uint8_t b[16]) {
    auto* p = reinterpret_cast<std::byte*>(b);
    storeLe64(p, t.lo);
    storeLe64(p + 8, t.hi);
}

// XTS over one data unit with the hardware AES: `blocks` 16-byte blocks from `in` to `out` (the
// same buffer is allowed), `tweak` the encrypted tweak of the first block (E_K2(sector number)).
// The kernel derives the following tweaks by doubling and runs eight blocks through the rounds
// together, so the pipelined AES unit works on independent blocks instead of waiting for each
// one's fourteen rounds in turn. Only valid when aesHardware() is true.
void aesXtsEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks);
void aesXtsDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t tweak[16], const std::uint8_t* in, std::uint8_t* out, std::size_t blocks);
} // namespace stein::crypto::detail
