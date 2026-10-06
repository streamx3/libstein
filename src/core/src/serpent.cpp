// SPDX-License-Identifier: MIT
// Serpent (Anderson, Biham, Knudsen), bitsliced form. The S-boxes are applied
// word-parallel by evaluating their truth tables (sixteen minterms, each an
// AND of the four input words or their complements, OR-ed per output bit
// with compile-time masks), which keeps the code a plain transcription of
// the specification's tables rather than hand-optimised boolean formulas.
#include "stein/core/cipher.hpp"

#include "stein/core/endian.hpp"

#include <bit>
#include <cstring>
#include <utility>

namespace stein::crypto {

namespace {

constexpr std::uint8_t kSbox[8][16] = {
    {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
    {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
    {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
    {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
    {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
    {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
    {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
    {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6},
};
constexpr std::uint32_t kPhi = 0x9e3779b9u;

constexpr std::uint8_t inverse(int s, int y) {
    for (int v = 0; v < 16; ++v)
        if (kSbox[s][v] == y) return static_cast<std::uint8_t>(v);
    return 0;
}

// For S-box `s` (or its inverse) and output bit `j`: the set of input nibbles whose image has
// bit j set, as a 16-bit mask. Computed at compile time so the OR-trees below are fixed.
constexpr std::uint16_t minterms(int s, bool inv, int j) {
    std::uint16_t m = 0;
    for (int v = 0; v < 16; ++v) {
        const int y = inv ? inverse(s, v) : kSbox[s][v];
        if ((y >> j) & 1) m = static_cast<std::uint16_t>(m | (1u << v));
    }
    return m;
}

template <std::uint16_t Mask, std::size_t... I>
constexpr std::uint32_t orSelected(const std::uint32_t (&m)[16], std::index_sequence<I...>) {
    return ((((Mask >> I) & 1u) ? m[I] : 0u) | ... | 0u);
}

// x[0..3] hold bit i of nibble i for all 32 positions; replace each nibble by table[nibble]. The
// sixteen minterms (AND of the four inputs or their complements) are shared by the four outputs.
template <int S, bool Inv>
inline void applySbox(std::uint32_t x[4]) {
    const std::uint32_t n0 = ~x[0], n1 = ~x[1], n2 = ~x[2], n3 = ~x[3];
    const std::uint32_t a[4] = {n0 & n1, x[0] & n1, n0 & x[1], x[0] & x[1]};
    const std::uint32_t b[4] = {n2 & n3, x[2] & n3, n2 & x[3], x[2] & x[3]};
    const std::uint32_t m[16] = {a[0] & b[0], a[1] & b[0], a[2] & b[0], a[3] & b[0], a[0] & b[1], a[1] & b[1], a[2] & b[1], a[3] & b[1],
                                 a[0] & b[2], a[1] & b[2], a[2] & b[2], a[3] & b[2], a[0] & b[3], a[1] & b[3], a[2] & b[3], a[3] & b[3]};
    using Seq = std::make_index_sequence<16>;
    x[0] = orSelected<minterms(S, Inv, 0)>(m, Seq{});
    x[1] = orSelected<minterms(S, Inv, 1)>(m, Seq{});
    x[2] = orSelected<minterms(S, Inv, 2)>(m, Seq{});
    x[3] = orSelected<minterms(S, Inv, 3)>(m, Seq{});
}

template <bool Inv>
inline void applySbox(int s, std::uint32_t x[4]) {
    switch (s & 7) {
    case 0: applySbox<0, Inv>(x); break;
    case 1: applySbox<1, Inv>(x); break;
    case 2: applySbox<2, Inv>(x); break;
    case 3: applySbox<3, Inv>(x); break;
    case 4: applySbox<4, Inv>(x); break;
    case 5: applySbox<5, Inv>(x); break;
    case 6: applySbox<6, Inv>(x); break;
    default: applySbox<7, Inv>(x); break;
    }
}

inline void linear(std::uint32_t x[4]) {
    x[0] = std::rotl(x[0], 13);
    x[2] = std::rotl(x[2], 3);
    x[1] ^= x[0] ^ x[2];
    x[3] ^= x[2] ^ (x[0] << 3);
    x[1] = std::rotl(x[1], 1);
    x[3] = std::rotl(x[3], 7);
    x[0] ^= x[1] ^ x[3];
    x[2] ^= x[3] ^ (x[1] << 7);
    x[0] = std::rotl(x[0], 5);
    x[2] = std::rotl(x[2], 22);
}

inline void linearInverse(std::uint32_t x[4]) {
    x[2] = std::rotr(x[2], 22);
    x[0] = std::rotr(x[0], 5);
    x[2] ^= x[3] ^ (x[1] << 7);
    x[0] ^= x[1] ^ x[3];
    x[3] = std::rotr(x[3], 7);
    x[1] = std::rotr(x[1], 1);
    x[3] ^= x[2] ^ (x[0] << 3);
    x[1] ^= x[0] ^ x[2];
    x[2] = std::rotr(x[2], 3);
    x[0] = std::rotr(x[0], 13);
}

} // namespace

Expected<Serpent> Serpent::create(std::span<const std::uint8_t> key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) return fail(ErrorCategory::InvalidArgument, "Serpent key must be 16, 24 or 32 bytes");
    std::uint8_t padded[32] = {};
    std::memcpy(padded, key.data(), key.size());
    if (key.size() < 32) padded[key.size()] = 1;   // short keys: a 1 bit then zeros
    std::uint32_t w[140];                           // w[-8..131] shifted by 8
    for (int i = 0; i < 8; ++i) w[i] = loadLe32(reinterpret_cast<const std::byte*>(padded + 4 * i));
    for (int i = 0; i < 132; ++i) w[i + 8] = std::rotl(w[i] ^ w[i + 3] ^ w[i + 5] ^ w[i + 7] ^ kPhi ^ static_cast<std::uint32_t>(i), 11);
    Serpent s;
    for (int i = 0; i < 33; ++i) {
        std::uint32_t x[4] = {w[8 + 4 * i], w[9 + 4 * i], w[10 + 4 * i], w[11 + 4 * i]};
        applySbox<false>((3 - i) & 7, x);
        for (int j = 0; j < 4; ++j) s.m_k[4 * i + j] = x[j];
    }
    return s;
}

void Serpent::encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint32_t x[4];
    for (int i = 0; i < 4; ++i) x[i] = loadLe32(reinterpret_cast<const std::byte*>(in + 4 * i));
    for (int r = 0; r < 32; ++r) {
        for (int j = 0; j < 4; ++j) x[j] ^= m_k[4 * r + j];
        applySbox<false>(r, x);
        if (r < 31) linear(x);
    }
    for (int j = 0; j < 4; ++j) x[j] ^= m_k[128 + j];
    for (int i = 0; i < 4; ++i) storeLe32(reinterpret_cast<std::byte*>(out + 4 * i), x[i]);
}

void Serpent::decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint32_t x[4];
    for (int i = 0; i < 4; ++i) x[i] = loadLe32(reinterpret_cast<const std::byte*>(in + 4 * i));
    for (int j = 0; j < 4; ++j) x[j] ^= m_k[128 + j];
    for (int r = 31; r >= 0; --r) {
        if (r < 31) linearInverse(x);
        applySbox<true>(r, x);
        for (int j = 0; j < 4; ++j) x[j] ^= m_k[4 * r + j];
    }
    for (int i = 0; i < 4; ++i) storeLe32(reinterpret_cast<std::byte*>(out + 4 * i), x[i]);
}

} // namespace stein::crypto
