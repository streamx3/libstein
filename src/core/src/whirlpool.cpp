// SPDX-License-Identifier: MIT
// Whirlpool (ISO/IEC 10118-3, the final 2003 version): a 512-bit block
// cipher in Miyaguchi-Preneel mode, 10 rounds. The S-box is built from the
// specification's three 4-bit mini-boxes and the diffusion matrix is folded
// into eight 256-entry tables, so nothing here is copied from a listing.
#include "stein/core/hash.hpp"

#include "stein/core/endian.hpp"

#include <bit>
#include <cstring>

namespace stein {

namespace {

constexpr std::uint8_t kE[16] = {0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF, 0x3, 0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0};
constexpr std::uint8_t kR[16] = {0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9, 0xF, 0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0};
constexpr std::uint8_t kCirculant[8] = {1, 1, 4, 1, 8, 5, 2, 9};

inline std::uint8_t gfMul(std::uint8_t a, std::uint8_t b) {
    unsigned r = 0, x = a;
    for (int i = 0; i < 8; ++i) {
        if ((b >> i) & 1) r ^= x;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    return static_cast<std::uint8_t>(r);
}

struct Tables {
    std::uint8_t sbox[256];
    std::uint64_t c[8][256];
    std::uint64_t rc[11];
    Tables() {
        std::uint8_t eInv[16];
        for (int i = 0; i < 16; ++i) eInv[kE[i]] = static_cast<std::uint8_t>(i);
        for (int x = 0; x < 256; ++x) {
            std::uint8_t u = kE[x >> 4], l = eInv[x & 0xF];
            const std::uint8_t r = kR[u ^ l];
            u = kE[u ^ r];
            l = eInv[l ^ r];
            sbox[x] = static_cast<std::uint8_t>((u << 4) | l);
        }
        for (int x = 0; x < 256; ++x) {
            std::uint64_t v = 0;
            for (int j = 0; j < 8; ++j) v |= std::uint64_t{gfMul(sbox[x], kCirculant[j])} << (56 - 8 * j);
            c[0][x] = v;
            for (int k = 1; k < 8; ++k) c[k][x] = std::rotr(v, 8 * k);
        }
        rc[0] = 0;
        for (int r = 1; r <= 10; ++r) {
            std::uint64_t v = 0;
            for (int j = 0; j < 8; ++j) v |= std::uint64_t{sbox[8 * (r - 1) + j]} << (56 - 8 * j);
            rc[r] = v;
        }
    }
};
const Tables& tables() {
    static const Tables t;
    return t;
}

inline void round(const Tables& t, const std::uint64_t in[8], std::uint64_t out[8]) {
    for (int i = 0; i < 8; ++i) {
        std::uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v ^= t.c[k][static_cast<std::uint8_t>(in[(i - k) & 7] >> (56 - 8 * k))];
        out[i] = v;
    }
}

} // namespace

void Whirlpool::reset() {
    m_state.fill(0);
    m_bits = 0;
    m_bufferLen = 0;
}

void Whirlpool::transform(const std::uint8_t block[64]) {
    const Tables& t = tables();
    std::uint64_t k[8], state[8], l[8], b[8];
    for (int i = 0; i < 8; ++i) {
        b[i] = loadBe64(reinterpret_cast<const std::byte*>(block + 8 * i));
        k[i] = m_state[i];
        state[i] = b[i] ^ k[i];
    }
    for (int r = 1; r <= 10; ++r) {
        round(t, k, l);
        l[0] ^= t.rc[r];
        std::memcpy(k, l, sizeof k);
        round(t, state, l);
        for (int i = 0; i < 8; ++i) state[i] = l[i] ^ k[i];
    }
    for (int i = 0; i < 8; ++i) m_state[i] ^= state[i] ^ b[i];
}

void Whirlpool::update(std::span<const std::byte> data) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    m_bits += static_cast<std::uint64_t>(n) * 8;
    if (m_bufferLen) {
        const std::size_t take = std::min(n, 64 - m_bufferLen);
        std::memcpy(m_buffer.data() + m_bufferLen, p, take);
        m_bufferLen += take;
        p += take;
        n -= take;
        if (m_bufferLen == 64) {
            transform(m_buffer.data());
            m_bufferLen = 0;
        }
    }
    while (n >= 64) {
        transform(p);
        p += 64;
        n -= 64;
    }
    if (n) {
        std::memcpy(m_buffer.data(), p, n);
        m_bufferLen = n;
    }
}

std::vector<std::uint8_t> Whirlpool::finish() {
    const std::uint64_t bits = m_bits;
    std::uint8_t pad[64] = {0x80};
    // Pad to 32 bytes short of a block, then a 256-bit big-endian length (we track 64 bits of it).
    const std::size_t padLen = (m_bufferLen < 32) ? (32 - m_bufferLen) : (96 - m_bufferLen);
    std::uint8_t lenField[32] = {};
    storeBe64(reinterpret_cast<std::byte*>(lenField + 24), bits);
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(pad), padLen));
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(lenField), 32));
    std::vector<std::uint8_t> out(64);
    for (int i = 0; i < 8; ++i) storeBe64(reinterpret_cast<std::byte*>(out.data() + 8 * i), m_state[i]);
    return out;
}

} // namespace stein
