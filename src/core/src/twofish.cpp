// SPDX-License-Identifier: MIT
// Twofish (Schneier et al.), with the key-dependent S-boxes and the MDS
// matrix folded into four 256-entry tables ("full keying").
#include "stein/core/cipher.hpp"

#include "stein/core/endian.hpp"

#include <bit>

namespace stein::crypto {

namespace {

constexpr std::uint8_t kQ0[4][16] = {
    {0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4},
    {0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD},
    {0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1},
    {0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA},
};
constexpr std::uint8_t kQ1[4][16] = {
    {0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5},
    {0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8},
    {0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF},
    {0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA},
};
constexpr std::uint8_t kMds[4][4] = {{0x01, 0xEF, 0x5B, 0x5B}, {0x5B, 0xEF, 0xEF, 0x01}, {0xEF, 0x5B, 0x01, 0xEF}, {0xEF, 0x01, 0xEF, 0x5B}};
constexpr std::uint8_t kRs[4][8] = {
    {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
    {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
    {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
    {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03},
};
constexpr unsigned kMdsPoly = 0x169, kRsPoly = 0x14D;
constexpr std::uint32_t kRho = 0x01010101u;

inline std::uint8_t gfMul(std::uint8_t a, std::uint8_t b, unsigned poly) {
    unsigned r = 0, x = a;
    for (int i = 0; i < 8; ++i) {
        if ((b >> i) & 1) r ^= x;
        x <<= 1;
        if (x & 0x100) x ^= poly;
    }
    return static_cast<std::uint8_t>(r);
}

std::uint8_t qPermute(const std::uint8_t t[4][16], std::uint8_t x) {
    auto ror4 = [](unsigned v) { return ((v >> 1) | (v << 3)) & 0xF; };
    unsigned a0 = x >> 4, b0 = x & 0xF;
    unsigned a1 = a0 ^ b0, b1 = a0 ^ ror4(b0) ^ ((8 * a0) & 0xF);
    unsigned a2 = t[0][a1], b2 = t[1][b1];
    unsigned a3 = a2 ^ b2, b3 = a2 ^ ror4(b2) ^ ((8 * a2) & 0xF);
    unsigned a4 = t[2][a3], b4 = t[3][b3];
    return static_cast<std::uint8_t>(16 * b4 + a4);
}

struct Tables {
    std::uint8_t q0[256], q1[256];
    std::uint32_t mds[4][256];   // mds[j][x]: column j of the MDS matrix times x, packed little-endian by row
    Tables() {
        for (int x = 0; x < 256; ++x) {
            q0[x] = qPermute(kQ0, static_cast<std::uint8_t>(x));
            q1[x] = qPermute(kQ1, static_cast<std::uint8_t>(x));
        }
        for (int j = 0; j < 4; ++j)
            for (int x = 0; x < 256; ++x) {
                std::uint32_t v = 0;
                for (int i = 0; i < 4; ++i) v |= std::uint32_t{gfMul(kMds[i][j], static_cast<std::uint8_t>(x), kMdsPoly)} << (8 * i);
                mds[j][x] = v;
            }
    }
};
const Tables& tables() {
    static const Tables t;
    return t;
}

// The h function's byte chain for byte lane i with k key words (l[j] is byte i of L_j), before the MDS.
std::uint8_t hByte(int i, std::uint8_t x, const std::uint8_t* l, unsigned k) {
    const Tables& t = tables();
    const std::uint8_t* const q[2] = {t.q0, t.q1};
    // Stage patterns from the specification: which q to use per lane at each stage.
    static constexpr int stage4[4] = {1, 0, 0, 1}, stage3[4] = {1, 1, 0, 0}, stage2[4] = {0, 1, 0, 1}, stage1[4] = {0, 0, 1, 1}, stage0[4] = {1, 0, 1, 0};
    std::uint8_t y = x;
    if (k == 4) y = static_cast<std::uint8_t>(q[stage4[i]][y] ^ l[3]);
    if (k >= 3) y = static_cast<std::uint8_t>(q[stage3[i]][y] ^ l[2]);
    y = static_cast<std::uint8_t>(q[stage2[i]][y] ^ l[1]);
    y = static_cast<std::uint8_t>(q[stage1[i]][y] ^ l[0]);
    return q[stage0[i]][y];
}

std::uint32_t h(std::uint32_t x, const std::uint32_t* L, unsigned k) {
    const Tables& t = tables();
    std::uint32_t out = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint8_t l[4];
        for (unsigned j = 0; j < k; ++j) l[j] = static_cast<std::uint8_t>(L[j] >> (8 * i));
        out ^= t.mds[i][hByte(i, static_cast<std::uint8_t>(x >> (8 * i)), l, k)];
    }
    return out;
}

} // namespace

Expected<Twofish> Twofish::create(std::span<const std::uint8_t> key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) return fail(ErrorCategory::InvalidArgument, "Twofish key must be 16, 24 or 32 bytes");
    const unsigned k = static_cast<unsigned>(key.size() / 8);
    std::uint32_t m[8], me[4], mo[4], s[4];
    for (unsigned i = 0; i < 2 * k; ++i) m[i] = loadLe32(reinterpret_cast<const std::byte*>(key.data() + 4 * i));
    for (unsigned i = 0; i < k; ++i) {
        me[i] = m[2 * i];
        mo[i] = m[2 * i + 1];
        std::uint32_t v = 0;
        for (int row = 0; row < 4; ++row) {
            std::uint8_t acc = 0;
            for (int col = 0; col < 8; ++col) acc ^= gfMul(kRs[row][col], key[8 * i + col], kRsPoly);
            v |= std::uint32_t{acc} << (8 * row);
        }
        s[k - 1 - i] = v;   // S is used in reverse order: L_0 = S_{k-1}
    }
    Twofish tf;
    for (unsigned i = 0; i < 20; ++i) {
        const std::uint32_t a = h(2 * i * kRho, me, k);
        const std::uint32_t b = std::rotl(h((2 * i + 1) * kRho, mo, k), 8);
        tf.m_k[2 * i] = a + b;
        tf.m_k[2 * i + 1] = std::rotl(a + 2 * b, 9);
    }
    const Tables& t = tables();
    for (int lane = 0; lane < 4; ++lane) {
        std::uint8_t l[4];
        for (unsigned j = 0; j < k; ++j) l[j] = static_cast<std::uint8_t>(s[j] >> (8 * lane));
        for (int x = 0; x < 256; ++x) tf.m_sbox[lane][x] = t.mds[lane][hByte(lane, static_cast<std::uint8_t>(x), l, k)];
    }
    return tf;
}

std::uint32_t Twofish::g(std::uint32_t x) const {
    return m_sbox[0][x & 0xFF] ^ m_sbox[1][(x >> 8) & 0xFF] ^ m_sbox[2][(x >> 16) & 0xFF] ^ m_sbox[3][x >> 24];
}

void Twofish::encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint32_t r[4];
    for (int i = 0; i < 4; ++i) r[i] = loadLe32(reinterpret_cast<const std::byte*>(in + 4 * i)) ^ m_k[i];
    for (int round = 0; round < 16; ++round) {
        const std::uint32_t t0 = g(r[0]), t1 = g(std::rotl(r[1], 8));
        const std::uint32_t f0 = t0 + t1 + m_k[2 * round + 8], f1 = t0 + 2 * t1 + m_k[2 * round + 9];
        r[2] = std::rotr(r[2] ^ f0, 1);
        r[3] = std::rotl(r[3], 1) ^ f1;
        std::swap(r[0], r[2]);
        std::swap(r[1], r[3]);
    }
    // Undo the last swap and whiten.
    storeLe32(reinterpret_cast<std::byte*>(out), r[2] ^ m_k[4]);
    storeLe32(reinterpret_cast<std::byte*>(out + 4), r[3] ^ m_k[5]);
    storeLe32(reinterpret_cast<std::byte*>(out + 8), r[0] ^ m_k[6]);
    storeLe32(reinterpret_cast<std::byte*>(out + 12), r[1] ^ m_k[7]);
}

void Twofish::decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint32_t r[4];
    r[2] = loadLe32(reinterpret_cast<const std::byte*>(in)) ^ m_k[4];
    r[3] = loadLe32(reinterpret_cast<const std::byte*>(in + 4)) ^ m_k[5];
    r[0] = loadLe32(reinterpret_cast<const std::byte*>(in + 8)) ^ m_k[6];
    r[1] = loadLe32(reinterpret_cast<const std::byte*>(in + 12)) ^ m_k[7];
    for (int round = 15; round >= 0; --round) {
        std::swap(r[0], r[2]);
        std::swap(r[1], r[3]);
        const std::uint32_t t0 = g(r[0]), t1 = g(std::rotl(r[1], 8));
        const std::uint32_t f0 = t0 + t1 + m_k[2 * round + 8], f1 = t0 + 2 * t1 + m_k[2 * round + 9];
        r[2] = std::rotl(r[2], 1) ^ f0;
        r[3] = std::rotr(r[3] ^ f1, 1);
    }
    for (int i = 0; i < 4; ++i) storeLe32(reinterpret_cast<std::byte*>(out + 4 * i), r[i] ^ m_k[i]);
}

} // namespace stein::crypto
