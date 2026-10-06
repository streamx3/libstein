// SPDX-License-Identifier: MIT
// Camellia-256 (RFC 3713): 24 Feistel rounds with FL/FL^-1 layers every six.
#include "stein/core/cipher.hpp"

#include "stein/core/endian.hpp"

#include <bit>

namespace stein::crypto {

namespace {

constexpr std::uint8_t kS1[256] = {
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26, 166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34, 254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210, 16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226, 82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89, 120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164, 64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158};
constexpr std::uint64_t kSigma[6] = {0xA09E667F3BCC908Bull, 0xB67AE8584CAA73B2ull, 0xC6EF372FE94F82BEull, 0x54FF53A5F1D36F1Cull, 0x10E527FADE682D1Dull, 0xB05688C2B3E6C1FDull};

inline std::uint8_t rotl8(std::uint8_t x, int n) { return static_cast<std::uint8_t>((x << n) | (x >> (8 - n))); }
inline std::uint8_t s1(std::uint8_t x) { return kS1[x]; }
inline std::uint8_t s2(std::uint8_t x) { return rotl8(kS1[x], 1); }
inline std::uint8_t s3(std::uint8_t x) { return rotl8(kS1[x], 7); }
inline std::uint8_t s4(std::uint8_t x) { return kS1[rotl8(x, 1)]; }

std::uint64_t F(std::uint64_t in, std::uint64_t ke) {
    const std::uint64_t x = in ^ ke;
    const std::uint8_t t1 = s1(static_cast<std::uint8_t>(x >> 56)), t2 = s2(static_cast<std::uint8_t>(x >> 48)), t3 = s3(static_cast<std::uint8_t>(x >> 40)),
                       t4 = s4(static_cast<std::uint8_t>(x >> 32)), t5 = s2(static_cast<std::uint8_t>(x >> 24)), t6 = s3(static_cast<std::uint8_t>(x >> 16)),
                       t7 = s4(static_cast<std::uint8_t>(x >> 8)), t8 = s1(static_cast<std::uint8_t>(x));
    const std::uint8_t y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8, y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8, y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8, y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7,
                       y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8, y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8, y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8, y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    return (std::uint64_t{y1} << 56) | (std::uint64_t{y2} << 48) | (std::uint64_t{y3} << 40) | (std::uint64_t{y4} << 32) | (std::uint64_t{y5} << 24) | (std::uint64_t{y6} << 16) |
           (std::uint64_t{y7} << 8) | y8;
}

std::uint64_t FL(std::uint64_t in, std::uint64_t ke) {
    std::uint32_t x1 = static_cast<std::uint32_t>(in >> 32), x2 = static_cast<std::uint32_t>(in);
    const std::uint32_t k1 = static_cast<std::uint32_t>(ke >> 32), k2 = static_cast<std::uint32_t>(ke);
    x2 ^= std::rotl(x1 & k1, 1);
    x1 ^= (x2 | k2);
    return (std::uint64_t{x1} << 32) | x2;
}

std::uint64_t FLInv(std::uint64_t in, std::uint64_t ke) {
    std::uint32_t y1 = static_cast<std::uint32_t>(in >> 32), y2 = static_cast<std::uint32_t>(in);
    const std::uint32_t k1 = static_cast<std::uint32_t>(ke >> 32), k2 = static_cast<std::uint32_t>(ke);
    y1 ^= (y2 | k2);
    y2 ^= std::rotl(y1 & k1, 1);
    return (std::uint64_t{y1} << 32) | y2;
}

struct U128 {
    std::uint64_t hi, lo;
    U128 rotl(unsigned n) const {
        if (n == 0) return *this;
        if (n >= 64) return U128{lo, hi}.rotl(n - 64);
        return {(hi << n) | (lo >> (64 - n)), (lo << n) | (hi >> (64 - n))};
    }
};

} // namespace

Expected<Camellia> Camellia::create(std::span<const std::uint8_t> key) {
    if (key.size() != 32) return fail(ErrorCategory::InvalidArgument, "Camellia key must be 32 bytes (Camellia-256)");
    auto be = [&](std::size_t off) { return loadBe64(reinterpret_cast<const std::byte*>(key.data() + off)); };
    const U128 kl{be(0), be(8)}, kr{be(16), be(24)};
    std::uint64_t d1 = kl.hi ^ kr.hi, d2 = kl.lo ^ kr.lo;
    d2 ^= F(d1, kSigma[0]);
    d1 ^= F(d2, kSigma[1]);
    d1 ^= kl.hi;
    d2 ^= kl.lo;
    d2 ^= F(d1, kSigma[2]);
    d1 ^= F(d2, kSigma[3]);
    const U128 ka{d1, d2};
    d1 = ka.hi ^ kr.hi;
    d2 = ka.lo ^ kr.lo;
    d2 ^= F(d1, kSigma[4]);
    d1 ^= F(d2, kSigma[5]);
    const U128 kb{d1, d2};

    Camellia c;
    auto set = [](std::uint64_t* dst, U128 v) {
        dst[0] = v.hi;
        dst[1] = v.lo;
    };
    set(c.m_kw, kl.rotl(0));
    set(c.m_k, kb.rotl(0));
    set(c.m_k + 2, kr.rotl(15));
    set(c.m_k + 4, ka.rotl(15));
    set(c.m_ke, kr.rotl(30));
    set(c.m_k + 6, kb.rotl(30));
    set(c.m_k + 8, kl.rotl(45));
    set(c.m_k + 10, ka.rotl(45));
    set(c.m_ke + 2, kl.rotl(60));
    set(c.m_k + 12, kr.rotl(60));
    set(c.m_k + 14, kb.rotl(60));
    set(c.m_k + 16, kl.rotl(77));
    set(c.m_ke + 4, ka.rotl(77));
    set(c.m_k + 18, kr.rotl(94));
    set(c.m_k + 20, ka.rotl(94));
    set(c.m_k + 22, kl.rotl(111));
    set(c.m_kw + 2, kb.rotl(111));
    return c;
}

void Camellia::run(const std::uint8_t in[16], std::uint8_t out[16], const std::uint64_t kw[4], const std::uint64_t k[24], const std::uint64_t ke[6]) const {
    std::uint64_t d1 = loadBe64(reinterpret_cast<const std::byte*>(in)) ^ kw[0];
    std::uint64_t d2 = loadBe64(reinterpret_cast<const std::byte*>(in + 8)) ^ kw[1];
    for (int g = 0; g < 4; ++g) {
        d2 ^= F(d1, k[6 * g]);
        d1 ^= F(d2, k[6 * g + 1]);
        d2 ^= F(d1, k[6 * g + 2]);
        d1 ^= F(d2, k[6 * g + 3]);
        d2 ^= F(d1, k[6 * g + 4]);
        d1 ^= F(d2, k[6 * g + 5]);
        if (g < 3) {
            d1 = FL(d1, ke[2 * g]);
            d2 = FLInv(d2, ke[2 * g + 1]);
        }
    }
    storeBe64(reinterpret_cast<std::byte*>(out), d2 ^ kw[2]);
    storeBe64(reinterpret_cast<std::byte*>(out + 8), d1 ^ kw[3]);
}

void Camellia::encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const { run(in, out, m_kw, m_k, m_ke); }

void Camellia::decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    // Decryption is encryption with the subkeys in reverse order.
    const std::uint64_t kw[4] = {m_kw[2], m_kw[3], m_kw[0], m_kw[1]};
    std::uint64_t k[24], ke[6];
    for (int i = 0; i < 24; ++i) k[i] = m_k[23 - i];
    for (int i = 0; i < 6; ++i) ke[i] = m_ke[5 - i];
    run(in, out, kw, k, ke);
}

} // namespace stein::crypto
