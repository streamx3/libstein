// SPDX-License-Identifier: MIT
// Kuznyechik, GOST R 34.12-2015 (RFC 7801). The S-box and the linear
// transform are folded into 16 x 256 tables per direction, built once.
#include "stein/core/cipher.hpp"

#include <cstring>

namespace stein::crypto {

namespace {

constexpr std::uint8_t kPi[256] = {
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182};
constexpr std::uint8_t kL[16] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};

inline std::uint8_t gfMul(std::uint8_t a, std::uint8_t b) {
    unsigned r = 0, x = a;
    for (int i = 0; i < 8; ++i) {
        if ((b >> i) & 1) r ^= x;
        x <<= 1;
        if (x & 0x100) x ^= 0x1C3;
    }
    return static_cast<std::uint8_t>(r);
}

using Block = std::array<std::uint8_t, 16>;

// R: the first byte becomes l(a), the rest shift down by one.
Block R(const Block& a) {
    Block out;
    std::uint8_t l = 0;
    for (int i = 0; i < 16; ++i) l ^= gfMul(a[i], kL[i]);
    out[0] = l;
    for (int i = 1; i < 16; ++i) out[i] = a[i - 1];
    return out;
}
Block RInv(const Block& a) {
    Block out;
    for (int i = 0; i < 15; ++i) out[i] = a[i + 1];
    std::uint8_t l = 0;
    for (int i = 0; i < 15; ++i) l ^= gfMul(a[i + 1], kL[i]);
    l ^= gfMul(a[0], kL[15]);
    out[15] = l;
    return out;
}
Block L(Block a) {
    for (int i = 0; i < 16; ++i) a = R(a);
    return a;
}
Block LInv(Block a) {
    for (int i = 0; i < 16; ++i) a = RInv(a);
    return a;
}

struct Tables {
    std::uint8_t piInv[256];
    Block ls[16][256];      // L(S(x) at position i)
    Block linv[16][256];    // L^-1(x at position i)
    Block c[32];            // round constants
    Tables() {
        for (int x = 0; x < 256; ++x) piInv[kPi[x]] = static_cast<std::uint8_t>(x);
        for (int i = 0; i < 16; ++i)
            for (int x = 0; x < 256; ++x) {
                Block a{};
                a[i] = kPi[x];
                ls[i][x] = L(a);
                a[i] = static_cast<std::uint8_t>(x);
                linv[i][x] = LInv(a);
            }
        for (int i = 0; i < 32; ++i) {
            Block v{};
            v[15] = static_cast<std::uint8_t>(i + 1);
            c[i] = L(v);
        }
    }
};
const Tables& tables() {
    static const Tables t;
    return t;
}

inline void xorInto(Block& a, const Block& b) {
    for (int i = 0; i < 16; ++i) a[i] ^= b[i];
}

inline Block lsx(const Block& a) {
    const Tables& t = tables();
    Block out = t.ls[0][a[0]];
    for (int i = 1; i < 16; ++i) xorInto(out, t.ls[i][a[i]]);
    return out;
}

} // namespace

Expected<Kuznyechik> Kuznyechik::create(std::span<const std::uint8_t> key) {
    if (key.size() != 32) return fail(ErrorCategory::InvalidArgument, "Kuznyechik key must be 32 bytes");
    const Tables& t = tables();
    Kuznyechik k;
    Block a1, a0;
    std::memcpy(a1.data(), key.data(), 16);
    std::memcpy(a0.data(), key.data() + 16, 16);
    k.m_rk[0] = a1;
    k.m_rk[1] = a0;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            Block x = a1;
            xorInto(x, t.c[8 * i + j]);
            Block f = lsx(x);
            xorInto(f, a0);
            a0 = a1;
            a1 = f;
        }
        k.m_rk[2 * i + 2] = a1;
        k.m_rk[2 * i + 3] = a0;
    }
    return k;
}

void Kuznyechik::encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    Block a;
    std::memcpy(a.data(), in, 16);
    for (int i = 0; i < 9; ++i) {
        xorInto(a, m_rk[i]);
        a = lsx(a);
    }
    xorInto(a, m_rk[9]);
    std::memcpy(out, a.data(), 16);
}

void Kuznyechik::decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    const Tables& t = tables();
    Block a;
    std::memcpy(a.data(), in, 16);
    xorInto(a, m_rk[9]);
    for (int i = 8; i >= 0; --i) {
        Block l = t.linv[0][a[0]];
        for (int j = 1; j < 16; ++j) xorInto(l, t.linv[j][a[j]]);
        for (int j = 0; j < 16; ++j) a[j] = t.piInv[l[j]];
        xorInto(a, m_rk[i]);
    }
    std::memcpy(out, a.data(), 16);
}

} // namespace stein::crypto
