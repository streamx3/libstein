// SPDX-License-Identifier: MIT
// Streebog-512, GOST R 34.11-2012 (RFC 6986). The state is kept as eight
// little-endian 64-bit words (the standard's integers are little-endian byte
// strings), so message bytes load without reordering; the S-box (shared with
// Kuznyechik), the transposition and the linear transform are folded into
// eight 256-entry tables built from the 64 constants of the linear map.
#include "stein/core/hash.hpp"

#include "stein/core/endian.hpp"

#include <cstring>

namespace stein {

namespace {

extern const std::uint8_t kStreebogPi[256];
const std::uint8_t kStreebogPi[256] = {
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182};

// Linear map of one 64-bit row: the image of input bit (8 * byte + bit), little-endian; the
// standard's table A read from its last entry to its first.
constexpr std::uint64_t kA[64] = {
    0x641c314b2b8ee083ull, 0xc83862965601dd1bull, 0x8d70c431ac02a736ull, 0x07e095624504536cull,
    0x0edd37c48a08a6d8ull, 0x1ca76e95091051adull, 0x3853dc371220a247ull, 0x70a6a56e2440598eull,
    0xa48b474f9ef5dc18ull, 0x550b8e9e21f7a530ull, 0xaa16012142f35760ull, 0x492c024284fbaec0ull,
    0x9258048415eb419dull, 0x39b008152acb8227ull, 0x727d102a548b194eull, 0xe4fa2054a80b329cull,
    0xf97d86d98a327728ull, 0xeffa11af0964ee50ull, 0xc3e9224312c8c1a0ull, 0x9bcf4486248d9f5dull,
    0x2b838811480723baull, 0x561b0d22900e4669ull, 0xac361a443d1c8cd2ull, 0x456c34887a3805b9ull,
    0x5b068c651810a89eull, 0xb60c05ca30204d21ull, 0x71180a8960409a42ull, 0xe230140fc0802984ull,
    0xd960281e9d1d5215ull, 0xafc0503c273aa42aull, 0x439da0784e745554ull, 0x86275df09ce8aaa8ull,
    0x0321658cba93c138ull, 0x0642ca05693b9f70ull, 0x0c84890ad27623e0ull, 0x18150f14b9ec46ddull,
    0x302a1e286fc58ca7ull, 0x60543c50de970553ull, 0xc0a878a0a1330aa6ull, 0x9d4df05d5f661451ull,
    0xaccc9ca9328a8950ull, 0x4585254f64090fa0ull, 0x8a174a9ec8121e5dull, 0x092e94218d243cbaull,
    0x125c354207487869ull, 0x24b86a840e90f0d2ull, 0x486dd4151c3dfdb9ull, 0x90dab52a387ae76full,
    0x46b60f011a83988eull, 0x8c711e02341b2d01ull, 0x05e23c0468365a02ull, 0x0ad97808d06cb404ull,
    0x14aff010bdd87508ull, 0x2843fd2067adea10ull, 0x5086e740ce47c920ull, 0xa011d380818e8f40ull,
    0x83478b07b2468764ull, 0x1b8e0b0e798c13c8ull, 0x3601161cf205268dull, 0x6c022c38f90a4c07ull,
    0xd8045870ef14980eull, 0xad08b0e0c3282d1cull, 0x47107ddd9b505a38ull, 0x8e20faa72ba0b470ull,
};

// Iteration constants C1..C12 as eight little-endian words each.
constexpr std::uint64_t kC[12][8] = {
    {0xdd806559f2a64507ull, 0x05767436cc744d23ull, 0xa2422a08a460d315ull, 0x4b7ce09192676901ull, 0x714eb88d7585c4fcull, 0x2f6a76432e45d016ull, 0xebcb2f81c0657c1full, 0xb1085bda1ecadae9ull},
    {0xe679047021b19bb7ull, 0x55dda21bd7cbcd56ull, 0x5cb561c2db0aa7caull, 0x9ab5176b12d69958ull, 0x61d55e0f16b50131ull, 0xf3feea720a232b98ull, 0x4fe39d460f70b5d7ull, 0x6fa3b58aa99d2f1aull},
    {0x991e96f50aba0ab2ull, 0xc2b6f443867adb31ull, 0xc1c93a376062db09ull, 0xd3e20fe490359eb1ull, 0xf2ea7514b1297b7bull, 0x06f15e5f529c1f8bull, 0x0a39fc286a3d8435ull, 0xf574dcac2bce2fc7ull},
    {0x220cbebc84e3d12eull, 0x3453eaa193e837f1ull, 0xd8b71333935203beull, 0xa9d72c82ed03d675ull, 0x9d721cad685e353full, 0x488e857e335c3c7dull, 0xf948e1a05d71e4ddull, 0xef1fdfb3e81566d2ull},
    {0x601758fd7c6cfe57ull, 0x7a56a27ea9ea63f5ull, 0xdfff00b723271a16ull, 0xbfcd1747253af5a3ull, 0x359e35d7800fffbdull, 0x7f151c1f1686104aull, 0x9a3f410c6ca92363ull, 0x4bea6bacad474799ull},
    {0xfa68407a46647d6eull, 0xbf71c57236904f35ull, 0x0af21f66c2bec6b6ull, 0xcffaa6b71c9ab7b4ull, 0x187f9ab49af08ec6ull, 0x2d66c4f95142a46cull, 0x6fa4c33b7a3039c0ull, 0xae4faeae1d3ad3d9ull},
    {0x8886564d3a14d493ull, 0x3517454ca23c4af3ull, 0x06476983284a0504ull, 0x0992abc52d822c37ull, 0xd3473e33197a93c9ull, 0x399ec6c7e6bf87c9ull, 0x51ac86febf240954ull, 0xf4c70e16eeaac5ecull},
    {0xa47f0dd4bf02e71eull, 0x36acc2355951a8d9ull, 0x69d18d2bd1a5c42full, 0xf4892bcb929b0690ull, 0x89b4443b4ddbc49aull, 0x4eb7f8719c36de1eull, 0x03e7aa020c6e4141ull, 0x9b1f5b424d93c9a7ull},
    {0x7261445183235adbull, 0x0e38dc92cb1f2a60ull, 0x7b2b8a9aa6079c54ull, 0x800a440bdbb2ceb1ull, 0x3cd955b7e00d0984ull, 0x3a7d3a1b25894224ull, 0x944c9ad8ec165fdeull, 0x378f5a541631229bull},
    {0x74b4c7fb98459cedull, 0x3698fad1153bb6c3ull, 0x7a1e6c303b7652f4ull, 0x9fe76702af69334bull, 0x1fffe18a1b336103ull, 0x8941e71cff8a78dbull, 0x382ae548b2e4f3f3ull, 0xabbedea680056f52ull},
    {0x6bcaa4cd81f32d1bull, 0xdea2594ac06fd85dull, 0xefbacd1d7d476e98ull, 0x8a1d71efea48b9caull, 0x2001802114846679ull, 0xd8fa6bbbebab0761ull, 0x3002c6cd635afe94ull, 0x7bcd9ed0efc889fbull},
    {0x48bc924af11bd720ull, 0xfaf417d5d9b21b99ull, 0xe71da4aa88e12852ull, 0x5d80ef9d1891cc86ull, 0xf82012d430219f9bull, 0xcda43c32bcdf1d77ull, 0xd21380b00449b17aull, 0x378ee767f11631baull},
};

struct Tables {
    std::uint64_t t[8][256];   // t[i][x]: contribution of byte x at row position i after S and L
    Tables() {
        for (int i = 0; i < 8; ++i)
            for (int x = 0; x < 256; ++x) {
                std::uint64_t v = 0;
                for (int k = 0; k < 8; ++k)
                    if ((kStreebogPi[x] >> k) & 1) v ^= kA[8 * i + k];
                t[i][x] = v;
            }
    }
};
const Tables& tables() {
    static const Tables tb;
    return tb;
}

using Words = std::array<std::uint64_t, 8>;

// L(P(S(x))): row r of the result gathers byte r of every input row.
inline Words lps(const Words& in) {
    const Tables& tb = tables();
    Words out;
    for (int r = 0; r < 8; ++r) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v ^= tb.t[i][static_cast<std::uint8_t>(in[i] >> (8 * r))];
        out[r] = v;
    }
    return out;
}

inline Words operator^(const Words& a, const Words& b) {
    Words r;
    for (int i = 0; i < 8; ++i) r[i] = a[i] ^ b[i];
    return r;
}

// 512-bit little-endian addition.
inline void addInto(Words& acc, const Words& v) {
    std::uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        const std::uint64_t s = acc[i] + v[i];
        const std::uint64_t c1 = s < acc[i] ? 1 : 0;
        const std::uint64_t t = s + carry;
        const std::uint64_t c2 = t < s ? 1 : 0;
        acc[i] = t;
        carry = c1 | c2;
    }
}

inline Words load(const std::uint8_t block[64]) {
    Words w;
    for (int i = 0; i < 8; ++i) w[i] = loadLe64(reinterpret_cast<const std::byte*>(block + 8 * i));
    return w;
}

// g_N(h, m) = E(LPS(h ^ N), m) ^ h ^ m
Words g(const Words& h, const Words& n, const Words& m) {
    Words k = lps(h ^ n);
    Words s = lps(m ^ k);
    for (int i = 0; i < 11; ++i) {
        Words c;
        for (int j = 0; j < 8; ++j) c[j] = kC[i][j];
        k = lps(k ^ c);
        s = lps(s ^ k);
    }
    Words c;
    for (int j = 0; j < 8; ++j) c[j] = kC[11][j];
    k = lps(k ^ c);
    return s ^ k ^ h ^ m;
}

} // namespace

void Streebog512::reset() {
    m_h.fill(0);
    m_n.fill(0);
    m_sigma.fill(0);
    m_bufferLen = 0;
}

void Streebog512::transform(const std::uint8_t block[64]) {
    const Words m = load(block);
    m_h = g(m_h, m_n, m);
    addInto(m_n, Words{512, 0, 0, 0, 0, 0, 0, 0});
    addInto(m_sigma, m);
}

void Streebog512::update(std::span<const std::byte> data) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
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

std::vector<std::uint8_t> Streebog512::finish() {
    // Final (possibly empty) block: the message bytes, a 0x01, zeros; N advances by its bit length.
    std::uint8_t block[64] = {};
    std::memcpy(block, m_buffer.data(), m_bufferLen);
    block[m_bufferLen] = 0x01;
    const Words m = load(block);
    m_h = g(m_h, m_n, m);
    addInto(m_n, Words{static_cast<std::uint64_t>(m_bufferLen) * 8, 0, 0, 0, 0, 0, 0, 0});
    addInto(m_sigma, m);
    const Words zero{};
    m_h = g(m_h, zero, m_n);
    m_h = g(m_h, zero, m_sigma);
    std::vector<std::uint8_t> out(64);
    for (int i = 0; i < 8; ++i) storeLe64(reinterpret_cast<std::byte*>(out.data() + 8 * i), m_h[i]);
    return out;
}

} // namespace stein
