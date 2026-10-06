// SPDX-License-Identifier: MIT
// RFC 1321 (MD5) and FIPS 180-4 (SHA-256). SHA-256 dispatches to the SHA-NI /
// ARMv8 kernels in sha256_hw.cpp when the CPU has them (see hash_impl.hpp).
#include "stein/core/hash.hpp"

#include "hash_impl.hpp"

#include <cstdio>
#include <algorithm>
#include <cstring>

namespace stein {

std::string_view toString(HashAlgorithm a) {
    switch (a) {
    case HashAlgorithm::Md5: return "md5";
    case HashAlgorithm::Sha1: return "sha1";
    case HashAlgorithm::Sha256: return "sha256";
    case HashAlgorithm::Sha512: return "sha512";
    case HashAlgorithm::Ripemd160: return "ripemd160";
    case HashAlgorithm::Blake2s256: return "blake2s256";
    case HashAlgorithm::Whirlpool: return "whirlpool";
    case HashAlgorithm::Streebog512: return "streebog512";
    }
    return "?";
}

std::unique_ptr<Hasher> Hasher::create(HashAlgorithm a) {
    switch (a) {
    case HashAlgorithm::Md5: return std::make_unique<Md5>();
    case HashAlgorithm::Sha1: return std::make_unique<Sha1>();
    case HashAlgorithm::Sha256: return std::make_unique<Sha256>();
    case HashAlgorithm::Sha512: return std::make_unique<Sha512>();
    case HashAlgorithm::Ripemd160: return std::make_unique<Ripemd160>();
    case HashAlgorithm::Blake2s256: return std::make_unique<Blake2s256>();
    case HashAlgorithm::Whirlpool: return std::make_unique<Whirlpool>();
    case HashAlgorithm::Streebog512: return std::make_unique<Streebog512>();
    }
    return nullptr;
}

std::vector<std::uint8_t> Hasher::digest(HashAlgorithm a, std::span<const std::byte> data) {
    auto h = create(a);
    h->update(data);
    return h->finish();
}

std::string Hasher::hex(std::span<const std::uint8_t> digest) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(digest.size() * 2);
    for (auto b : digest) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0xF]);
    }
    return s;
}

namespace {

inline std::uint32_t rotl(std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

} // namespace

// ----------------------------------------------------------------------------- MD5

namespace {
constexpr std::uint32_t kMd5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
constexpr int kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                           5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                           4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                           6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

} // namespace

void Md5::reset() {
    m_state = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    m_bits = 0;
    m_bufferLen = 0;
}

void Md5::transform(const std::uint8_t block[64]) {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i)
        m[i] = static_cast<std::uint32_t>(block[i * 4]) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    std::uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f;
        int g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        std::uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + kMd5K[i] + m[g], kMd5S[i]);
        a = tmp;
    }
    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
}

void Md5::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    m_bits += static_cast<std::uint64_t>(n) * 8;
    if (m_bufferLen) {
        std::size_t take = std::min(n, 64 - m_bufferLen);
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

std::vector<std::uint8_t> Md5::finish() {
    std::uint64_t bits = m_bits;
    std::uint8_t pad = 0x80;
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
    std::uint8_t zero = 0;
    while (m_bufferLen != 56) update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff);
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(len), 8));
    std::vector<std::uint8_t> out(16);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<std::uint8_t>((m_state[i] >> (8 * j)) & 0xff);
    return out;
}

// -------------------------------------------------------------------------- SHA-256

namespace {
constexpr std::uint32_t kShaK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
}

void Sha256::reset() {
    m_state = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
               0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    m_bits = 0;
    m_bufferLen = 0;
}

namespace detail {
void sha256Portable(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks) {
  while (blocks--) {
    const std::uint8_t* block = data;
    data += 64;
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) | static_cast<std::uint32_t>(block[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4],
                  f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t t1 = h + S1 + ch + kShaK[i] + w[i];
        std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }
}
} // namespace detail

void Sha256::transform(const std::uint8_t block[64]) { transformBlocks(block, 1); }

void Sha256::transformBlocks(const std::uint8_t* data, std::size_t blocks) {
    static const bool hw = detail::sha256HardwareAvailable();
    if (hw) detail::sha256Hardware(m_state.data(), data, blocks);
    else detail::sha256Portable(m_state.data(), data, blocks);
}

void Sha256::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    m_bits += static_cast<std::uint64_t>(n) * 8;
    if (m_bufferLen) {
        std::size_t take = std::min(n, 64 - m_bufferLen);
        std::memcpy(m_buffer.data() + m_bufferLen, p, take);
        m_bufferLen += take;
        p += take;
        n -= take;
        if (m_bufferLen == 64) {
            transform(m_buffer.data());
            m_bufferLen = 0;
        }
    }
    if (n >= 64) {
        const std::size_t blocks = n / 64;
        transformBlocks(p, blocks);
        p += blocks * 64;
        n -= blocks * 64;
    }
    if (n) {
        std::memcpy(m_buffer.data(), p, n);
        m_bufferLen = n;
    }
}

std::vector<std::uint8_t> Sha256::finish() {
    std::uint64_t bits = m_bits;
    std::uint8_t pad = 0x80;
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
    std::uint8_t zero = 0;
    while (m_bufferLen != 56) update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[7 - i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff);
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(len), 8));
    std::vector<std::uint8_t> out(32);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<std::uint8_t>((m_state[i] >> (24 - 8 * j)) & 0xff);
    return out;
}

} // namespace stein

// ----------------------------------------------------------------------------- SHA-1 (FIPS 180-4)

namespace stein {

void Sha1::reset() {
    m_state = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    m_bits = 0;
    m_bufferLen = 0;
}

void Sha1::transform(const std::uint8_t block[64]) {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) | static_cast<std::uint32_t>(block[i * 4 + 3]);
    auto rotl = [](std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); };
    for (int i = 16; i < 80; ++i) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    std::uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3], e = m_state[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        const std::uint32_t t = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = t;
    }
    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
}

void Sha1::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    m_bits += static_cast<std::uint64_t>(n) * 8;
    if (m_bufferLen) {
        std::size_t take = std::min(n, 64 - m_bufferLen);
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

std::vector<std::uint8_t> Sha1::finish() {
    std::uint64_t bits = m_bits;
    const std::uint8_t pad = 0x80, zero = 0;
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
    while (m_bufferLen != 56) update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[7 - i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff);
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(len), 8));
    std::vector<std::uint8_t> out(20);
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) out[static_cast<std::size_t>(i * 4 + j)] = static_cast<std::uint8_t>((m_state[static_cast<std::size_t>(i)] >> (24 - 8 * j)) & 0xff);
    return out;
}

} // namespace stein

// ----------------------------------------------------------------------------- SHA-512 (FIPS 180-4)

namespace stein {

namespace {
constexpr std::uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};
inline std::uint64_t rotr64(std::uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
} // namespace

void Sha512::reset() {
    m_state = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    m_bits = 0;
    m_bufferLen = 0;
}

void Sha512::transform(const std::uint8_t block[128]) {
    std::uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        std::uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v = (v << 8) | block[i * 8 + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; ++i) {
        const std::uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const std::uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint64_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3], e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];
    for (int i = 0; i < 80; ++i) {
        const std::uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const std::uint64_t ch = (e & f) ^ (~e & g);
        const std::uint64_t t1 = h + S1 + ch + kSha512K[i] + w[i];
        const std::uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint64_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
}

void Sha512::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    m_bits += static_cast<std::uint64_t>(n) * 8;
    if (m_bufferLen) {
        const std::size_t take = std::min(n, 128 - m_bufferLen);
        std::memcpy(m_buffer.data() + m_bufferLen, p, take);
        m_bufferLen += take;
        p += take;
        n -= take;
        if (m_bufferLen == 128) {
            transform(m_buffer.data());
            m_bufferLen = 0;
        }
    }
    while (n >= 128) {
        transform(p);
        p += 128;
        n -= 128;
    }
    if (n) {
        std::memcpy(m_buffer.data(), p, n);
        m_bufferLen = n;
    }
}

std::vector<std::uint8_t> Sha512::finish() {
    const std::uint64_t bits = m_bits;
    std::uint8_t pad = 0x80;
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
    std::uint8_t zero = 0;
    while (m_bufferLen != 112) update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
    std::uint8_t len[16] = {};   // 128-bit length, high half zero
    for (int i = 0; i < 8; ++i) len[15 - i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff);
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(len), 16));
    std::vector<std::uint8_t> out(64);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) out[i * 8 + j] = static_cast<std::uint8_t>((m_state[i] >> (56 - 8 * j)) & 0xff);
    return out;
}

} // namespace stein

// ----------------------------------------------------------------------------- RIPEMD-160

namespace stein {

namespace {
constexpr std::uint8_t kRmdR[80] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                                    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                                    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
constexpr std::uint8_t kRmdRp[80] = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                                     15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                                     12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
constexpr std::uint8_t kRmdS[80] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                                    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                                    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
constexpr std::uint8_t kRmdSp[80] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                                     9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                                     8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
constexpr std::uint32_t kRmdK[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
constexpr std::uint32_t kRmdKp[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};
inline std::uint32_t rotl32(std::uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
inline std::uint32_t rmdF(int j, std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    switch (j / 16) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
    }
}
} // namespace

void Ripemd160::reset() {
    m_state = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    m_bits = 0;
    m_bufferLen = 0;
}

void Ripemd160::transform(const std::uint8_t block[64]) {
    std::uint32_t x[16];
    for (int i = 0; i < 16; ++i)
        x[i] = static_cast<std::uint32_t>(block[i * 4]) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) | (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    std::uint32_t al = m_state[0], bl = m_state[1], cl = m_state[2], dl = m_state[3], el = m_state[4];
    std::uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
    for (int j = 0; j < 80; ++j) {
        std::uint32_t t = rotl32(al + rmdF(j, bl, cl, dl) + x[kRmdR[j]] + kRmdK[j / 16], kRmdS[j]) + el;
        al = el;
        el = dl;
        dl = rotl32(cl, 10);
        cl = bl;
        bl = t;
        t = rotl32(ar + rmdF(79 - j, br, cr, dr) + x[kRmdRp[j]] + kRmdKp[j / 16], kRmdSp[j]) + er;
        ar = er;
        er = dr;
        dr = rotl32(cr, 10);
        cr = br;
        br = t;
    }
    const std::uint32_t t = m_state[1] + cl + dr;
    m_state[1] = m_state[2] + dl + er;
    m_state[2] = m_state[3] + el + ar;
    m_state[3] = m_state[4] + al + br;
    m_state[4] = m_state[0] + bl + cr;
    m_state[0] = t;
}

void Ripemd160::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
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

std::vector<std::uint8_t> Ripemd160::finish() {
    const std::uint64_t bits = m_bits;
    std::uint8_t pad = 0x80;
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
    std::uint8_t zero = 0;
    while (m_bufferLen != 56) update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff);   // little-endian length
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(len), 8));
    std::vector<std::uint8_t> out(20);
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<std::uint8_t>((m_state[i] >> (8 * j)) & 0xff);
    return out;
}

} // namespace stein

// ----------------------------------------------------------------------------- BLAKE2s-256 (RFC 7693)

namespace stein {

namespace {
constexpr std::uint32_t kBlake2sIv[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
constexpr std::uint8_t kBlake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
inline std::uint32_t rotr32(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
} // namespace

void Blake2s256::reset() {
    for (int i = 0; i < 8; ++i) m_h[i] = kBlake2sIv[i];
    m_h[0] ^= 0x01010000u ^ 32u;   // digest length 32, no key, fanout 1, depth 1
    m_counter = 0;
    m_bufferLen = 0;
}

void Blake2s256::compress(const std::uint8_t block[64], bool last) {
    std::uint32_t m[16], v[16];
    for (int i = 0; i < 16; ++i)
        m[i] = static_cast<std::uint32_t>(block[i * 4]) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) | (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    for (int i = 0; i < 8; ++i) {
        v[i] = m_h[i];
        v[i + 8] = kBlake2sIv[i];
    }
    v[12] ^= static_cast<std::uint32_t>(m_counter);
    v[13] ^= static_cast<std::uint32_t>(m_counter >> 32);
    if (last) v[14] = ~v[14];
    auto g = [&](int r, int i, int a, int b, int c, int d) {
        v[a] = v[a] + v[b] + m[kBlake2sSigma[r][2 * i]];
        v[d] = rotr32(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + m[kBlake2sSigma[r][2 * i + 1]];
        v[d] = rotr32(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 7);
    };
    for (int r = 0; r < 10; ++r) {
        g(r, 0, 0, 4, 8, 12);
        g(r, 1, 1, 5, 9, 13);
        g(r, 2, 2, 6, 10, 14);
        g(r, 3, 3, 7, 11, 15);
        g(r, 4, 0, 5, 10, 15);
        g(r, 5, 1, 6, 11, 12);
        g(r, 6, 2, 7, 8, 13);
        g(r, 7, 3, 4, 9, 14);
    }
    for (int i = 0; i < 8; ++i) m_h[i] ^= v[i] ^ v[i + 8];
}

void Blake2s256::update(std::span<const std::byte> data) {
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    while (n > 0) {
        if (m_bufferLen == 64) {   // a full buffer is only compressed once more data follows (the last block is flagged)
            m_counter += 64;
            compress(m_buffer.data(), false);
            m_bufferLen = 0;
        }
        const std::size_t take = std::min(n, 64 - m_bufferLen);
        std::memcpy(m_buffer.data() + m_bufferLen, p, take);
        m_bufferLen += take;
        p += take;
        n -= take;
    }
}

std::vector<std::uint8_t> Blake2s256::finish() {
    m_counter += m_bufferLen;
    std::memset(m_buffer.data() + m_bufferLen, 0, 64 - m_bufferLen);
    compress(m_buffer.data(), true);
    std::vector<std::uint8_t> out(32);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<std::uint8_t>((m_h[i] >> (8 * j)) & 0xff);
    return out;
}

} // namespace stein
