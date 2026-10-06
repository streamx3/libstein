// SPDX-License-Identifier: MIT
// Straightforward implementations from RFC 1321 (MD5) and FIPS 180-4 (SHA-256).
// Not optimised; correctness and readability first. An OpenSSL/mbedTLS backend
// can replace these behind Hasher::create() when speed matters.
#include "stein/core/hash.hpp"

#include <cstdio>
#include <algorithm>
#include <cstring>

namespace stein {

std::string_view toString(HashAlgorithm a) {
    switch (a) {
    case HashAlgorithm::Md5: return "md5";
    case HashAlgorithm::Sha256: return "sha256";
    }
    return "?";
}

std::unique_ptr<Hasher> Hasher::create(HashAlgorithm a) {
    switch (a) {
    case HashAlgorithm::Md5: return std::make_unique<Md5>();
    case HashAlgorithm::Sha256: return std::make_unique<Sha256>();
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

void Sha256::transform(const std::uint8_t block[64]) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) | static_cast<std::uint32_t>(block[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3], e = m_state[4],
                  f = m_state[5], g = m_state[6], h = m_state[7];
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
    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
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
