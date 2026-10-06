// SPDX-License-Identifier: MIT
#include "stein/core/crypto.hpp"

#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"

#include <algorithm>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace stein::crypto {

namespace {

inline std::uint32_t rotl(std::uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

inline void quarterRound(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

// One 64-byte keystream block (RFC 8439 §2.3).
void chachaBlock(const std::uint32_t state[16], std::uint8_t out[64]) {
    std::uint32_t x[16];
    std::memcpy(x, state, sizeof x);
    for (int i = 0; i < 10; ++i) {
        quarterRound(x[0], x[4], x[8], x[12]);
        quarterRound(x[1], x[5], x[9], x[13]);
        quarterRound(x[2], x[6], x[10], x[14]);
        quarterRound(x[3], x[7], x[11], x[15]);
        quarterRound(x[0], x[5], x[10], x[15]);
        quarterRound(x[1], x[6], x[11], x[12]);
        quarterRound(x[2], x[7], x[8], x[13]);
        quarterRound(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) storeLe32(reinterpret_cast<std::byte*>(out) + 4 * i, x[i] + state[i]);
}

void chachaInit(std::uint32_t state[16], const Key256& key, const Nonce96& nonce, std::uint32_t counter) {
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) state[4 + i] = loadLe32(reinterpret_cast<const std::byte*>(key.data()) + 4 * i);
    state[12] = counter;
    for (int i = 0; i < 3; ++i) state[13 + i] = loadLe32(reinterpret_cast<const std::byte*>(nonce.data()) + 4 * i);
}

inline std::uint32_t u8to32(const std::uint8_t* p) { return loadLe32(reinterpret_cast<const std::byte*>(p)); }

// poly1305-donna, 32-bit limbs (26 bits each).
struct Poly1305State {
    std::uint32_t r[5], h[5] = {0, 0, 0, 0, 0}, pad[4];
    std::uint8_t buffer[16];
    std::size_t leftover = 0;

    explicit Poly1305State(const Key256& key) {
        const std::uint8_t* k = key.data();
        r[0] = (u8to32(k + 0)) & 0x3ffffff;
        r[1] = (u8to32(k + 3) >> 2) & 0x3ffff03;
        r[2] = (u8to32(k + 6) >> 4) & 0x3ffc0ff;
        r[3] = (u8to32(k + 9) >> 6) & 0x3f03fff;
        r[4] = (u8to32(k + 12) >> 8) & 0x00fffff;
        for (int i = 0; i < 4; ++i) pad[i] = u8to32(k + 16 + 4 * i);
    }

    void blocks(const std::uint8_t* m, std::size_t bytes, std::uint32_t hibit) {
        const std::uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
        const std::uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        std::uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        while (bytes >= 16) {
            h0 += (u8to32(m + 0)) & 0x3ffffff;
            h1 += (u8to32(m + 3) >> 2) & 0x3ffffff;
            h2 += (u8to32(m + 6) >> 4) & 0x3ffffff;
            h3 += (u8to32(m + 9) >> 6) & 0x3ffffff;
            h4 += (u8to32(m + 12) >> 8) | hibit;
            std::uint64_t d0 = std::uint64_t{h0} * r0 + std::uint64_t{h1} * s4 + std::uint64_t{h2} * s3 + std::uint64_t{h3} * s2 + std::uint64_t{h4} * s1;
            std::uint64_t d1 = std::uint64_t{h0} * r1 + std::uint64_t{h1} * r0 + std::uint64_t{h2} * s4 + std::uint64_t{h3} * s3 + std::uint64_t{h4} * s2;
            std::uint64_t d2 = std::uint64_t{h0} * r2 + std::uint64_t{h1} * r1 + std::uint64_t{h2} * r0 + std::uint64_t{h3} * s4 + std::uint64_t{h4} * s3;
            std::uint64_t d3 = std::uint64_t{h0} * r3 + std::uint64_t{h1} * r2 + std::uint64_t{h2} * r1 + std::uint64_t{h3} * r0 + std::uint64_t{h4} * s4;
            std::uint64_t d4 = std::uint64_t{h0} * r4 + std::uint64_t{h1} * r3 + std::uint64_t{h2} * r2 + std::uint64_t{h3} * r1 + std::uint64_t{h4} * r0;
            std::uint32_t c = static_cast<std::uint32_t>(d0 >> 26); h0 = static_cast<std::uint32_t>(d0) & 0x3ffffff; d1 += c;
            c = static_cast<std::uint32_t>(d1 >> 26); h1 = static_cast<std::uint32_t>(d1) & 0x3ffffff; d2 += c;
            c = static_cast<std::uint32_t>(d2 >> 26); h2 = static_cast<std::uint32_t>(d2) & 0x3ffffff; d3 += c;
            c = static_cast<std::uint32_t>(d3 >> 26); h3 = static_cast<std::uint32_t>(d3) & 0x3ffffff; d4 += c;
            c = static_cast<std::uint32_t>(d4 >> 26); h4 = static_cast<std::uint32_t>(d4) & 0x3ffffff; h0 += c * 5;
            c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
            m += 16;
            bytes -= 16;
        }
        h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    }

    void update(const std::uint8_t* m, std::size_t bytes) {
        if (leftover) {
            const std::size_t want = std::min(16 - leftover, bytes);
            std::memcpy(buffer + leftover, m, want);
            bytes -= want;
            m += want;
            leftover += want;
            if (leftover < 16) return;
            blocks(buffer, 16, 1u << 24);
            leftover = 0;
        }
        if (bytes >= 16) {
            const std::size_t want = bytes & ~std::size_t{15};
            blocks(m, want, 1u << 24);
            m += want;
            bytes -= want;
        }
        if (bytes) {
            std::memcpy(buffer, m, bytes);
            leftover = bytes;
        }
    }

    Tag128 finish() {
        if (leftover) {
            buffer[leftover++] = 1;
            for (; leftover < 16; ++leftover) buffer[leftover] = 0;
            blocks(buffer, 16, 0);
            leftover = 0;
        }
        std::uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        std::uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
        c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
        c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
        c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        // g = h + 5 - 2^130; select g when no borrow.
        std::uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        std::uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        std::uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        std::uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        std::uint32_t g4 = h4 + c - (1u << 26);
        std::uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
        // h mod 2^128
        h0 = (h0 | (h1 << 26));
        h1 = ((h1 >> 6) | (h2 << 20));
        h2 = ((h2 >> 12) | (h3 << 14));
        h3 = ((h3 >> 18) | (h4 << 8));
        std::uint64_t f = std::uint64_t{h0} + pad[0]; h0 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h1} + pad[1] + (f >> 32); h1 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h2} + pad[2] + (f >> 32); h2 = static_cast<std::uint32_t>(f);
        f = std::uint64_t{h3} + pad[3] + (f >> 32); h3 = static_cast<std::uint32_t>(f);
        Tag128 tag;
        storeLe32(reinterpret_cast<std::byte*>(tag.data()) + 0, h0);
        storeLe32(reinterpret_cast<std::byte*>(tag.data()) + 4, h1);
        storeLe32(reinterpret_cast<std::byte*>(tag.data()) + 8, h2);
        storeLe32(reinterpret_cast<std::byte*>(tag.data()) + 12, h3);
        return tag;
    }
};

// Poly1305 over AAD || pad16 || ciphertext || pad16 || le64(aad len) || le64(ct len), key = first 32 keystream bytes.
Tag128 aeadTag(const Key256& key, const Nonce96& nonce, std::span<const std::byte> aad, std::span<const std::byte> ciphertext) {
    std::uint32_t state[16];
    chachaInit(state, key, nonce, 0);
    std::uint8_t block[64];
    chachaBlock(state, block);
    Key256 otk;
    std::memcpy(otk.data(), block, 32);
    Poly1305State mac(otk);
    static const std::uint8_t zeros[16] = {};
    mac.update(reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size());
    if (aad.size() % 16) mac.update(zeros, 16 - aad.size() % 16);
    mac.update(reinterpret_cast<const std::uint8_t*>(ciphertext.data()), ciphertext.size());
    if (ciphertext.size() % 16) mac.update(zeros, 16 - ciphertext.size() % 16);
    std::uint8_t lens[16];
    storeLe64(reinterpret_cast<std::byte*>(lens), aad.size());
    storeLe64(reinterpret_cast<std::byte*>(lens) + 8, ciphertext.size());
    mac.update(lens, 16);
    return mac.finish();
}

} // namespace

void chacha20Xor(const Key256& key, const Nonce96& nonce, std::uint32_t counter, std::span<const std::byte> in, std::span<std::byte> out) {
    std::uint32_t state[16];
    chachaInit(state, key, nonce, counter);
    std::uint8_t block[64];
    std::size_t pos = 0;
    const std::size_t n = std::min(in.size(), out.size());
    while (pos < n) {
        chachaBlock(state, block);
        ++state[12];
        const std::size_t take = std::min<std::size_t>(64, n - pos);
        for (std::size_t i = 0; i < take; ++i) out[pos + i] = in[pos + i] ^ std::byte{block[i]};
        pos += take;
    }
}

Tag128 poly1305(const Key256& key, std::span<const std::byte> message) {
    Poly1305State mac(key);
    mac.update(reinterpret_cast<const std::uint8_t*>(message.data()), message.size());
    return mac.finish();
}

void aeadEncrypt(const Key256& key, const Nonce96& nonce, std::span<const std::byte> aad, std::span<const std::byte> plaintext, std::span<std::byte> out) {
    auto ct = out.first(plaintext.size());
    chacha20Xor(key, nonce, 1, plaintext, ct);
    const Tag128 tag = aeadTag(key, nonce, aad, ct);
    std::memcpy(out.data() + plaintext.size(), tag.data(), kTagSize);
}

Expected<void> aeadDecrypt(const Key256& key, const Nonce96& nonce, std::span<const std::byte> aad, std::span<const std::byte> in, std::span<std::byte> out) {
    if (in.size() < kTagSize) return fail(ErrorCategory::InvalidFormat, "ciphertext shorter than the tag");
    const auto ct = in.first(in.size() - kTagSize);
    if (out.size() < ct.size()) return fail(ErrorCategory::InvalidArgument, "output buffer too small");
    const Tag128 expected = aeadTag(key, nonce, aad, ct);
    const auto given = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(in.data()) + ct.size(), kTagSize);
    if (!equalConstantTime(expected, given)) {
        std::fill(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(ct.size()), std::byte{0});
        return fail(ErrorCategory::Integrity, "authentication tag mismatch (wrong key or corrupted data)");
    }
    chacha20Xor(key, nonce, 1, ct, out.first(ct.size()));
    return {};
}

std::array<std::uint8_t, 32> hmacSha256(std::span<const std::byte> key, std::span<const std::byte> message) {
    std::array<std::uint8_t, 64> k{};
    if (key.size() > 64) {
        auto d = Hasher::digest(HashAlgorithm::Sha256, key);
        std::copy(d.begin(), d.end(), k.begin());
    } else {
        std::memcpy(k.data(), key.data(), key.size());
    }
    std::array<std::byte, 64> ipad{}, opad{};
    for (int i = 0; i < 64; ++i) {
        ipad[static_cast<std::size_t>(i)] = std::byte(k[static_cast<std::size_t>(i)] ^ 0x36);
        opad[static_cast<std::size_t>(i)] = std::byte(k[static_cast<std::size_t>(i)] ^ 0x5c);
    }
    Sha256 inner;
    inner.update(ipad);
    inner.update(message);
    const auto ih = inner.finish();
    Sha256 outer;
    outer.update(opad);
    outer.update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(ih.data()), ih.size()));
    const auto oh = outer.finish();
    std::array<std::uint8_t, 32> out{};
    std::copy(oh.begin(), oh.end(), out.begin());
    return out;
}

void pbkdf2Sha256(std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out) {
    // Precompute the keyed inner/outer states once; each iteration is two compressions.
    std::array<std::uint8_t, 64> k{};
    if (password.size() > 64) {
        auto d = Hasher::digest(HashAlgorithm::Sha256, password);
        std::copy(d.begin(), d.end(), k.begin());
    } else {
        std::memcpy(k.data(), password.data(), password.size());
    }
    std::array<std::byte, 64> ipad{}, opad{};
    for (std::size_t i = 0; i < 64; ++i) {
        ipad[i] = std::byte(k[i] ^ 0x36);
        opad[i] = std::byte(k[i] ^ 0x5c);
    }
    Sha256 innerBase, outerBase;
    innerBase.update(ipad);
    outerBase.update(opad);
    auto prf = [&](std::span<const std::byte> msg, std::array<std::uint8_t, 32>& result) {
        Sha256 in = innerBase;
        in.update(msg);
        const auto ih = in.finish();
        Sha256 o = outerBase;
        o.update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(ih.data()), ih.size()));
        const auto oh = o.finish();
        std::copy(oh.begin(), oh.end(), result.begin());
    };
    std::uint32_t block = 1;
    std::size_t done = 0;
    std::vector<std::byte> first(salt.begin(), salt.end());
    first.resize(salt.size() + 4);
    while (done < out.size()) {
        storeBe32(first.data() + salt.size(), block);
        std::array<std::uint8_t, 32> u{}, t{};
        prf(first, u);
        t = u;
        for (std::uint32_t i = 1; i < iterations; ++i) {
            prf(std::span<const std::byte>(reinterpret_cast<const std::byte*>(u.data()), u.size()), u);
            for (std::size_t j = 0; j < 32; ++j) t[j] ^= u[j];
        }
        const std::size_t take = std::min<std::size_t>(32, out.size() - done);
        std::memcpy(out.data() + done, t.data(), take);
        done += take;
        ++block;
    }
}

// ----------------------------------------------------------------------------- BLAKE2b

namespace {

constexpr std::uint64_t kBlake2bIv[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                                        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
constexpr std::uint8_t kBlake2bSigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

inline std::uint64_t rotr64(std::uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }

struct Blake2bState {
    std::uint64_t h[8];
    std::uint64_t t[2] = {0, 0};
    std::uint8_t buf[128];
    std::size_t bufLen = 0;
    std::size_t outLen;

    Blake2bState(std::size_t outlen, std::size_t keylen) : outLen(outlen) {
        for (int i = 0; i < 8; ++i) h[i] = kBlake2bIv[i];
        h[0] ^= 0x01010000ull ^ (static_cast<std::uint64_t>(keylen) << 8) ^ static_cast<std::uint64_t>(outlen);
    }

    void compress(const std::uint8_t block[128], bool last) {
        std::uint64_t m[16], v[16];
        for (int i = 0; i < 16; ++i) m[i] = loadLe64(reinterpret_cast<const std::byte*>(block) + 8 * i);
        for (int i = 0; i < 8; ++i) {
            v[i] = h[i];
            v[i + 8] = kBlake2bIv[i];
        }
        v[12] ^= t[0];
        v[13] ^= t[1];
        if (last) v[14] = ~v[14];
        auto g = [&](int r, int i, int a, int b, int c, int d) {
            v[a] = v[a] + v[b] + m[kBlake2bSigma[r][2 * i]];
            v[d] = rotr64(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = rotr64(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + m[kBlake2bSigma[r][2 * i + 1]];
            v[d] = rotr64(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = rotr64(v[b] ^ v[c], 63);
        };
        for (int r = 0; r < 12; ++r) {
            g(r, 0, 0, 4, 8, 12);
            g(r, 1, 1, 5, 9, 13);
            g(r, 2, 2, 6, 10, 14);
            g(r, 3, 3, 7, 11, 15);
            g(r, 4, 0, 5, 10, 15);
            g(r, 5, 1, 6, 11, 12);
            g(r, 6, 2, 7, 8, 13);
            g(r, 7, 3, 4, 9, 14);
        }
        for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
    }

    void update(const std::uint8_t* p, std::size_t n) {
        while (n) {
            if (bufLen == 128) {
                t[0] += 128;
                if (t[0] < 128) ++t[1];
                compress(buf, false);
                bufLen = 0;
            }
            const std::size_t take = std::min(n, 128 - bufLen);
            std::memcpy(buf + bufLen, p, take);
            bufLen += take;
            p += take;
            n -= take;
        }
    }

    void finish(std::uint8_t* out) {
        t[0] += bufLen;
        if (t[0] < bufLen) ++t[1];
        std::memset(buf + bufLen, 0, 128 - bufLen);
        compress(buf, true);
        std::uint8_t full[64];
        for (int i = 0; i < 8; ++i) storeLe64(reinterpret_cast<std::byte*>(full) + 8 * i, h[i]);
        std::memcpy(out, full, outLen);
    }
};

} // namespace

void blake2b(std::span<std::uint8_t> out, std::span<const std::byte> message, std::span<const std::byte> key) {
    const std::size_t outLen = std::min<std::size_t>(out.size(), 64);
    Blake2bState st(outLen, key.size());
    if (!key.empty()) {
        std::uint8_t block[128] = {};
        std::memcpy(block, key.data(), std::min<std::size_t>(key.size(), 64));
        st.update(block, 128);
    }
    st.update(reinterpret_cast<const std::uint8_t*>(message.data()), message.size());
    st.finish(out.data());
}

// ----------------------------------------------------------------------------- Argon2id

namespace {

constexpr std::size_t kArgonBlockWords = 128;   // 1024 bytes
struct ArgonBlock {
    std::uint64_t v[kArgonBlockWords];
};

inline void argonXor(ArgonBlock& dst, const ArgonBlock& a, const ArgonBlock& b) {
    for (std::size_t i = 0; i < kArgonBlockWords; ++i) dst.v[i] = a.v[i] ^ b.v[i];
}

inline std::uint64_t mulLo(std::uint64_t a, std::uint64_t b) { return 2 * (a & 0xFFFFFFFFull) * (b & 0xFFFFFFFFull); }

inline void argonGb(std::uint64_t& a, std::uint64_t& b, std::uint64_t& c, std::uint64_t& d) {
    a = a + b + mulLo(a, b); d = rotr64(d ^ a, 32);
    c = c + d + mulLo(c, d); b = rotr64(b ^ c, 24);
    a = a + b + mulLo(a, b); d = rotr64(d ^ a, 16);
    c = c + d + mulLo(c, d); b = rotr64(b ^ c, 63);
}

inline void argonP(std::uint64_t& v0, std::uint64_t& v1, std::uint64_t& v2, std::uint64_t& v3, std::uint64_t& v4, std::uint64_t& v5, std::uint64_t& v6, std::uint64_t& v7,
                   std::uint64_t& v8, std::uint64_t& v9, std::uint64_t& v10, std::uint64_t& v11, std::uint64_t& v12, std::uint64_t& v13, std::uint64_t& v14, std::uint64_t& v15) {
    argonGb(v0, v4, v8, v12); argonGb(v1, v5, v9, v13); argonGb(v2, v6, v10, v14); argonGb(v3, v7, v11, v15);
    argonGb(v0, v5, v10, v15); argonGb(v1, v6, v11, v12); argonGb(v2, v7, v8, v13); argonGb(v3, v4, v9, v14);
}

// G(X, Y): the Argon2 compression function. `out` may alias neither input.
void argonG(const ArgonBlock& x, const ArgonBlock& y, ArgonBlock& out) {
    ArgonBlock r;
    argonXor(r, x, y);
    ArgonBlock q = r;
    std::uint64_t* w = q.v;
    for (int i = 0; i < 8; ++i) {   // rows: 16 consecutive words
        std::uint64_t* p = w + 16 * i;
        argonP(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    for (int i = 0; i < 8; ++i) {   // columns: word pairs (2i, 2i+1) of every row
        argonP(w[2 * i], w[2 * i + 1], w[16 + 2 * i], w[16 + 2 * i + 1], w[32 + 2 * i], w[32 + 2 * i + 1], w[48 + 2 * i], w[48 + 2 * i + 1],
               w[64 + 2 * i], w[64 + 2 * i + 1], w[80 + 2 * i], w[80 + 2 * i + 1], w[96 + 2 * i], w[96 + 2 * i + 1], w[112 + 2 * i], w[112 + 2 * i + 1]);
    }
    argonXor(out, q, r);
}

// Variable-length hash H'(X) of RFC 9106 §3.3.
void argonHPrime(std::span<std::uint8_t> out, std::span<const std::byte> input) {
    const std::uint32_t t = static_cast<std::uint32_t>(out.size());
    std::vector<std::byte> buf(4 + input.size());
    storeLe32(buf.data(), t);
    std::memcpy(buf.data() + 4, input.data(), input.size());
    if (t <= 64) {
        blake2b(out, buf);
        return;
    }
    const std::size_t r = (t + 31) / 32 - 2;
    std::array<std::uint8_t, 64> v{};
    blake2b(v, buf);
    std::size_t pos = 0;
    for (std::size_t i = 0; i < r; ++i) {
        std::memcpy(out.data() + pos, v.data(), 32);
        pos += 32;
        if (i + 1 < r) {   // V_{r+1} below is derived from V_r itself
            std::array<std::uint8_t, 64> next{};
            blake2b(next, std::span<const std::byte>(reinterpret_cast<const std::byte*>(v.data()), 64));
            v = next;
        }
    }
    const std::size_t rest = t - 32 * r;
    std::array<std::uint8_t, 64> last{};
    blake2b(std::span<std::uint8_t>(last).first(rest), std::span<const std::byte>(reinterpret_cast<const std::byte*>(v.data()), 64));
    std::memcpy(out.data() + pos, last.data(), rest);
}

void le32push(std::vector<std::byte>& v, std::uint32_t x) {
    std::byte b[4];
    storeLe32(b, x);
    v.insert(v.end(), b, b + 4);
}

} // namespace

Expected<void> argon2(Argon2Type type, std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t passes, std::uint32_t memoryKiB,
                      std::uint32_t parallelism, std::span<std::uint8_t> out, std::span<const std::byte> secret, std::span<const std::byte> ad) {
    if (parallelism == 0 || parallelism > 0xFFFFFF) return fail(ErrorCategory::InvalidArgument, "argon2: bad parallelism");
    if (passes == 0) return fail(ErrorCategory::InvalidArgument, "argon2: passes must be >= 1");
    if (memoryKiB < 8 * parallelism) return fail(ErrorCategory::InvalidArgument, "argon2: memory must be at least 8 KiB per lane");
    if (out.size() < 4) return fail(ErrorCategory::InvalidArgument, "argon2: output too short");
    if (salt.size() < 8) return fail(ErrorCategory::InvalidArgument, "argon2: salt must be at least 8 bytes");
    constexpr std::uint32_t kVersion = 0x13;
    const std::uint32_t kTypeId = static_cast<std::uint32_t>(type);
    // H0
    std::vector<std::byte> h0in;
    le32push(h0in, parallelism);
    le32push(h0in, static_cast<std::uint32_t>(out.size()));
    le32push(h0in, memoryKiB);
    le32push(h0in, passes);
    le32push(h0in, kVersion);
    le32push(h0in, kTypeId);
    le32push(h0in, static_cast<std::uint32_t>(password.size()));
    h0in.insert(h0in.end(), password.begin(), password.end());
    le32push(h0in, static_cast<std::uint32_t>(salt.size()));
    h0in.insert(h0in.end(), salt.begin(), salt.end());
    le32push(h0in, static_cast<std::uint32_t>(secret.size()));
    h0in.insert(h0in.end(), secret.begin(), secret.end());
    le32push(h0in, static_cast<std::uint32_t>(ad.size()));
    h0in.insert(h0in.end(), ad.begin(), ad.end());
    std::array<std::uint8_t, 64> h0{};
    blake2b(h0, h0in);

    const std::uint32_t lanes = parallelism;
    const std::uint32_t mPrime = 4 * lanes * (memoryKiB / (4 * lanes));
    const std::uint32_t q = mPrime / lanes;          // lane length
    const std::uint32_t segLen = q / 4;
    std::vector<ArgonBlock> memory(mPrime);
    auto block = [&](std::uint32_t lane, std::uint32_t index) -> ArgonBlock& { return memory[static_cast<std::size_t>(lane) * q + index]; };

    // First two blocks of every lane.
    for (std::uint32_t l = 0; l < lanes; ++l) {
        for (std::uint32_t j = 0; j < 2; ++j) {
            std::vector<std::byte> in(h0.size() + 8);
            std::memcpy(in.data(), h0.data(), h0.size());
            storeLe32(in.data() + 64, j);
            storeLe32(in.data() + 68, l);
            std::array<std::uint8_t, 1024> raw{};
            argonHPrime(raw, in);
            for (std::size_t w = 0; w < kArgonBlockWords; ++w) block(l, j).v[w] = loadLe64(reinterpret_cast<const std::byte*>(raw.data()) + 8 * w);
        }
    }

    ArgonBlock zero{};
    std::memset(zero.v, 0, sizeof zero.v);
    for (std::uint32_t pass = 0; pass < passes; ++pass) {
        for (std::uint32_t slice = 0; slice < 4; ++slice) {
            for (std::uint32_t lane = 0; lane < lanes; ++lane) {
                // Argon2i: always data-independent; Argon2d: never; Argon2id: first half of pass 0.
                const bool independent = type == Argon2Type::I || (type == Argon2Type::Id && pass == 0 && slice < 2);
                ArgonBlock addr{}, inputBlock{};
                std::memset(inputBlock.v, 0, sizeof inputBlock.v);
                inputBlock.v[0] = pass;
                inputBlock.v[1] = lane;
                inputBlock.v[2] = slice;
                inputBlock.v[3] = mPrime;
                inputBlock.v[4] = passes;
                inputBlock.v[5] = kTypeId;
                std::uint32_t start = (pass == 0 && slice == 0) ? 2 : 0;
                if (independent && start != 0) {
                    // Generate the first address block (counter 1) even though indices 0,1 are prefilled.
                    inputBlock.v[6] = 1;
                    ArgonBlock tmp;
                    argonG(zero, inputBlock, tmp);
                    argonG(zero, tmp, addr);
                }
                for (std::uint32_t index = start; index < segLen; ++index) {
                    std::uint32_t j1, j2;
                    if (independent) {
                        if (index % 128 == 0) {
                            inputBlock.v[6] = index / 128 + 1;
                            ArgonBlock tmp;
                            argonG(zero, inputBlock, tmp);
                            argonG(zero, tmp, addr);
                        }
                        const std::uint64_t pr = addr.v[index % 128];
                        j1 = static_cast<std::uint32_t>(pr);
                        j2 = static_cast<std::uint32_t>(pr >> 32);
                    } else {
                        const std::uint32_t cur = slice * segLen + index;
                        const std::uint32_t prev = cur == 0 ? q - 1 : cur - 1;
                        const std::uint64_t pr = block(lane, prev).v[0];
                        j1 = static_cast<std::uint32_t>(pr);
                        j2 = static_cast<std::uint32_t>(pr >> 32);
                    }
                    const std::uint32_t refLane = (pass == 0 && slice == 0) ? lane : j2 % lanes;
                    const bool sameLane = refLane == lane;
                    std::uint64_t refArea;
                    if (pass == 0) {
                        if (slice == 0) refArea = index - 1;
                        else if (sameLane) refArea = static_cast<std::uint64_t>(slice) * segLen + index - 1;
                        else refArea = static_cast<std::uint64_t>(slice) * segLen - (index == 0 ? 1 : 0);
                    } else {
                        if (sameLane) refArea = static_cast<std::uint64_t>(q) - segLen + index - 1;
                        else refArea = static_cast<std::uint64_t>(q) - segLen - (index == 0 ? 1 : 0);
                    }
                    std::uint64_t rel = j1;
                    rel = (rel * rel) >> 32;
                    rel = refArea - 1 - ((refArea * rel) >> 32);
                    const std::uint32_t startPos = pass == 0 ? 0 : (slice == 3 ? 0 : (slice + 1) * segLen);
                    const std::uint32_t refIndex = static_cast<std::uint32_t>((startPos + rel) % q);
                    const std::uint32_t cur = slice * segLen + index;
                    const std::uint32_t prev = cur == 0 ? q - 1 : cur - 1;
                    ArgonBlock fresh;
                    argonG(block(lane, prev), block(refLane, refIndex), fresh);
                    if (pass == 0) block(lane, cur) = fresh;
                    else argonXor(block(lane, cur), block(lane, cur), fresh);
                }
            }
        }
    }
    // Final block: XOR of the last block of every lane.
    ArgonBlock c = block(0, q - 1);
    for (std::uint32_t l = 1; l < lanes; ++l) argonXor(c, c, block(l, q - 1));
    std::array<std::byte, 1024> cbytes{};
    for (std::size_t w = 0; w < kArgonBlockWords; ++w) storeLe64(cbytes.data() + 8 * w, c.v[w]);
    argonHPrime(out, cbytes);
    return {};
}

Expected<void> randomBytes(std::span<std::uint8_t> out) {
    if (out.empty()) return {};
#if defined(_WIN32)
    if (BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return fail(ErrorCategory::Internal, "BCryptGenRandom failed");
    return {};
#elif defined(__APPLE__)
    arc4random_buf(out.data(), out.size());
    return {};
#elif defined(__linux__)
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t n = ::getrandom(out.data() + done, out.size() - done, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    if (done == out.size()) return {};
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail(ErrorCategory::Internal, "no randomness source", errno);
    while (done < out.size()) {
        const ssize_t n = ::read(fd, out.data() + done, out.size() - done);
        if (n <= 0) {
            ::close(fd);
            return fail(ErrorCategory::Internal, "reading /dev/urandom failed", errno);
        }
        done += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return {};
#else
    return fail(ErrorCategory::Unsupported, "no randomness source on this platform");
#endif
}

bool equalConstantTime(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    if (a.size() != b.size()) return false;
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace stein::crypto

// ----------------------------------------------------------------------------- generic HMAC / PBKDF2

namespace stein::crypto {

namespace {
// Keyed HMAC state over a concrete hasher type: the inner and outer pads are absorbed
// once, then each MAC copies the two small hasher objects instead of allocating.
template <class H>
struct HmacState {
    H inner, outer;
    explicit HmacState(std::span<const std::byte> key) {
        const std::size_t blockSize = H().blockSize();
        std::vector<std::uint8_t> k(blockSize, 0);
        if (key.size() > blockSize) {
            H h;
            h.update(key);
            auto d = h.finish();
            std::copy(d.begin(), d.end(), k.begin());
        } else if (!key.empty()) {
            std::memcpy(k.data(), key.data(), key.size());
        }
        std::vector<std::byte> ipad(blockSize), opad(blockSize);
        for (std::size_t i = 0; i < blockSize; ++i) {
            ipad[i] = std::byte(k[i] ^ 0x36);
            opad[i] = std::byte(k[i] ^ 0x5c);
        }
        inner.update(ipad);
        outer.update(opad);
    }
    std::vector<std::uint8_t> mac(std::span<const std::byte> msg) const {
        H in = inner;
        in.update(msg);
        const auto ih = in.finish();
        H out = outer;
        out.update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(ih.data()), ih.size()));
        return out.finish();
    }
};

template <class H>
void pbkdf2With(std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out) {
    const HmacState<H> prf(password);
    const std::size_t hLen = H().digestSize();
    std::uint32_t block = 1;
    std::size_t done = 0;
    while (done < out.size()) {
        std::vector<std::byte> first(salt.begin(), salt.end());
        first.resize(salt.size() + 4);
        first[salt.size()] = std::byte(block >> 24);
        first[salt.size() + 1] = std::byte(block >> 16);
        first[salt.size() + 2] = std::byte(block >> 8);
        first[salt.size() + 3] = std::byte(block);
        auto u = prf.mac(first);
        auto t = u;
        for (std::uint32_t i = 1; i < iterations; ++i) {
            u = prf.mac(std::span<const std::byte>(reinterpret_cast<const std::byte*>(u.data()), u.size()));
            for (std::size_t j = 0; j < hLen; ++j) t[j] ^= u[j];
        }
        const std::size_t take = std::min(hLen, out.size() - done);
        std::memcpy(out.data() + done, t.data(), take);
        done += take;
        ++block;
    }
}
} // namespace

std::vector<std::uint8_t> hmac(HashAlgorithm hash, std::span<const std::byte> key, std::span<const std::byte> message) {
    switch (hash) {
    case HashAlgorithm::Sha256: {
        auto d = hmacSha256(key, message);
        return std::vector<std::uint8_t>(d.begin(), d.end());
    }
    case HashAlgorithm::Sha512: return HmacState<Sha512>(key).mac(message);
    case HashAlgorithm::Sha1: return HmacState<Sha1>(key).mac(message);
    case HashAlgorithm::Md5: return HmacState<Md5>(key).mac(message);
    case HashAlgorithm::Ripemd160: return HmacState<Ripemd160>(key).mac(message);
    case HashAlgorithm::Blake2s256: return HmacState<Blake2s256>(key).mac(message);
    }
    return {};
}

void pbkdf2(HashAlgorithm hash, std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out) {
    switch (hash) {
    case HashAlgorithm::Sha256: pbkdf2Sha256(password, salt, iterations, out); return;
    case HashAlgorithm::Sha512: pbkdf2With<Sha512>(password, salt, iterations, out); return;
    case HashAlgorithm::Sha1: pbkdf2With<Sha1>(password, salt, iterations, out); return;
    case HashAlgorithm::Md5: pbkdf2With<Md5>(password, salt, iterations, out); return;
    case HashAlgorithm::Ripemd160: pbkdf2With<Ripemd160>(password, salt, iterations, out); return;
    case HashAlgorithm::Blake2s256: pbkdf2With<Blake2s256>(password, salt, iterations, out); return;
    }
}

} // namespace stein::crypto
