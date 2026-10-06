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
