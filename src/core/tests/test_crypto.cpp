// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "crypto_vectors.hpp"
#include "kdf_vectors.hpp"
#include "stein/core/crypto.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"

#include <algorithm>

using namespace stein;

namespace {
std::vector<std::byte> hexBytes(const char* hex) {
    std::vector<std::byte> out;
    for (std::size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
        auto nib = [](char c) { return static_cast<std::uint8_t>(c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0'); };
        out.push_back(std::byte(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1]))));
    }
    return out;
}
template <std::size_t N> std::array<std::uint8_t, N> fixed(const char* hex) {
    auto v = hexBytes(hex);
    std::array<std::uint8_t, N> a{};
    for (std::size_t i = 0; i < N && i < v.size(); ++i) a[i] = std::to_integer<std::uint8_t>(v[i]);
    return a;
}
std::string hexOf(std::span<const std::byte> b) {
    std::string s;
    for (auto x : b) {
        char buf[3];
        std::snprintf(buf, sizeof buf, "%02x", std::to_integer<unsigned>(x));
        s += buf;
    }
    return s;
}
} // namespace

TEST_CASE("chacha20: keystream vectors from the oracle") {
    for (const auto& v : test::vectors::kStream) {
        const auto key = fixed<32>(v.key);
        const auto nonce = fixed<12>(v.nonce);
        const auto expect = hexBytes(v.keystream);
        std::vector<std::byte> zeros(expect.size()), out(expect.size());
        crypto::chacha20Xor(key, nonce, v.counter, zeros, out);
        CHECK(hexOf(out) == v.keystream);
    }
}

TEST_CASE("chacha20-poly1305: RFC 8439 and oracle vectors, tamper detection") {
    for (const auto& v : test::vectors::kAead) {
        const auto key = fixed<32>(v.key);
        const auto nonce = fixed<12>(v.nonce);
        const auto aad = hexBytes(v.aad);
        const auto pt = hexBytes(v.plaintext);
        const auto expect = hexBytes(v.ciphertextAndTag);
        std::vector<std::byte> ct(pt.size() + crypto::kTagSize);
        crypto::aeadEncrypt(key, nonce, aad, pt, ct);
        CHECK(hexOf(ct) == v.ciphertextAndTag);
        std::vector<std::byte> back(pt.size());
        REQUIRE(crypto::aeadDecrypt(key, nonce, aad, ct, back));
        CHECK(back == pt);
        // Any flipped bit in ciphertext, tag or AAD fails authentication.
        auto bad = ct;
        bad[bad.size() / 2] ^= std::byte{0x01};
        auto r = crypto::aeadDecrypt(key, nonce, aad, bad, back);
        CHECK_FALSE(r);
        CHECK(r.error().category() == ErrorCategory::Integrity);
        if (!aad.empty()) {
            auto badAad = aad;
            badAad[0] ^= std::byte{0x80};
            CHECK_FALSE(crypto::aeadDecrypt(key, nonce, badAad, ct, back));
        }
        auto badNonce = nonce;
        badNonce[11] ^= 1;
        CHECK_FALSE(crypto::aeadDecrypt(key, badNonce, aad, ct, back));
    }
    // RFC 8439 §2.8.2 tag (first vector in the table).
    CHECK(std::string(test::vectors::kAead[0].ciphertextAndTag).substr(2 * 114) == "1ae10b594f09e26a7e902ecbd0600691");
}

TEST_CASE("hmac-sha256 and pbkdf2-hmac-sha256 vectors") {
    for (const auto& v : test::vectors::kHmac) {
        const auto mac = crypto::hmacSha256(hexBytes(v.key), hexBytes(v.message));
        CHECK(Hasher::hex(mac) == v.mac);
    }
    for (const auto& v : test::vectors::kPbkdf2) {
        std::vector<std::uint8_t> out(v.length);
        crypto::pbkdf2Sha256(hexBytes(v.password), hexBytes(v.salt), v.iterations, out);
        CHECK(Hasher::hex(out) == v.derived);
    }
}

TEST_CASE("random bytes and constant-time compare") {
    std::array<std::uint8_t, 32> a{}, b{};
    REQUIRE(crypto::randomBytes(a));
    REQUIRE(crypto::randomBytes(b));
    CHECK(a != b);
    CHECK(std::count(a.begin(), a.end(), 0) < 16);
    CHECK(crypto::equalConstantTime(a, a));
    CHECK_FALSE(crypto::equalConstantTime(a, b));
    CHECK_FALSE(crypto::equalConstantTime(std::span<const std::uint8_t>(a).first(16), a));
}

TEST_CASE("blake2b: unkeyed and keyed vectors, all output lengths") {
    for (const auto& v : test::vectors::kBlake2b) {
        std::vector<std::uint8_t> out(v.outLen);
        crypto::blake2b(out, hexBytes(v.message), hexBytes(v.key));
        CHECK(Hasher::hex(out) == v.digest);
    }
}

TEST_CASE("argon2id: RFC 9106 vector and oracle vectors") {
    for (const auto& v : test::vectors::kArgon2id) {
        std::vector<std::uint8_t> out(v.outLen);
        auto r = crypto::argon2id(hexBytes(v.password), hexBytes(v.salt), v.t, v.mKiB, v.p, out, hexBytes(v.secret), hexBytes(v.ad));
        REQUIRE(r);
        CHECK(Hasher::hex(out) == v.tag);
    }
    std::vector<std::uint8_t> out(32);
    CHECK_FALSE(crypto::argon2id(hexBytes("00"), hexBytes("0000000000000000"), 0, 64, 1, out));
    CHECK_FALSE(crypto::argon2id(hexBytes("00"), hexBytes("0000000000000000"), 1, 4, 1, out));
    CHECK_FALSE(crypto::argon2id(hexBytes("00"), hexBytes("0000"), 1, 64, 1, out));
}

#include "stein/core/keys.hpp"

TEST_CASE("key area: argon2id and pbkdf2 slots side by side, JSON round trip") {
    auto keys = Keys::create("alpha", KdfParams::fast(), "first");
    REQUIRE(keys);
    REQUIRE(keys->master());
    auto id = keys->addSlot(*keys->master(), "beta", KdfParams::pbkdf2(1000), "legacy");
    REQUIRE(id);
    CHECK(*id == 1);
    const std::string json = keys->toJson();
    CHECK(json.find("\"argon2id\"") != std::string::npos);
    CHECK(json.find("\"pbkdf2-hmac-sha256\"") != std::string::npos);
    auto back = Keys::fromJson(json);
    REQUIRE(back);
    CHECK(back->slots().size() == 2);
    CHECK(back->slots()[0].kdf.kind == KdfParams::Kind::Argon2id);
    CHECK(back->slots()[1].kdf.kind == KdfParams::Kind::Pbkdf2Sha256);
    CHECK(back->slots()[1].kdf.cost == 1000);
    CHECK(*back->unlock("alpha") == *keys->master());
    CHECK(*back->unlock("beta") == *keys->master());
    CHECK(back->unlock("gamma").error().category() == ErrorCategory::Integrity);
    CHECK_FALSE(Keys::create("x", KdfParams::pbkdf2(10)));
    CHECK_FALSE(Keys::create("x", KdfParams::argon2id(1, 4, 1)));
    CHECK(KdfParams().kind == KdfParams::Kind::Argon2id);
}
