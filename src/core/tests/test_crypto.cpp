// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "crypto_vectors.hpp"
#include "kdf_vectors.hpp"
#include "stein/core/crypto.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"

#include <algorithm>
#include <cstring>

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

#include "aes_vectors.hpp"
#include "stein/core/aes.hpp"

#include "../src/aes_impl.hpp"

TEST_CASE("aes: FIPS-197 and oracle block vectors, portable and hardware kernels agree") {
    MESSAGE("aes hardware: ", crypto::aesHardwareAvailable());
    for (const auto& v : test::vectors::kAesBlock) {
        const auto key = hexBytes(v.key);
        std::vector<std::uint8_t> k(key.size());
        for (std::size_t i = 0; i < k.size(); ++i) k[i] = std::to_integer<std::uint8_t>(key[i]);
        auto aes = crypto::Aes::create(k);
        REQUIRE(aes);
        const auto pt = hexBytes(v.plaintext);
        std::uint8_t in[16], out[16], back[16];
        for (int i = 0; i < 16; ++i) in[i] = std::to_integer<std::uint8_t>(pt[static_cast<std::size_t>(i)]);
        aes->encryptBlock(in, out);
        CHECK(Hasher::hex(out) == v.ciphertext);
        aes->decryptBlock(out, back);
        CHECK(std::memcmp(back, in, 16) == 0);
        // Both kernels, explicitly.
        std::uint8_t p1[16], p2[16];
        crypto::detail::aesEncryptPortable(aes->roundKeys(), aes->rounds(), in, p1);
        CHECK(Hasher::hex(p1) == v.ciphertext);
        crypto::detail::aesDecryptPortable(aes->roundKeys(), aes->rounds(), p1, p2);
        CHECK(std::memcmp(p2, in, 16) == 0);
        if (crypto::aesHardwareAvailable()) {
            crypto::detail::aesEncryptHardware(aes->roundKeys(), aes->rounds(), in, p1);
            CHECK(Hasher::hex(p1) == v.ciphertext);
            crypto::detail::aesDecryptHardware(aes->roundKeys(), aes->rounds(), p1, p2);
            CHECK(std::memcmp(p2, in, 16) == 0);
        }
    }
    CHECK_FALSE(crypto::Aes::create(std::vector<std::uint8_t>(20)));
}

TEST_CASE("aes-xts: plain64 sector tweak vectors and round trips") {
    for (const auto& v : test::vectors::kXts) {
        const auto key = hexBytes(v.key);
        std::vector<std::uint8_t> k(key.size());
        for (std::size_t i = 0; i < k.size(); ++i) k[i] = std::to_integer<std::uint8_t>(key[i]);
        auto xts = crypto::AesXts::create(k);
        REQUIRE(xts);
        const auto pt = hexBytes(v.plaintext);
        std::vector<std::byte> ct(pt.size()), back(pt.size());
        REQUIRE(xts->encrypt(v.sector, pt, ct));
        CHECK(hexOf(ct) == v.ciphertext);
        REQUIRE(xts->decrypt(v.sector, ct, back));
        CHECK(back == pt);
        if (pt.size() % 512 == 0 && pt.size() > 512) {
            // Per-sector helpers: sector n of the run uses tweak first+n.
            std::vector<std::byte> ct2(pt.size());
            REQUIRE(xts->encryptSectors(v.sector, 512, pt, ct2));
            CHECK(std::equal(ct2.begin(), ct2.begin() + 512, ct.begin()));
            REQUIRE(xts->decryptSectors(v.sector, 512, ct2, back));
            CHECK(back == pt);
        }
    }
    std::vector<std::uint8_t> same(64, 1);
    CHECK_FALSE(crypto::AesXts::create(same));
    std::vector<std::uint8_t> k(64);
    for (std::size_t i = 0; i < 64; ++i) k[i] = static_cast<std::uint8_t>(i);
    auto xts = crypto::AesXts::create(k);
    REQUIRE(xts);
    std::vector<std::byte> odd(20), o(20);
    CHECK_FALSE(xts->encrypt(0, odd, o));
}

TEST_CASE("sha1 vectors and base64 round trips") {
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha1, {})) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha1, test::bytesOf("abc"))) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha1, test::bytesOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) == "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    std::string million(1000000, 'a');
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha1, test::bytesOf(million))) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    for (std::size_t n = 0; n < 70; ++n) {
        std::vector<std::byte> b(n);
        for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::byte>(i * 37 + n);
        const auto text = toBase64(b);
        CHECK(text.size() == (n + 2) / 3 * 4);
        auto back = fromBase64(text);
        REQUIRE(back);
        CHECK(*back == b);
    }
    CHECK(toBase64(test::bytesOf("Man")) == "TWFu");
    CHECK(toBase64(test::bytesOf("Ma")) == "TWE=");
    CHECK(fromBase64("TWE").value() == std::vector<std::byte>{std::byte{'M'}, std::byte{'a'}});
    CHECK_FALSE(fromBase64("T*E="));
}

TEST_CASE("sha512, hmac-sha512 and pbkdf2-hmac-sha512 vectors") {
    auto bytes = [](std::string_view s) { return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()); };
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha512, bytes(""))) ==
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha512, bytes("abc"))) ==
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha512, bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))) ==
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    // Incremental update across the 128-byte block boundary.
    {
        Sha512 h;
        std::string a(100, 'a'), b(100, 'a');
        h.update(bytes(a));
        h.update(bytes(b));
        CHECK(Hasher::hex(h.finish()) == Hasher::hex(Hasher::digest(HashAlgorithm::Sha512, bytes(std::string(200, 'a')))));
    }
    // RFC 4231 test case 2.
    CHECK(Hasher::hex(crypto::hmac(HashAlgorithm::Sha512, bytes("Jefe"), bytes("what do ya want for nothing?"))) ==
          "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    // PBKDF2-HMAC-SHA512("password", "salt", 1, 64) and c = 4096 (well-known vectors).
    std::vector<std::uint8_t> dk(64);
    crypto::pbkdf2(HashAlgorithm::Sha512, bytes("password"), bytes("salt"), 1, dk);
    CHECK(Hasher::hex(dk) == "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
    crypto::pbkdf2(HashAlgorithm::Sha512, bytes("password"), bytes("salt"), 4096, dk);
    CHECK(Hasher::hex(dk) == "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
    // Generic SHA-256 path agrees with the native one.
    std::vector<std::uint8_t> a(32), b(32);
    crypto::pbkdf2(HashAlgorithm::Sha256, bytes("pw"), bytes("salt"), 100, a);
    crypto::pbkdf2Sha256(bytes("pw"), bytes("salt"), 100, b);
    CHECK(a == b);
}

#include "inflate_vectors.hpp"
#include "stein/core/inflate.hpp"

TEST_CASE("inflate: stored, fixed and dynamic blocks, raw/zlib/gzip wrappers, truncation and small buffers") {
    for (const auto& v : test::vectors::kInflate) {
        CAPTURE(v.name);
        auto comp = hexBytes(v.compressedHex);
        std::vector<std::byte> out(v.plainLength);
        const std::string kind = v.kind;
        auto n = kind == "raw" ? compress::inflateRaw(comp, out) : kind == "gzip" ? compress::inflateGzip(comp, out) : compress::inflateZlib(comp, out);
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.plainLength);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, out)) == v.plainSha256);
        // Too small an output buffer is OutOfRange, a truncated stream InvalidFormat.
        std::vector<std::byte> small(v.plainLength / 2);
        auto s = kind == "raw" ? compress::inflateRaw(comp, small) : kind == "gzip" ? compress::inflateGzip(comp, small) : compress::inflateZlib(comp, small);
        REQUIRE_FALSE(s);
        CHECK(s.error().category() == ErrorCategory::OutOfRange);
        auto cut = std::span<const std::byte>(comp).subspan(0, comp.size() / 2);
        auto t = kind == "raw" ? compress::inflateRaw(cut, out) : kind == "gzip" ? compress::inflateGzip(cut, out) : compress::inflateZlib(cut, out);
        CHECK_FALSE(t);
    }
    // Adler-32 of "Wikipedia" (RFC 1950 example value).
    const std::string w = "Wikipedia";
    CHECK(compress::adler32(std::span<const std::byte>(reinterpret_cast<const std::byte*>(w.data()), w.size())) == 0x11E60398u);
}

#include "bzip2_vectors.hpp"
#include "stein/core/bzip2.hpp"

TEST_CASE("bunzip2: single and multi-block streams, long runs, truncation and small buffers") {
    for (const auto& v : test::vectors::kBzip2) {
        CAPTURE(v.name);
        auto comp = hexBytes(v.compressedHex);
        std::vector<std::byte> out(v.plainLength);
        auto n = compress::bunzip2(comp, out);
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.plainLength);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, out)) == v.plainSha256);
        std::vector<std::byte> small(v.plainLength / 2);
        auto s = compress::bunzip2(comp, small);
        REQUIRE_FALSE(s);
        CHECK(s.error().category() == ErrorCategory::OutOfRange);
        auto t = compress::bunzip2(std::span<const std::byte>(comp).subspan(0, comp.size() / 2), out);
        CHECK_FALSE(t);
    }
}
