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
            crypto::detail::aesEncryptHardware(aes->encryptKeyBytes(), aes->rounds(), in, p1);
            CHECK(Hasher::hex(p1) == v.ciphertext);
            crypto::detail::aesDecryptHardware(aes->decryptKeyBytes(), aes->rounds(), p1, p2);
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
        std::vector<std::byte> comp(reinterpret_cast<const std::byte*>(v.data), reinterpret_cast<const std::byte*>(v.data) + v.size);
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

#include "extra_hash_vectors.hpp"

TEST_CASE("ripemd160 and blake2s256: digests, HMAC and PBKDF2 agree with Python") {
    auto alg = [](const std::string& n) { return n == "ripemd160" ? HashAlgorithm::Ripemd160 : HashAlgorithm::Blake2s256; };
    auto bytes = [](std::string_view s) { return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()); };
    for (const auto& v : test::vectors::kExtraHashes) {
        CAPTURE(v.algorithm);
        CAPTURE(v.message);
        CHECK(Hasher::hex(Hasher::digest(alg(v.algorithm), bytes(v.message))) == v.digest);
        // Incremental feeding must match one-shot.
        auto h = Hasher::create(alg(v.algorithm));
        const std::string m = v.message;
        for (std::size_t i = 0; i < m.size(); i += 7) h->update(bytes(std::string_view(m).substr(i, 7)));
        CHECK(Hasher::hex(h->finish()) == v.digest);
    }
    for (const auto& v : test::vectors::kExtraHmacJefe) CHECK(Hasher::hex(crypto::hmac(alg(v.algorithm), bytes("Jefe"), bytes("what do ya want for nothing?"))) == v.hex);
    for (const auto& v : test::vectors::kExtraPbkdf2) {
        std::vector<std::uint8_t> dk(64);
        crypto::pbkdf2(alg(v.algorithm), bytes("password"), bytes("salt"), 2000, dk);
        CHECK(Hasher::hex(dk) == v.hex);
    }
}

#include "lzo_vectors.hpp"
#include "stein/core/lzo.hpp"

// The generators mirror the liblzo2 program that produced lzo_vectors.hpp.
static std::vector<std::byte> lzoPlain(std::string_view name, std::size_t size) {
    std::string base(name);
    if (base.size() > 5 && base.ends_with("_fast")) base.resize(base.size() - 5);
    std::vector<std::byte> out;
    out.reserve(size);
    auto push = [&](unsigned v) { out.push_back(std::byte(v & 0xFF)); };
    if (base == "run") {
        for (std::size_t i = 0; i < 5000; ++i) push('z');
    } else if (base == "literals") {
        for (unsigned i = 0; i < 300; ++i) push(i * 7 + 3);
    } else if (base == "random4k") {
        std::uint64_t r = 88172645463325252ull;
        for (int i = 0; i < 4096; ++i) {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            push(static_cast<unsigned>(r >> 11));
        }
    } else if (base == "text60k") {
        static const char* const words[] = {"alpha ", "beta ", "gamma ", "delta ", "epsilon ", "the quick brown fox ", "jumps over ", "lazy dog\n"};
        std::uint32_t r = 12345;
        while (out.size() < 60000) {
            r = r * 1103515245u + 12345u;
            for (const char* w = words[r >> 29]; *w; ++w) push(static_cast<unsigned char>(*w));
        }
    } else if (base == "far") {
        for (int rep = 0; rep < 30; ++rep)
            for (int i = 0; i < 2000; ++i) push(static_cast<unsigned>((i & 0xff) ^ (rep & 1)));
    }
    return out;
}

TEST_CASE("lzo1x: liblzo2 vectors (lzo1x_999 and lzo1x_1), truncation and small buffers") {
    for (const auto& v : test::vectors::kLzo) {
        CAPTURE(v.name);
        auto comp = hexBytes(std::string(v.compressedHex).c_str());
        std::vector<std::byte> want = v.plainHex.empty() ? lzoPlain(v.name, v.size) : hexBytes(std::string(v.plainHex).c_str());
        REQUIRE(want.size() == v.size);
        REQUIRE(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, want)) == v.sha256);   // the generator mirrors the oracle's
        std::vector<std::byte> out(v.size);
        auto n = compress::lzo1xDecompress(comp, out);
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.size);
        CHECK(out == want);
        if (v.size > 1) {
            std::vector<std::byte> small(v.size - 1);
            auto s = compress::lzo1xDecompress(comp, small);
            REQUIRE_FALSE(s);
            CHECK(s.error().category() == ErrorCategory::OutOfRange);
        }
        auto t = compress::lzo1xDecompress(std::span<const std::byte>(comp).subspan(0, comp.size() - 3), out);
        CHECK_FALSE(t);
    }
    std::vector<std::byte> out(16);
    CHECK_FALSE(compress::lzo1xDecompress({}, out));
    const std::byte badMarker[] = {std::byte{0x12}, std::byte{0}, std::byte{0}};   // length code 2 with distance 0
    CHECK_FALSE(compress::lzo1xDecompress(badMarker, out));
}

#include "stein/core/zstd.hpp"
#include "zstd_vectors.hpp"

template <typename V>
static std::vector<std::byte> joinedHex(const V& v) {
    std::string hex;
    for (auto part : v.compressedHex) hex += part;
    return hexBytes(hex.c_str());
}

TEST_CASE("zstd: reference CLI vectors at several levels, checksums, concatenated frames, truncation and small buffers") {
    for (const auto& v : test::vectors::kZstd) {
        CAPTURE(v.name);
        auto comp = joinedHex(v);
        std::vector<std::byte> out(v.size + 16);
        auto n = compress::zstdDecompress(comp, out);
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.size);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(out).subspan(0, *n))) == v.sha256);
        if (v.size > 1) {
            std::vector<std::byte> small(v.size - 1);
            auto s = compress::zstdDecompress(comp, small);
            REQUIRE_FALSE(s);
            CHECK(s.error().category() == ErrorCategory::OutOfRange);
        }
        auto t = compress::zstdDecompress(std::span<const std::byte>(comp).subspan(0, comp.size() - 2), out);
        CHECK_FALSE(t);
        if (std::string_view(v.name).find("nc") == std::string_view::npos && v.size > 0) {
            auto size = compress::zstdContentSize(comp);
            REQUIRE(size);
            CHECK(*size == v.size);
            // Flip a byte of the payload: the content checksum catches it (or the format does).
            auto bad = comp;
            bad[bad.size() / 2] ^= std::byte{0x55};
            CHECK_FALSE(compress::zstdDecompress(bad, out));
        }
    }
    // Single-frame decoding stops at the first frame: the concatenated vector's first frame is "short".
    for (const auto& v : test::vectors::kZstd)
        if (std::string_view(v.name) == "concat") {
            auto comp = joinedHex(v);
            std::vector<std::byte> out(v.size);
            auto n = compress::zstdDecompressFrame(comp, out);
            REQUIRE(n);
            CHECK(*n == 28);
            CHECK(std::string(reinterpret_cast<const char*>(out.data()), *n) == "hello hello hello hello zstd");
        }
    // XXH64 reference values.
    CHECK(compress::xxh64({}) == 0xEF46DB3751D8E999ull);
    const char* msg = "Nobody inspects the spammish repetition";
    CHECK(compress::xxh64(std::span<const std::byte>(reinterpret_cast<const std::byte*>(msg), std::strlen(msg))) == 0xFBCEA83C8A378BF1ull);
}

#include "lzma_vectors.hpp"
#include "stein/core/lzma.hpp"

TEST_CASE("lzma/lzma2/xz: XZ Utils vectors (checks crc32/crc64/sha256/none, multi-block, .lzma, raw LZMA1, concatenated streams), BCJ refused") {
    for (const auto& v : test::vectors::kLzma) {
        CAPTURE(v.name);
        auto comp = joinedHex(v);
        std::vector<std::byte> out(v.size + 16);
        const std::string_view kind = v.kind, name = v.name;
        auto run = [&](std::span<const std::byte> c, std::span<std::byte> o) {
            return kind == "xz" ? compress::xzDecompress(c, o) : kind == "lzma" ? compress::lzmaDecompress(c, o) : compress::lzmaDecompressRaw(c, o, 0x5D);
        };
        auto n = run(comp, out);
        if (name.find("bcj") != std::string_view::npos) {
            REQUIRE_FALSE(n);
            CHECK_MESSAGE(n.error().category() == ErrorCategory::Unsupported, n.error().toString());
            continue;
        }
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.size);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(out).subspan(0, *n))) == v.sha256);
        if (v.size > 1) {
            std::vector<std::byte> small(v.size - 1);
            auto s = run(comp, small);
            REQUIRE_FALSE(s);
            CHECK(s.error().category() == ErrorCategory::OutOfRange);
        }
        if (comp.size() > 20) {
            auto t = run(std::span<const std::byte>(comp).subspan(0, comp.size() - 8), out);
            CHECK_FALSE(t);
        }
        if (kind == "xz" && name.find("nocheck") == std::string_view::npos && v.size > 64) {
            auto bad = comp;
            bad[bad.size() / 2] ^= std::byte{0x55};
            CHECK_FALSE(compress::xzDecompress(bad, out));
        }
    }
    const char* msg = "123456789";
    CHECK(compress::crc64(std::span<const std::byte>(reinterpret_cast<const std::byte*>(msg), 9)) == 0x995DC9BBDF1939FAull);
}

#include "lzfse_vectors.hpp"
#include "stein/core/lzfse.hpp"

TEST_CASE("lzfse: Apple encoder vectors (raw, lzvn and FSE v2 blocks, multi-block), truncation and small buffers") {
    for (const auto& v : test::vectors::kLzfse) {
        CAPTURE(v.name);
        CAPTURE(v.blocks);
        auto comp = joinedHex(v);
        std::vector<std::byte> out(v.size + 16);
        auto n = compress::lzfseDecompress(comp, out);
        REQUIRE_MESSAGE(n, (n ? std::string() : n.error().toString()));
        CHECK(*n == v.size);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(out).subspan(0, *n))) == v.sha256);
        if (v.size > 1) {
            std::vector<std::byte> small(v.size - 1);
            auto s = compress::lzfseDecompress(comp, small);
            REQUIRE_FALSE(s);
            CHECK(s.error().category() == ErrorCategory::OutOfRange);
        }
        auto t = compress::lzfseDecompress(std::span<const std::byte>(comp).subspan(0, comp.size() - 6), out);
        CHECK_FALSE(t);   // the end block is gone
    }
}

#include "cipher_vectors.hpp"
#include "stein/core/cipher.hpp"

static std::vector<std::uint8_t> u8Bytes(const char* hex) {
    auto b = hexBytes(hex);
    std::vector<std::uint8_t> out(b.size());
    for (std::size_t i = 0; i < b.size(); ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    return out;
}

TEST_CASE("serpent, twofish, camellia-256, kuznyechik: Botan/GOST block and XTS vectors, round trips") {
    for (const auto& v : test::vectors::cipher::kBlocks) {
        const std::string cipherName = v.cipher, keyHex = v.key;
        CAPTURE(cipherName);
        CAPTURE(keyHex);
        auto alg = crypto::cipherFromString(v.cipher);
        REQUIRE(alg);
        auto c = crypto::BlockCipher::create(*alg, u8Bytes(v.key));
        REQUIRE_MESSAGE(c, (c ? std::string() : c.error().toString()));
        const auto pt = u8Bytes(v.plain);
        std::uint8_t out[16], back[16];
        (*c)->encryptBlock(pt.data(), out);
        CHECK(Hasher::hex(out) == v.cipherText);
        (*c)->decryptBlock(out, back);
        CHECK(std::memcmp(back, pt.data(), 16) == 0);
    }
    for (const auto& v : test::vectors::cipher::kXts) {
        const std::string cipherName = v.cipher;
        CAPTURE(cipherName);
        CAPTURE(v.sector);
        auto alg = crypto::cipherFromString(v.cipher);
        REQUIRE(alg);
        auto xts = crypto::Xts::create(*alg, u8Bytes(v.key));
        REQUIRE_MESSAGE(xts, (xts ? std::string() : xts.error().toString()));
        const auto pt = hexBytes(v.plain);
        std::vector<std::byte> ct(pt.size()), back(pt.size());
        REQUIRE(xts->encrypt(v.sector, pt, ct));
        CHECK(hexOf(ct) == v.cipherText);
        REQUIRE(xts->decrypt(v.sector, ct, back));
        CHECK(back == pt);
    }
    // Bad keys.
    std::vector<std::uint8_t> k32(32, 1), k64(64, 2);
    CHECK_FALSE(crypto::BlockCipher::create(crypto::CipherAlgorithm::Camellia, std::span<const std::uint8_t>(k32).first(16)));
    CHECK_FALSE(crypto::BlockCipher::create(crypto::CipherAlgorithm::Kuznyechik, std::span<const std::uint8_t>(k32).first(24)));
    CHECK_FALSE(crypto::Xts::create(crypto::CipherAlgorithm::Serpent, k32));   // Serpent-XTS needs two 256-bit keys
    CHECK_FALSE(crypto::Xts::create(crypto::CipherAlgorithm::Serpent, k64));   // identical halves
}

TEST_CASE("xts cascades compose layer by layer in VeraCrypt order; pbkdf2Range matches the full derivation") {
    std::vector<std::uint8_t> key(192);
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 7 + 3);
    const crypto::CipherAlgorithm order[3] = {crypto::CipherAlgorithm::Aes, crypto::CipherAlgorithm::Twofish, crypto::CipherAlgorithm::Serpent};
    auto cascade = crypto::Xts::create(order, key);
    REQUIRE(cascade);
    CHECK(cascade->layers() == 3);
    // Primary keys are the first 96 bytes in table order, tweak keys the next 96.
    auto layer = [&](int i) {
        std::vector<std::uint8_t> k(key.begin() + 32 * i, key.begin() + 32 * i + 32);
        k.insert(k.end(), key.begin() + 96 + 32 * i, key.begin() + 96 + 32 * i + 32);
        auto x = crypto::Xts::create(order[i], k);
        REQUIRE(x);
        return std::move(*x);
    };
    const auto aes = layer(0), twofish = layer(1), serpent = layer(2);
    std::vector<std::byte> plain(1024), a(1024), b(1024), c(1024), all(1024), back(1024);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = std::byte(i * 13 + 1);
    // "AES-Twofish-Serpent" encrypts with Serpent, then Twofish, then AES.
    REQUIRE(serpent.encryptSectors(77, 512, plain, a));
    REQUIRE(twofish.encryptSectors(77, 512, a, b));
    REQUIRE(aes.encryptSectors(77, 512, b, c));
    REQUIRE(cascade->encryptSectors(77, 512, plain, all));
    CHECK(all == c);
    REQUIRE(cascade->decryptSectors(77, 512, all, back));
    CHECK(back == plain);
    CHECK(crypto::Xts::keySize(order) == 192);
    CHECK_FALSE(crypto::Xts::create(order, std::span<const std::uint8_t>(key).first(128)));

    auto bytes = [](std::string_view s) { return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()); };
    for (HashAlgorithm h : {HashAlgorithm::Sha512, HashAlgorithm::Sha256, HashAlgorithm::Whirlpool, HashAlgorithm::Ripemd160}) {
        std::vector<std::uint8_t> full(192), part(192 - 50);
        crypto::pbkdf2(h, bytes("pw"), bytes("salt"), 37, full);
        crypto::pbkdf2Range(h, bytes("pw"), bytes("salt"), 37, 50, part);
        CHECK(std::equal(part.begin(), part.end(), full.begin() + 50));
        std::vector<std::uint8_t> head(64);
        crypto::pbkdf2Range(h, bytes("pw"), bytes("salt"), 37, 0, head);
        CHECK(std::equal(head.begin(), head.end(), full.begin()));
    }
}

TEST_CASE("whirlpool and streebog-512: digests, HMAC and PBKDF2 agree with Botan") {
    auto alg = [](const std::string& n) { return n == "whirlpool" ? HashAlgorithm::Whirlpool : n == "streebog512" ? HashAlgorithm::Streebog512 : HashAlgorithm::Sha512; };
    auto bytes = [](std::string_view s) { return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()); };
    for (const auto& v : test::vectors::cipher::kHashes) {
        CAPTURE(v.algorithm);
        CAPTURE(v.messageHex);
        const auto m = hexBytes(v.messageHex);
        CHECK(Hasher::hex(Hasher::digest(alg(v.algorithm), m)) == v.digest);
        auto h = Hasher::create(alg(v.algorithm));
        for (std::size_t i = 0; i < m.size(); i += 7) h->update(std::span<const std::byte>(m).subspan(i, std::min<std::size_t>(7, m.size() - i)));
        CHECK(Hasher::hex(h->finish()) == v.digest);
        h->reset();
        h->update(m);
        CHECK(Hasher::hex(h->finish()) == v.digest);
        CHECK(h->blockSize() == 64);
    }
    for (const auto& v : test::vectors::cipher::kHmacJefe) CHECK(Hasher::hex(crypto::hmac(alg(v.algorithm), bytes("Jefe"), bytes("what do ya want for nothing?"))) == v.hex);
    const std::string longKey(131, '\xaa');
    for (const auto& v : test::vectors::cipher::kHmacLongKey) CHECK(Hasher::hex(crypto::hmac(alg(v.algorithm), bytes(longKey), bytes("Test Using Larger Than Block-Size Key - Hash Key First"))) == v.hex);
    for (const auto& v : test::vectors::cipher::kPbkdf2) {
        CAPTURE(v.algorithm);
        std::vector<std::uint8_t> dk(192);
        crypto::pbkdf2(alg(v.algorithm), bytes("password"), bytes("salt"), 2000, dk);
        CHECK(Hasher::hex(dk) == v.hex);
    }
    CHECK(toString(HashAlgorithm::Whirlpool) == "whirlpool");
    CHECK(toString(HashAlgorithm::Streebog512) == "streebog512");
}
