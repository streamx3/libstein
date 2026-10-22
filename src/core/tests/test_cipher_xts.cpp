// SPDX-License-Identifier: MIT
// crypto::Xts over AES: known-answer vectors, the fast multi-block path
// against the per-block AesXts reference and against the generic cascade path
// on the same key, and a throughput benchmark (skipped by default; run with
// `--no-skip -tc="*throughput*"`).
#include "stein_test.hpp"

#include "aes_vectors.hpp"
#include "stein/core/aes.hpp"
#include "stein/core/cipher.hpp"
#include "stein/core/cpu.hpp"
#include "stein/core/units.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

using namespace stein;

namespace {

std::vector<std::uint8_t> keyBytes(const char* hex) {
    std::vector<std::uint8_t> out;
    auto nib = [](char c) { return static_cast<std::uint8_t>(c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0'); };
    for (std::size_t i = 0; hex[i] && hex[i + 1]; i += 2) out.push_back(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    return out;
}
std::vector<std::byte> dataBytes(const char* hex) {
    auto k = keyBytes(hex);
    std::vector<std::byte> out(k.size());
    for (std::size_t i = 0; i < k.size(); ++i) out[i] = std::byte(k[i]);
    return out;
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

// Deterministic pseudo-random bytes: the tests must be repeatable, so no std::random_device.
struct Xorshift {
    std::uint64_t s;
    std::uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    void fill(std::span<std::byte> out) {
        for (std::size_t i = 0; i < out.size(); i += 8) {
            const std::uint64_t v = next();
            for (std::size_t j = 0; j < 8 && i + j < out.size(); ++j) out[i + j] = std::byte((v >> (8 * j)) & 0xff);
        }
    }
    void fill(std::span<std::uint8_t> out) {
        for (auto& b : out) b = static_cast<std::uint8_t>(next() & 0xff);
    }
};

} // namespace

TEST_CASE("xts/aes: the generated AES-XTS vectors pass through crypto::Xts, whole and sector by sector, on both paths") {
    for (bool fast : {true, false}) {
        CAPTURE(fast);
        for (const auto& v : test::vectors::kXts) {
            CAPTURE(v.sector);
            const auto key = keyBytes(v.key);
            auto xts = crypto::Xts::create(crypto::CipherAlgorithm::Aes, key);
            REQUIRE_MESSAGE(xts, (xts ? std::string() : xts.error().toString()));
            xts->setFastPath(fast);
            CHECK(xts->layers() == 1);
            CHECK(xts->implementation() == (fast ? (crypto::aesHardwareAvailable() ? (cpuFeatures().aesni ? "aes-ni" : "arm-aes") : "aes-portable") : "generic"));
            const auto pt = dataBytes(v.plaintext);
            std::vector<std::byte> ct(pt.size()), back(pt.size());
            REQUIRE(xts->encrypt(v.sector, pt, ct));
            CHECK(hexOf(ct) == v.ciphertext);
            REQUIRE(xts->decrypt(v.sector, ct, back));
            CHECK(back == pt);
            if (pt.size() % 512 == 0 && pt.size() > 512) {
                std::vector<std::byte> ct2(pt.size());
                REQUIRE(xts->encryptSectors(v.sector, 512, pt, ct2));
                CHECK(std::equal(ct2.begin(), ct2.begin() + 512, ct.begin()));
                REQUIRE(xts->decryptSectors(v.sector, 512, ct2, back));
                CHECK(back == pt);
            }
        }
    }
    // Cascades never take the fast path.
    std::vector<std::uint8_t> key(128);
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 5 + 1);
    const crypto::CipherAlgorithm two[2] = {crypto::CipherAlgorithm::Aes, crypto::CipherAlgorithm::Twofish};
    auto cascade = crypto::Xts::create(two, key);
    REQUIRE(cascade);
    CHECK(cascade->implementation() == "generic");
    auto serpent = crypto::Xts::create(crypto::CipherAlgorithm::Serpent, std::span<const std::uint8_t>(key).first(64));
    REQUIRE(serpent);
    CHECK(serpent->implementation() == "generic");
}

TEST_CASE("xts/aes: random data through the fast path equals the generic path and the per-block AesXts reference: both key sizes, ragged block counts, in place") {
    Xorshift rng{0x9e3779b97f4a7c15ull};
    for (std::size_t keyLen : {std::size_t{32}, std::size_t{64}}) {
        CAPTURE(keyLen);
        std::vector<std::uint8_t> key(keyLen);
        rng.fill(key);
        key[keyLen / 2] ^= 1;   // the two halves must differ
        auto fast = crypto::Xts::create(crypto::CipherAlgorithm::Aes, key);
        auto generic = crypto::Xts::create(crypto::CipherAlgorithm::Aes, key);
        auto reference = crypto::AesXts::create(key);
        REQUIRE(fast);
        REQUIRE(generic);
        REQUIRE(reference);
        generic->setFastPath(false);
        CHECK(fast->implementation() != "generic");
        CHECK(generic->implementation() == "generic");
        // Sector numbers with the top bit and both 32-bit halves set exercise the little-endian tweak.
        const std::uint64_t sectors[] = {0, 1, 7, 0x123456789abcdefull, 0xffffffffffffffffull};
        // 16 and 128 bytes are below and exactly one group of eight blocks; 208 = 13 blocks is one
        // group plus a five-block tail; 512 and 4096 are the disk sector sizes.
        for (std::size_t bytes : {std::size_t{16}, std::size_t{128}, std::size_t{208}, std::size_t{512}, std::size_t{4096}}) {
            CAPTURE(bytes);
            for (std::uint64_t sector : sectors) {
                CAPTURE(sector);
                std::vector<std::byte> plain(bytes), ct(bytes), ctGen(bytes), ctRef(bytes), back(bytes), backGen(bytes), backRef(bytes);
                rng.fill(plain);
                REQUIRE(fast->encrypt(sector, plain, ct));
                REQUIRE(generic->encrypt(sector, plain, ctGen));
                REQUIRE(reference->encrypt(sector, plain, ctRef));
                CHECK(ct == ctGen);
                CHECK(ct == ctRef);
                REQUIRE(fast->decrypt(sector, ct, back));
                REQUIRE(generic->decrypt(sector, ct, backGen));
                REQUIRE(reference->decrypt(sector, ct, backRef));
                CHECK(back == plain);
                CHECK(backGen == plain);
                CHECK(backRef == plain);
                // In place: the same buffer as input and output.
                std::vector<std::byte> inPlace = ct;
                REQUIRE(fast->decrypt(sector, inPlace, inPlace));
                CHECK(inPlace == plain);
                REQUIRE(fast->encrypt(sector, inPlace, inPlace));
                CHECK(inPlace == ct);
            }
        }
        // Multi-sector runs: 37 sectors of 512 and 9 of 4096 with consecutive tweaks from a high start.
        for (std::uint32_t sectorSize : {512u, 4096u}) {
            CAPTURE(sectorSize);
            const std::size_t n = sectorSize == 512 ? 37 : 9;
            std::vector<std::byte> plain(n * sectorSize), ct(plain.size()), ctGen(plain.size()), ctRef(plain.size()), back(plain.size());
            rng.fill(plain);
            const std::uint64_t first = 0x8000000000000000ull - 5;
            REQUIRE(fast->encryptSectors(first, sectorSize, plain, ct));
            REQUIRE(generic->encryptSectors(first, sectorSize, plain, ctGen));
            REQUIRE(reference->encryptSectors(first, sectorSize, plain, ctRef));
            CHECK(ct == ctGen);
            CHECK(ct == ctRef);
            REQUIRE(fast->decryptSectors(first, sectorSize, ct, back));
            CHECK(back == plain);
            REQUIRE(generic->decryptSectors(first, sectorSize, ct, back));
            CHECK(back == plain);
        }
    }
}

TEST_CASE("xts/aes: throughput of decryptSectors over 64 MiB, generic path and fast path" * doctest::skip()) {
    std::vector<std::uint8_t> key(64);
    Xorshift rng{0x243f6a8885a308d3ull};
    rng.fill(key);
    const std::size_t total = 64 * MiB;
    std::vector<std::byte> in(total), out(total);
    rng.fill(in);
    MESSAGE("cpu: " << cpuFeatures().summary());
    for (bool fast : {false, true}) {
        auto xts = crypto::Xts::create(crypto::CipherAlgorithm::Aes, key);
        REQUIRE(xts);
        xts->setFastPath(fast);
        for (std::uint32_t sectorSize : {512u, 4096u}) {
            double best = 0;
            for (int rep = 0; rep < 3; ++rep) {
                const auto t0 = std::chrono::steady_clock::now();
                REQUIRE(xts->decryptSectors(0, sectorSize, in, out));
                const auto dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                best = std::max(best, static_cast<double>(total) / dt / (1024.0 * 1024.0));
            }
            MESSAGE("decryptSectors [" << xts->implementation() << "] " << sectorSize << "-byte sectors: " << static_cast<long>(best) << " MiB/s");
        }
    }
}
