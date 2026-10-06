// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/container/luks.hpp"
#include "stein/container/tcrypt.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/fs/reader.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>

using namespace stein;
using stein::test::loadSparseFixture;

namespace {
std::map<std::string, std::string> oracle(const std::string& name) {
    std::map<std::string, std::string> m;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/luks/" + name + ".oracle.txt");
    std::string line;
    while (std::getline(in, line))
        if (auto eq = line.find('='); eq != std::string::npos) m[line.substr(0, eq)] = line.substr(eq + 1);
    return m;
}
} // namespace

TEST_CASE("luks: unlock LUKS1 (sha256, sha1) and LUKS2 (argon2id, pbkdf2 with 4K sectors) and read the payload") {
    const char* names[] = {"luks1", "luks1_sha1", "luks2", "luks2_pbkdf2"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        auto o = oracle(fixture);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        const auto& info = luks->info();
        CHECK(info.supported);
        CHECK(info.cipher == "aes");
        CHECK(info.mode == "xts-plain64");
        CHECK(info.keyBytes == 64);
        CHECK(info.payloadOffset == std::stoull(o["payload_offset"]));
        CHECK(info.sectorSize == std::stoul(o["sector_size"]));
        CHECK(info.version == (fixture.rfind("luks1", 0) == 0 ? 1 : 2));
        REQUIRE(!info.slots.empty());
        CHECK(info.slots[0].active);
        if (fixture == "luks2") CHECK(info.slots[0].kdf == "argon2id");
        if (fixture == "luks1_sha1") CHECK(info.hash == "sha1");
        // Wrong passphrase.
        auto wrong = luks->unlock("not it");
        REQUIRE_FALSE(wrong);
        CHECK(wrong.error().category() == ErrorCategory::Integrity);
        // Right passphrase: master key equals cryptsetup's dump.
        auto key = luks->unlock(o["passphrase"]);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == o["master_key"]);
        // Payload decrypts to the ext2 filesystem the oracle encrypted.
        auto payload = luks->openPayload(*key);
        REQUIRE(payload);
        CHECK((*payload)->isReadOnly());
        CHECK((*payload)->sectorSize() == info.sectorSize);
        auto fs = fs::probe(*payload);
        REQUIRE(fs);
        REQUIRE(*fs);
        CHECK((*fs)->type() == fs::FsType::Ext2);
        CHECK((*fs)->info().label == o["label"]);
        // Unaligned reads through the decrypting device are consistent with aligned ones.
        auto a = (*payload)->read(0, 8192);
        auto b = (*payload)->read(1000, 3000);
        REQUIRE(a);
        REQUIRE(b);
        CHECK(std::equal(b->begin(), b->end(), a->begin() + 1000));
        // A tampered master key is refused by the digest.
        auto bad = *key;
        bad[0] ^= 1;
        CHECK(luks->openPayload(bad).error().category() == ErrorCategory::Integrity);
        // Writable payload: write plaintext, read it back, the ciphertext on the parent changed.
        auto rw = luks->openPayload(*key, false);
        REQUIRE(rw);
        auto before = dev->read(info.payloadOffset + 65536, 512);
        REQUIRE((*rw)->writeAt(65536 + 7, stein::test::bytesOf("plaintext marker")));
        auto readBack = (*rw)->read(65536 + 7, 16);
        REQUIRE(readBack);
        CHECK(std::string(reinterpret_cast<const char*>(readBack->data()), 16) == "plaintext marker");
        auto after = dev->read(info.payloadOffset + 65536, 512);
        CHECK(*before != *after);
        CHECK(std::search(after->begin(), after->end(), readBack->begin(), readBack->end()) == after->end());
    }
}

TEST_CASE("luks: anti-forensic merge of a known split") {
    // Split a key into stripes the way AFsplit does, then merge it back.
    const std::string hash = "sha256";
    std::vector<std::uint8_t> key(32);
    for (std::size_t i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(i * 7);
    const std::uint32_t stripes = 5;
    std::vector<std::uint8_t> split(32 * stripes);
    std::vector<std::uint8_t> buf(32, 0);
    auto diffuse = [&](std::vector<std::uint8_t>& b) {
        std::vector<std::uint8_t> out(32);
        for (std::uint32_t i = 0; i < 1; ++i) {   // 32 bytes = one sha256 digest
            auto h = Hasher::create(HashAlgorithm::Sha256);
            std::byte iv[4] = {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
            h->update(iv);
            h->update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(b.data()), 32));
            auto d = h->finish();
            std::copy(d.begin(), d.end(), out.begin());
        }
        b = out;
    };
    for (std::uint32_t s = 0; s + 1 < stripes; ++s) {
        for (std::size_t j = 0; j < 32; ++j) split[s * 32 + j] = static_cast<std::uint8_t>(s * 31 + j);   // arbitrary stripe
        for (std::size_t j = 0; j < 32; ++j) buf[j] ^= split[s * 32 + j];
        diffuse(buf);
    }
    for (std::size_t j = 0; j < 32; ++j) split[(stripes - 1) * 32 + j] = buf[j] ^ key[j];
    auto merged = container::afMerge(split, 32, stripes, hash);
    REQUIRE(merged);
    CHECK(*merged == key);
    CHECK_FALSE(container::afMerge(split, 32, stripes, "md4"));
}

TEST_CASE("tcrypt: VeraCrypt (sha512 default, sha256/blake2s/ripemd160 with PIM, hidden volume) and TrueCrypt (sha512, ripemd160) volumes open by trial decryption") {
    struct Case { const char* name; const char* passphrase; std::uint32_t pim; const char* variant; const char* prf; const char* label; bool hidden; ByteCount payloadOffset, payloadSize; };
    const Case cases[] = {
        {"veracrypt_sha512", "stein-vera", 0, "VeraCrypt", "sha512", "inside_vc", false, 131072, 262144},
        {"veracrypt_sha256_pim", "stein-pim", 3, "VeraCrypt", "sha256", "inside_vc", false, 131072, 262144},
        {"truecrypt_sha512", "stein-true", 0, "TrueCrypt", "sha512", "inside_vc", false, 131072, 262144},
        {"veracrypt_hidden", "stein-outer", 1, "VeraCrypt", "sha512", "outer_vc", false, 131072, 524288},
        {"veracrypt_hidden", "stein-hidden", 1, "VeraCrypt", "sha256", "hidden_vc", true, 393216, 262144},
        {"truecrypt_ripemd160", "stein-rmd", 0, "TrueCrypt", "ripemd160", "inside_vc", false, 131072, 262144},
        {"veracrypt_blake2s_pim", "stein-blake", 2, "VeraCrypt", "blake2s", "inside_vc", false, 131072, 262144},
        {"veracrypt_ripemd160_pim", "stein-vrmd", 4, "VeraCrypt", "ripemd160", "inside_vc", false, 131072, 262144},
    };
    for (const auto& c : cases) {
        const std::string fixture = c.name;
        CAPTURE(fixture);
        CAPTURE(c.passphrase);
#if !defined(NDEBUG)
        if (c.pim == 0 && std::string(c.variant) == "VeraCrypt" && !std::getenv("STEIN_SLOW_TESTS")) {
            MESSAGE("skipping the 500000-iteration default-PIM volume in a debug build (set STEIN_SLOW_TESTS=1 to run it)");
            continue;
        }
#endif
        auto dev = loadSparseFixture("tcrypt/" + fixture + ".sparse");
        container::TcryptOptions opt;
        opt.pim = c.pim;
        auto t = container::Tcrypt::unlock(dev, c.passphrase, opt);
        REQUIRE_MESSAGE(t, (t ? std::string() : t.error().toString()));
        CHECK(t->info().variant == c.variant);
        CHECK(t->info().prf == c.prf);
        CHECK(t->info().hidden == c.hidden);
        CHECK_FALSE(t->info().backupHeader);
        CHECK(t->info().payloadOffset == c.payloadOffset);
        CHECK(t->info().payloadSize == c.payloadSize);
        CHECK(t->info().headerVersion == 5);
        auto payload = t->openPayload(true);
        REQUIRE(payload);
        auto probed = fs::probe(*payload);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->type() == fs::FsType::Ext2);
        CHECK((*probed)->info().label == c.label);
        auto reader = (*probed)->openReader();
        REQUIRE(reader);
        auto hello = fs::resolvePath(**reader, "hello.txt");
        REQUIRE(hello);
        auto data = fs::readAll(**reader, *hello);
        REQUIRE(data);
        const std::string text(reinterpret_cast<const char*>(data->data()), data->size());
        CHECK(text.find("secret inside " + fixture) != std::string::npos);
        if (c.hidden) CHECK(text.rfind("hidden secret", 0) == 0);
        // Wrong passphrase: no header decrypts (skipped where the default 500k iterations would make it slow).
        // Wrong passphrase on a representative pair only: every extra PRF multiplies the trial cost.
        if (fixture == "veracrypt_sha256_pim" || fixture == "truecrypt_sha512") {
            container::TcryptOptions wrongOpt = opt;
            wrongOpt.veracrypt = c.pim != 0;   // a pim of 0 would mean several 500000+-iteration VeraCrypt trials per header
            auto wrong = container::Tcrypt::unlock(dev, std::string(c.passphrase) + "x", wrongOpt);
            REQUIRE_FALSE(wrong);
            CHECK(wrong.error().category() == ErrorCategory::Integrity);
        }
    }
    // Backup header: damage the primary (and hidden) header areas, the copies at the end still open the volume.
    {
        auto dev = loadSparseFixture("tcrypt/veracrypt_sha256_pim.sparse");
        std::vector<std::byte> junk(131072, std::byte{0x5A});
        REQUIRE(dev->writeAt(0, junk));
        container::TcryptOptions opt;
        opt.pim = 3;
        auto t = container::Tcrypt::unlock(dev, "stein-pim", opt);
        REQUIRE_MESSAGE(t, (t ? std::string() : t.error().toString()));
        CHECK(t->info().backupHeader);
        CHECK(t->info().headerOffset == dev->size() - 131072);
        auto payload = t->openPayload(true);
        REQUIRE(payload);
        auto probed = fs::probe(*payload);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().label == "inside_vc");
        opt.backupHeaders = false;
        CHECK_FALSE(container::Tcrypt::unlock(dev, "stein-pim", opt));
    }
}
