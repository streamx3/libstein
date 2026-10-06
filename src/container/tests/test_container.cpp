// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/container/luks.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"

#include <algorithm>
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
