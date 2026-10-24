// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/container/luks.hpp"
#include "stein/container/tcrypt.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/json.hpp"
#include "stein/core/secure.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/fs/reader.hpp"
#include "stein/layout/gen/luks.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <optional>

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

TEST_CASE("tcrypt: VeraCrypt and TrueCrypt volumes open by trial decryption: every PRF, every cipher, cascades, PIM, hidden volume") {
    struct Case { const char* name; const char* passphrase; std::uint32_t pim; const char* variant; const char* prf; const char* label; bool hidden; ByteCount payloadOffset, payloadSize; const char* cipher; bool restrictPrf; };
    const Case cases[] = {
        {"veracrypt_sha512", "stein-vera", 0, "VeraCrypt", "sha512", "inside_vc", false, 131072, 262144, "aes-xts-plain64", true},
        {"veracrypt_sha256_pim", "stein-pim", 3, "VeraCrypt", "sha256", "inside_vc", false, 131072, 262144, "aes-xts-plain64", true},
        {"truecrypt_sha512", "stein-true", 0, "TrueCrypt", "sha512", "inside_vc", false, 131072, 262144, "aes-xts-plain64", false},
        {"veracrypt_hidden", "stein-outer", 1, "VeraCrypt", "sha512", "outer_vc", false, 131072, 524288, "aes-xts-plain64", true},
        {"veracrypt_hidden", "stein-hidden", 1, "VeraCrypt", "sha256", "hidden_vc", true, 393216, 262144, "aes-xts-plain64", true},
        {"truecrypt_ripemd160", "stein-rmd", 0, "TrueCrypt", "ripemd160", "inside_vc", false, 131072, 262144, "aes-xts-plain64", false},
        {"veracrypt_blake2s_pim", "stein-blake", 2, "VeraCrypt", "blake2s", "inside_vc", false, 131072, 262144, "aes-xts-plain64", true},
        {"veracrypt_ripemd160_pim", "stein-vrmd", 4, "VeraCrypt", "ripemd160", "inside_vc", false, 131072, 262144, "aes-xts-plain64", false},
        {"veracrypt_serpent_pim", "stein-serp", 1, "VeraCrypt", "sha512", "inside_vc", false, 131072, 262144, "serpent-xts-plain64", true},
        {"veracrypt_twofish_pim", "stein-two", 1, "VeraCrypt", "sha256", "inside_vc", false, 131072, 262144, "twofish-xts-plain64", true},
        {"veracrypt_camellia_whirlpool_pim", "stein-cam", 1, "VeraCrypt", "whirlpool", "inside_vc", false, 131072, 262144, "camellia-xts-plain64", true},
        {"veracrypt_kuznyechik_streebog_pim", "stein-kuz", 1, "VeraCrypt", "streebog", "inside_vc", false, 131072, 262144, "kuznyechik-xts-plain64", true},
        {"veracrypt_aes_twofish_serpent_pim", "stein-cascade", 1, "VeraCrypt", "sha512", "inside_vc", false, 131072, 262144, "aes-twofish-serpent-xts-plain64", true},
        {"veracrypt_kuznyechik_serpent_camellia_pim", "stein-gost", 1, "VeraCrypt", "blake2s", "inside_vc", false, 131072, 262144, "kuznyechik-serpent-camellia-xts-plain64", true},
        {"truecrypt_whirlpool", "stein-whirl", 0, "TrueCrypt", "whirlpool", "inside_vc", false, 131072, 262144, "aes-xts-plain64", true},
        {"truecrypt_serpent_twofish_aes", "stein-tcascade", 0, "TrueCrypt", "sha512", "inside_vc", false, 131072, 262144, "serpent-twofish-aes-xts-plain64", true},
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
        if (c.restrictPrf) opt.prf = c.prf;   // the full trial over all PRFs (six 192-byte derivations per header) runs on the TrueCrypt and ripemd160 volumes only
        auto t = container::Tcrypt::unlock(dev, c.passphrase, opt);
        REQUIRE_MESSAGE(t, (t ? std::string() : t.error().toString()));
        CHECK(t->info().variant == c.variant);
        CHECK(t->info().prf == c.prf);
        CHECK(t->info().cipher == c.cipher);
        CHECK(t->info().cascade.size() * 64 == t->masterKey().size());
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
            wrongOpt.prf = c.prf;              // one PRF: a wrong passphrase costs the cascade-length derivation at every header location
            auto wrong = container::Tcrypt::unlock(dev, std::string(c.passphrase) + "x", wrongOpt);
            REQUIRE_FALSE(wrong);
            CHECK(wrong.error().category() == ErrorCategory::Integrity);
        }
    }
    // PRF restriction: the right one opens the volume, a wrong one fails like a wrong passphrase, an unknown one is rejected.
    {
        auto dev = loadSparseFixture("tcrypt/veracrypt_twofish_pim.sparse");
        container::TcryptOptions opt;
        opt.pim = 1;
        opt.prf = "sha256";
        REQUIRE(container::Tcrypt::unlock(dev, "stein-two", opt));
        opt.prf = "whirlpool";
        auto wrong = container::Tcrypt::unlock(dev, "stein-two", opt);
        REQUIRE_FALSE(wrong);
        CHECK(wrong.error().category() == ErrorCategory::Integrity);
        opt.prf = "md4";
        auto unknown = container::Tcrypt::unlock(dev, "stein-two", opt);
        REQUIRE_FALSE(unknown);
        CHECK(unknown.error().category() == ErrorCategory::InvalidArgument);
        CHECK(container::Tcrypt::prfNames().size() == 6);
        CHECK(container::Tcrypt::cipherNames().size() == 15);
    }
    // Backup header: damage the primary (and hidden) header areas, the copies at the end still open the volume.
    {
        auto dev = loadSparseFixture("tcrypt/veracrypt_sha256_pim.sparse");
        std::vector<std::byte> junk(131072, std::byte{0x5A});
        REQUIRE(dev->writeAt(0, junk));
        container::TcryptOptions opt;
        opt.pim = 3;
        opt.prf = "sha256";   // the junk header area now costs a full trial per PRF and location
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

// ---------------------------------------------------------------------------------------------
// LUKS2 header surgery for the tests below. The JSON area is plain text, so a variant of the
// fixture (an integrity segment, a second key slot, a token) is the fixture with its JSON
// rewritten and the checksum of that copy recomputed the way cryptsetup does it: csum_alg over the
// 4096-byte binary header with the csum field zeroed, then the whole JSON area, padding included.
namespace {
using Luks2Hdr = layout::gen::Luks2Hdr;
constexpr ByteCount kLuks2Binary = 4096;
using JsonEdit = std::function<std::string(const std::string&)>;

std::uint64_t luks2HeaderSize(MemoryDevice& dev, ByteCount at) {
    auto bin = dev.read(at, kLuks2Binary);
    REQUIRE(bin);
    return loadBe64(bin->data() + Luks2Hdr::kHdrSizeOffset);
}
// The JSON text of one header copy: the NUL-terminated string at the start of its area.
std::string luks2Json(MemoryDevice& dev, ByteCount at) {
    const std::uint64_t hdrSize = luks2HeaderSize(dev, at);
    auto area = dev.read(at + kLuks2Binary, hdrSize - kLuks2Binary);
    REQUIRE(area);
    std::string text(reinterpret_cast<const char*>(area->data()), area->size());
    return text.substr(0, text.find('\0'));
}
// Rewrites one copy: `edit` on its JSON, an optional new seqid and checksum algorithm, the checksum recomputed.
void rewriteLuks2Copy(MemoryDevice& dev, ByteCount at, const JsonEdit& edit, std::optional<std::uint64_t> seqid = std::nullopt, HashAlgorithm csumAlg = HashAlgorithm::Sha256) {
    auto bin = dev.read(at, kLuks2Binary);
    REQUIRE(bin);
    const std::uint64_t hdrSize = loadBe64(bin->data() + Luks2Hdr::kHdrSizeOffset);
    std::vector<std::byte> area(hdrSize - kLuks2Binary, std::byte{0});
    const std::string text = edit(luks2Json(dev, at));
    REQUIRE(text.size() < area.size());
    std::memcpy(area.data(), text.data(), text.size());
    if (seqid) storeBe64(bin->data() + Luks2Hdr::kSeqidOffset, *seqid);
    Luks2Hdr::setCsumAlg(*bin, toString(csumAlg));
    std::fill_n(bin->begin() + Luks2Hdr::kCsumOffset, Luks2Hdr::kCsumSize, std::byte{0});
    auto hasher = Hasher::create(csumAlg);
    hasher->update(*bin);
    hasher->update(area);
    const auto digest = hasher->finish();
    std::memcpy(bin->data() + Luks2Hdr::kCsumOffset, digest.data(), digest.size());
    REQUIRE(dev.writeAt(at, *bin));
    REQUIRE(dev.writeAt(at + kLuks2Binary, area));
}
// Both copies, consistently (what cryptsetup does on every metadata write).
void rewriteLuks2Json(MemoryDevice& dev, const JsonEdit& edit) {
    const std::uint64_t hdrSize = luks2HeaderSize(dev, 0);
    rewriteLuks2Copy(dev, 0, edit);
    rewriteLuks2Copy(dev, hdrSize, edit);
}
// Edits through the JSON tree (parse, mutate, dump) and by plain text replacement.
JsonEdit editJson(const std::function<void(json::Value&)>& mutate) {
    return [mutate](const std::string& text) {
        auto j = json::Value::parse(text);
        REQUIRE(j);
        mutate(*j);
        return j->dump();
    };
}
JsonEdit replaceText(std::string from, std::string to) {
    return [from, to](const std::string& text) {
        const auto pos = text.find(from);
        REQUIRE_MESSAGE(pos != std::string::npos, from);
        std::string out = text;
        out.replace(pos, from.size(), to);
        return out;
    };
}
// root[section][id][key] = value, with json::Value's copy-out/copy-in access.
void setNested(json::Value& root, const std::string& section, const std::string& id, const std::string& key, json::Value value) {
    json::Value inner = root.get(section).get(id);
    inner.set(key, std::move(value));
    json::Value outer = root.get(section);
    outer.set(id, std::move(inner));
    root.set(section, std::move(outer));
}
void setIn(json::Value& object, const std::string& section, const std::string& key, json::Value value) {
    json::Value inner = object.get(section);
    inner.set(key, std::move(value));
    object.set(section, std::move(inner));
}
void setSlot(json::Value& root, const std::string& id, const json::Value& slot) {
    json::Value slots = root.get("keyslots");
    slots.set(id, slot);
    root.set("keyslots", slots);
}
void bindDigest(json::Value& root, const std::vector<std::string>& slotIds) {
    json::Value ids = json::Value::array();
    for (const auto& id : slotIds) ids.push(id);
    setNested(root, "digests", "0", "keyslots", ids);
}
std::string payloadLabel(std::shared_ptr<BlockDevice> payload) {
    auto fs = fs::probe(std::move(payload));
    REQUIRE(fs);
    REQUIRE(*fs);
    return (*fs)->info().label;
}
constexpr const char* kLuksPassphrase = "luks test passphrase";
} // namespace

TEST_CASE("luks2: both header copies are checked; a damaged primary opens from the secondary, the higher seqid wins, csum_alg is honoured") {
    auto expectOpens = [&](std::shared_ptr<MemoryDevice> dev, int copy, bool primaryValid, bool secondaryValid) {
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().headerCopyUsed == copy);
        CHECK(luks->info().primaryValid == primaryValid);
        CHECK(luks->info().secondaryValid == secondaryValid);
        CHECK(luks->info().headerSize == 16384);
        CHECK(luks->info().supported);
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK(payloadLabel(*payload) == "inside_luks");
        return *luks;
    };
    // Untouched: the primary is used and both copies verify.
    expectOpens(loadSparseFixture("luks/luks2.sparse"), 0, true, true);
    // Primary JSON bytes overwritten (its checksum no longer matches): the secondary opens the volume.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(dev->writeAt(kLuks2Binary + 20, stein::test::bytesOf("garbage in the JSON area")));
        expectOpens(dev, 1, false, true);
    }
    // Primary JSON truncated but its checksum recomputed: the checksum passes, the parse fails, the secondary is used.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Copy(*dev, 0, [](const std::string& text) { return text.substr(0, text.size() / 2); });
        expectOpens(dev, 1, false, true);
    }
    // The first 4 KiB zeroed (no magic, no hdr_size to find the secondary by): the standard sizes are scanned.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(dev->writeAt(0, std::vector<std::byte>(kLuks2Binary)));
        expectOpens(dev, 1, false, true);
    }
    // Secondary damaged, primary fine: opens from the primary and reports the damage.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(dev->writeAt(16384 + kLuks2Binary + 20, stein::test::bytesOf("garbage")));
        expectOpens(dev, 0, true, false);
    }
    // Both damaged: InvalidFormat naming both copies. No header anywhere: NotFound (what the probe keys on).
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(dev->writeAt(kLuks2Binary + 20, stein::test::bytesOf("garbage")));
        REQUIRE(dev->writeAt(16384 + kLuks2Binary + 20, stein::test::bytesOf("garbage")));
        auto luks = container::Luks::open(dev);
        REQUIRE_FALSE(luks);
        CHECK(luks.error().category() == ErrorCategory::InvalidFormat);
        CHECK_MESSAGE(luks.error().message().find("primary copy") != std::string::npos, luks.error().message());
        CHECK_MESSAGE(luks.error().message().find("secondary copy") != std::string::npos, luks.error().message());
        auto blank = std::make_shared<MemoryDevice>(8 * MiB);
        CHECK(container::Luks::open(blank).error().category() == ErrorCategory::NotFound);
        auto tiny = std::make_shared<MemoryDevice>(512);
        CHECK(container::Luks::open(tiny).error().category() == ErrorCategory::NotFound);
    }
    // seqid: a secondary rewritten with a newer seqid wins over an intact primary, and the other way round.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Copy(*dev, 16384, editJson([](json::Value& j) { setNested(j, "keyslots", "0", "priority", 2); }), 10);
        auto luks = expectOpens(dev, 1, true, true);
        CHECK(luks.info().slots[0].priority == 2);
        rewriteLuks2Copy(*dev, 0, editJson([](json::Value& j) { setNested(j, "keyslots", "0", "priority", 0); }), 11);
        luks = expectOpens(dev, 0, true, true);
        CHECK(luks.info().slots[0].priority == 0);
    }
    // csum_alg other than sha256 on either copy.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Copy(*dev, 0, [](const std::string& text) { return text; }, std::nullopt, HashAlgorithm::Sha512);
        rewriteLuks2Copy(*dev, 16384, [](const std::string& text) { return text; }, std::nullopt, HashAlgorithm::Sha1);
        expectOpens(dev, 0, true, true);
        rewriteLuks2Copy(*dev, 0, [](const std::string& text) { return text; }, std::nullopt, HashAlgorithm::Ripemd160);
        expectOpens(dev, 0, true, true);
    }
    // LUKS1 has one header: reported as the primary, both flags true, no header size.
    {
        auto luks = container::Luks::open(loadSparseFixture("luks/luks1.sparse"));
        REQUIRE(luks);
        CHECK(luks->info().headerCopyUsed == 0);
        CHECK(luks->info().primaryValid);
        CHECK(luks->info().secondaryValid);
        CHECK(luks->info().headerSize == 0);
    }
}

TEST_CASE("luks2: refused with the reason when the data would not decrypt correctly: integrity, several segments, non-crypt segment, mandatory requirements, unknown flags, unknown modes") {
    auto refused = [](const JsonEdit& edit, const std::string& why) {
        CAPTURE(why);
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, edit);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK_FALSE(luks->info().supported);
        CHECK_MESSAGE(luks->info().unsupportedWhy.find(why) != std::string::npos, luks->info().unsupportedWhy);
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Unsupported);
        CHECK(key.error().message() == luks->info().unsupportedWhy);
        // Even the right volume key is refused: the payload would read as garbage.
        auto master = fromHex(oracle("luks2")["master_key"]);
        REQUIRE(master);
        std::vector<std::uint8_t> masterKey(master->size());
        for (std::size_t i = 0; i < masterKey.size(); ++i) masterKey[i] = std::to_integer<std::uint8_t>((*master)[i]);
        CHECK(luks->openPayload(masterKey).error().category() == ErrorCategory::Unsupported);
        return *luks;
    };
    refused(editJson([](json::Value& j) {
        json::Value integrity = json::Value::object();
        integrity.set("type", "hmac(sha256)");
        integrity.set("journal_encryption", "none");
        integrity.set("journal_integrity", "none");
        setNested(j, "segments", "0", "integrity", integrity);
    }), "dm-integrity");
    refused(editJson([](json::Value& j) {
        json::Value segments = j.get("segments");
        segments.set("1", j.get("segments").get("0"));
        j.set("segments", segments);
    }), "2 data segments");
    refused(replaceText("\"type\":\"crypt\"", "\"type\":\"linear\""), "segment type \"linear\"");
    auto luks = refused(editJson([](json::Value& j) {
        json::Value requirements = json::Value::object();
        requirements.set("mandatory", json::Value::array().push("online-reencrypt"));
        setIn(j, "config", "requirements", requirements);
    }), "online-reencrypt");
    CHECK(luks.info().requirements == std::vector<std::string>{"online-reencrypt"});
    luks = refused(editJson([](json::Value& j) { setIn(j, "config", "flags", json::Value::array().push("allow-discards").push("opal-locked")); }), "opal-locked");
    CHECK(luks.info().flags == std::vector<std::string>{"allow-discards", "opal-locked"});
    refused(replaceText("\"encryption\":\"aes-xts-plain64\",\"sector_size\"", "\"encryption\":\"aes-cbc-essiv:sha256\",\"sector_size\""), "ESSIV");
    refused(replaceText("\"encryption\":\"aes-xts-plain64\",\"sector_size\"", "\"encryption\":\"aes-xts-plain64be\",\"sector_size\""), "plain64be");
    refused(replaceText("\"encryption\":\"aes-xts-plain64\",\"sector_size\"", "\"encryption\":\"capi:xts(aes)-plain64\",\"sector_size\""), "crypto API");
    // The flags dm-crypt merely schedules by are harmless.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, editJson([](json::Value& j) { setIn(j, "config", "flags", json::Value::array().push("allow-discards").push("no-journal").push("same-cpu-crypt")); }));
        auto ok = container::Luks::open(dev);
        REQUIRE(ok);
        CHECK(ok->info().supported);
        CHECK(ok->info().flags.size() == 3);
        CHECK(ok->info().requirements.empty());
        REQUIRE(ok->unlock(kLuksPassphrase));
    }
    // A segment cipher the crypto core has (serpent) is accepted: the key slot still decrypts with aes, so the
    // volume key verifies, and the payload, written with aes, is no longer the ext2 it was.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, replaceText("\"encryption\":\"aes-xts-plain64\",\"sector_size\"", "\"encryption\":\"serpent-xts-plain64\",\"sector_size\""));
        auto serpent = container::Luks::open(dev);
        REQUIRE(serpent);
        CHECK(serpent->info().supported);
        CHECK(serpent->info().cipher == "serpent");
        CHECK(serpent->info().mode == "xts-plain64");
        auto payload = serpent->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        auto probed = fs::probe(*payload);
        CHECK((!probed || !*probed));
    }
}

TEST_CASE("luks2: every usable slot is tried, unsupported slots are skipped with a reason, tokens and priority are read, the volume key size comes from the digest, numbers are parsed defensively") {
    // Keyslot "1" = keyslot 0 with `tweak` applied, bound to the digest unless told otherwise.
    auto withSecondSlot = [](const std::function<void(json::Value&)>& tweak, bool bindToDigest = true) {
        return editJson([tweak, bindToDigest](json::Value& j) {
            json::Value slot = j.get("keyslots").get("0");
            tweak(slot);
            setSlot(j, "1", slot);
            if (bindToDigest) bindDigest(j, {"0", "1"});
        });
    };
    auto openWith = [](const JsonEdit& edit) {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, edit);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        return *luks;
    };
    const std::string masterKey = oracle("luks2")["master_key"];
    struct Skipped { const char* why; std::function<void(json::Value&)> tweak; };
    const Skipped skipped[] = {
        {"kdf scrypt", [](json::Value& s) { setIn(s, "kdf", "type", "scrypt"); }},
        {"kdf hash md5", [](json::Value& s) { setIn(s, "kdf", "type", "pbkdf2"); setIn(s, "kdf", "hash", "md5"); setIn(s, "kdf", "iterations", 1000); }},
        {"af hash md5", [](json::Value& s) { setIn(s, "af", "hash", "md5"); }},
        {"af type \"luks3\"", [](json::Value& s) { setIn(s, "af", "type", "luks3"); }},
        {"ESSIV", [](json::Value& s) { setIn(s, "area", "encryption", "aes-cbc-essiv:sha256"); }},
        {"area type \"journal\"", [](json::Value& s) { setIn(s, "area", "type", "journal"); }},
        {"area key_size missing", [](json::Value& s) { setIn(s, "area", "key_size", 0); }},
        {"key size 32 is not the volume key's 64", [](json::Value& s) { s.set("key_size", 32); }},
        {"above this machine's cap", [](json::Value& s) { setIn(s, "kdf", "memory", std::uint64_t{0xFFFFFFFFull}); }},
        {"parameters t=0", [](json::Value& s) { setIn(s, "kdf", "time", 0); }},
    };
    for (const auto& c : skipped) {
        CAPTURE(c.why);
        auto luks = openWith(withSecondSlot([&](json::Value& s) { c.tweak(s); s.set("priority", 2); }));
        REQUIRE(luks.info().slots.size() == 2);
        CHECK(luks.info().supported);
        CHECK(luks.info().slots[0].unsupportedWhy.empty());
        CHECK(luks.info().slots[1].id == 1);
        CHECK(luks.info().slots[1].active);
        CHECK(luks.info().slots[1].priority == 2);
        CHECK_MESSAGE(luks.info().slots[1].unsupportedWhy.find(c.why) != std::string::npos, luks.info().slots[1].unsupportedWhy);
        // The preferred slot cannot be tried; the normal one still opens the volume. A wrong passphrase is Integrity, not Unsupported.
        auto key = luks.unlock(kLuksPassphrase);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == masterKey);
        auto wrong = luks.unlock("not it");
        REQUIRE_FALSE(wrong);
        CHECK(wrong.error().category() == ErrorCategory::Integrity);
    }
    // A slot the digest does not cover cannot hold the volume key.
    {
        auto luks = openWith(withSecondSlot([](json::Value&) {}, false));
        REQUIRE(luks.info().slots.size() == 2);
        CHECK_MESSAGE(luks.info().slots[1].unsupportedWhy.find("not bound") != std::string::npos, luks.info().slots[1].unsupportedWhy);
        REQUIRE(luks.unlock(kLuksPassphrase));
    }
    // No usable slot at all: Unsupported, listing every slot's reason; the payload itself is fine.
    {
        auto luks = openWith(editJson([](json::Value& j) {
            json::Value s0 = j.get("keyslots").get("0"), s1 = s0;
            setIn(s0, "kdf", "type", "scrypt");
            setIn(s1, "af", "hash", "md5");
            setSlot(j, "0", s0);
            setSlot(j, "1", s1);
            bindDigest(j, {"0", "1"});
        }));
        CHECK_FALSE(luks.info().supported);
        CHECK_MESSAGE(luks.info().unsupportedWhy.find("no usable key slot") != std::string::npos, luks.info().unsupportedWhy);
        CHECK(luks.info().unsupportedWhy.find("slot 0: kdf scrypt") != std::string::npos);
        CHECK(luks.info().unsupportedWhy.find("slot 1: af hash md5") != std::string::npos);
        auto key = luks.unlock(kLuksPassphrase);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Unsupported);
    }
    // Two usable slots and a wrong passphrase: both are tried, Integrity. A lone priority-0 ("ignore") slot still opens.
    {
        auto luks = openWith(withSecondSlot([](json::Value&) {}));
        auto wrong = luks.unlock("not it");
        REQUIRE_FALSE(wrong);
        CHECK(wrong.error().category() == ErrorCategory::Integrity);
        REQUIRE(luks.unlock(kLuksPassphrase));
        auto ignored = openWith(editJson([](json::Value& j) { setNested(j, "keyslots", "0", "priority", 0); }));
        CHECK(ignored.info().slots[0].priority == 0);
        CHECK(ignored.info().supported);
        REQUIRE(ignored.unlock(kLuksPassphrase));
    }
    // Tokens attach to the slots they name, in token order; one naming no real slot changes nothing.
    {
        auto luks = openWith(editJson([](json::Value& j) {
            json::Value tpm = json::Value::object();
            tpm.set("type", "systemd-tpm2");
            tpm.set("keyslots", json::Value::array().push("0"));
            json::Value clevis = json::Value::object();
            clevis.set("type", "clevis");
            clevis.set("keyslots", json::Value::array().push("0").push("7"));
            json::Value tokens = json::Value::object();
            tokens.set("0", tpm);
            tokens.set("1", clevis);
            j.set("tokens", tokens);
        }));
        REQUIRE(luks.info().slots.size() == 1);
        CHECK(luks.info().slots[0].tokens == std::vector<std::string>{"systemd-tpm2", "clevis"});
        REQUIRE(luks.unlock(kLuksPassphrase));
        CHECK(container::Luks::open(loadSparseFixture("luks/luks2.sparse"))->info().slots[0].tokens.empty());
    }
    // The volume key size comes from the digest's slot, not from whichever slot the JSON lists first.
    {
        auto luks = openWith(editJson([](json::Value& j) {
            json::Value real = j.get("keyslots").get("0");
            json::Value reencrypt = json::Value::object();
            reencrypt.set("type", "reencrypt");
            reencrypt.set("key_size", 32);
            reencrypt.set("mode", "reencrypt");
            reencrypt.set("direction", "forward");
            json::Value slots = json::Value::object();
            slots.set("0", reencrypt);
            slots.set("1", real);
            j.set("keyslots", slots);
            bindDigest(j, {"1"});
        }));
        CHECK(luks.info().keyBytes == 64);
        REQUIRE(luks.info().slots.size() == 2);
        CHECK_FALSE(luks.info().slots[0].active);
        CHECK(luks.info().slots[0].kdf == "reencrypt");
        CHECK(luks.info().slots[1].active);
        CHECK(luks.info().slots[1].unsupportedWhy.empty());
        CHECK(luks.info().supported);
        auto key = luks.unlock(kLuksPassphrase);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == masterKey);
    }
    // Numbers in the JSON are data: a malformed one is InvalidFormat from open(), never an exception.
    {
        const std::pair<const char*, const char*> bad[] = {
            {"\"key_size\":64,\"af\"", "\"key_size\":\"sixty-four\",\"af\""},
            {"\"offset\":\"1048576\"", "\"offset\":\"1048576abc\""},
            {"\"offset\":\"1048576\"", "\"offset\":\"-1\""},
            {"\"offset\":\"1048576\"", "\"offset\":\"\""},
            {"\"sector_size\":512", "\"sector_size\":\"\""},
            {"\"sector_size\":512", "\"sector_size\":513"},
            {"\"iterations\":1000", "\"iterations\":-5"},
            {"\"stripes\":4000", "\"stripes\":\"4000x\""},
            {"\"keyslots\":{\"0\"", "\"keyslots\":{\"zero\""},
            {"\"offset\":\"32768\"", "\"offset\":\"99999999999999999999999\""},
            {"\"time\":4", "\"time\":4294967296"},
        };
        for (const auto& [from, to] : bad) {
            CAPTURE(to);
            auto dev = loadSparseFixture("luks/luks2.sparse");
            rewriteLuks2Json(*dev, replaceText(from, to));
            auto luks = container::Luks::open(dev);
            REQUIRE_FALSE(luks);
            CHECK(luks.error().category() == ErrorCategory::InvalidFormat);
        }
    }
    // Cancellation: before a slot and between Argon2 slices.
    {
        auto luks = container::Luks::open(loadSparseFixture("luks/luks2.sparse"));
        REQUIRE(luks);
        container::UnlockOptions opt;
        opt.cancelled = [] { return true; };
        auto key = luks->unlock(kLuksPassphrase, opt);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Cancelled);
        int polls = 0;
        opt.cancelled = [&] { return ++polls > 2; };   // poll 1: before the slot; poll 2: slice 0; poll 3: slice 1 cancels
        key = luks->unlock(kLuksPassphrase, opt);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Cancelled);
        CHECK(polls == 3);
        opt.cancelled = [] { return false; };
        REQUIRE(luks->unlock(kLuksPassphrase, opt));
        auto payload = luks->openPayload(kLuksPassphrase, true, opt);
        REQUIRE(payload);
        CHECK(payloadLabel(*payload) == "inside_luks");
    }
}

TEST_CASE("luks: detached header: header fields and key material from one device, the payload from another, the stored offset counting on the data device") {
    // A header backup (everything before the payload) opens a disk whose own header was wiped: the
    // segment offset still counts on the data device, as dm-crypt maps it.
    {
        auto whole = loadSparseFixture("luks/luks2.sparse");
        auto header = std::make_shared<MemoryDevice>(std::vector<std::byte>(whole->bytes().begin(), whole->bytes().begin() + 1 * MiB));
        auto data = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(data->writeAt(0, std::vector<std::byte>(1 * MiB)));
        CHECK(container::Luks::open(data).error().category() == ErrorCategory::NotFound);
        auto luks = container::Luks::open(header, data);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().payloadOffset == 1 * MiB);
        CHECK(luks->info().payloadSize == data->size() - 1 * MiB);
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK(payloadLabel(*payload) == "inside_luks");
        CHECK(container::Luks::open(nullptr, data).error().category() == ErrorCategory::InvalidArgument);
    }
    // What cryptsetup luksFormat --header writes: segment offset 0, the payload from the data device's first byte.
    for (const char* name : {"luks2", "luks2_pbkdf2"}) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto whole = loadSparseFixture("luks/" + fixture + ".sparse");
        auto header = std::make_shared<MemoryDevice>(std::vector<std::byte>(whole->bytes().begin(), whole->bytes().begin() + 1 * MiB));
        rewriteLuks2Json(*header, replaceText("\"offset\":\"1048576\"", "\"offset\":\"0\""));
        auto data = std::make_shared<MemoryDevice>(std::vector<std::byte>(whole->bytes().begin() + 1 * MiB, whole->bytes().end()));
        auto luks = container::Luks::open(header, data);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().payloadOffset == 0);
        CHECK(luks->info().payloadSize == data->size());
        CHECK(luks->info().sectorSize == std::stoul(oracle(fixture)["sector_size"]));
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == oracle(fixture)["master_key"]);
        auto payload = luks->openPayload(*key, true);
        REQUIRE(payload);
        CHECK(payloadLabel(*payload) == "inside_luks");
        // Writes land on the data device; the header device is untouched.
        const std::vector<std::byte> headerBefore(header->bytes().begin(), header->bytes().end());
        const std::vector<std::byte> dataBefore(data->bytes().begin(), data->bytes().end());
        auto rw = luks->openPayload(*key, false);
        REQUIRE(rw);
        REQUIRE((*rw)->writeAt(70000, stein::test::bytesOf("detached write")));
        auto back = (*rw)->read(70000, 14);
        REQUIRE(back);
        CHECK(std::string(reinterpret_cast<const char*>(back->data()), 14) == "detached write");
        CHECK(std::equal(header->bytes().begin(), header->bytes().end(), headerBefore.begin()));
        CHECK_FALSE(std::equal(data->bytes().begin(), data->bytes().end(), dataBefore.begin()));
    }
    // LUKS1: payload_offset is a plain field (512-byte sectors), 0 for a detached header. With the original
    // offset the payload is looked for 2 MiB into the data device: the key verifies, what decrypts there is not the filesystem.
    {
        auto whole = loadSparseFixture("luks/luks1.sparse");
        const ByteCount payloadOffset = 4096 * 512;
        std::vector<std::byte> hdrBytes(whole->bytes().begin(), whole->bytes().begin() + payloadOffset);
        auto original = std::make_shared<MemoryDevice>(hdrBytes);
        storeBe32(hdrBytes.data() + layout::gen::Luks1Phdr::kPayloadOffsetOffset, 0);
        auto header = std::make_shared<MemoryDevice>(hdrBytes);
        auto data = std::make_shared<MemoryDevice>(std::vector<std::byte>(whole->bytes().begin() + payloadOffset, whole->bytes().end()));
        auto luks = container::Luks::open(header, data);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().version == 1);
        CHECK(luks->info().payloadOffset == 0);
        CHECK(luks->info().payloadSize == data->size());
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK(payloadLabel(*payload) == "inside_luks");
        auto misplaced = container::Luks::open(original, data);
        REQUIRE(misplaced);
        CHECK(misplaced->info().payloadOffset == payloadOffset);
        CHECK(misplaced->info().payloadSize == data->size() - payloadOffset);
        auto garbage = misplaced->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(garbage, (garbage ? std::string() : garbage.error().toString()));
        auto probed = fs::probe(*garbage);
        CHECK((!probed || !*probed));
        // And a data device too small for the stored offset is OutOfRange, not a read past its end.
        auto small = std::make_shared<MemoryDevice>(std::vector<std::byte>(whole->bytes().begin() + payloadOffset, whole->bytes().begin() + payloadOffset + 256 * KiB));
        auto tooSmall = container::Luks::open(original, small);
        REQUIRE(tooSmall);
        CHECK(tooSmall->info().payloadSize == 0);
        CHECK(tooSmall->openPayload(kLuksPassphrase, true).error().category() == ErrorCategory::OutOfRange);
    }
}

TEST_CASE("luks: cipher and hash names: xts-plain64 over aes, serpent, twofish, camellia; ripemd160 and whirlpool; cbc-essiv, plain64be and capi: refused") {
    using crypto::CipherAlgorithm;
    CHECK(container::luksCipher("aes", "xts-plain64").value() == CipherAlgorithm::Aes);
    CHECK(container::luksCipher("serpent", "xts-plain64").value() == CipherAlgorithm::Serpent);
    CHECK(container::luksCipher("twofish", "xts-plain64").value() == CipherAlgorithm::Twofish);
    CHECK(container::luksCipher("camellia", "xts-plain64").value() == CipherAlgorithm::Camellia);
    auto refused = [](const char* cipher, const char* mode, const char* why) {
        CAPTURE(cipher);
        CAPTURE(mode);
        auto r = container::luksCipher(cipher, mode);
        REQUIRE_FALSE(r);
        CHECK(r.error().category() == ErrorCategory::Unsupported);
        CHECK_MESSAGE(r.error().message().find(why) != std::string::npos, r.error().message());
    };
    refused("aes", "cbc-essiv:sha256", "ESSIV");
    refused("aes", "xts-plain64be", "plain64be");
    refused("aes", "xts-plain", "32-bit");
    refused("aes", "cbc-plain64", "CBC");
    refused("capi:xts(aes)", "plain64", "crypto API");
    refused("blowfish", "xts-plain64", "blowfish");
    refused("aes", "", "only xts-plain64");
    CHECK(container::luksHash("sha256").value() == HashAlgorithm::Sha256);
    CHECK(container::luksHash("sha1").value() == HashAlgorithm::Sha1);
    CHECK(container::luksHash("sha512").value() == HashAlgorithm::Sha512);
    CHECK(container::luksHash("ripemd160").value() == HashAlgorithm::Ripemd160);
    CHECK(container::luksHash("whirlpool").value() == HashAlgorithm::Whirlpool);
    CHECK_FALSE(container::luksHash("md5").has_value());
    CHECK_FALSE(container::luksHash("SHA256").has_value());
    // A LUKS1 header patched to name another hash or cipher runs the real paths: the fixture's key material was
    // made with sha256 and aes, so the result is a wrong passphrase (Integrity), not Unsupported. Names we lack refuse up front.
    struct Patch { std::uint32_t offset; const char* value; bool supported; const char* why; };
    const Patch patches[] = {
        {layout::gen::Luks1Phdr::kHashSpecOffset, "ripemd160", true, ""},
        {layout::gen::Luks1Phdr::kHashSpecOffset, "whirlpool", true, ""},
        {layout::gen::Luks1Phdr::kHashSpecOffset, "sha512", true, ""},
        {layout::gen::Luks1Phdr::kHashSpecOffset, "md4", false, "hash md4"},
        {layout::gen::Luks1Phdr::kCipherNameOffset, "serpent", true, ""},
        {layout::gen::Luks1Phdr::kCipherNameOffset, "twofish", true, ""},
        {layout::gen::Luks1Phdr::kCipherNameOffset, "camellia", true, ""},
        {layout::gen::Luks1Phdr::kCipherNameOffset, "blowfish", false, "blowfish"},
        {layout::gen::Luks1Phdr::kCipherModeOffset, "cbc-essiv:sha256", false, "ESSIV"},
        {layout::gen::Luks1Phdr::kCipherModeOffset, "xts-plain64be", false, "plain64be"},
    };
    for (const auto& p : patches) {
        CAPTURE(p.value);
        auto dev = loadSparseFixture("luks/luks1.sparse");
        std::vector<std::byte> field(32, std::byte{0});
        std::memcpy(field.data(), p.value, std::strlen(p.value));
        REQUIRE(dev->writeAt(p.offset, field));
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().supported == p.supported);
        if (p.offset == layout::gen::Luks1Phdr::kHashSpecOffset) CHECK(luks->info().hash == p.value);
        if (p.offset == layout::gen::Luks1Phdr::kCipherNameOffset) CHECK(luks->info().cipher == p.value);
        if (p.offset == layout::gen::Luks1Phdr::kCipherModeOffset) CHECK(luks->info().mode == p.value);
        REQUIRE(luks->info().slots.size() == 8);
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE_FALSE(key);
        if (p.supported) {
            CHECK(luks->info().slots[0].unsupportedWhy.empty());
            CHECK(key.error().category() == ErrorCategory::Integrity);
        } else {
            CHECK(key.error().category() == ErrorCategory::Unsupported);
            CHECK_MESSAGE(luks->info().unsupportedWhy.find(p.why) != std::string::npos, luks->info().unsupportedWhy);
            CHECK(luks->info().slots[0].unsupportedWhy == luks->info().unsupportedWhy);
        }
    }
}

// A timing, not a unit test (STEIN_BENCH=1): one unlock of the luks2 fixture. Its slot is argon2id
// t=4 m=64KiB p=1, a single lane, so the lane threads cannot apply and this is the single-thread
// path before and after them; the KDF is a small part of the 500 KiB AF merge and digest check.
TEST_CASE("luks2: unlock timing of the fixture (STEIN_BENCH=1)") {
    if (!std::getenv("STEIN_BENCH")) {
        MESSAGE("set STEIN_BENCH=1 to time an unlock of the luks2 fixture");
        return;
    }
    auto luks = container::Luks::open(loadSparseFixture("luks/luks2.sparse"));
    REQUIRE(luks);
    double best = 1e9, total = 0;
    constexpr int kRuns = 5;
    for (int i = 0; i < kRuns; ++i) {
        const auto start = std::chrono::steady_clock::now();
        REQUIRE(luks->unlock(kLuksPassphrase));
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        best = std::min(best, s);
        total += s;
    }
    MESSAGE("luks2 fixture unlock (argon2id t=4 m=64KiB p=1, 4000 stripes): best ", best, " s, mean ", total / kRuns, " s over ", kRuns, " runs");
}

// ---------------------------------------------------------------------------------------------
// End to end on this platform (doc/design/06-luks-on-macos.md, plan step 5): what a user with an
// encrypted disk hits, fixture by fixture. open, a wrong passphrase, the right one, the payload
// probed as the ext2 it holds and its root directory read through a Reader; the 4096-byte-sector
// fixture read past its first sector and checked against the oracle's master key; the read cache
// above the payload against a bare XtsDevice; and the unlock cost, printed so a regression in the
// KDF shows in the log. The NFS mount of the payload lives in test_mount (it links stein::mount).
#include "../src/xts_device.hpp"
#include "stein/block/cached_device.hpp"
#include "stein/layout/gen/ext.hpp"

#include <cstdio>
#include <random>

namespace {
const char* const kLuksFixtures[] = {"luks1", "luks1_sha1", "luks2", "luks2_pbkdf2"};

std::vector<std::uint8_t> oracleMasterKey(const std::string& fixture) {
    auto bytes = fromHex(oracle(fixture)["master_key"]);
    REQUIRE(bytes);
    std::vector<std::uint8_t> key(bytes->size());
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = std::to_integer<std::uint8_t>((*bytes)[i]);
    return key;
}
std::vector<std::byte> readAll(BlockDevice& dev, ByteCount offset, ByteCount length) {
    auto bytes = dev.read(offset, length);
    REQUIRE_MESSAGE(bytes, (bytes ? std::string() : bytes.error().toString()));
    return *bytes;
}
// A decrypting view with no cache in front of it, built the way Luks::openPayload builds its inner device.
std::shared_ptr<BlockDevice> bareXts(std::shared_ptr<BlockDevice> dev, const container::LuksInfo& info, std::span<const std::uint8_t> masterKey) {
    auto cipher = container::luksCipher(info.cipher, info.mode);   // aes for the old fixtures, serpent for luks2_serpent
    REQUIRE(cipher);
    auto xts = crypto::Xts::create(*cipher, masterKey);
    REQUIRE(xts);
    return std::make_shared<container::detail::XtsDevice>(std::move(dev), Region{info.payloadOffset, info.payloadSize}, info.sectorSize, info.ivTweak, std::move(*xts), true, "bare");
}

// ---------------------------------------------------------------------------------------------
// Review of bcfb2ad: a damaged or hostile header is settled when it is parsed, with the reason,
// and never costs a derivation, an unbounded allocation or a read into garbage.

// A device whose first `badBytes` cannot be read (a disk with its first sectors gone); everything else intact.
class UnreadableHeadDevice final : public BlockDevice {
public:
    UnreadableHeadDevice(std::shared_ptr<MemoryDevice> inner, ByteCount badBytes) : m_inner(std::move(inner)), m_bad(badBytes) {}
    std::string name() const override { return "unreadable-head"; }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (offset < m_bad) return fail(ErrorCategory::Io, "unreadable sector at " + std::to_string(offset));
        return m_inner->readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override { return fail(ErrorCategory::Permission, "read-only"); }
    Expected<void> flush() override { return {}; }

private:
    std::shared_ptr<MemoryDevice> m_inner;
    ByteCount m_bad;
};

// The luks2 fixture with `tweak` applied to its only keyslot, both header copies rewritten.
std::shared_ptr<MemoryDevice> luks2WithSlot0(const std::function<void(json::Value&)>& tweak) {
    auto dev = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(dev);
    rewriteLuks2Json(*dev, editJson([&](json::Value& j) {
        json::Value slot = j.get("keyslots").get("0");
        tweak(slot);
        setSlot(j, "0", slot);
    }));
    return dev;
}
// `obj` without `key` (json::Value has no erase).
json::Value without(const json::Value& obj, std::string_view key) {
    json::Value out = json::Value::object();
    for (const auto& [k, v] : obj.asObject())
        if (k != key) out.set(k, v);
    return out;
}
bool allZero(std::span<const std::uint8_t> bytes) { return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; }); }
double msSince(std::chrono::steady_clock::time_point start) { return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count(); }
} // namespace

TEST_CASE("luks2: a slot that could not open the volume is settled at parse time, with its reason, and costs no derivation: key sizes XTS refuses, implausible stripes, an area inside the header, beyond the device or too small, Argon2 lanes out of bounds") {
    struct Case { const char* why; std::function<void(json::Value&)> tweak; };
    const Case cases[] = {
        {"area key_size 48 (XTS takes 64 bytes, or 32 with aes)", [](json::Value& s) { setIn(s, "area", "key_size", 48); }},
        {"key size 48 (XTS takes 64 bytes, or 32 with aes)", [](json::Value& s) { s.set("key_size", 48); }},   // the only slot: this is the volume key size itself
        {"implausible key material size (4294967295 stripes of 64 bytes)", [](json::Value& s) { setIn(s, "af", "stripes", std::uint64_t{4294967295ull}); }},
        {"key material (256000 bytes) larger than its area (4096)", [](json::Value& s) { setIn(s, "area", "size", "4096"); }},
        {"key material area at 4096 lies inside the header", [](json::Value& s) { setIn(s, "area", "offset", "4096"); }},
        {"key material area at 1099511627776 runs beyond the end of the device", [](json::Value& s) { setIn(s, "area", "offset", "1099511627776"); }},
        {"argon2id parameters t=4 m=64KiB p=536870912 are invalid", [](json::Value& s) { setIn(s, "kdf", "cpus", std::uint64_t{536870912}); }},   // 8 * 2^29 wraps to 0 in 32 bits
        {"argon2id parameters t=4 m=64KiB p=16777216 are invalid", [](json::Value& s) { setIn(s, "kdf", "cpus", std::uint64_t{16777216}); }},     // one above Argon2's lane maximum
        // The reviewer's case, last so that a regression fails on the cases above before it stalls here: before
        // the fix a 4 GiB area key was allocated and the KDF asked to fill it (hours) before XTS refused it.
        {"area key_size 4294967295 (XTS takes", [](json::Value& s) { setIn(s, "area", "key_size", std::uint64_t{4294967295ull}); }},
        {"key size 4294967295 (XTS takes", [](json::Value& s) { s.set("key_size", std::uint64_t{4294967295ull}); }},
    };
    for (const auto& c : cases) {
        const std::string why = c.why;
        CAPTURE(why);
        const auto start = std::chrono::steady_clock::now();
        auto luks = container::Luks::open(luks2WithSlot0(c.tweak));
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        REQUIRE(luks->info().slots.size() == 1);
        CHECK_MESSAGE(luks->info().slots[0].unsupportedWhy.find(c.why) != std::string::npos, luks->info().slots[0].unsupportedWhy);
        CHECK_FALSE(luks->info().supported);
        CHECK_MESSAGE(luks->info().unsupportedWhy.find("no usable key slot") != std::string::npos, luks->info().unsupportedWhy);
        // Unsupported straight away: the cancel hook, polled before every slot and every Argon2 slice, is never asked.
        int polls = 0;
        container::UnlockOptions opt;
        opt.cancelled = [&] { ++polls; return false; };
        auto key = luks->unlock(kLuksPassphrase, opt);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Unsupported);
        CHECK(polls == 0);
        CHECK(msSince(start) < 2000);
    }
    // Beside a good slot the bad one is skipped and the volume opens; the bad slot still costs nothing.
    for (const auto& c : cases) {
        const std::string why = c.why;
        if (why.starts_with("key size")) continue;   // a second slot's own key size hits the volume-key check first (tested above and in the slots case)
        CAPTURE(why);
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, editJson([&](json::Value& j) {
            json::Value slot = j.get("keyslots").get("0");
            c.tweak(slot);
            slot.set("priority", 2);
            setSlot(j, "1", slot);
            bindDigest(j, {"0", "1"});
        }));
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        REQUIRE(luks->info().slots.size() == 2);
        CHECK(luks->info().supported);
        CHECK(luks->info().slots[0].unsupportedWhy.empty());
        CHECK_MESSAGE(luks->info().slots[1].unsupportedWhy.find(c.why) != std::string::npos, luks->info().slots[1].unsupportedWhy);
        int polls = 0;
        container::UnlockOptions opt;
        opt.cancelled = [&] { ++polls; return false; };
        auto key = luks->unlock(kLuksPassphrase, opt);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == oracle("luks2")["master_key"]);
        CHECK(polls == 17);   // once before slot 0, then its 16 Argon2 slices (t=4): the preferred but unusable slot 1 was never derived
    }
}

TEST_CASE("luks2: what cannot be right is InvalidFormat from open(): a digest that is not the hash's size, a missing digest or salt, a segment offset that is not whole sectors or lies inside the header and key material, an iv_tweak that is not whole sectors") {
    auto refused = [](const JsonEdit& edit, const char* fixture = "luks2") {
        auto dev = loadSparseFixture(std::string("luks/") + fixture + ".sparse");
        REQUIRE(dev);
        rewriteLuks2Json(*dev, edit);
        auto luks = container::Luks::open(dev);
        REQUIRE_FALSE(luks);
        CHECK(luks.error().category() == ErrorCategory::InvalidFormat);
        return luks.error().message();
    };
    auto setDigest = [](const std::string& key, const json::Value& value) {
        return editJson([=](json::Value& j) { setNested(j, "digests", "0", key, value); });
    };
    // Before the fix a 16-byte digest made the right passphrase a "wrong passphrase" (PBKDF2 of 16 bytes never equals it), and a long
    // one sized a PBKDF2 run with no bound.
    CHECK(refused(setDigest("digest", "AAECAwQFBgcICQoLDA0ODw==")).find("digest value is 16 bytes, sha256 makes 32") != std::string::npos);
    CHECK(refused(setDigest("digest", std::string(64, 'A'))).find("digest value is 48 bytes") != std::string::npos);
    CHECK(refused(setDigest("digest", "")).find("digest value is missing") != std::string::npos);
    CHECK(refused(setDigest("salt", "")).find("digest salt is missing") != std::string::npos);
    CHECK(refused(setDigest("salt", 42)).find("digest salt is missing") != std::string::npos);
    CHECK(refused(editJson([](json::Value& j) {
        json::Value digests = j.get("digests");
        digests.set("0", without(j.get("digests").get("0"), "digest"));
        j.set("digests", digests);
    })).find("digest value is missing") != std::string::npos);
    // A pbkdf2 slot without its salt: before the fix it parsed with an empty salt and read as a wrong passphrase.
    CHECK(refused(editJson([](json::Value& j) {
        json::Value slot = j.get("keyslots").get("0");
        slot.set("kdf", without(slot.get("kdf"), "salt"));
        setSlot(j, "0", slot);
    }), "luks2_pbkdf2").find("keyslot 0 salt is missing") != std::string::npos);
    CHECK(refused(editJson([](json::Value& j) { setNested(j, "keyslots", "0", "kdf", [&] { json::Value k = j.get("keyslots").get("0").get("kdf"); k.set("salt", ""); return k; }()); })).find("keyslot 0 salt is missing") != std::string::npos);
    // The segment offset: dm-crypt maps 512-byte sectors; the fixture's key material ends at 32768 + 258048.
    CHECK(refused(replaceText("\"offset\":\"1048576\"", "\"offset\":\"1048577\"")).find("segment offset 1048577 is not a multiple of 512") != std::string::npos);
    CHECK(refused(replaceText("\"offset\":\"1048576\"", "\"offset\":\"16384\"")).find("segment offset 16384 lies inside the header and key material (first 290816 bytes)") != std::string::npos);
    CHECK(refused(replaceText("\"offset\":\"1048576\"", "\"offset\":\"204800\"")).find("lies inside the header and key material") != std::string::npos);
    // iv_tweak counts 512-byte sectors: on 4096-byte sectors it must be a multiple of 8; on 512-byte sectors any value is whole.
    CHECK(refused(replaceText("\"iv_tweak\":\"0\"", "\"iv_tweak\":\"3\""), "luks2_pbkdf2").find("iv_tweak 3 is not a multiple of the sector size in 512-byte units (8)") != std::string::npos);
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, replaceText("\"iv_tweak\":\"0\"", "\"iv_tweak\":\"3\""));
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().ivTweak == 3);
    }
    // Offset 0 on the header's own device is what cryptsetup writes for a detached header: a header only, not damage.
    {
        auto dev = loadSparseFixture("luks/luks2.sparse");
        rewriteLuks2Json(*dev, replaceText("\"offset\":\"1048576\"", "\"offset\":\"0\""));
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().headerOnly);
        CHECK(luks->info().payloadSize == 0);
        CHECK(luks->info().supported);
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE(key);
        CHECK(Hasher::hex(*key) == oracle("luks2")["master_key"]);
        auto payload = luks->openPayload(*key, true);
        REQUIRE_FALSE(payload);
        CHECK(payload.error().category() == ErrorCategory::OutOfRange);
    }
}

TEST_CASE("luks1: key material inside the header, beyond the device or implausibly striped makes the slot unusable; a key size XTS refuses makes the volume unsupported; a payload offset inside the header or key material is InvalidFormat; offset 0 is a header only") {
    using Phdr = layout::gen::Luks1Phdr;
    using Keyslot = layout::gen::Luks1Keyslot;
    // No checksum seals a LUKS1 header, so its fields are patched in place.
    auto patched = [](const std::function<void(std::span<std::byte>)>& edit) {
        auto dev = loadSparseFixture("luks/luks1.sparse");
        REQUIRE(dev);
        edit(dev->bytes());
        return dev;
    };
    auto slot0 = [](std::span<std::byte> hdr) { return hdr.subspan(0xD0, 48); };
    auto unusable = [&](const std::function<void(std::span<std::byte>)>& edit, const std::string& why) {
        CAPTURE(why);
        auto luks = container::Luks::open(patched(edit));
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK_FALSE(luks->info().supported);
        REQUIRE(luks->info().slots.size() == 8);
        CHECK_MESSAGE(luks->info().slots[0].unsupportedWhy.find(why) != std::string::npos, luks->info().slots[0].unsupportedWhy);
        CHECK_MESSAGE(luks->info().unsupportedWhy.find(why) != std::string::npos, luks->info().unsupportedWhy);
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE_FALSE(key);
        CHECK(key.error().category() == ErrorCategory::Unsupported);
        return *luks;
    };
    // key_material_offset 1 (512 bytes) is inside the 592-byte phdr; 0x7FFFFFFF sectors is past any device; 2^32 - 1 stripes of 64 bytes is 256 GiB.
    auto luks = unusable([&](std::span<std::byte> b) { Keyslot::setKeyMaterialOffset(slot0(b), 1); }, "key material at 512 lies inside the header");
    CHECK(luks.info().unsupportedWhy.find("no usable key slot") != std::string::npos);
    unusable([&](std::span<std::byte> b) { Keyslot::setKeyMaterialOffset(slot0(b), 0x7FFFFFFFu); }, "runs beyond the end of the device");
    unusable([&](std::span<std::byte> b) { Keyslot::setStripes(slot0(b), 0xFFFFFFFFu); }, "implausible key material size (4294967295 stripes of 64 bytes)");
    // key_bytes 48 with aes-xts-plain64: a header-level reason, shared by every slot.
    unusable([](std::span<std::byte> b) { Phdr::setKeyBytes(b, 48); }, "key size 48 (XTS takes 64 bytes, or 32 with aes)");
    // payload_offset inside the phdr (sector 1) or inside slot 0's key material (sector 9: 4608 < 4096 + 4000 * 64).
    for (std::uint32_t sectors : {1u, 9u}) {
        CAPTURE(sectors);
        auto bad = container::Luks::open(patched([&](std::span<std::byte> b) { Phdr::setPayloadOffset(b, sectors); }));
        REQUIRE_FALSE(bad);
        CHECK(bad.error().category() == ErrorCategory::InvalidFormat);
        CHECK_MESSAGE(bad.error().message().find("lies inside the header and key material (first 260096 bytes)") != std::string::npos, bad.error().message());
    }
    // payload_offset 0 on the header's own device: a detached header opened by itself. The slot unlocks; there is no payload here.
    {
        auto alone = container::Luks::open(patched([](std::span<std::byte> b) { Phdr::setPayloadOffset(b, 0); }));
        REQUIRE_MESSAGE(alone, (alone ? std::string() : alone.error().toString()));
        CHECK(alone->info().headerOnly);
        CHECK(alone->info().payloadSize == 0);
        CHECK(alone->info().supported);
        auto key = alone->unlock(kLuksPassphrase);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(Hasher::hex(*key) == oracle("luks1")["master_key"]);
        auto payload = alone->openPayload(kLuksPassphrase, true);
        REQUIRE_FALSE(payload);
        CHECK(payload.error().category() == ErrorCategory::OutOfRange);
    }
    // Untouched, the fixture is not a header only.
    CHECK_FALSE(container::Luks::open(loadSparseFixture("luks/luks1.sparse"))->info().headerOnly);
}

TEST_CASE("luks2: high_priority (cryptsetup >= 2.7 --perf-high_priority) is a harmless flag; a name we do not know is still refused") {
    auto dev = loadSparseFixture("luks/luks2.sparse");
    rewriteLuks2Json(*dev, editJson([](json::Value& j) { setIn(j, "config", "flags", json::Value::array().push("high_priority").push("allow-discards")); }));
    auto ok = container::Luks::open(dev);
    REQUIRE_MESSAGE(ok, (ok ? std::string() : ok.error().toString()));
    CHECK(ok->info().supported);
    CHECK(ok->info().flags == std::vector<std::string>{"high_priority", "allow-discards"});
    REQUIRE(ok->unlock(kLuksPassphrase));
    dev = loadSparseFixture("luks/luks2.sparse");
    rewriteLuks2Json(*dev, editJson([](json::Value& j) { setIn(j, "config", "flags", json::Value::array().push("high_priority").push("low_priority")); }));
    auto unknown = container::Luks::open(dev);
    REQUIRE(unknown);
    CHECK_FALSE(unknown->info().supported);
    CHECK_MESSAGE(unknown->info().unsupportedWhy.find("unknown flags low_priority") != std::string::npos, unknown->info().unsupportedWhy);
}

TEST_CASE("luks: a device whose first sectors cannot be read opens from the LUKS2 secondary copy; with no copy to fall back on, the I/O error is what is reported") {
    // Before the fix the read error of the first 4 KiB was returned before the secondary was looked for.
    {
        auto mem = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(mem);
        auto dev = std::make_shared<UnreadableHeadDevice>(mem, 4096);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().headerCopyUsed == 1);
        CHECK_FALSE(luks->info().primaryValid);
        CHECK(luks->info().secondaryValid);
        CHECK(luks->info().supported);
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK(payloadLabel(*payload) == "inside_luks");
    }
    // LUKS1 has no second copy: the read error, not "no LUKS header".
    {
        auto luks = container::Luks::open(std::make_shared<UnreadableHeadDevice>(loadSparseFixture("luks/luks1.sparse"), 4096));
        REQUIRE_FALSE(luks);
        CHECK(luks.error().category() == ErrorCategory::Io);
    }
    // The secondary damaged as well: InvalidFormat naming both copies, the primary's reason being the read error.
    {
        auto mem = loadSparseFixture("luks/luks2.sparse");
        REQUIRE(mem->writeAt(16384 + kLuks2Binary + 20, stein::test::bytesOf("garbage")));
        auto luks = container::Luks::open(std::make_shared<UnreadableHeadDevice>(mem, 4096));
        REQUIRE_FALSE(luks);
        CHECK(luks.error().category() == ErrorCategory::InvalidFormat);
        CHECK_MESSAGE(luks.error().message().find("primary copy unreadable sector at 0") != std::string::npos, luks.error().message());
        CHECK_MESSAGE(luks.error().message().find("secondary copy") != std::string::npos, luks.error().message());
        // And the secondary gone: nothing found anywhere, so the I/O error is the news.
        REQUIRE(mem->writeAt(16384, std::vector<std::byte>(kLuks2Binary)));
        auto none = container::Luks::open(std::make_shared<UnreadableHeadDevice>(mem, 4096));
        REQUIRE_FALSE(none);
        CHECK(none.error().category() == ErrorCategory::Io);
    }
}

TEST_CASE("luks2: iv_tweak counts 512-byte sectors whatever the segment's sector size (dm-crypt's iv_offset): 40 is five 4096-byte sectors, or forty 512-byte ones") {
    // The payload re-encrypted the way dm-crypt would read it with iv_offset 40 and the header's iv_tweak set to match: the volume must read as before.
    for (const char* name : {"luks2_pbkdf2", "luks2"}) {   // 4096- and 512-byte sectors
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto original = container::Luks::open(dev);
        REQUIRE(original);
        const container::LuksInfo info = original->info();
        const auto masterKey = oracleMasterKey(fixture);
        auto xts = crypto::Xts::create(crypto::CipherAlgorithm::Aes, masterKey);
        REQUIRE(xts);
        const std::uint64_t tweak512 = 40;
        const std::uint64_t tweakSectors = tweak512 * 512 / info.sectorSize;   // 5 or 40
        auto cipher = readAll(*dev, info.payloadOffset, info.payloadSize);
        std::vector<std::byte> plain(cipher.size()), shifted(cipher.size());
        REQUIRE(xts->decryptSectors(0, info.sectorSize, cipher, plain));
        REQUIRE(xts->encryptSectors(tweakSectors, info.sectorSize, plain, shifted));
        CHECK(shifted != cipher);
        REQUIRE(dev->writeAt(info.payloadOffset, shifted));
        rewriteLuks2Json(*dev, replaceText("\"iv_tweak\":\"0\"", "\"iv_tweak\":\"40\""));
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().ivTweak == 40);   // as stored
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK(payloadLabel(*payload) == "inside_luks");
        CHECK(readAll(**payload, 0, info.payloadSize) == plain);
        // The same bytes through a bare view whose tweak is in the device's own sectors.
        auto bareXts2 = crypto::Xts::create(crypto::CipherAlgorithm::Aes, masterKey);
        REQUIRE(bareXts2);
        auto bare = std::make_shared<container::detail::XtsDevice>(dev, Region{info.payloadOffset, info.payloadSize}, info.sectorSize, tweakSectors, std::move(*bareXts2), true, "bare");
        CHECK(readAll(*bare, 0, info.payloadSize) == plain);
        // Before the fix 40 was added in sectors of the segment's size: on 4096-byte sectors that is 32 KiB off, garbage.
        if (info.sectorSize != 512) {
            auto wrongXts = crypto::Xts::create(crypto::CipherAlgorithm::Aes, masterKey);
            REQUIRE(wrongXts);
            auto wrong = std::make_shared<container::detail::XtsDevice>(dev, Region{info.payloadOffset, info.payloadSize}, info.sectorSize, tweak512, std::move(*wrongXts), true, "wrong");
            CHECK(readAll(*wrong, 0, info.payloadSize) != plain);
        }
    }
}

TEST_CASE("luks1: the payload is whole sectors even when the device is not: a trailing partial sector is left out, on the header's device and on a detached data device") {
    using Phdr = layout::gen::Luks1Phdr;
    auto whole = loadSparseFixture("luks/luks1.sparse");
    REQUIRE(whole);
    const ByteCount payloadOffset = 4096 * 512;
    // 100 bytes past the last whole sector. Before the fix payloadSize kept them and the last sector could not be read.
    std::vector<std::byte> odd(whole->bytes().begin(), whole->bytes().end());
    odd.resize(odd.size() + 100);
    auto dev = std::make_shared<MemoryDevice>(odd);
    REQUIRE(dev->size() % 512 == 100);
    auto luks = container::Luks::open(dev);
    REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
    CHECK(luks->info().payloadSize == whole->size() - payloadOffset);
    CHECK(luks->info().payloadSize % 512 == 0);
    auto payload = luks->openPayload(kLuksPassphrase, true);
    REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
    CHECK((*payload)->size() == luks->info().payloadSize);
    REQUIRE((*payload)->read((*payload)->size() - 512, 512));
    CHECK(payloadLabel(*payload) == "inside_luks");
    // Detached: the header with payload_offset 0, the data device 100 bytes longer than its sectors.
    std::vector<std::byte> hdrBytes(whole->bytes().begin(), whole->bytes().begin() + static_cast<std::ptrdiff_t>(payloadOffset));
    storeBe32(hdrBytes.data() + Phdr::kPayloadOffsetOffset, 0);
    auto header = std::make_shared<MemoryDevice>(hdrBytes);
    std::vector<std::byte> dataBytes(whole->bytes().begin() + static_cast<std::ptrdiff_t>(payloadOffset), whole->bytes().end());
    dataBytes.resize(dataBytes.size() + 100);
    auto data = std::make_shared<MemoryDevice>(dataBytes);
    auto detached = container::Luks::open(header, data);
    REQUIRE_MESSAGE(detached, (detached ? std::string() : detached.error().toString()));
    CHECK_FALSE(detached->info().headerOnly);
    CHECK(detached->info().payloadSize == data->size() - 100);
    auto p2 = detached->openPayload(kLuksPassphrase, true);
    REQUIRE_MESSAGE(p2, (p2 ? std::string() : p2.error().toString()));
    REQUIRE((*p2)->read((*p2)->size() - 512, 512));
    CHECK(payloadLabel(*p2) == "inside_luks");
}

TEST_CASE("secureZero zeroes a buffer and is not elided; WipeOnExit and WipeBytesOnExit wipe when their scope ends, however it ends") {
    std::vector<std::uint8_t> buf(4096, 0xA5);
    secureZero(buf.data(), buf.size());
    // Read back through a volatile view, so the check itself cannot be folded away either.
    volatile const std::uint8_t* v = buf.data();
    std::uint32_t acc = 0;
    for (std::size_t i = 0; i < buf.size(); ++i) acc |= v[i];
    CHECK(acc == 0);
    secureZero(nullptr, 0);
    secureZero(buf.data(), 0);
    std::vector<std::uint8_t> key(64, 0x5C);
    {
        WipeOnExit guard(key);
        CHECK(key[0] == 0x5C);
    }
    CHECK(allZero(key));
    CHECK(key.size() == 64);
    std::array<std::byte, 32> arr;
    arr.fill(std::byte{0xFF});
    { WipeOnExit guard(arr); }
    CHECK(std::all_of(arr.begin(), arr.end(), [](std::byte b) { return b == std::byte{0}; }));
    std::uint64_t words[16];
    std::fill(std::begin(words), std::end(words), 0x1111111111111111ull);
    { WipeBytesOnExit guard(words, sizeof words); }
    CHECK(std::all_of(std::begin(words), std::end(words), [](std::uint64_t w) { return w == 0; }));
    // A vector that grew under the guard: the buffer it holds at the end is the one wiped.
    std::vector<std::uint8_t> grown;
    {
        WipeOnExit guard(grown);
        grown.assign(1000, 0x77);
    }
    CHECK(allZero(grown));
    // An early return still wipes.
    std::vector<std::uint8_t> early(16, 0x42);
    [&]() -> int {
        WipeOnExit guard(early);
        if (early[0] == 0x42) return 1;
        return 0;
    }();
    CHECK(allZero(early));
}

TEST_CASE("luks end to end: each fixture opens, refuses a wrong passphrase, unlocks, and its payload is the ext2 'inside_luks' whose root directory a Reader lists") {
    for (const char* name : kLuksFixtures) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto o = oracle(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        const auto& info = luks->info();
        CHECK(info.supported);
        CHECK(info.unsupportedWhy.empty());
        CHECK(info.version == (fixture.rfind("luks1", 0) == 0 ? 1 : 2));
        CHECK(info.payloadOffset == std::stoull(o["payload_offset"]));
        CHECK(info.payloadSize == dev->size() - info.payloadOffset);
        CHECK(info.payloadSize >= std::stoull(o["plain_size"]));
        // A wrong passphrase is Integrity (every usable slot was tried, none opened), never
        // Unsupported or a crash: one character off, empty, and the passphrase with a trailing newline
        // as a key file made by `echo` would carry it.
        for (const char* wrong : {"luks test passphrasE", "", "luks test passphrase\n"}) {
            CAPTURE(wrong);
            auto r = luks->unlock(wrong);
            REQUIRE_FALSE(r);
            CHECK(r.error().category() == ErrorCategory::Integrity);
        }
        auto key = luks->unlock(kLuksPassphrase);
        REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
        CHECK(key->size() == info.keyBytes);
        CHECK(Hasher::hex(*key) == o["master_key"]);
        // The read-only payload is the decrypting device behind a read cache; both report the
        // segment's geometry.
        auto payload = luks->openPayload(kLuksPassphrase, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK((*payload)->isReadOnly());
        CHECK((*payload)->size() == info.payloadSize);
        CHECK((*payload)->sectorSize() == info.sectorSize);
        auto cached = std::dynamic_pointer_cast<CachedDevice>(*payload);
        REQUIRE(cached);
        REQUIRE(cached->parent());
        CHECK(cached->parent()->name().find("(luks)") != std::string::npos);
        CHECK(cached->parent()->parent() == dev);
        // The filesystem inside, as the fixture script made it: mkfs.ext2 -b 1024 -L inside_luks on 256 KiB.
        auto probed = fs::probe(*payload);
        REQUIRE_MESSAGE(probed, (probed ? std::string() : probed.error().toString()));
        REQUIRE(*probed);
        CHECK((*probed)->type() == fs::FsType::Ext2);
        CHECK((*probed)->info().label == o["label"]);
        REQUIRE((*probed)->info().blockSize);
        CHECK(*(*probed)->info().blockSize == 1024);
        REQUIRE((*probed)->info().totalBytes);
        CHECK(*(*probed)->info().totalBytes == std::stoull(o["plain_size"]));
        CHECK(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        CHECK(root->id == 2);
        auto entries = (*reader)->readdir(*root);
        REQUIRE_MESSAGE(entries, (entries ? std::string() : entries.error().toString()));
        std::vector<std::string> names;
        for (const auto& e : *entries) {
            names.push_back(e.name);
            auto st = (*reader)->stat(e.inode);
            REQUIRE_MESSAGE(st, e.name);
            CHECK(st->type != fs::FileType::Unknown);
        }
        CHECK(std::find(names.begin(), names.end(), "lost+found") != names.end());
        CHECK(names.size() == 1);   // a fresh mkfs.ext2: lost+found and nothing else
        auto lf = (*reader)->lookup(*root, "lost+found");
        REQUIRE(lf);
        CHECK(lf->id == 11);   // the first non-reserved inode, where mke2fs always puts it
        CHECK(fs::resolvePath(**reader, "/lost+found").value() == *lf);
        auto st = (*reader)->stat(*lf);
        REQUIRE(st);
        CHECK(st->type == fs::FileType::Directory);
        CHECK((st->mode & 0777) == 0700);
        CHECK(st->nlink == 2);
        CHECK(st->size >= 12 * 1024);   // mke2fs preallocates lost+found 12 blocks, so fsck can link into it
        auto inside = (*reader)->readdir(*lf);
        REQUIRE(inside);
        CHECK(inside->empty());
        CHECK((*reader)->lookup(*root, "nothing-here").error().category() == ErrorCategory::NotFound);
        // The walk above read the superblock, the group descriptors and the inode table more than
        // once: the cache saw it and decrypted them once.
        const auto stats = cached->stats();
        CHECK(stats.misses >= 1);
        CHECK(stats.hits > stats.misses);
        CHECK(stats.chunks >= 1);
        CHECK(stats.cachedBytes <= cached->options().budget);
    }
}

TEST_CASE("luks2_pbkdf2 (4096-byte sectors): bytes past the first sector, the inode table and lost+found, decrypt the same by passphrase and by the oracle's master key, and parse") {
    const std::string fixture = "luks2_pbkdf2";
    auto o = oracle(fixture);
    auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
    REQUIRE(dev);
    auto luks = container::Luks::open(dev);
    REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
    const auto& info = luks->info();
    REQUIRE(info.sectorSize == 4096);
    CHECK(info.slots[0].kdf == "pbkdf2");
    const ByteCount plainSize = std::stoull(o["plain_size"]);
    // Three views of the same payload: by passphrase (cached), by the master key cryptsetup dumped
    // (cached), and the bare decrypting device under them.
    auto byPassphrase = luks->openPayload(kLuksPassphrase, true);
    REQUIRE_MESSAGE(byPassphrase, (byPassphrase ? std::string() : byPassphrase.error().toString()));
    const auto masterKey = oracleMasterKey(fixture);
    auto byKey = luks->openPayload(masterKey, true);
    REQUIRE_MESSAGE(byKey, (byKey ? std::string() : byKey.error().toString()));
    auto bare = bareXts(dev, info, masterKey);
    const auto plainA = readAll(**byPassphrase, 0, plainSize);
    const auto plainB = readAll(**byKey, 0, plainSize);
    const auto plainC = readAll(*bare, 0, plainSize);
    CHECK(plainA == plainB);
    CHECK(plainA == plainC);
    // Past the first 4 KiB sector the plaintext is a mostly empty filesystem: bitmaps, eleven inodes
    // and two directory blocks, around a thousand non-zero bytes in 252 KiB. XTS with a 4096-byte
    // sector uses one tweak per 4 KiB, so a 512-byte-sector mistake would still decrypt sector 0
    // right and turn everything after it into noise that is non-zero in 255 of 256 bytes.
    const auto beyond = std::span<const std::byte>(plainA).subspan(4096);
    const auto nonZero = static_cast<std::size_t>(std::count_if(beyond.begin(), beyond.end(), [](std::byte b) { return b != std::byte{0}; }));
    CHECK(nonZero > 512);
    CHECK(nonZero < beyond.size() / 8);
    // Unaligned windows straddling sector boundaries come out of the cached device as from the whole read.
    const std::pair<ByteCount, ByteCount> windows[] = {{4000, 4200}, {8191, 2}, {12288 - 1, 4098}, {plainSize - 4097, 4097}};
    for (const auto& [off, len] : windows) {
        CAPTURE(off);
        CAPTURE(len);
        const auto window = readAll(**byPassphrase, off, len);
        CHECK(std::equal(window.begin(), window.end(), plainA.begin() + static_cast<std::ptrdiff_t>(off)));
        const auto bareWindow = readAll(*bare, off, len);
        CHECK(window == bareWindow);
    }
    // Walk the ext2 on-disk structures by hand from the decrypted bytes: superblock -> group
    // descriptor -> inode table -> the root and lost+found inodes -> lost+found's first directory
    // block. Every step lands past the first sector.
    layout::gen::ExtSuperblock sb(std::span<const std::byte>(plainA).subspan(1024, layout::gen::ExtSuperblock::kSize));
    REQUIRE(sb.magic() == 0xEF53);
    const ByteCount blockSize = ByteCount{1024} << sb.logBlockSize();
    CHECK(blockSize == 1024);
    const std::uint32_t inodeSize = sb.revLevel() >= 1 ? sb.inodeSize() : 128;
    REQUIRE(inodeSize >= 128);
    const ByteCount groupDescriptors = (ByteCount{sb.firstDataBlock()} + 1) * blockSize;
    const ByteCount inodeTable = ByteCount{loadLe32(plainA.data() + groupDescriptors + 8)} * blockSize;   // bg_inode_table
    REQUIRE(inodeTable >= 4096);
    REQUIRE(inodeTable + ByteCount{11} * inodeSize <= plainSize);
    auto inodeAt = [&](std::uint32_t number) { return std::span<const std::byte>(plainA).subspan(static_cast<std::size_t>(inodeTable + (number - 1) * inodeSize), inodeSize); };
    const auto rootInode = inodeAt(2), lostFoundInode = inodeAt(11);
    CHECK((loadLe16(rootInode.data()) & 0xF000) == 0x4000);        // i_mode: directory
    CHECK((loadLe16(lostFoundInode.data()) & 0xF000) == 0x4000);
    CHECK((loadLe16(lostFoundInode.data()) & 0777) == 0700);
    CHECK(loadLe16(lostFoundInode.data() + 26) == 2);              // i_links_count
    const ByteCount lostFoundBlock = ByteCount{loadLe32(lostFoundInode.data() + 40)} * blockSize;   // i_block[0]
    REQUIRE(lostFoundBlock > inodeTable);
    REQUIRE(lostFoundBlock + blockSize <= plainSize);
    const std::byte* dirent = plainA.data() + lostFoundBlock;
    CHECK(loadLe32(dirent) == 11);                                 // "." points at itself
    CHECK(dirent[6] == std::byte{1});                              // name_len
    CHECK(dirent[8] == std::byte{'.'});
    const std::uint16_t recLen = loadLe16(dirent + 4);
    REQUIRE(recLen >= 12);
    CHECK(loadLe32(dirent + recLen) == 2);                         // ".." is the root
    // The Reader, fed from the cached payload, agrees with the hand parse.
    auto probed = fs::probe(*byPassphrase);
    REQUIRE(probed);
    REQUIRE(*probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    auto lf = (*reader)->lookup((*reader)->root().value(), "lost+found");
    REQUIRE(lf);
    CHECK(lf->id == 11);
    auto st = (*reader)->stat(*lf);
    REQUIRE(st);
    CHECK(st->mode == static_cast<std::uint32_t>(loadLe16(lostFoundInode.data()) & 07777));
    CHECK(st->nlink == 2);
    // Tampering with one ciphertext sector past the first changes exactly that sector's plaintext
    // (XTS: no chaining), and the cache in front does not hide the change once told.
    {
        auto rw = luks->openPayload(masterKey, false);
        REQUIRE(rw);
        CHECK_FALSE(std::dynamic_pointer_cast<CachedDevice>(*rw));   // writable payloads stay uncached
        std::vector<std::byte> flipped(dev->bytes().begin() + static_cast<std::ptrdiff_t>(info.payloadOffset + inodeTable), dev->bytes().begin() + static_cast<std::ptrdiff_t>(info.payloadOffset + inodeTable + 16));
        flipped[0] ^= std::byte{0x80};
        REQUIRE(dev->writeAt(info.payloadOffset + inodeTable, flipped));
        const auto after = readAll(*bare, 0, plainSize);
        const ByteCount sector = inodeTable / 4096 * 4096;
        CHECK(std::equal(after.begin(), after.begin() + static_cast<std::ptrdiff_t>(sector), plainA.begin()));
        CHECK_FALSE(std::equal(after.begin() + static_cast<std::ptrdiff_t>(sector), after.begin() + static_cast<std::ptrdiff_t>(sector + 4096), plainA.begin() + static_cast<std::ptrdiff_t>(sector)));
        CHECK(std::equal(after.begin() + static_cast<std::ptrdiff_t>(sector + 4096), after.end(), plainA.begin() + static_cast<std::ptrdiff_t>(sector + 4096)));
        auto cached = std::dynamic_pointer_cast<CachedDevice>(*byPassphrase);
        REQUIRE(cached);
        cached->invalidate();
        CHECK(readAll(**byPassphrase, 0, plainSize) == after);
    }
}

TEST_CASE("luks: the read cache above the payload returns what a bare XtsDevice decrypts, for 1000 random (offset, length) pairs per fixture, and with 4 KiB chunks that evict") {
    for (const char* name : kLuksFixtures) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        const auto& info = luks->info();
        const auto masterKey = oracleMasterKey(fixture);
        auto payload = luks->openPayload(kLuksPassphrase, true);   // as the app and the mount get it
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        auto cached = std::dynamic_pointer_cast<CachedDevice>(*payload);
        REQUIRE(cached);
        auto bare = bareXts(dev, info, masterKey);
        // A second cache with chunks of one 4 KiB sector and room for four: every read of more than
        // 16 KiB evicts, and most windows cross chunk boundaries.
        auto small = CachedDevice::create(bareXts(dev, info, masterKey), CachedDevice::Options{4096, 16 * KiB});
        REQUIRE(small);
        CHECK(small->options().chunkSize == 4096);
        CHECK(small->options().budget == 16 * KiB);
        std::mt19937_64 rng(0x5EED0000u + static_cast<unsigned>(fixture.size()) * 0x101u + static_cast<unsigned>(fixture.back()));
        const ByteCount plainSize = std::stoull(oracle(fixture)["plain_size"]);
        int mismatches = 0, failures = 0;
        std::string first;
        std::vector<std::byte> a, b, c;
        for (int i = 0; i < 1000; ++i) {
            // Lengths up to 64 KiB; two thirds of the offsets inside the filesystem plus the sector
            // after it (where the data is), the rest anywhere in the payload (encrypted zeros).
            const ByteCount len = 1 + rng() % (64 * KiB);
            const ByteCount span = i % 3 == 2 ? info.payloadSize : std::min<ByteCount>(info.payloadSize, plainSize + info.sectorSize);
            const ByteCount off = rng() % std::max<ByteCount>(1, span - std::min(len, span));
            const ByteCount n = std::min(len, info.payloadSize - off);
            a.resize(static_cast<std::size_t>(n));
            b.resize(static_cast<std::size_t>(n));
            c.resize(static_cast<std::size_t>(n));
            auto ra = (*payload)->readAt(off, a), rb = bare->readAt(off, b), rc = small->readAt(off, c);
            if (!ra || !rb || !rc) {
                ++failures;
                if (first.empty()) first = "read " + std::to_string(off) + "+" + std::to_string(n) + ": " + (!ra ? ra.error().toString() : !rb ? rb.error().toString() : rc.error().toString());
                continue;
            }
            if (a != b || c != b) {
                ++mismatches;
                if (first.empty()) first = "offset " + std::to_string(off) + " length " + std::to_string(n) + (a != b ? " (openPayload cache)" : " (4 KiB cache)");
            }
        }
        CHECK_MESSAGE(failures == 0, first);
        CHECK_MESSAGE(mismatches == 0, first);
        const auto big = cached->stats(), tiny = small->stats();
        CHECK(big.hits + big.misses >= 1000);
        CHECK(big.hits > big.misses);
        CHECK(big.cachedBytes <= cached->options().budget);
        CHECK(tiny.evictions > 0);
        CHECK(tiny.cachedBytes <= 16 * KiB);
        CHECK(tiny.chunks <= 4);
        MESSAGE(fixture << ": openPayload cache " << big.hits << " hits / " << big.misses << " misses, " << big.chunks << " chunks; 4 KiB cache " << tiny.hits << " hits / " << tiny.misses << " misses, " << tiny.evictions << " evictions");
    }
}

TEST_CASE("luks: unlock time per fixture, right and wrong passphrase (what the user waits for after typing)") {
    // Not a benchmark: the numbers go to the log so a KDF regression is visible, and a bound far
    // above the measured cost catches a pathological one. Debug builds included.
    std::string line;
    for (const char* name : kLuksFixtures) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto luks = container::Luks::open(loadSparseFixture("luks/" + fixture + ".sparse"));
        REQUIRE(luks);
        auto time = [&](const char* passphrase, bool expectOk) {
            double best = 1e9;
            for (int i = 0; i < 3; ++i) {
                const auto start = std::chrono::steady_clock::now();
                auto key = luks->unlock(passphrase);
                best = std::min(best, std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
                CHECK(key.has_value() == expectOk);
            }
            return best;
        };
        const double ok = time(kLuksPassphrase, true), wrong = time("not it", false);
        CHECK(ok < 20000);
        CHECK(wrong < 20000);
        char buf[160];
        std::snprintf(buf, sizeof buf, "%s%s (%s %s): %.1f ms, wrong passphrase %.1f ms", line.empty() ? "" : "; ", fixture.c_str(), luks->info().slots[0].kdf.c_str(), luks->info().slots[0].kdfDetail.c_str(), ok, wrong);
        line += buf;
    }
    MESSAGE("unlock, best of 3: " << line);
}

// ---------------------------------------------------------------------------------------------
// What real disks look like: fixtures made with cryptsetup 2.8.4 on Ubuntu 26.04 (2026-10-22),
// each with its luksDump beside it (.dump.txt) and an oracle (.oracle.txt: passphrases, master
// key, format options, what the payload holds). cryptsetup's defaults (argon2id t=10 m=1 GiB
// p=4, a 512-bit key, 4096-byte sectors) with a second slot carrying a luks2-keyring token;
// serpent; a 256-bit key; a detached header; a label; LUKS1 with ripemd160 and with a
// 17.5M-iteration slot; and cbc-essiv, which must be refused. An Argon2id slot at 1 GiB and the
// LUKS1 slot each cost seconds, so one real unlock (luks2_real, slot 0) stays in the always-on
// suite and the other passphrase unlocks run with STEIN_SLOW_TESTS=1 like the default-PIM
// VeraCrypt volume; everything about the payloads goes through the oracle's master key (the
// digest check, no KDF) and runs always.
#include <set>

namespace {
constexpr const char* kSecondPassphrase = "second slot passphrase";
bool slowTests() { return std::getenv("STEIN_SLOW_TESTS") != nullptr; }

// ext4_small.oracle.txt is `sha256sum` output: "<hex>  <path>" per line.
std::map<std::string, std::string> ext4SmallOracle() {
    std::map<std::string, std::string> m;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/luks/ext4_small.oracle.txt");
    std::string line;
    while (std::getline(in, line))
        if (auto sep = line.find("  "); sep != std::string::npos) m[line.substr(sep + 2)] = line.substr(0, sep);
    REQUIRE(m.size() == 6);
    return m;
}
std::string sha256Hex(std::span<const std::byte> bytes) { return Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, bytes)); }

// The ext4 'small_luks' the cryptsetup payloads hold, read through a Reader and checked file by
// file against ext4_small.oracle.txt. Returns the bytes read, so a caller can say it was not empty.
std::uint64_t checkSmallLuksPayload(std::shared_ptr<BlockDevice> payload) {
    auto probed = fs::probe(std::move(payload));
    REQUIRE_MESSAGE(probed, (probed ? std::string() : probed.error().toString()));
    REQUIRE(*probed);
    CHECK((*probed)->type() == fs::FsType::Ext4);
    CHECK((*probed)->info().label == "small_luks");
    REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
    auto reader = (*probed)->openReader();
    REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
    auto root = (*reader)->root();
    REQUIRE(root);
    auto entries = (*reader)->readdir(*root);
    REQUIRE_MESSAGE(entries, (entries ? std::string() : entries.error().toString()));
    std::set<std::string> names;
    for (const auto& e : *entries) names.insert(e.name);
    CHECK(names == std::set<std::string>{"big.bin", "dir", "hello.txt", "lost+found"});
    std::uint64_t total = 0;
    for (const auto& [path, sha] : ext4SmallOracle()) {
        CAPTURE(path);
        auto inode = fs::resolvePath(**reader, path);
        REQUIRE_MESSAGE(inode, (inode ? std::string() : inode.error().toString()));
        auto st = (*reader)->stat(*inode);
        REQUIRE(st);
        CHECK(st->type == fs::FileType::File);
        auto bytes = fs::readAll(**reader, *inode);
        REQUIRE_MESSAGE(bytes, (bytes ? std::string() : bytes.error().toString()));
        CHECK(bytes->size() == st->size);
        CHECK(sha256Hex(*bytes) == sha);
        total += bytes->size();
    }
    CHECK(total > 0);
    return total;
}

// luksDump, transcribed: what info() must read back from each header.
struct RealFixture {
    const char* name;
    int version;
    const char* cipher;
    const char* mode;
    const char* hash;          // LUKS1 header hash / LUKS2 digest hash
    std::uint32_t keyBytes;
    std::uint32_t sectorSize;
    ByteCount payloadOffset;   // on the device it was formatted on; 0 for the detached header
    const char* uuid;
    const char* label;
    const char* kdf;           // slot 0
    const char* kdfDetail;
    bool supported;
};
const RealFixture kRealFixtures[] = {
    {"luks2_real", 2, "aes", "xts-plain64", "sha256", 64, 4096, 2 * MiB, "9e98058a-b62a-40dd-9c42-1e2bb8e021c4", "", "argon2id", "t=10 m=1048576KiB p=4", true},
    {"luks2_serpent", 2, "serpent", "xts-plain64", "sha256", 64, 4096, 2 * MiB, "b5c9fda8-5a7b-41da-85a8-ea687ae0a2d9", "", "argon2id", "t=10 m=1048576KiB p=4", true},
    {"luks2_aes128", 2, "aes", "xts-plain64", "sha256", 32, 4096, 2 * MiB, "ba0bf9bf-dd40-4787-a023-1a60f61ee529", "", "argon2id", "t=10 m=1048576KiB p=4", true},
    {"luks2_detached_header", 2, "aes", "xts-plain64", "sha256", 64, 4096, 0, "34a5bc01-8f8f-46af-b43e-5cec3c915692", "", "argon2id", "t=9 m=1048576KiB p=4", true},
    {"luks2_label", 2, "aes", "xts-plain64", "sha256", 64, 4096, 2 * MiB, "44043269-2435-40c7-ad01-da527193ddb4", "STEIN_LUKS", "argon2id", "t=10 m=1048576KiB p=4", true},
    {"luks1_aes128", 1, "aes", "xts-plain64", "sha256", 32, 512, 2 * MiB, "f414f6e3-4639-4fb1-a5cb-3ddacdfd1d10", "", "pbkdf2", "sha256 17549388 iterations", true},
    {"luks1_ripemd160", 1, "aes", "xts-plain64", "ripemd160", 64, 512, 2 * MiB, "7f777410-b353-4a39-bf3b-5b4fac1e4f99", "", "pbkdf2", "ripemd160 747914 iterations", true},
    {"luks1_cbc_essiv", 1, "aes", "cbc-essiv:sha256", "sha256", 32, 512, 2 * MiB, "dfdf3c6c-3e47-4660-bfe7-349ba5285537", "", "pbkdf2", "sha256 17458080 iterations", false},
};

double millisecondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}
} // namespace

TEST_CASE("luks (cryptsetup 2.8.4 fixtures): info() reads what luksDump prints: version, cipher, key size, sector size, label, uuid, the slots and their KDFs, the token on slot 1, both header copies valid; cbc-essiv is refused by name") {
    for (const auto& f : kRealFixtures) {
        const std::string fixture = f.name;
        CAPTURE(fixture);
        auto o = oracle(fixture);
        REQUIRE(o.count("master_key") == 1);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        const auto& info = luks->info();
        CHECK(info.version == f.version);
        CHECK(info.cipher == f.cipher);
        CHECK(info.mode == f.mode);
        CHECK(info.hash == f.hash);
        CHECK(info.keyBytes == f.keyBytes);
        CHECK(o["master_key"].size() == 2 * f.keyBytes);   // the oracle's key is the size the header says
        CHECK(info.sectorSize == f.sectorSize);
        CHECK(info.payloadOffset == f.payloadOffset);
        // Offset 0 on the header's own device is a detached header opened by itself: no payload here.
        CHECK(info.headerOnly == (f.payloadOffset == 0));
        CHECK(info.payloadSize == (f.payloadOffset == 0 ? 0 : dev->size() - f.payloadOffset));
        CHECK(info.uuid == f.uuid);
        CHECK(info.label == f.label);
        CHECK(info.supported == f.supported);
        CHECK(info.flags.empty());
        CHECK(info.requirements.empty());
        // Both copies are intact on a header cryptsetup wrote; the primary is used.
        CHECK(info.headerCopyUsed == 0);
        CHECK(info.primaryValid);
        CHECK(info.secondaryValid);
        CHECK(info.headerSize == (f.version == 2 ? 16384u : 0u));
        REQUIRE_FALSE(info.slots.empty());
        CHECK(info.slots.size() == (f.version == 1 ? 8u : fixture == "luks2_real" ? 2u : 1u));
        CHECK(info.slots[0].id == 0);
        CHECK(info.slots[0].active);
        CHECK(info.slots[0].priority == 1);
        CHECK(info.slots[0].kdf == f.kdf);
        CHECK(info.slots[0].kdfDetail == f.kdfDetail);
        CHECK(info.slots[0].tokens.empty());
        for (std::size_t i = 1; i < info.slots.size(); ++i) {
            CHECK(info.slots[i].id == static_cast<int>(i));
            if (f.version == 1) CHECK_FALSE(info.slots[i].active);   // luksDump: slots 1..7 DISABLED
        }
        if (fixture == "luks2_real") {
            // luksAddKey put the second passphrase in slot 1; the luks2-keyring token names that slot.
            REQUIRE(info.slots.size() == 2);
            CHECK(info.slots[1].active);
            CHECK(info.slots[1].priority == 1);
            CHECK(info.slots[1].kdf == "argon2id");
            CHECK(info.slots[1].kdfDetail == f.kdfDetail);
            CHECK(info.slots[1].tokens == std::vector<std::string>{"luks2-keyring"});
            CHECK(info.slots[1].unsupportedWhy.empty());
        }
        if (f.supported) {
            CHECK(info.unsupportedWhy.empty());
            CHECK(info.slots[0].unsupportedWhy.empty());
        } else {
            // aes-cbc-essiv:sha256: the header parses, the reason names the mode, and nothing
            // runs the 17M-iteration KDF only to produce garbage: unlock and both openPayload
            // overloads refuse up front.
            CHECK_MESSAGE(info.unsupportedWhy.find("cbc-essiv") != std::string::npos, info.unsupportedWhy);
            CHECK(info.slots[0].unsupportedWhy == info.unsupportedWhy);
            const auto start = std::chrono::steady_clock::now();
            auto key = luks->unlock(kLuksPassphrase);
            REQUIRE_FALSE(key);
            CHECK(key.error().category() == ErrorCategory::Unsupported);
            CHECK(key.error().message() == info.unsupportedWhy);
            auto byKey = luks->openPayload(oracleMasterKey(fixture), true);
            REQUIRE_FALSE(byKey);
            CHECK(byKey.error().category() == ErrorCategory::Unsupported);
            auto byPassphrase = luks->openPayload(kLuksPassphrase, true);
            REQUIRE_FALSE(byPassphrase);
            CHECK(byPassphrase.error().category() == ErrorCategory::Unsupported);
            CHECK(millisecondsSince(start) < 1000);   // refused, not derived
        }
    }
}

TEST_CASE("luks (cryptsetup 2.8.4 fixtures): opened with the oracle's master key, the payloads are the ext4 'small_luks' whose files hash as the oracle says, and the read cache above them returns what a bare XtsDevice decrypts for 1000 random windows (aes, serpent, aes-128, the detached pair); header-only fixtures vouch for the key by digest") {
    // Every openPayload(masterKey) runs the digest's PBKDF2 (half a million to a million
    // iterations on these headers), so each payload is opened once and everything is checked on
    // that one device: the files through a Reader, then random windows against a bare XtsDevice
    // over the same bytes (serpent takes the generic XTS path, aes the hardware one).
    auto checkPayload = [](std::shared_ptr<BlockDevice> data, const container::Luks& luks, const std::string& fixture, std::span<const std::uint8_t> masterKey, ByteCount expectSize) {
        auto payload = luks.openPayload(masterKey, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK((*payload)->isReadOnly());
        CHECK((*payload)->sectorSize() == 4096);
        CHECK((*payload)->size() == expectSize);
        auto cached = std::dynamic_pointer_cast<CachedDevice>(*payload);   // read-only: behind the read cache, as the app gets it
        REQUIRE(cached);
        CHECK(cached->parent()->name().find("(luks)") != std::string::npos);
        const auto bytes = checkSmallLuksPayload(*payload);
        const auto& info = luks.info();
        auto bare = bareXts(std::move(data), info, masterKey);
        std::mt19937_64 rng(0xC0FFEE00u + static_cast<unsigned>(fixture.size()) * 0x101u + static_cast<unsigned>(fixture.back()));
        int mismatches = 0, failures = 0;
        std::string first;
        std::vector<std::byte> a, b;
        for (int i = 0; i < 1000; ++i) {
            // Windows up to 64 KiB; two thirds inside the first 2 MiB (the ext4 and the sector after
            // it), the rest anywhere in the payload (encrypted zeros).
            const ByteCount len = 1 + rng() % (64 * KiB);
            const ByteCount span = i % 3 == 2 ? info.payloadSize : std::min<ByteCount>(info.payloadSize, 2 * MiB);
            const ByteCount off = rng() % std::max<ByteCount>(1, span - std::min(len, span));
            const ByteCount n = std::min(len, info.payloadSize - off);
            a.resize(static_cast<std::size_t>(n));
            b.resize(static_cast<std::size_t>(n));
            auto ra = (*payload)->readAt(off, a), rb = bare->readAt(off, b);
            if (!ra || !rb) {
                ++failures;
                if (first.empty()) first = "read " + std::to_string(off) + "+" + std::to_string(n) + ": " + (!ra ? ra.error().toString() : rb.error().toString());
                continue;
            }
            if (a != b) {
                ++mismatches;
                if (first.empty()) first = "offset " + std::to_string(off) + " length " + std::to_string(n);
            }
        }
        CHECK_MESSAGE(failures == 0, first);
        CHECK_MESSAGE(mismatches == 0, first);
        const auto stats = cached->stats();
        CHECK(stats.hits + stats.misses >= 1000);
        CHECK(stats.hits > stats.misses);
        CHECK(stats.cachedBytes <= cached->options().budget);
        MESSAGE(fixture << " (" << info.cipher << "): " << bytes << " bytes of files read back and hashed; cache " << stats.hits << " hits / " << stats.misses << " misses, " << stats.chunks << " chunks over 1000 random windows");
    };
    for (const char* name : {"luks2_real", "luks2_serpent", "luks2_aes128"}) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        const auto masterKey = oracleMasterKey(fixture);
        CHECK(masterKey.size() == luks->info().keyBytes);
        checkPayload(dev, *luks, fixture, masterKey, dev->size() - 2 * MiB);
        if (fixture == "luks2_real") {
            // A key one bit off is refused by the digest before a sector is read; a short one too.
            auto bad = masterKey;
            bad.back() ^= 0x01;
            CHECK(luks->openPayload(bad, true).error().category() == ErrorCategory::Integrity);
            CHECK_FALSE(luks->openPayload(std::span<const std::uint8_t>(masterKey).first(masterKey.size() - 1), true));
        }
    }
    // Detached header (luksFormat --header): the key material in one image, the payload from byte 0
    // of the other, as dm-crypt maps it. The data image alone is not LUKS; the header alone is a
    // header only: the digest still vouches for the key, but there is no payload to decrypt (its
    // own bytes would only make garbage).
    {
        auto header = loadSparseFixture("luks/luks2_detached_header.sparse");
        auto data = loadSparseFixture("luks/luks2_detached_data.sparse");
        REQUIRE(header);
        REQUIRE(data);
        CHECK(container::Luks::open(data).error().category() == ErrorCategory::NotFound);
        auto luks = container::Luks::open(header, data);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().payloadOffset == 0);
        CHECK(luks->info().payloadSize == data->size());
        CHECK(luks->info().sectorSize == 4096);
        CHECK(luks->info().uuid == "34a5bc01-8f8f-46af-b43e-5cec3c915692");
        const auto masterKey = oracleMasterKey("luks2_detached_header");
        checkPayload(data, *luks, "luks2_detached (header + data)", masterKey, data->size());
        auto alone = container::Luks::open(header);
        REQUIRE_MESSAGE(alone, (alone ? std::string() : alone.error().toString()));
        CHECK(alone->info().headerOnly);
        CHECK(alone->info().payloadOffset == 0);
        CHECK(alone->info().payloadSize == 0);
        CHECK(alone->info().supported);
        CHECK_FALSE(luks->info().headerOnly);
        auto own = alone->openPayload(masterKey, true);
        REQUIRE_FALSE(own);
        CHECK(own.error().category() == ErrorCategory::OutOfRange);
        auto bad = masterKey;
        bad[3] ^= 0x10;
        CHECK(alone->openPayload(bad, true).error().category() == ErrorCategory::Integrity);
    }
    // Header-only fixtures (the image cut 64 KiB past the payload offset): the digest vouches for
    // the oracle's key and what little payload there is has the header's sector size. The
    // ripemd160 digest (46217 iterations, cheap) also gets a tampered key.
    for (const char* name : {"luks2_label", "luks1_aes128", "luks1_ripemd160"}) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().payloadSize == 64 * KiB);
        const auto masterKey = oracleMasterKey(fixture);
        CHECK(masterKey.size() == luks->info().keyBytes);
        auto payload = luks->openPayload(masterKey, true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        CHECK((*payload)->size() == 64 * KiB);
        CHECK((*payload)->sectorSize() == luks->info().sectorSize);
        REQUIRE((*payload)->read(0, 64 * KiB));
        if (fixture == "luks1_ripemd160") {
            auto bad = masterKey;
            bad[0] ^= 0x80;
            CHECK(luks->openPayload(bad, true).error().category() == ErrorCategory::Integrity);
        }
    }
}

TEST_CASE("luks (cryptsetup 2.8.4 fixtures): unlock with the passphrase and the time it takes: cryptsetup's default argon2id slot always; cancellation; the second slot, serpent, aes-128, the label, the detached pair and the LUKS1 slots with STEIN_SLOW_TESTS=1") {
    // The numbers go to the log (and the orchestrator's measurements): what a user waits for
    // after typing, slot by slot, in this build. Each unlock is the KDF, the AF merge and the
    // digest check (itself PBKDF2 at half a million to a million iterations on these headers).
    std::string line;
    auto timed = [&](const std::string& what, auto&& fn) {
        const auto start = std::chrono::steady_clock::now();
        auto r = fn();
        const double ms = millisecondsSince(start);
        char buf[64];
        std::snprintf(buf, sizeof buf, ": %.0f ms", ms);
        line += (line.empty() ? "" : "; ") + what + buf;
        return r;
    };
    auto real = container::Luks::open(loadSparseFixture("luks/luks2_real.sparse"));
    REQUIRE(real);
    const auto realOracle = oracle("luks2_real");
    // Slot 0 with the first passphrase: cryptsetup's default slot, argon2id t=10 m=1 GiB p=4 on four lanes.
    auto key = timed("luks2_real slot 0 (" + real->info().slots[0].kdf + " " + real->info().slots[0].kdfDetail + ")", [&] { return real->unlock(kLuksPassphrase); });
    REQUIRE_MESSAGE(key, (key ? std::string() : key.error().toString()));
    CHECK(key->size() == 64);
    CHECK(Hasher::hex(*key) == realOracle.at("master_key"));
    auto payload = real->openPayload(*key, true);
    REQUIRE(payload);
    CHECK(payloadLabel(*payload) == "small_luks");
    // Cancel from the hook: polled before the slot and before every one of the 40 slices, so the
    // derivation stops within one slice, long before the whole thing would have finished.
    {
        container::UnlockOptions opt;
        int polls = 0;
        opt.cancelled = [&] { return ++polls > 3; };
        const auto start = std::chrono::steady_clock::now();
        auto cancelled = real->unlock(kLuksPassphrase, opt);
        const double ms = millisecondsSince(start);
        REQUIRE_FALSE(cancelled);
        CHECK(cancelled.error().category() == ErrorCategory::Cancelled);
        CHECK(polls == 4);
        char buf[64];
        std::snprintf(buf, sizeof buf, "; cancelled after 2 slices: %.0f ms", ms);
        line += buf;
    }
    if (!slowTests()) {
        MESSAGE("set STEIN_SLOW_TESTS=1 to also unlock luks2_real slot 1, luks2_serpent, luks2_aes128, luks2_label, the detached pair and the LUKS1 fixtures with their passphrases (Argon2id at 1 GiB per slot, PBKDF2 at 17.5M iterations for luks1_aes128)");
    } else {
        // The second passphrase opens slot 1 to the same volume key; a wrong one costs both slots.
        auto second = timed("luks2_real slot 1 (second passphrase)", [&] { return real->unlock(kSecondPassphrase); });
        REQUIRE_MESSAGE(second, (second ? std::string() : second.error().toString()));
        CHECK(Hasher::hex(*second) == realOracle.at("master_key"));
        auto wrong = timed("luks2_real wrong passphrase (both slots tried)", [&] { return real->unlock("not it"); });
        REQUIRE_FALSE(wrong);
        CHECK(wrong.error().category() == ErrorCategory::Integrity);
        for (const char* name : {"luks2_serpent", "luks2_aes128", "luks2_label", "luks1_ripemd160", "luks1_aes128"}) {
            const std::string fixture = name;
            CAPTURE(fixture);
            auto luks = container::Luks::open(loadSparseFixture("luks/" + fixture + ".sparse"));
            REQUIRE(luks);
            auto k = timed(fixture + " slot 0 (" + luks->info().slots[0].kdf + " " + luks->info().slots[0].kdfDetail + ")", [&] { return luks->unlock(kLuksPassphrase); });
            REQUIRE_MESSAGE(k, (k ? std::string() : k.error().toString()));
            CHECK(k->size() == luks->info().keyBytes);
            CHECK(Hasher::hex(*k) == oracle(fixture).at("master_key"));
            if (fixture == "luks2_serpent" || fixture == "luks2_aes128") {
                auto p = luks->openPayload(*k, true);
                REQUIRE(p);
                CHECK(payloadLabel(*p) == "small_luks");
            }
        }
        // The detached pair through the convenience overload: unlock + openPayload by passphrase.
        auto detached = container::Luks::open(loadSparseFixture("luks/luks2_detached_header.sparse"), loadSparseFixture("luks/luks2_detached_data.sparse"));
        REQUIRE(detached);
        auto p = timed("luks2_detached header + data (" + detached->info().slots[0].kdfDetail + ")", [&] { return detached->openPayload(kLuksPassphrase, true); });
        REQUIRE_MESSAGE(p, (p ? std::string() : p.error().toString()));
        CHECK(payloadLabel(*p) == "small_luks");
    }
    MESSAGE("unlock, cryptsetup 2.8.4 fixtures: " << line);
}
