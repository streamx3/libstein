// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/block/cached_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/container/luks.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/json.hpp"
#include "stein/layout/gen/luks.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include "stein/probe/topology.hpp"

using namespace stein;
using stein::test::loadSparseFixture;

namespace {
// Build a disk: GPT fixture with a FAT12 filesystem copied into partition 1 and ext2 into partition 2.
std::shared_ptr<MemoryDevice> composite() {
    auto disk = loadSparseFixture("pt/gpt_basic.sparse");
    auto fat = loadSparseFixture("fs/fat12.sparse");    // 4 MiB fits partition 1 (2 MiB)? no: use only metadata bytes
    auto ext2 = loadSparseFixture("fs/ext2.sparse");    // 16 MiB; partition 2 is 4 MiB -> copy first 1 MiB (superblock + gdt)
    // Partition 1: 2048..6143 (2 MiB). FAT12 image is 4 MiB; copy its first 64 KiB (boot sector, FATs, root dir).
    auto p1 = disk->read(2048 * 512, 512);
    std::copy_n(fat->bytes().begin(), 64 * 1024, disk->bytes().begin() + 2048 * 512);
    // Partition 2: 6144..14335 (4 MiB). Copy the ext2 superblock region (first 64 KiB).
    std::copy_n(ext2->bytes().begin(), 64 * 1024, disk->bytes().begin() + 6144 * 512);
    return disk;
}
} // namespace

TEST_CASE("probe: GPT disk with filesystems in partitions") {
    auto disk = composite();
    auto tree = probe::probe(disk);
    REQUIRE(tree);
    CHECK(tree->kind == probe::NodeKind::Device);
    REQUIRE(tree->table);
    CHECK(tree->table->type() == pt::TableType::Gpt);
    // children: p1, p2, p3 (the 1007 KiB alignment gap before p1 is below the 1 MiB display threshold)
    REQUIRE(tree->children.size() == 3);
    const auto& p1 = tree->children[0];
    CHECK(p1.kind == probe::NodeKind::Partition);
    CHECK(p1.partition->index == 1);
    REQUIRE(p1.content);
    CHECK(p1.content->type() == fs::FsType::Fat12);
    CHECK(p1.content->info().label == "STEIN_FAT12");
    CHECK(p1.region.offset == 2048 * 512);
    const auto& p2 = tree->children[1];
    REQUIRE(p2.content);
    CHECK(p2.content->type() == fs::FsType::Ext2);
    // The ext2 image claims 16 MiB but sits in a 4 MiB partition -> warning.
    bool warned = false;
    for (const auto& n : p2.notes) warned = warned || n.code == "probe.fs_larger_than_region";
    CHECK(warned);
    CHECK(p2.health() == layout::Validity::Warning);
    const auto& p3 = tree->children[2];
    CHECK(!p3.content);
    CHECK(!p3.table);
    auto text = probe::toText(*tree);
    CHECK(text.find("gpt table") != std::string::npos);
    CHECK(text.find("FAT12 \"STEIN_FAT12\"") != std::string::npos);
    CHECK(text.find("[WARN]") != std::string::npos);
}

TEST_CASE("probe: whole-device filesystem and blank device") {
    auto fs = loadSparseFixture("fs/ntfs.sparse");
    auto tree = probe::probe(fs);
    REQUIRE(tree);
    CHECK(!tree->table);
    REQUIRE(tree->content);
    CHECK(tree->content->type() == fs::FsType::Ntfs);
    CHECK(tree->children.empty());
    CHECK(probe::toText(*tree).find("NTFS \"STEIN_NTFS\"") != std::string::npos);

    auto blank = std::make_shared<MemoryDevice>(8 * MiB, 512);
    auto t2 = probe::probe(blank);
    REQUIRE(t2);
    CHECK(!t2->table);
    CHECK(!t2->content);
    CHECK(t2->health() == layout::Validity::Ok);
}

TEST_CASE("probe: MBR with extended and logicals, nested table inside a partition") {
    auto disk = loadSparseFixture("pt/mbr_basic.sparse");
    // Put a tiny GPT image inside logical partition 6 (18432.., 8192 sectors = 4 MiB): copy the first 1 MiB of gpt_basic
    // and its backup header cannot fit, so the nested GPT reads degraded; it still proves nesting works.
    auto gpt = loadSparseFixture("pt/gpt_basic.sparse");
    std::copy_n(gpt->bytes().begin(), 1 * MiB, disk->bytes().begin() + 18432 * 512);
    auto tree = probe::probe(disk);
    REQUIRE(tree);
    REQUIRE(tree->table);
    CHECK(tree->table->type() == pt::TableType::Mbr);
    const probe::Node* ext = nullptr;
    const probe::Node* p6 = nullptr;
    for (const auto& c : tree->children) {
        if (c.partition && c.partition->isExtended) ext = &c;
        if (c.partition && c.partition->index == 6) p6 = &c;
    }
    REQUIRE(ext);
    CHECK(ext->children.empty());   // the container itself is not probed for content
    CHECK(!ext->content);
    REQUIRE(p6);
    REQUIRE(p6->table);
    CHECK(p6->table->type() == pt::TableType::Gpt);
    CHECK(p6->table->partitions().size() == 3);
    CHECK(p6->children.size() >= 3);
    CHECK(p6->children[0].region.offset == (18432 + 2048) * 512);   // nested offsets are absolute
    auto text = probe::toText(*tree);
    CHECK(text.find("[extended]") != std::string::npos);
    CHECK(text.find("[logical]") != std::string::npos);
}

TEST_CASE("probe: a LUKS container opens with a passphrase and shows its plaintext content") {
    auto disk = loadSparseFixture("luks/luks2.sparse");
    probe::Options o;
    auto locked = probe::probe(disk, o);
    REQUIRE(locked);
    REQUIRE(locked->content);
    CHECK(locked->content->type() == fs::FsType::Luks2);
    CHECK(locked->children.empty());
    o.passphrases = {"wrong one", "luks test passphrase"};
    auto open = probe::probe(disk, o);
    REQUIRE(open);
    REQUIRE(open->children.size() == 1);
    const auto& d = open->children[0];
    CHECK(d.kind == probe::NodeKind::Decrypted);
    REQUIRE(d.content);
    CHECK(d.content->type() == fs::FsType::Ext2);
    CHECK(d.content->info().label == "inside_luks");
    CHECK(d.region.offset == 1 * MiB);
    auto text = probe::toText(*open);
    CHECK(text.find("decrypted payload") != std::string::npos);
    CHECK(text.find("inside_luks") != std::string::npos);
    o.passphrases = {"nope"};
    auto stillLocked = probe::probe(disk, o);
    REQUIRE(stillLocked);
    CHECK(stillLocked->children.empty());
    bool noted = false;
    for (const auto& n : stillLocked->notes) noted = noted || n.code == "luks.locked";
    CHECK(noted);
}

// What a disk with its first sectors wiped looks like: the LUKS2 secondary copy at 16 KiB is all
// that is left of the header. The detector finds it, the container opens from it, the passphrase
// opens the payload; before the fix the probe showed unknown data.
TEST_CASE("probe: a LUKS2 disk whose first 4 KiB were wiped is recognised from the secondary header copy and still opens with the passphrase") {
    auto disk = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(disk);
    REQUIRE(disk->writeAt(0, std::vector<std::byte>(4096)));
    probe::Options o;
    auto locked = probe::probe(disk, o);
    REQUIRE(locked);
    REQUIRE(locked->content);
    CHECK(locked->content->type() == fs::FsType::Luks2);
    CHECK(locked->children.empty());
    bool noted = false;
    for (const auto& n : locked->notes) noted = noted || (n.code == "luks2.primary_missing" && n.message.find("secondary copy at 16384") != std::string::npos);
    CHECK(noted);
    o.passphrases = {"luks test passphrase"};
    auto open = probe::probe(disk, o);
    REQUIRE(open);
    REQUIRE(open->children.size() == 1);
    const auto& d = open->children[0];
    CHECK(d.kind == probe::NodeKind::Decrypted);
    REQUIRE(d.content);
    CHECK(d.content->type() == fs::FsType::Ext2);
    CHECK(d.content->info().label == "inside_luks");
    CHECK(d.region.offset == 1 * MiB);
}

TEST_CASE("probe: an LVM physical volume lists its logical volumes and probes the ones it can map") {
    auto pv0 = loadSparseFixture("lvm/pv0.sparse");
    auto tree = probe::probe(pv0);
    REQUIRE(tree);
    REQUIRE(tree->content);
    CHECK(tree->content->type() == fs::FsType::Lvm2Pv);
    REQUIRE(tree->children.size() == 4);
    std::map<std::string, const probe::Node*> byName;
    for (const auto& c : tree->children) {
        CHECK(c.kind == probe::NodeKind::Volume);
        byName[c.name] = &c;
    }
    REQUIRE(byName.count("stein_vg/linear"));
    REQUIRE(byName.count("stein_vg/striped"));
    REQUIRE(byName.count("stein_vg/frag"));
    const auto* lin = byName["stein_vg/linear"];
    REQUIRE(lin->content);
    CHECK(lin->content->info().label == "lv_linear");
    const auto* frag = byName["stein_vg/frag"];
    REQUIRE(frag->content);
    CHECK(frag->content->info().label == "lv_frag");
    const auto* st = byName["stein_vg/striped"];
    CHECK_FALSE(st->device);
    bool missing = false;
    for (const auto& n : st->notes) missing = missing || n.code == "lvm.missing_pv";
    CHECK(missing);
    auto text = probe::toText(*tree);
    CHECK(text.find("volume stein_vg/linear") != std::string::npos);
    CHECK(text.find("lv_frag") != std::string::npos);
    CHECK(text.find("not mappable here") != std::string::npos);
    probe::Options o;
    o.volumes = false;
    auto flat = probe::probe(pv0, o);
    REQUIRE(flat);
    CHECK(flat->children.empty());
}

// ---------------------------------------------------------------------------------------------
// LUKS helpers: the oracle file beside each fixture (passphrase, master key, payload offset), and
// LUKS2 header surgery for a variant no fixture has (no cryptsetup here): the JSON of each copy is
// rewritten and its checksum recomputed the way cryptsetup does it, csum_alg over the 4096-byte
// binary header with the csum field zeroed, then the whole JSON area, padding included.
namespace {
std::map<std::string, std::string> oracle(const std::string& name) {
    std::map<std::string, std::string> m;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/luks/" + name + ".oracle.txt");
    std::string line;
    while (std::getline(in, line))
        if (auto eq = line.find('='); eq != std::string::npos) m[line.substr(0, eq)] = line.substr(eq + 1);
    return m;
}
std::vector<std::uint8_t> fromHex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}
using Luks2Hdr = layout::gen::Luks2Hdr;
constexpr ByteCount kLuks2Binary = 4096;
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
void rewriteLuks2Copy(MemoryDevice& dev, ByteCount at, const std::function<void(json::Value&)>& mutate) {
    auto bin = dev.read(at, kLuks2Binary);
    REQUIRE(bin);
    const std::uint64_t hdrSize = loadBe64(bin->data() + Luks2Hdr::kHdrSizeOffset);
    auto j = json::Value::parse(luks2Json(dev, at));
    REQUIRE(j);
    mutate(*j);
    const std::string text = j->dump();
    std::vector<std::byte> area(hdrSize - kLuks2Binary, std::byte{0});
    REQUIRE(text.size() < area.size());
    std::memcpy(area.data(), text.data(), text.size());
    std::fill_n(bin->begin() + Luks2Hdr::kCsumOffset, Luks2Hdr::kCsumSize, std::byte{0});
    auto hasher = Hasher::create(HashAlgorithm::Sha256);   // the fixtures' csum_alg
    hasher->update(*bin);
    hasher->update(area);
    const auto digest = hasher->finish();
    std::memcpy(bin->data() + Luks2Hdr::kCsumOffset, digest.data(), digest.size());
    REQUIRE(dev.writeAt(at, *bin));
    REQUIRE(dev.writeAt(at + kLuks2Binary, area));
}
// Both copies, consistently (what cryptsetup does on every metadata write).
void rewriteLuks2Json(MemoryDevice& dev, const std::function<void(json::Value&)>& mutate) {
    const std::uint64_t hdrSize = luks2HeaderSize(dev, 0);
    rewriteLuks2Copy(dev, 0, mutate);
    rewriteLuks2Copy(dev, hdrSize, mutate);
}
// root[section][id][key] = value, with json::Value's copy-out/copy-in access.
void setNested(json::Value& root, const std::string& section, const std::string& id, const std::string& key, json::Value value) {
    json::Value inner = root.get(section).get(id);
    inner.set(key, std::move(value));
    json::Value outer = root.get(section);
    outer.set(id, std::move(inner));
    root.set(section, std::move(outer));
}
const probe::Note* findNote(const probe::Node& n, std::string_view code) {
    for (const auto& note : n.notes)
        if (note.code == code) return &note;
    return nullptr;
}
bool hasNote(const probe::Node& n, std::string_view code) { return findNote(n, code) != nullptr; }
constexpr const char* kLuksPassphrase = "luks test passphrase";
} // namespace

TEST_CASE("probe: a cached master key opens a LUKS container with no passphrase (LUKS2 and LUKS1); a foreign key is ignored, a stale one falls back to the passphrases") {
    for (const std::string name : {"luks2", "luks1"}) {
        CAPTURE(name);
        auto disk = loadSparseFixture("luks/" + name + ".sparse");
        REQUIRE(disk);
        const auto o = oracle(name);
        auto luks = container::Luks::open(disk);
        REQUIRE(luks);
        const std::string uuid = luks->info().uuid;
        CHECK_FALSE(uuid.empty());
        const auto key = fromHex(o.at("master_key"));
        REQUIRE(key.size() == 64);

        probe::Options opts;
        opts.masterKeys[uuid] = key;
        int unlocked = 0;
        opts.onUnlocked = [&](const std::string&, const std::vector<std::uint8_t>&) { ++unlocked; };
        int polls = 0;
        opts.cancelled = [&] { ++polls; return false; };
        auto tree = probe::probe(disk, opts);
        REQUIRE(tree);
        REQUIRE(tree->children.size() == 1);
        const auto& d = tree->children[0];
        CHECK(d.kind == probe::NodeKind::Decrypted);
        REQUIRE(d.content);
        CHECK(d.content->type() == fs::FsType::Ext2);
        CHECK(d.content->info().label == o.at("label"));
        CHECK(d.region.offset == std::stoull(o.at("payload_offset")));
        CHECK(unlocked == 0);   // the key came from the cache, not from a passphrase
        CHECK(polls == 0);      // no key derivation ran, so there was nothing to cancel
        CHECK_FALSE(hasNote(*tree, "luks.locked"));

        // A key filed under another UUID is not tried; with no passphrase the container stays locked
        // and, nothing having been tried, says nothing.
        probe::Options foreign;
        foreign.masterKeys["00000000-0000-0000-0000-000000000000"] = key;
        auto locked = probe::probe(disk, foreign);
        REQUIRE(locked);
        CHECK(locked->children.empty());
        CHECK_FALSE(hasNote(*locked, "luks.locked"));
        CHECK_FALSE(hasNote(*locked, "luks.unlock"));

        // A stale key (another volume's, or one of the wrong size) is skipped without a note; the
        // passphrase takes over and its unlock is reported.
        const auto other = fromHex(oracle(name == "luks2" ? "luks1" : "luks2").at("master_key"));
        for (const auto& stale : {other, std::vector<std::uint8_t>(32, 0x5a)}) {
            probe::Options fallback;
            fallback.masterKeys[uuid] = stale;
            fallback.passphrases = {kLuksPassphrase};
            int reported = 0;
            fallback.onUnlocked = [&](const std::string& u, const std::vector<std::uint8_t>& k) {
                ++reported;
                CHECK(u == uuid);
                CHECK(k == key);
            };
            auto t2 = probe::probe(disk, fallback);
            REQUIRE(t2);
            REQUIRE(t2->children.size() == 1);
            CHECK(t2->children[0].content);
            CHECK(reported == 1);
            CHECK_FALSE(hasNote(*t2, "luks.unlock"));
            CHECK_FALSE(hasNote(*t2, "luks.locked"));
        }
    }
}

TEST_CASE("probe: onUnlocked reports the UUID and the fixture's master key once per passphrase unlock; the payload is cached above the decryption; no secret reaches a note") {
    auto disk = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(disk);
    const auto o = oracle("luks2");
    probe::Options opts;
    opts.passphrases = {"wrong one", kLuksPassphrase, "never reached"};
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> reports;
    opts.onUnlocked = [&](const std::string& uuid, const std::vector<std::uint8_t>& key) { reports.emplace_back(uuid, key); };
    auto tree = probe::probe(disk, opts);
    REQUIRE(tree);
    REQUIRE(tree->children.size() == 1);
    REQUIRE(reports.size() == 1);
    auto luks = container::Luks::open(disk);
    REQUIRE(luks);
    CHECK(reports[0].first == luks->info().uuid);
    REQUIRE(tree->content);
    CHECK(reports[0].first == tree->content->info().uuid);   // the UUID the filesystem probe shows for the row
    CHECK(reports[0].second == fromHex(o.at("master_key")));
    // What was reported is what the probe takes back: a second probe with the key alone opens it.
    probe::Options again;
    again.masterKeys[reports[0].first] = reports[0].second;
    auto t2 = probe::probe(disk, again);
    REQUIRE(t2);
    REQUIRE(t2->children.size() == 1);
    REQUIRE(t2->children[0].content);
    CHECK(t2->children[0].content->info().label == "inside_luks");

    // Read-only payload: a CachedDevice over the XTS decryption, already warm from the probe's reads;
    // the superblock the probe read comes back as a hit without another decryption.
    auto* cached = dynamic_cast<CachedDevice*>(tree->children[0].device.get());
    REQUIRE(cached);
    const auto before = cached->stats();
    CHECK(before.misses > 0);
    auto superblock = tree->children[0].device->read(1024, 1024);
    REQUIRE(superblock);
    CHECK(cached->stats().hits > before.hits);
    CHECK(cached->stats().misses == before.misses);
    CHECK(tree->children[0].device->isReadOnly());

    // No note anywhere in the tree carries the passphrase or any part of the key.
    std::function<void(const probe::Node&)> scan = [&](const probe::Node& n) {
        for (const auto& note : n.notes) {
            CHECK(note.message.find(kLuksPassphrase) == std::string::npos);
            CHECK(note.message.find(o.at("master_key").substr(0, 16)) == std::string::npos);
        }
        for (const auto& c : n.children) scan(c);
    };
    scan(*tree);
    CHECK(probe::toText(*tree).find(o.at("master_key").substr(0, 16)) == std::string::npos);
}

TEST_CASE("probe: a cancelled job leaves the container locked with no note and no error, and the hook reaches the Argon2 slices") {
    auto disk = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(disk);
    probe::Options opts;
    opts.passphrases = {kLuksPassphrase};
    int polls = 0, unlocked = 0;
    opts.onUnlocked = [&](const std::string&, const std::vector<std::uint8_t>&) { ++unlocked; };

    // Cancelled from the start: the cheap work (header, content type) is done, the KDF never runs,
    // and nothing is said about the passphrase since it was not refuted.
    opts.cancelled = [&] { ++polls; return true; };
    auto tree = probe::probe(disk, opts);
    REQUIRE(tree);
    REQUIRE(tree->content);
    CHECK(tree->content->type() == fs::FsType::Luks2);
    CHECK(tree->children.empty());
    CHECK_FALSE(hasNote(*tree, "luks.locked"));
    CHECK_FALSE(hasNote(*tree, "luks.unlock"));
    CHECK(polls == 1);
    CHECK(unlocked == 0);

    // Cancelled on the third poll: the probe's own, unlock()'s before the slot, then Argon2's before
    // its first slice. Had the KDF not polled, the slot would have opened and a child appeared.
    polls = 0;
    opts.cancelled = [&] { return ++polls >= 3; };
    tree = probe::probe(disk, opts);
    REQUIRE(tree);
    CHECK(tree->children.empty());
    CHECK_FALSE(hasNote(*tree, "luks.locked"));
    CHECK_FALSE(hasNote(*tree, "luks.unlock"));
    CHECK(polls >= 3);
    CHECK(unlocked == 0);

    // Never cancelled: the same options open it, and the hook was polled before each of the
    // fixture's 16 Argon2 slices (t=4 passes of 4 slices) on top of the probe's and unlock()'s polls.
    polls = 0;
    opts.cancelled = [&] { ++polls; return false; };
    tree = probe::probe(disk, opts);
    REQUIRE(tree);
    REQUIRE(tree->children.size() == 1);
    CHECK(tree->children[0].content);
    CHECK(polls >= 2 + 16);
    CHECK(unlocked == 1);
}

TEST_CASE("probe: a container we cannot open (dm-integrity) gets luks.unsupported with the reason and no Decrypted child, passphrases or not; a damaged header is luks.header") {
    auto disk = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(disk);
    rewriteLuks2Json(*disk, [](json::Value& j) {
        json::Value integrity = json::Value::object();
        integrity.set("type", "hmac(sha256)");
        integrity.set("journal_encryption", "none");
        integrity.set("journal_integrity", "none");
        setNested(j, "segments", "0", "integrity", integrity);
    });
    auto luks = container::Luks::open(disk);
    REQUIRE(luks);
    REQUIRE_FALSE(luks->info().supported);

    // No passphrase: the verdict is there anyway, so a UI can hide its Unlock action up front.
    probe::Options none;
    auto tree = probe::probe(disk, none);
    REQUIRE(tree);
    REQUIRE(tree->content);
    CHECK(tree->content->type() == fs::FsType::Luks2);
    const auto* note = findNote(*tree, "luks.unsupported");
    REQUIRE(note);
    CHECK(note->severity == layout::Validity::Info);
    CHECK(note->message == "cannot open in-process: " + luks->info().unsupportedWhy);
    CHECK(note->message.find("dm-integrity") != std::string::npos);
    CHECK(tree->children.empty());
    CHECK(tree->health() < layout::Validity::Warning);   // not a fault of the disk: Info, no [WARN] in the rendering
    CHECK(probe::toText(*tree).find("[WARN]") == std::string::npos);

    // The right passphrase and the right cached key change nothing: no child, no KDF, and no
    // luks.locked, since the container is not locked but unsupported.
    probe::Options all;
    all.passphrases = {kLuksPassphrase};
    all.masterKeys[luks->info().uuid] = fromHex(oracle("luks2").at("master_key"));
    int polls = 0, unlocked = 0;
    all.cancelled = [&] { ++polls; return false; };
    all.onUnlocked = [&](const std::string&, const std::vector<std::uint8_t>&) { ++unlocked; };
    auto t2 = probe::probe(disk, all);
    REQUIRE(t2);
    CHECK(t2->children.empty());
    CHECK(findNote(*t2, "luks.unsupported"));
    CHECK_FALSE(hasNote(*t2, "luks.locked"));
    CHECK_FALSE(hasNote(*t2, "luks.unlock"));
    CHECK(polls == 0);
    CHECK(unlocked == 0);

    // Both header copies with a broken checksum: not unsupported but unreadable, a Warning.
    auto damaged = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(damaged);
    const std::uint64_t hdrSize = luks2HeaderSize(*damaged, 0);
    for (ByteCount at : {ByteCount{0}, ByteCount{hdrSize}}) damaged->bytes()[at + kLuks2Binary + 64] ^= std::byte{0x01};
    probe::Options withPass;
    withPass.passphrases = {kLuksPassphrase};
    auto t3 = probe::probe(damaged, withPass);
    REQUIRE(t3);
    CHECK(t3->children.empty());
    const auto* hdr = findNote(*t3, "luks.header");
    REQUIRE(hdr);
    CHECK(hdr->severity == layout::Validity::Warning);
    CHECK_FALSE(hasNote(*t3, "luks.unsupported"));
    CHECK_FALSE(hasNote(*t3, "luks.locked"));
}
