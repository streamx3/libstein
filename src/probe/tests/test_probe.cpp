// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/block/slice_device.hpp"

#include <algorithm>
#include <map>
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
