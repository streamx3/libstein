// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/crc32.hpp"
#include "stein/layout/gen/mbr.hpp"
#include "stein/pt/apm_table.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/mbr_table.hpp"
#include "stein/pt/partition_table.hpp"

#include <algorithm>
#include <array>
#include <set>

using namespace stein;
using namespace stein::pt;
using layout::Validity;
using stein::test::loadSparseFixture;

namespace {
// Compares two devices over the given regions and reports the first differing byte.
void checkRegionsEqual(BlockDevice& a, BlockDevice& b, const std::vector<Region>& regions) {
    for (std::size_t i = 0; i < regions.size(); ++i) {
        auto x = a.read(regions[i].offset, regions[i].length);
        auto y = b.read(regions[i].offset, regions[i].length);
        REQUIRE(x);
        REQUIRE(y);
        std::size_t diff = 0;
        while (diff < x->size() && (*x)[diff] == (*y)[diff]) ++diff;
        INFO("region ", i, " @", regions[i].offset, " first difference at +", diff, ": ",
             diff < x->size() ? std::to_integer<int>((*x)[diff]) : -1, " vs ",
             diff < y->size() ? std::to_integer<int>((*y)[diff]) : -1);
        CHECK(diff == x->size());
    }
}

bool hasDiagnostic(const PartitionTable& t, std::string_view code) {
    for (const auto& d : t.diagnostics())
        if (d.code == code) return true;
    return false;
}
} // namespace

TEST_CASE("type registry") {
    auto esp = PartitionType::gpt(*Uuid::parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"));
    CHECK(types::name(esp) == "EFI System");
    CHECK(types::role(esp) == Role::EfiSystem);
    CHECK(types::find(esp)->sgdiskCode == std::string("EF00"));
    CHECK(types::fromSgdiskCode("8300") == types::forRole(Role::LinuxFilesystem, TableType::Gpt));
    CHECK(types::name(PartitionType::mbr(0x83)) == "Linux");
    CHECK(types::name(PartitionType::mbr(0x7F)) == "Unknown (0x7F)");
    CHECK(types::role(PartitionType::mbr(0x05)) == Role::Extended);
    CHECK(types::role(PartitionType::mbr(0x00)) == Role::Empty);
    CHECK(PartitionType::mbr(0x0C).code() == "0x0C");
    CHECK(types::all().size() > 100);
    CHECK(types::name(PartitionType::apm("Apple_HFS")) == "Apple HFS / HFS+");
    CHECK(types::role(PartitionType::apm("Apple_Free")) == Role::Empty);
    CHECK(PartitionType::apm("Apple_Free").isEmpty());
    // Every GPT GUID in the registry must be unique and parse back.
    for (const auto& a : types::all())
        if (a.type.scheme == TableType::Gpt) CHECK(Uuid::parse(a.type.gptGuid.toString()) == a.type.gptGuid);
}

TEST_CASE("GPT: read sgdisk fixture") {
    auto dev = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(dev);
    auto table = PartitionTable::read(dev);
    REQUIRE(table);
    CHECK((*table)->type() == TableType::Gpt);
    CHECK((*table)->health() == Validity::Ok);
    auto* gpt = dynamic_cast<GptTable*>(table->get());
    REQUIRE(gpt);
    CHECK(gpt->diskGuid().toString() == "11111111-2222-3333-4444-555555555555");
    CHECK(gpt->primaryState().valid());
    CHECK(gpt->backupState().valid());
    CHECK(gpt->primaryState().entriesCrcOk);
    CHECK(gpt->hasProtectiveMbr());
    CHECK(!gpt->isHybridMbr());
    CHECK(gpt->firstUsableLba() == 34);
    CHECK(gpt->lastUsableLba() == 32734);
    CHECK(gpt->entryCount() == 128);
    auto parts = gpt->partitions();
    REQUIRE(parts.size() == 3);
    CHECK(parts[0].index == 1);
    CHECK(parts[0].firstLba == 2048);
    CHECK(parts[0].lastLba == 6143);
    CHECK(parts[0].name == "EFI System");
    CHECK(types::role(parts[0].type) == Role::EfiSystem);
    CHECK(parts[0].uuid.toString() == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    CHECK(parts[1].name == "Linux data");
    CHECK(parts[1].attributes == (1ull << 2));
    CHECK(parts[2].firstLba == 14336);
    CHECK(parts[2].lastLba == 32734);
    CHECK(parts[2].attributes == (1ull << 63));
    CHECK(types::role(parts[2].type) == Role::WindowsBasicData);
    auto freeR = gpt->freeRegions();
    REQUIRE(freeR.size() == 1);
    CHECK(freeR[0].firstLba == 34);
    CHECK(freeR[0].lastLba == 2047);
    CHECK(freeR[0].sectors() == 2014);   // matches "2014 free sectors" in sgdisk -v
    auto regions = gpt->metadataRegions();
    CHECK(regions.size() == 5);
    CHECK(regions[4].offset == 32767 * 512);
    auto tree = gpt->describe();
    CHECK(tree.child("primary GPT header")->child("header_crc32")->validity == Validity::Ok);
    CHECK(tree.child("primary GPT header")->child("disk_guid")->value == "11111111-2222-3333-4444-555555555555");
    CHECK(tree.child("primary partition entries")->children.size() == 3);
    CHECK(tree.child("primary partition entries")->children[0].child("partition_type_guid")->pretty == "EFI System");
    CHECK(tree.child("protective MBR")->child("entries")->children.size() == 1);
    CHECK(tree.child("protective MBR")->child("entries")->children[0].child("type")->pretty == "GPT protective");
}

TEST_CASE("GPT: write round trip reproduces sgdisk's bytes") {
    auto dev = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(dev);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto copy = std::make_shared<MemoryDevice>(dev->size(), 512);
    REQUIRE((*table)->write(*copy));
    // Headers, entry arrays and PMBR must be byte-identical to what sgdisk wrote.
    checkRegionsEqual(*dev, *copy, (*table)->metadataRegions());
    auto reread = GptTable::read(copy);
    REQUIRE(reread);
    CHECK((*reread)->health() <= Validity::Info);
    CHECK((*reread)->partitions().size() == 3);
}

TEST_CASE("GPT: corrupt primary header is diagnosed and repaired from the backup") {
    auto dev = loadSparseFixture("pt/gpt_broken_primary.sparse");
    REQUIRE(dev);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(!gpt.primaryState().valid());
    CHECK(gpt.backupState().valid());
    CHECK(gpt.partitions().size() == 3);   // loaded from the backup
    CHECK(gpt.health() == Validity::Error);
    CHECK(hasDiagnostic(gpt, "gpt.primary_header"));
    CHECK(hasDiagnostic(gpt, "gpt.loaded_from_backup"));
    CHECK(gpt.describe().child("primary GPT header")->validity == Validity::Error);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(gpt.primaryState().valid());
    CHECK(gpt.backupState().valid());
    CHECK(gpt.health() <= Validity::Info);
    CHECK(gpt.partitions().size() == 3);
    CHECK(gpt.partitions()[0].name == "EFI System");
    // The repaired primary must equal the pristine fixture's primary.
    auto pristine = loadSparseFixture("pt/gpt_basic.sparse");
    CHECK(*dev->read(512, 512) == *pristine->read(512, 512));
    CHECK(*dev->read(1024, 128 * 128) == *pristine->read(1024, 128 * 128));
}

TEST_CASE("GPT: corrupt backup is diagnosed and rebuilt from the primary") {
    auto dev = loadSparseFixture("pt/gpt_broken_backup.sparse");
    REQUIRE(dev);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.primaryState().valid());
    CHECK(!gpt.backupState().valid());
    CHECK(hasDiagnostic(gpt, "gpt.backup_header"));
    CHECK(gpt.partitions().size() == 3);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(gpt.backupState().valid());
    auto pristine = loadSparseFixture("pt/gpt_basic.sparse");
    CHECK(*dev->read(32767 * 512, 512) == *pristine->read(32767 * 512, 512));
}

TEST_CASE("GPT: grown disk -> backup not at end, relocated by repair") {
    auto dev = loadSparseFixture("pt/gpt_grown.sparse");
    REQUIRE(dev);
    CHECK(dev->size() == 24 * MiB);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.primaryState().valid());
    CHECK(gpt.backupState().valid());   // found via alternate_lba even though it is not at the end
    CHECK(hasDiagnostic(gpt, "gpt.backup_not_at_end"));
    CHECK(hasDiagnostic(gpt, "gpt.pmbr_size_mismatch"));   // the 0xEE entry still spans the old 16 MiB
    CHECK(gpt.lastUsableLba() == 32734);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(!hasDiagnostic(gpt, "gpt.backup_not_at_end"));
    CHECK(!hasDiagnostic(gpt, "gpt.pmbr_size_mismatch"));
    CHECK(gpt.health() == Validity::Ok);
    CHECK(gpt.backupState().lba == 24 * MiB / 512 - 1);
    CHECK(gpt.lastUsableLba() == 24 * MiB / 512 - 34);
    CHECK(gpt.partitions().size() == 3);
}

TEST_CASE("GPT: both headers destroyed, protective MBR remains") {
    auto dev = loadSparseFixture("pt/gpt_both_broken.sparse");
    REQUIRE(dev);
    auto table = PartitionTable::read(dev);
    REQUIRE(table);
    CHECK((*table)->type() == TableType::Gpt);
    CHECK((*table)->partitions().empty());
    CHECK((*table)->health() == Validity::Error);
    CHECK(hasDiagnostic(**table, "gpt.unrecoverable"));
    auto* gpt = dynamic_cast<GptTable*>(table->get());
    CHECK(gpt->repair(*dev, RepairOptions{}).error().category() == ErrorCategory::InvalidFormat);
}

TEST_CASE("GPT: 4096-byte sectors") {
    auto dev = loadSparseFixture("pt/gpt_4k.sparse");
    REQUIRE(dev);
    CHECK(dev->sectorSize() == 4096);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.health() <= Validity::Info);
    CHECK(gpt.firstUsableLba() == 6);
    CHECK(gpt.lastUsableLba() == 8186);
    CHECK(gpt.entryArraySectors() == 4);
    REQUIRE(gpt.partitions().size() == 1);
    CHECK(gpt.partitions()[0].firstLba == 256);
    CHECK(gpt.partitions()[0].lastLba == 2303);
    CHECK(gpt.partitions()[0].name == "Linux 4Kn");
    auto copy = std::make_shared<MemoryDevice>(dev->size(), 4096);
    REQUIRE(gpt.write(*copy));
    checkRegionsEqual(*dev, *copy, gpt.metadataRegions());
}

TEST_CASE("GPT: create, edit, write, read back") {
    Geometry geo{.sizeBytes = 64 * MiB, .logicalSectorSize = 512, .physicalSectorSize = 4096};
    auto table = GptTable::createEmpty(geo);
    table->setDiskGuid(*Uuid::parse("01234567-89AB-CDEF-0123-456789ABCDEF"));
    CHECK(table->firstUsableLba() == 34);
    CHECK(table->lastUsableLba() == 64 * MiB / 512 - 34);
    Partition p;
    p.firstLba = 2048;
    p.lastLba = 2048 + 20480 - 1;
    p.type = *types::forRole(Role::EfiSystem, TableType::Gpt);
    p.name = "EFI";
    p.uuid = *Uuid::parse("AAAAAAAA-0000-0000-0000-000000000001");
    REQUIRE(table->addPartition(p));
    CHECK(table->partitions()[0].index == 1);
    Partition q = p;
    q.index = 0;
    q.firstLba = p.lastLba + 1;
    q.lastLba = table->lastUsableLba();
    q.type = *types::forRole(Role::LinuxFilesystem, TableType::Gpt);
    q.name = "root";
    q.uuid = *Uuid::parse("AAAAAAAA-0000-0000-0000-000000000002");
    REQUIRE(table->addPartition(q));
    CHECK(table->partitions()[1].index == 2);
    Partition bad = q;
    bad.index = 0;
    CHECK(table->addPartition(bad).error().category() == ErrorCategory::InvalidArgument);   // overlap
    bad.firstLba = 10;
    bad.lastLba = 20;
    CHECK(table->addPartition(bad).error().category() == ErrorCategory::OutOfRange);
    bad = q;
    bad.index = 0;
    bad.firstLba = 0;
    bad.lastLba = 0;
    bad.name = std::string(37, 'a');
    CHECK(table->addPartition(bad).error().category() == ErrorCategory::InvalidArgument);
    CHECK(table->freeRegions().size() == 1);
    CHECK(table->freeRegions()[0].sectors() == 2014);

    auto dev = std::make_shared<MemoryDevice>(geo.sizeBytes, 512);
    REQUIRE(table->write(*dev));
    auto back = PartitionTable::read(dev);
    REQUIRE(back);
    CHECK((*back)->type() == TableType::Gpt);
    CHECK((*back)->health() == Validity::Ok);
    REQUIRE((*back)->partitions().size() == 2);
    CHECK((*back)->partitions()[1].name == "root");
    CHECK(dynamic_cast<GptTable*>(back->get())->diskGuid() == table->diskGuid());
    REQUIRE((*back)->removePartition(1));
    CHECK((*back)->partitions().size() == 1);
    Partition upd = (*back)->partitions()[0];
    upd.name = "renamed";
    REQUIRE((*back)->updatePartition(upd));
    CHECK((*back)->partitions()[0].name == "renamed");
    // Writing to a device with another sector size must be refused.
    MemoryDevice other(geo.sizeBytes, 4096);
    CHECK(table->write(other).error().category() == ErrorCategory::InvalidArgument);
    // Too small: refused before anything is written.
    MemoryDevice tiny(1 * MiB, 512);
    CHECK(table->write(tiny).error().category() == ErrorCategory::OutOfRange);
}

TEST_CASE("MBR: read sfdisk fixture with extended + logicals") {
    auto dev = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(dev);
    auto table = PartitionTable::read(dev);
    REQUIRE(table);
    CHECK((*table)->type() == TableType::Mbr);
    auto* mbr = dynamic_cast<MbrTable*>(table->get());
    REQUIRE(mbr);
    CHECK(mbr->diskSignature() == 0xdeadbeef);
    CHECK(mbr->health() <= Validity::Info);
    auto parts = mbr->partitions();
    REQUIRE(parts.size() == 5);
    CHECK(parts[0].index == 1);
    CHECK(parts[0].firstLba == 2048);
    CHECK(parts[0].sectors() == 4096);
    CHECK(parts[0].type.mbrId == 0x83);
    CHECK(parts[0].attributes == Partition::kMbrBootable);
    CHECK(parts[1].type.mbrId == 0x0C);
    CHECK(parts[2].isExtended);
    CHECK(parts[2].firstLba == 10240);
    CHECK(parts[2].sectors() == 22528);
    CHECK(parts[3].index == 5);
    CHECK(parts[3].isLogical);
    CHECK(parts[3].firstLba == 12288);
    CHECK(parts[3].sectors() == 4096);
    CHECK(parts[3].ebrLba == 10240);
    CHECK(parts[4].index == 6);
    CHECK(parts[4].firstLba == 18432);
    CHECK(parts[4].sectors() == 8192);
    CHECK(parts[4].type.mbrId == 0x07);
    CHECK(parts[4].ebrLba.has_value());
    CHECK(mbr->metadataRegions().size() == 3);
    auto tree = mbr->describe();
    CHECK(tree.child("MBR sector")->child("entries")->children.size() == 3);
    CHECK(tree.children.size() == 3);   // MBR + 2 EBRs
    CHECK(tree.children[1].name == "EBR @ LBA 10240");
    CHECK(tree.children[1].child("entries")->children[0].name == "logical partition");
    CHECK(tree.children[1].child("entries")->children[1].name == "next EBR link");

    // Round trip: our writer must reproduce sfdisk's MBR and EBR sectors.
    auto copy = std::make_shared<MemoryDevice>(dev->size(), 512);
    REQUIRE(mbr->write(*copy));
    checkRegionsEqual(*dev, *copy, mbr->metadataRegions());
}

TEST_CASE("MBR: empty table, whole-disk FAT, and NoPartitionTable") {
    auto empty = loadSparseFixture("pt/mbr_empty.sparse");
    REQUIRE(empty);
    auto t = PartitionTable::read(empty);
    REQUIRE(t);
    CHECK((*t)->type() == TableType::Mbr);
    CHECK((*t)->partitions().empty());
    CHECK((*t)->freeRegions().size() == 1);

    auto fat = loadSparseFixture("pt/fat_whole.sparse");
    REQUIRE(fat);
    auto f = PartitionTable::read(fat);
    REQUIRE(f);
    CHECK((*f)->type() == TableType::None);
    CHECK((*f)->addPartition(Partition{}).error().category() == ErrorCategory::Unsupported);

    auto blank = std::make_shared<MemoryDevice>(4 * MiB, 512);
    auto b = PartitionTable::read(blank);
    REQUIRE(b);
    CHECK((*b)->type() == TableType::None);
}

TEST_CASE("MBR: create with logicals, write, read back") {
    Geometry geo{.sizeBytes = 32 * MiB, .logicalSectorSize = 512};
    auto table = MbrTable::createEmpty(geo);
    table->setDiskSignature(0x12345678);
    Partition p1;
    p1.firstLba = 2048;
    p1.lastLba = 2048 + 8192 - 1;
    p1.type = PartitionType::mbr(0x0C);
    p1.attributes = Partition::kMbrBootable;
    REQUIRE(table->addPartition(p1));
    Partition ext;
    ext.firstLba = 10240;
    ext.lastLba = geo.sectors() - 1;
    ext.type = PartitionType::mbr(0x05);
    REQUIRE(table->addPartition(ext));
    CHECK(table->extendedPartition() != nullptr);
    CHECK(table->extendedPartition()->index == 2);
    Partition l1;
    l1.isLogical = true;
    l1.firstLba = 12288;
    l1.lastLba = 12288 + 4096 - 1;
    l1.type = PartitionType::mbr(0x83);
    REQUIRE(table->addPartition(l1));
    CHECK(table->find(5)->ebrLba == 10240);   // first logical's EBR is the extended start
    Partition l2 = l1;
    l2.firstLba = 20480;
    l2.lastLba = 20480 + 8192 - 1;
    l2.type = PartitionType::mbr(0x07);
    REQUIRE(table->addPartition(l2));
    CHECK(table->find(6)->ebrLba == 20480 - MbrTable::kDefaultEbrGap);
    Partition outside = l1;
    outside.firstLba = 4096;
    outside.lastLba = 5000;
    CHECK(!table->addPartition(outside));
    CHECK(table->removePartition(2).error().category() == ErrorCategory::Busy);

    auto dev = std::make_shared<MemoryDevice>(geo.sizeBytes, 512);
    REQUIRE(table->write(*dev));
    auto back = MbrTable::read(dev);
    REQUIRE(back);
    CHECK((*back)->health() <= Validity::Info);
    REQUIRE((*back)->partitions().size() == 4);
    CHECK((*back)->diskSignature() == 0x12345678);
    CHECK((*back)->partitions()[0].attributes == Partition::kMbrBootable);
    CHECK((*back)->partitions()[2].index == 5);
    CHECK((*back)->partitions()[2].firstLba == 12288);
    CHECK((*back)->partitions()[3].index == 6);
    CHECK((*back)->partitions()[3].firstLba == 20480);
    CHECK((*back)->partitions()[3].sectors() == 8192);
    // CHS of the first partition must be the classic 255/63 mapping: LBA 2048 -> C0/H32/S33.
    auto s0 = dev->read(0x1BE, 16);
    CHECK(std::to_integer<int>((*s0)[1]) == 32);
    CHECK(std::to_integer<int>((*s0)[2]) == 33);
    CHECK(std::to_integer<int>((*s0)[3]) == 0);
}

TEST_CASE("APM: read parted fixture, round trip, create") {
    auto dev = loadSparseFixture("pt/apm_basic.sparse");
    REQUIRE(dev);
    auto table = PartitionTable::read(dev);
    REQUIRE(table);
    CHECK((*table)->type() == TableType::Apm);
    auto* apm = dynamic_cast<ApmTable*>(table->get());
    REQUIRE(apm);
    CHECK(apm->health() <= Validity::Info);
    CHECK(apm->mapBlockSize() == 512);
    CHECK(apm->mapEntries() == 5);
    CHECK(apm->mapBlocks() == 63);
    CHECK(apm->firstUsableLba() == 64);
    // Every slot as read, map and Apple_Free included: the OS makes a device of each (sda1 is the map).
    REQUIRE(apm->slots().size() == 5);
    CHECK(apm->slots()[0].slot == 1);
    CHECK(apm->slots()[0].isMap);
    CHECK(apm->slots()[0].type == "Apple_partition_map");
    CHECK(apm->slots()[0].firstLba == 1);
    CHECK(apm->slots()[0].lastLba == 63);
    CHECK(apm->slots()[1].slot == 2);
    CHECK(!apm->slots()[1].isMap);
    CHECK(!apm->slots()[1].isFree);
    CHECK(apm->slots()[1].firstLba == 2048);
    CHECK(apm->slots()[1].name == "Data");
    CHECK(apm->slots()[3].isFree);
    CHECK(apm->slots()[4].isFree);
    // mmls oracle: Apple_HFS 2048..10239 "Data" (slot 2), Apple_UNIX_SVR2 10240..18431 "primary" (slot 3)
    REQUIRE(apm->partitions().size() == 2);
    CHECK(apm->partitions()[0].index == 2);
    CHECK(apm->partitions()[0].firstLba == 2048);
    CHECK(apm->partitions()[0].lastLba == 10239);
    CHECK(apm->partitions()[0].type.apmType == "Apple_HFS");
    CHECK(apm->partitions()[0].name == "Data");
    CHECK(apm->partitions()[0].attributes == 0x7F);
    CHECK(apm->partitions()[1].type.apmType == "Apple_UNIX_SVR2");
    CHECK(apm->partitions()[1].name == "primary");
    auto freeR = apm->freeRegions();
    REQUIRE(freeR.size() == 2);
    CHECK(freeR[0].firstLba == 64);
    CHECK(freeR[0].lastLba == 2047);
    CHECK(freeR[1].firstLba == 18432);
    CHECK(apm->metadataRegions().size() == 1);
    CHECK(apm->metadataRegions()[0].length == 64 * 512);
    auto tree = apm->describe();
    CHECK(tree.children.size() == 6);   // Block0 + 5 entries
    CHECK(tree.child("map entry 1")->child("pm_par_type")->pretty == "the partition map itself");
    CHECK(tree.child("map entry 2")->child("pm_part_status")->pretty.find("valid|allocated|in_use") == 0);

    // Write round trip: our writer regenerates the map; re-read must give the same partitions.
    auto copy = std::make_shared<MemoryDevice>(dev->size(), 512);
    REQUIRE(apm->write(*copy));
    auto back = ApmTable::read(copy);
    REQUIRE(back);
    REQUIRE((*back)->partitions().size() == 2);
    CHECK((*back)->partitions()[0].firstLba == 2048);
    CHECK((*back)->partitions()[1].lastLba == 18431);
    CHECK((*back)->partitions()[0].name == "Data");
    CHECK((*back)->health() <= Validity::Info);
    // Entry 1 (the map) and the partition entries must match parted's bytes in the fields that matter.
    CHECK(*copy->read(512, 16) == *dev->read(512, 16));
    CHECK(*copy->read(1024 + 8, 8) == *dev->read(1024 + 8, 8));   // start/count of partition 2

    // Create from scratch.
    Geometry geo{.sizeBytes = 32 * MiB, .logicalSectorSize = 512};
    auto fresh = ApmTable::createEmpty(geo, 63);
    CHECK(fresh->firstUsableLba() == 64);
    Partition p;
    p.firstLba = 64;
    p.lastLba = 64 + 8192 - 1;
    p.type = PartitionType::apm("Apple_HFS");
    p.name = "Macintosh HD";
    REQUIRE(fresh->addPartition(p));
    CHECK(fresh->partitions()[0].index == 2);
    Partition bad = p;
    bad.index = 0;
    bad.type = PartitionType::apm("Apple_Free");
    CHECK(!fresh->addPartition(bad));
    auto d2 = std::make_shared<MemoryDevice>(geo.sizeBytes, 512);
    REQUIRE(fresh->write(*d2));
    auto r2 = PartitionTable::read(d2);
    REQUIRE(r2);
    CHECK((*r2)->type() == TableType::Apm);
    CHECK((*r2)->partitions().size() == 1);
    CHECK((*r2)->partitions()[0].name == "Macintosh HD");
    CHECK((*r2)->health() <= Validity::Info);
}

TEST_CASE("PartitionTable::createEmpty dispatch") {
    Geometry geo{.sizeBytes = 8 * MiB, .logicalSectorSize = 512};
    CHECK((*PartitionTable::createEmpty(TableType::Gpt, geo))->type() == TableType::Gpt);
    CHECK((*PartitionTable::createEmpty(TableType::Mbr, geo))->type() == TableType::Mbr);
    CHECK((*PartitionTable::createEmpty(TableType::None, geo))->type() == TableType::None);
    CHECK((*PartitionTable::createEmpty(TableType::Apm, geo))->type() == TableType::Apm);
    CHECK(PartitionTable::createEmpty(TableType::Sun, geo).error().category() == ErrorCategory::Unsupported);
}

TEST_CASE("GPT: each entry array is described from its own bytes") {
    auto dev = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(dev);
    // Rename partition 2 in the backup array only (backup entries start at LBA 32735).
    const ByteCount backupEntry2 = ByteCount{32735} * 512 + 128;
    const char16_t x = u'X';
    REQUIRE(dev->writeAt(backupEntry2 + 0x38, std::as_bytes(std::span(&x, 1))));
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.partitions()[1].name == "Linux data");       // the primary is the source of truth
    CHECK(hasDiagnostic(gpt, "gpt.backup_entries"));
    const auto tree = gpt.describe();
    const auto* primary = tree.child("primary partition entries");
    const auto* backup = tree.child("backup partition entries");
    REQUIRE(primary);
    REQUIRE(backup);
    REQUIRE(primary->children.size() == 3);
    REQUIRE(backup->children.size() == 3);
    CHECK(primary->children[1].child("partition_name")->value == "Linux data");
    CHECK(backup->children[1].child("partition_name")->value == "Xinux data");
    CHECK(backup->children[1].absOffset == backupEntry2);
    CHECK(primary->validity == Validity::Ok);
    CHECK(backup->validity == Validity::Error);
    CHECK(backup->message.find("CRC") != std::string::npos);
}

TEST_CASE("GPT: reserved tail of the header block is checked and repaired; attribute bits named by type") {
    auto dev = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(dev);
    {
        auto table = GptTable::read(dev);
        REQUIRE(table);
        const auto tree = (*table)->describe();
        const auto* entries = tree.child("primary partition entries");
        REQUIRE(entries);
        REQUIRE(entries->children.size() == 3);
        CHECK(entries->children[0].child("attributes")->pretty == "none");
        CHECK(entries->children[1].child("attributes")->pretty == "legacy_bios_bootable");   // Linux data, bit 2
        CHECK(entries->children[2].child("attributes")->pretty == "no_drive_letter");        // Microsoft basic data, bit 63
        CHECK(tree.child("primary GPT header")->child("reserved_tail")->validity == Validity::Ok);
        CHECK(tree.child("primary GPT header")->size == 512);
        CHECK(!hasDiagnostic(**table, "gpt.primary_header_reserved"));
    }
    const std::byte junk{0x5A};
    REQUIRE(dev->writeAt(512 + 200, std::span<const std::byte>(&junk, 1)));
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.health() == Validity::Warning);
    CHECK(hasDiagnostic(gpt, "gpt.primary_header_reserved"));
    const auto tree = gpt.describe();
    CHECK(tree.child("primary GPT header")->child("reserved_tail")->validity == Validity::Warning);
    CHECK(tree.child("primary GPT header")->child("reserved_tail")->absOffset == 512 + 92);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    auto again = GptTable::read(dev);
    REQUIRE(again);
    CHECK(!hasDiagnostic(**again, "gpt.primary_header_reserved"));
    CHECK((*again)->health() == Validity::Ok);
}


// ============================================================================ MBR repair and rules

namespace {
constexpr ByteCount kEntry1 = 0x1BE, kEntry2 = 0x1CE, kEntry3 = 0x1DE, kEntry4 = 0x1EE;   // entry offsets inside a sector
constexpr ByteCount kEbr1 = 10240 * 512, kEbr2 = 16384 * 512;                           // mbr_basic's EBRs

void pokeU8(BlockDevice& d, ByteCount off, std::uint8_t v) {
    const std::byte b{v};
    REQUIRE(d.writeAt(off, std::span<const std::byte>(&b, 1)));
}
void pokeU32(BlockDevice& d, ByteCount off, std::uint32_t v) {
    const std::array<std::byte, 4> b{std::byte(v & 0xFF), std::byte((v >> 8) & 0xFF), std::byte((v >> 16) & 0xFF), std::byte((v >> 24) & 0xFF)};
    REQUIRE(d.writeAt(off, b));
}
// An MBR entry as a partitioner writes it; CHS left zero (sfdisk fills it, the kernel ignores it).
void pokeEntry(BlockDevice& d, ByteCount off, std::uint8_t status, std::uint8_t type, std::uint32_t first, std::uint32_t count) {
    std::array<std::byte, 16> e{};
    e[0] = std::byte{status};
    e[4] = std::byte{type};
    REQUIRE(d.writeAt(off, e));
    pokeU32(d, off + 8, first);
    pokeU32(d, off + 12, count);
}
std::shared_ptr<MemoryDevice> snapshot(const MemoryDevice& d) {
    return std::make_shared<MemoryDevice>(std::vector<std::byte>(d.bytes().begin(), d.bytes().end()), d.sectorSize());
}
const Diagnostic* findDiagnostic(const PartitionTable& t, std::string_view code) {
    for (const auto& d : t.diagnostics())
        if (d.code == code) return &d;
    return nullptr;
}
bool isRepairable(const PartitionTable& t, std::string_view code) {
    const auto* d = findDiagnostic(t, code);
    return d && d->repairable;
}
std::size_t logicalCount(const PartitionTable& t) {
    std::size_t n = 0;
    for (const auto& p : t.partitions()) n += p.isLogical;
    return n;
}

// A device whose listed sectors fail to read until something is written over them, the way a
// disk remaps a bad block on write.
class FaultyDevice final : public BlockDevice {
public:
    FaultyDevice(std::shared_ptr<MemoryDevice> inner, std::set<Lba> bad) : m_inner(std::move(inner)), m_bad(std::move(bad)) {}
    std::string name() const override { return "faulty"; }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        for (Lba l : m_bad)
            if (Region{offset, dst.size()}.contains(l * 512)) return fail(ErrorCategory::Io, "bad sector " + std::to_string(l));
        return m_inner->readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        for (auto it = m_bad.begin(); it != m_bad.end();) it = Region{offset, src.size()}.contains(*it * 512) ? m_bad.erase(it) : std::next(it);
        return m_inner->writeAt(offset, src);
    }
    Expected<void> flush() override { return {}; }
    bool isBad(Lba l) const { return m_bad.count(l) != 0; }

private:
    std::shared_ptr<MemoryDevice> m_inner;
    std::set<Lba> m_bad;
};
} // namespace

TEST_CASE("MBR: EBR with a lost boot signature is recovered through its link and rewritten byte-identically") {
    auto dev = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(dev);
    auto pristine = snapshot(*dev);
    REQUIRE(dev->zeroRange(kEbr2 + 0x1FE, 2));
    auto table = MbrTable::read(dev);
    REQUIRE(table);
    auto& mbr = **table;
    CHECK(mbr.health() == Validity::Error);
    CHECK(isRepairable(mbr, "mbr.ebr_chain_broken"));
    CHECK(isRepairable(mbr, "mbr.logical_lost"));
    CHECK(logicalCount(mbr) == 1);
    CHECK(mbr.partitions().size() == 4);
    const auto tree = mbr.describe();
    REQUIRE(tree.child("EBR @ LBA 16384"));
    CHECK(tree.child("EBR @ LBA 16384")->validity == Validity::Error);
    CHECK(tree.child("EBR @ LBA 10240")->validity == Validity::Ok);

    REQUIRE(mbr.repair(*dev, RepairOptions{}));
    CHECK(mbr.health() <= Validity::Info);
    CHECK(logicalCount(mbr) == 2);
    REQUIRE(mbr.partitions().size() == 5);
    CHECK(mbr.partitions()[4].index == 6);
    CHECK(mbr.partitions()[4].firstLba == 18432);
    CHECK(mbr.partitions()[4].type.mbrId == 0x07);
    CHECK(mbr.partitions()[4].ebrLba == 16384);
    // Every sector sfdisk wrote is back, the two EBRs included.
    REQUIRE(mbr.metadataRegions().size() == 3);
    checkRegionsEqual(*dev, *pristine, mbr.metadataRegions());
    auto again = MbrTable::read(dev);
    REQUIRE(again);
    CHECK((*again)->diagnostics().empty());
}

TEST_CASE("MBR: a zeroed middle EBR loses its own logical; the orphaned EBRs behind it are recovered") {
    auto dev = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(dev);
    {
        // A third logical so that the chain has a middle link: EBR#3 lands on the 1 MiB grid at 26624.
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        Partition l7;
        l7.isLogical = true;
        l7.firstLba = 28672;
        l7.lastLba = 32767;
        l7.type = PartitionType::mbr(0x83);
        REQUIRE((*table)->addPartition(l7));
        CHECK((*table)->find(7)->ebrLba == 26624);
        REQUIRE((*table)->write(*dev));
    }
    auto pristine = snapshot(*dev);
    {
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        CHECK((*table)->health() <= Validity::Info);
        CHECK(logicalCount(**table) == 3);
    }
    REQUIRE(dev->zeroRange(kEbr2, 512));
    auto table = MbrTable::read(dev);
    REQUIRE(table);
    auto& mbr = **table;
    CHECK(isRepairable(mbr, "mbr.ebr_chain_broken"));
    CHECK(isRepairable(mbr, "mbr.logical_lost"));
    CHECK(logicalCount(mbr) == 1);

    REQUIRE(mbr.repair(*dev, RepairOptions{}));
    CHECK(mbr.health() <= Validity::Info);
    // Logical 6 lived only in the zeroed sector and is gone; the old logical 7 is back as 6.
    REQUIRE(logicalCount(mbr) == 2);
    const Partition* a = mbr.find(5);
    const Partition* b = mbr.find(6);
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->firstLba == 12288);
    CHECK(b->firstLba == 28672);
    CHECK(b->lastLba == 32767);
    CHECK(b->type.mbrId == 0x83);
    CHECK(b->ebrLba == 26624);
    // The recovered EBR is untouched, the head EBR keeps its logical and now links straight to it.
    CHECK(*dev->read(26624 * 512, 512) == *pristine->read(26624 * 512, 512));
    CHECK(*dev->read(kEbr1 + kEntry1, 16) == *pristine->read(kEbr1 + kEntry1, 16));
    auto link = dev->read(kEbr1 + kEntry2, 16);
    REQUIRE(link);
    CHECK(std::to_integer<int>((*link)[4]) == 0x05);
    CHECK(layout::gen::MbrEntry(*link).firstLba() == 26624 - 10240);
    CHECK(layout::gen::MbrEntry(*link).sectorCount() == 32767 - 26624 + 1);
}

TEST_CASE("MBR: unreadable EBRs: the orphan scan rebuilds the chain, and repair refuses to write an empty one") {
    SUBCASE("unreadable head EBR, the second EBR is found on the 1 MiB grid") {
        auto mem = loadSparseFixture("pt/mbr_basic.sparse");
        REQUIRE(mem);
        auto dev = std::make_shared<FaultyDevice>(mem, std::set<Lba>{10240});
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(isRepairable(mbr, "mbr.ebr_unreadable"));
        CHECK(isRepairable(mbr, "mbr.logical_lost"));
        CHECK(logicalCount(mbr) == 0);
        CHECK(mbr.partitions().size() == 3);
        const auto tree = mbr.describe();
        REQUIRE(tree.child("EBR @ LBA 10240"));
        CHECK(tree.child("EBR @ LBA 10240")->validity == Validity::Error);
        REQUIRE(mbr.repair(*dev, RepairOptions{}));
        CHECK(!dev->isBad(10240));   // the head EBR was rewritten
        CHECK(mbr.health() <= Validity::Info);
        REQUIRE(logicalCount(mbr) == 1);
        const Partition* l = mbr.find(5);
        REQUIRE(l);
        CHECK(l->firstLba == 18432);
        CHECK(l->sectors() == 8192);
        CHECK(l->type.mbrId == 0x07);
        CHECK(l->ebrLba == 10240);   // the chain head moved to the extended partition's first sector
    }
    SUBCASE("unreadable middle EBR with nothing behind it: the chain is closed at the last good EBR") {
        auto mem = loadSparseFixture("pt/mbr_basic.sparse");
        REQUIRE(mem);
        auto dev = std::make_shared<FaultyDevice>(mem, std::set<Lba>{16384});
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(isRepairable(mbr, "mbr.ebr_unreadable"));
        CHECK(logicalCount(mbr) == 1);
        REQUIRE(mbr.repair(*dev, RepairOptions{}));
        CHECK(mbr.health() <= Validity::Info);
        CHECK(logicalCount(mbr) == 1);
        CHECK(std::all_of(mem->bytes().begin() + kEbr1 + kEntry2, mem->bytes().begin() + kEbr1 + kEntry2 + 16, [](std::byte b) { return b == std::byte{0}; }));
    }
    SUBCASE("unreadable head EBR and nothing recoverable: repair fails without writing") {
        auto mem = loadSparseFixture("pt/mbr_basic.sparse");
        REQUIRE(mem);
        REQUIRE(mem->zeroRange(kEbr2, 512));
        auto dev = std::make_shared<FaultyDevice>(mem, std::set<Lba>{10240});
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(logicalCount(mbr) == 0);
        auto r = mbr.repair(*dev, RepairOptions{});
        REQUIRE(!r);
        CHECK(r.error().category() == ErrorCategory::InvalidFormat);
        CHECK(dev->isBad(10240));    // untouched
        CHECK(isRepairable(mbr, "mbr.ebr_unreadable"));
    }
}

TEST_CASE("MBR: looping, mis-typed and out-of-range EBR links are diagnosed and repaired") {
    auto pristine = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(pristine);
    SUBCASE("loop: the second EBR links back to the first") {
        auto dev = snapshot(*pristine);
        pokeEntry(*dev, kEbr2 + kEntry2, 0x00, 0x05, 0, 10240);
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(isRepairable(mbr, "mbr.ebr_chain_loop"));
        CHECK(logicalCount(mbr) == 2);
        REQUIRE(mbr.repair(*dev, RepairOptions{}));
        CHECK(mbr.health() <= Validity::Info);
        checkRegionsEqual(*dev, *pristine, mbr.metadataRegions());
    }
    SUBCASE("link typed 0x83 instead of 0x05") {
        auto dev = snapshot(*pristine);
        pokeU8(*dev, kEbr1 + kEntry2 + 4, 0x83);
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(mbr.health() == Validity::Warning);
        CHECK(isRepairable(mbr, "mbr.ebr_link_type"));
        CHECK(logicalCount(mbr) == 2);
        const auto tree = mbr.describe();
        REQUIRE(tree.child("EBR @ LBA 10240"));
        REQUIRE(tree.child("EBR @ LBA 10240")->child("entries")->children.size() == 2);
        CHECK(tree.child("EBR @ LBA 10240")->child("entries")->children[1].name == "next EBR link");
        CHECK(tree.child("EBR @ LBA 10240")->child("entries")->children[1].validity == Validity::Warning);
        REQUIRE(mbr.repair(*dev, RepairOptions{}));
        CHECK(mbr.health() <= Validity::Info);
        checkRegionsEqual(*dev, *pristine, mbr.metadataRegions());
    }
    SUBCASE("link pointing past the extended partition: the lost EBR is found by the scan") {
        auto dev = snapshot(*pristine);
        pokeU32(*dev, kEbr1 + kEntry2 + 8, 0x00FF0000);
        auto table = MbrTable::read(dev);
        REQUIRE(table);
        auto& mbr = **table;
        CHECK(isRepairable(mbr, "mbr.ebr_link_outside"));
        CHECK(isRepairable(mbr, "mbr.logical_lost"));
        CHECK(logicalCount(mbr) == 1);
        REQUIRE(mbr.repair(*dev, RepairOptions{}));
        CHECK(mbr.health() <= Validity::Info);
        CHECK(logicalCount(mbr) == 2);
        REQUIRE(mbr.metadataRegions().size() == 3);
        checkRegionsEqual(*dev, *pristine, mbr.metadataRegions());
    }
}

TEST_CASE("MBR: a status byte other than 0x00/0x80 is a warning; sectors that are not tables stay rejected") {
    auto pristine = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(pristine);
    auto dev = snapshot(*pristine);
    pokeU8(*dev, kEntry2, 0x01);
    auto any = PartitionTable::read(dev);
    REQUIRE(any);
    CHECK((*any)->type() == TableType::Mbr);
    auto table = MbrTable::read(dev);
    REQUIRE(table);
    auto& mbr = **table;
    CHECK(mbr.health() == Validity::Warning);
    CHECK(isRepairable(mbr, "mbr.entry_status"));
    CHECK(findDiagnostic(mbr, "mbr.entry_status")->message.find("0x01") != std::string::npos);
    CHECK(mbr.partitions().size() == 5);
    CHECK(mbr.partitions()[1].attributes == 0);
    const auto tree = mbr.describe();
    REQUIRE(tree.child("MBR sector")->child("entries")->children.size() == 3);
    CHECK(tree.child("MBR sector")->child("entries")->children[1].name == "entry 2");
    CHECK(tree.child("MBR sector")->child("entries")->children[1].validity == Validity::Warning);
    CHECK(tree.child("MBR sector")->child("entries")->children[0].validity == Validity::Ok);
    REQUIRE(mbr.repair(*dev, RepairOptions{}));
    CHECK(mbr.diagnostics().empty());
    CHECK(*dev->read(0, 512) == *pristine->read(0, 512));

    // Boot code at 0x1BE with a 0x55AA signature: every "entry" has a stray status, none is certain.
    auto bogus = std::make_shared<MemoryDevice>(4 * MiB, 512);
    pokeU8(*bogus, 0, 0xEB);
    for (ByteCount off : {kEntry1, kEntry2, kEntry3, kEntry4}) pokeEntry(*bogus, off, 0x33, 0x07, 2048, 100);
    pokeU8(*bogus, 0x1FE, 0x55);
    pokeU8(*bogus, 0x1FF, 0xAA);
    CHECK(MbrTable::read(bogus).error().category() == ErrorCategory::NotFound);
    CHECK((*PartitionTable::read(bogus))->type() == TableType::None);
    // One certain entry does not rescue a doubtful one whose LBAs run off the device.
    auto mixed = snapshot(*pristine);
    pokeEntry(*mixed, kEntry4, 0x33, 0x07, 0x7FFFFFFF, 100);
    CHECK(MbrTable::read(mixed).error().category() == ErrorCategory::NotFound);
}

TEST_CASE("MBR: CHS sector 0 and stale slots are reported per entry; repair reproduces sfdisk's sector") {
    auto pristine = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(pristine);
    auto dev = snapshot(*pristine);
    REQUIRE(dev->zeroRange(kEntry1 + 1, 3));      // first CHS of entry 1 -> C0/H0/S0
    pokeU32(*dev, kEntry4 + 12, 5);               // slot 4: type 0, but a sector count left behind
    auto table = MbrTable::read(dev);
    REQUIRE(table);
    auto& mbr = **table;
    CHECK(mbr.health() == Validity::Warning);
    CHECK(isRepairable(mbr, "mbr.chs_invalid"));
    CHECK(isRepairable(mbr, "mbr.entry_stale"));
    CHECK(findDiagnostic(mbr, "mbr.entry_stale")->severity == Validity::Info);
    CHECK(mbr.partitions().size() == 5);          // the stale slot is not a partition
    const auto tree = mbr.describe();
    const auto* entries = tree.child("MBR sector")->child("entries");
    REQUIRE(entries);
    REQUIRE(entries->children.size() == 4);       // the stale slot is shown
    CHECK(entries->children[0].validity == Validity::Warning);
    CHECK(entries->children[0].child("first_chs")->value == "C0/H0/S0");
    CHECK(entries->children[3].name == "entry 4");
    CHECK(entries->children[3].validity == Validity::Info);
    REQUIRE(mbr.repair(*dev, RepairOptions{}));
    CHECK(mbr.diagnostics().empty());
    CHECK(*dev->read(0, 512) == *pristine->read(0, 512));
}

TEST_CASE("MBR: table-level diagnostics") {
    auto pristine = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(pristine);
    auto readWith = [&](auto patch) {
        auto dev = snapshot(*pristine);
        patch(*dev);
        auto t = MbrTable::read(dev);
        REQUIRE(t);
        return std::move(*t);
    };
    SUBCASE("overlap") {
        auto t = readWith([](BlockDevice& d) { pokeU32(d, kEntry1 + 12, 5000); });
        CHECK(findDiagnostic(*t, "mbr.overlap")->severity == Validity::Error);
        CHECK(!isRepairable(*t, "mbr.overlap"));
    }
    SUBCASE("out of range") {
        auto t = readWith([](BlockDevice& d) { pokeU32(d, kEntry2 + 12, 0x00FFFFFF); });
        CHECK(findDiagnostic(*t, "mbr.out_of_range")->severity == Validity::Error);
    }
    SUBCASE("more than one bootable") {
        auto t = readWith([](BlockDevice& d) { pokeU8(d, kEntry2, 0x80); });
        CHECK(findDiagnostic(*t, "mbr.multiple_bootable")->severity == Validity::Warning);
        CHECK(!findDiagnostic(*t, "mbr.entry_status"));
    }
    SUBCASE("more than one extended; an all-zero first EBR is an empty chain, not a break") {
        auto t = readWith([](BlockDevice& d) { pokeU8(d, kEntry2 + 4, 0x0F); });
        CHECK(findDiagnostic(*t, "mbr.multiple_extended")->severity == Validity::Error);
        CHECK(!findDiagnostic(*t, "mbr.ebr_chain_broken"));
        CHECK(!findDiagnostic(*t, "mbr.logical_lost"));
        CHECK(logicalCount(*t) == 0);
    }
    SUBCASE("protective entry without a GPT") {
        auto t = readWith([](BlockDevice& d) { pokeU8(d, kEntry2 + 4, 0xEE); });
        CHECK(findDiagnostic(*t, "mbr.protective_entry")->severity == Validity::Warning);
    }
    SUBCASE("unaligned start") {
        auto t = readWith([](BlockDevice& d) {
            pokeU32(d, kEntry2 + 8, 6145);
            pokeU32(d, kEntry2 + 12, 4095);
        });
        CHECK(findDiagnostic(*t, "mbr.unaligned")->severity == Validity::Info);
    }
    SUBCASE("logical outside a shrunken extended partition") {
        auto t = readWith([](BlockDevice& d) { pokeU32(d, kEntry3 + 12, 12288); });
        CHECK(findDiagnostic(*t, "mbr.logical_outside_extended")->severity == Validity::Error);
        CHECK(logicalCount(*t) == 2);
    }
}

TEST_CASE("MBR: a created table gets a random disk signature; copy_protected survives a round trip") {
    Geometry geo{.sizeBytes = 8 * MiB, .logicalSectorSize = 512};
    auto a = MbrTable::createEmpty(geo);
    auto b = MbrTable::createEmpty(geo);
    CHECK(a->diskSignature() != 0);
    CHECK(b->diskSignature() != 0);
    CHECK(a->diskSignature() != b->diskSignature());
    auto dev = std::make_shared<MemoryDevice>(geo.sizeBytes, 512);
    REQUIRE(a->write(*dev));
    auto back = MbrTable::read(dev);
    REQUIRE(back);
    CHECK((*back)->diskSignature() == a->diskSignature());

    auto fixture = loadSparseFixture("pt/mbr_basic.sparse");
    REQUIRE(fixture);
    pokeU8(*fixture, 0x1BC, 0x5A);
    pokeU8(*fixture, 0x1BD, 0x5A);
    auto table = MbrTable::read(fixture);
    REQUIRE(table);
    CHECK((*table)->copyProtected() == 0x5A5A);
    CHECK((*table)->diskSignature() == 0xdeadbeef);
    auto copy = std::make_shared<MemoryDevice>(fixture->size(), 512);
    REQUIRE((*table)->write(*copy));
    CHECK(*copy->read(0x1B8, 6) == *fixture->read(0x1B8, 6));   // disk signature and copy_protected
    auto reread = MbrTable::read(copy);
    REQUIRE(reread);
    CHECK((*reread)->copyProtected() == 0x5A5A);
}

// ============================================================================ GPT GUIDs and PMBR

namespace {
bool isVersion4(const Uuid& u) { return !u.isNil() && (u.bytes()[6] >> 4) == 4 && (u.bytes()[8] & 0xC0) == 0x80; }
} // namespace

TEST_CASE("GPT: created tables and partitions get version-4 GUIDs; an explicit GUID is kept") {
    Geometry geo{.sizeBytes = 64 * MiB, .logicalSectorSize = 512};
    auto table = GptTable::createEmpty(geo);
    CHECK(isVersion4(table->diskGuid()));
    CHECK(GptTable::createEmpty(geo)->diskGuid() != table->diskGuid());
    Partition p;
    p.firstLba = 2048;
    p.lastLba = 4095;
    p.type = *types::forRole(Role::EfiSystem, TableType::Gpt);
    REQUIRE(table->addPartition(p));
    p.firstLba = 4096;
    p.lastLba = 6143;
    REQUIRE(table->addPartition(p));
    p.firstLba = 6144;
    p.lastLba = 8191;
    p.uuid = *Uuid::parse("AAAAAAAA-0000-0000-0000-000000000003");
    REQUIRE(table->addPartition(p));
    REQUIRE(table->partitions().size() == 3);
    CHECK(isVersion4(table->partitions()[0].uuid));
    CHECK(isVersion4(table->partitions()[1].uuid));
    CHECK(table->partitions()[0].uuid != table->partitions()[1].uuid);
    CHECK(table->partitions()[2].uuid.toString() == "AAAAAAAA-0000-0000-0000-000000000003");
    // An update without a GUID keeps the partition's identity.
    Partition upd = table->partitions()[0];
    const Uuid before = upd.uuid;
    upd.uuid = Uuid{};
    upd.name = "renamed";
    REQUIRE(table->updatePartition(upd));
    CHECK(table->partitions()[0].uuid == before);

    auto dev = std::make_shared<MemoryDevice>(geo.sizeBytes, 512);
    REQUIRE(table->write(*dev));
    auto back = GptTable::read(dev);
    REQUIRE(back);
    CHECK((*back)->health() == Validity::Ok);
    REQUIRE((*back)->partitions().size() == 3);
    for (std::size_t i = 0; i < 3; ++i) CHECK((*back)->partitions()[i].uuid == table->partitions()[i].uuid);
    CHECK((*back)->diskGuid() == table->diskGuid());
}

TEST_CASE("GPT: a protective MBR entry that does not cover the disk is diagnosed and rebuilt") {
    auto pristine = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(pristine);
    auto dev = snapshot(*pristine);
    pokeU32(*dev, kEntry1 + 12, 1000);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    CHECK(gpt.hasProtectiveMbr());
    CHECK(!gpt.isHybridMbr());
    CHECK(gpt.health() == Validity::Warning);
    CHECK(isRepairable(gpt, "gpt.pmbr_size_mismatch"));
    const auto tree = gpt.describe();
    REQUIRE(tree.child("protective MBR")->child("entries")->children.size() == 1);
    CHECK(tree.child("protective MBR")->child("entries")->children[0].validity == Validity::Warning);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(gpt.health() == Validity::Ok);
    CHECK(!findDiagnostic(gpt, "gpt.pmbr_size_mismatch"));
    CHECK(*dev->read(0, 512) == *pristine->read(0, 512));

    auto shifted = snapshot(*pristine);
    pokeU32(*shifted, kEntry1 + 8, 2);
    auto t2 = GptTable::read(shifted);
    REQUIRE(t2);
    CHECK(isRepairable(**t2, "gpt.pmbr_size_mismatch"));
}

TEST_CASE("GPT: hybrid MBR entries must mirror GPT partitions; repair leaves LBA 0 alone") {
    auto dev = loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(dev);
    // Entry 2 mirrors GPT partition 3 (14336 + 18399 sectors) as a FAT32 LBA partition.
    pokeEntry(*dev, kEntry2, 0x00, 0x0C, 14336, 18399);
    {
        auto table = GptTable::read(dev);
        REQUIRE(table);
        auto& gpt = **table;
        CHECK(gpt.hasProtectiveMbr());
        CHECK(gpt.isHybridMbr());
        CHECK(findDiagnostic(gpt, "gpt.pmbr_hybrid"));
        CHECK(!findDiagnostic(gpt, "gpt.hybrid_entry_mismatch"));
        CHECK(!findDiagnostic(gpt, "gpt.pmbr_size_mismatch"));
        CHECK(gpt.health() <= Validity::Info);
        CHECK(gpt.describe().child("hybrid MBR") != nullptr);
    }
    // One sector off: a stale copy of the partition.
    pokeU32(*dev, kEntry2 + 8, 14337);
    // And something repairable elsewhere, so that repair really writes.
    pokeU8(*dev, 32767 * 512 + 200, 0x5A);
    auto table = GptTable::read(dev);
    REQUIRE(table);
    auto& gpt = **table;
    const auto* mismatch = findDiagnostic(gpt, "gpt.hybrid_entry_mismatch");
    REQUIRE(mismatch);
    CHECK(mismatch->severity == Validity::Warning);
    CHECK(!mismatch->repairable);
    CHECK(mismatch->message.find("0x0C") != std::string::npos);
    CHECK(isRepairable(gpt, "gpt.backup_header_reserved"));
    const auto tree = gpt.describe();
    REQUIRE(tree.child("hybrid MBR")->child("entries")->children.size() == 2);
    CHECK(tree.child("hybrid MBR")->child("entries")->children[1].validity == Validity::Warning);
    CHECK(tree.child("hybrid MBR")->child("entries")->children[0].validity == Validity::Ok);
    const auto lba0 = *dev->read(0, 512);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(*dev->read(0, 512) == lba0);
    CHECK(!findDiagnostic(gpt, "gpt.backup_header_reserved"));
    CHECK(findDiagnostic(gpt, "gpt.hybrid_entry_mismatch"));
}
