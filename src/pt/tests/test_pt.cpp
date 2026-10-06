// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/crc32.hpp"
#include "stein/pt/apm_table.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/mbr_table.hpp"
#include "stein/pt/partition_table.hpp"

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
    CHECK(gpt.lastUsableLba() == 32734);
    REQUIRE(gpt.repair(*dev, RepairOptions{}));
    CHECK(!hasDiagnostic(gpt, "gpt.backup_not_at_end"));
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
