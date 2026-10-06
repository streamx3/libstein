// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/core/crc32.hpp"
#include "stein/layout/describe.hpp"
#include "stein/layout/gen/gpt.hpp"
#include "stein/layout/gen/mbr.hpp"

#include <array>

using namespace stein;
using namespace stein::layout;
using stein::test::bytesOf;

TEST_CASE("generated GptHeader: setters, getters, spec") {
    std::array<std::byte, gen::GptHeader::kSize> buf{};
    gen::GptHeader::setSignature(buf, "EFI PART");
    gen::GptHeader::setRevision(buf, 0x00010000);
    gen::GptHeader::setHeaderSize(buf, 92);
    gen::GptHeader::setMyLba(buf, 1);
    gen::GptHeader::setAlternateLba(buf, 2047);
    gen::GptHeader::setFirstUsableLba(buf, 34);
    gen::GptHeader::setLastUsableLba(buf, 2014);
    auto guid = *Uuid::parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    gen::GptHeader::setDiskGuid(buf, guid);
    gen::GptHeader::setPartitionEntriesLba(buf, 2);
    gen::GptHeader::setNumberOfPartitionEntries(buf, 128);
    gen::GptHeader::setSizeOfPartitionEntry(buf, 128);

    gen::GptHeader h(buf);
    CHECK(h.signature() == "EFI PART");
    CHECK(h.revision() == 0x00010000);
    CHECK(h.headerSize() == 92);
    CHECK(h.alternateLba() == 2047);
    CHECK(h.diskGuid() == guid);
    CHECK(gen::GptHeader::kDiskGuidOffset == 0x38);
    CHECK(gen::GptHeader::spec().size == 92);
    CHECK(gen::GptHeader::spec().find("header_crc32")->type == FieldType::Crc32);
    CHECK(gen::GptHeader::spec().find("nope") == nullptr);

    // On-disk byte order of the GUID: first group little-endian.
    CHECK(std::to_integer<int>(buf[0x38]) == 0x28);
    CHECK(std::to_integer<int>(buf[0x3B]) == 0xC1);

    auto tree = h.describe(512);
    CHECK(tree.isStruct);
    CHECK(tree.absOffset == 512);
    CHECK(tree.child("signature")->value == "EFI PART");
    CHECK(tree.child("signature")->validity == Validity::Ok);
    CHECK(tree.child("revision")->pretty == "1.0");
    CHECK(tree.child("disk_guid")->value == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    CHECK(tree.child("disk_guid")->absOffset == 512 + 0x38);
    CHECK(tree.child("header_crc32")->validity == Validity::Info);   // "not verified" until pt checks it
    CHECK(tree.child("partition_entries_crc32")->validity == Validity::Info);
    CHECK(tree.overall() == Validity::Info);

    // Break things and see the diagnostics.
    gen::GptHeader::setSignature(buf, "EFI PARX");
    gen::GptHeader::setHeaderSize(buf, 40);
    gen::GptHeader::setRevision(buf, 0x00020000);
    gen::GptHeader::setNumberOfPartitionEntries(buf, 0);
    tree = gen::GptHeader(buf).describe(512);
    CHECK(tree.child("signature")->validity == Validity::Error);
    CHECK(tree.child("header_size")->validity == Validity::Warning);
    CHECK(tree.child("revision")->validity == Validity::Warning);
    CHECK(tree.child("number_of_partition_entries")->validity == Validity::Warning);
    CHECK(tree.overall() == Validity::Error);
    auto text = tree.toText();
    CHECK(text.find("gpt_header @0x200 (92 B)") == 0);
    CHECK(text.find("[FAIL] expected \"EFI PART\"") != std::string::npos);
}

TEST_CASE("generated GptEntry: bits and utf16 name") {
    std::array<std::byte, gen::GptEntry::kSize> buf{};
    gen::GptEntry::setAttributes(buf, (1ull << 0) | (1ull << 63) | (1ull << 10));
    CHECK(gen::GptEntry::setPartitionName(buf, "EFI System Partition"));
    gen::GptEntry e(buf);
    CHECK(e.partitionName() == "EFI System Partition");
    CHECK(e.attributes() == ((1ull << 0) | (1ull << 63) | (1ull << 10)));
    auto tree = e.describe(1024);
    CHECK(tree.child("attributes")->pretty == "platform_required|ms_no_automount|unknown:0x0000000000000400");
    CHECK(tree.child("partition_name")->value == "EFI System Partition");
    CHECK(tree.child("partition_type_guid")->value == "00000000-0000-0000-0000-000000000000");
    std::string tooLong(40, 'x');
    CHECK(!gen::GptEntry::setPartitionName(buf, tooLong));
}

TEST_CASE("generated MbrEntry and ChsAddress") {
    std::array<std::byte, 16> buf{};
    gen::MbrEntry::setStatus(buf, 0x80);
    gen::MbrEntry::setType(buf, 0x83);
    gen::MbrEntry::setFirstChs(buf, ChsAddress{1023, 254, 63});
    gen::MbrEntry::setFirstLba(buf, 2048);
    gen::MbrEntry::setSectorCount(buf, 409600);
    gen::MbrEntry e(buf);
    CHECK(e.status() == 0x80);
    CHECK(e.type() == 0x83);
    CHECK(e.firstChs() == ChsAddress{1023, 254, 63});
    CHECK(e.firstChs().isLbaMarker());
    CHECK(e.firstLba() == 2048);
    CHECK(std::to_integer<int>(buf[1]) == 254);
    CHECK(std::to_integer<int>(buf[2]) == 0xFF);
    CHECK(std::to_integer<int>(buf[3]) == 0xFF);
    auto tree = e.describe(0x1BE);
    CHECK(tree.child("status")->pretty == "active (bootable)");
    CHECK(tree.child("first_chs")->value == "C1023/H254/S63");
    CHECK(tree.child("first_chs")->pretty == "beyond CHS range (LBA only)");
    gen::MbrEntry::setStatus(buf, 0x01);
    CHECK(gen::MbrEntry(buf).describe(0).child("status")->validity == Validity::Warning);
}

TEST_CASE("generated MbrSector: boot signature") {
    std::array<std::byte, 512> buf{};
    auto tree = gen::MbrSector(buf).describe(0);
    CHECK(tree.child("boot_signature")->validity == Validity::Error);
    gen::MbrSector::setBootSignature(buf, 0xAA55);
    CHECK(std::to_integer<int>(buf[510]) == 0x55);
    CHECK(std::to_integer<int>(buf[511]) == 0xAA);
    tree = gen::MbrSector(buf).describe(0);
    CHECK(tree.child("boot_signature")->validity == Validity::Ok);
    CHECK(tree.child("entries")->size == 64);
    CHECK(tree.child("entries")->absOffset == 0x1BE);
    CHECK(tree.child("bootstrap")->value == "<440 bytes>");
    CHECK(gen::MbrSector::kEntriesOffset == 0x1BE);
}

TEST_CASE("describe() with too few bytes") {
    std::array<std::byte, 10> buf{};
    auto tree = describe(gen::GptHeader::spec(), buf, 0);
    CHECK(tree.validity == Validity::Error);
    CHECK(tree.child("my_lba")->validity == Validity::Error);
    CHECK(tree.child("signature")->validity == Validity::Error);   // "expected" since bytes are zero
}
