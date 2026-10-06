// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/block/file_device.hpp"
#include "stein/block/concat_device.hpp"
#include "stein/block/memory_device.hpp"
#include "stein/block/overlay_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/block/sparse_file.hpp"

#include <array>
#include <filesystem>

using namespace stein;
using stein::test::bytesOf;

TEST_CASE("MemoryDevice read/write/range") {
    auto dev = std::make_shared<MemoryDevice>(4096, 512);
    CHECK(dev->size() == 4096);
    CHECK(dev->geometry().sectors() == 8);
    CHECK(dev->writeAt(1000, bytesOf("hello")));
    auto got = dev->read(1000, 5);
    REQUIRE(got);
    CHECK(std::string(reinterpret_cast<const char*>(got->data()), 5) == "hello");
    auto bad = dev->read(4094, 4);
    CHECK(!bad);
    CHECK(bad.error().category() == ErrorCategory::OutOfRange);
    CHECK(dev->zero(1000, 5));
    got = dev->read(1000, 5);
    CHECK(got->at(0) == std::byte{0});
    dev->setReadOnly(true);
    CHECK(dev->writeAt(0, bytesOf("x")).error().category() == ErrorCategory::Permission);
    auto sectors = dev->readSectors(1, 2);
    REQUIRE(sectors);
    CHECK(sectors->size() == 1024);
}

TEST_CASE("SliceDevice maps offsets onto the parent") {
    auto parent = std::make_shared<MemoryDevice>(8192, 512);
    auto slice = SliceDevice::create(parent, Region{1024, 2048}, "part1");
    REQUIRE(slice);
    CHECK((*slice)->size() == 2048);
    CHECK((*slice)->name() == "part1");
    CHECK((*slice)->writeAt(0, bytesOf("ABC")));
    auto onParent = parent->read(1024, 3);
    CHECK(std::string(reinterpret_cast<const char*>(onParent->data()), 3) == "ABC");
    CHECK((*slice)->read(2046, 4).error().category() == ErrorCategory::OutOfRange);
    CHECK((*slice)->extentsOnParent() == std::vector<Region>{Region{1024, 2048}});
    CHECK((*slice)->parent() == parent);
    CHECK(!SliceDevice::create(parent, Region{8000, 1000}));
    ReadOnlyDevice ro(*slice);
    CHECK(ro.isReadOnly());
    CHECK(ro.writeAt(0, bytesOf("z")).error().category() == ErrorCategory::Permission);
    std::array<std::byte, 3> buf{};
    CHECK(ro.readAt(0, buf));
    CHECK(buf[0] == std::byte{'A'});
}

TEST_CASE("FileDevice create/open/sparse") {
    auto dir = std::filesystem::temp_directory_path() / "stein_test_block";
    std::filesystem::create_directories(dir);
    auto path = dir / "disk.img";
    {
        auto dev = FileDevice::create(path, 16 * MiB, 4096);
        REQUIRE(dev);
        CHECK((*dev)->size() == 16 * MiB);
        CHECK((*dev)->sectorSize() == 4096);
        CHECK((*dev)->writeAt(10 * MiB, bytesOf("stein")));
        CHECK((*dev)->flush());
    }
    CHECK(std::filesystem::file_size(path) == 16 * MiB);
    {
        auto dev = FileDevice::open(path, FileDevice::Mode::ReadOnly);
        REQUIRE(dev);
        auto got = (*dev)->read(10 * MiB, 5);
        REQUIRE(got);
        CHECK(std::string(reinterpret_cast<const char*>(got->data()), 5) == "stein");
        CHECK((*dev)->writeAt(0, bytesOf("x")).error().category() == ErrorCategory::Permission);
        CHECK((*dev)->read(16 * MiB - 2, 4).error().category() == ErrorCategory::OutOfRange);
    }
    CHECK(!FileDevice::open(dir / "missing.img", FileDevice::Mode::ReadOnly));
    std::filesystem::remove_all(dir);
}

TEST_CASE("SparseFile capture/write/read/apply") {
    auto dir = std::filesystem::temp_directory_path() / "stein_test_sparse";
    std::filesystem::create_directories(dir);
    auto src = std::make_shared<MemoryDevice>(1 * MiB, 4096);
    CHECK(src->writeAt(0, bytesOf("head")));
    CHECK(src->writeAt(512 * KiB, bytesOf("middle")));
    auto captured = SparseFile::capture(*src, {Region{0, 4096}, Region{512 * KiB, 4096}});
    REQUIRE(captured);
    CHECK(captured->runs.size() == 2);
    CHECK(captured->sectorSize == 4096);
    auto path = dir / "piece.sparse";
    REQUIRE(SparseFile::write(path, *captured));
    auto loaded = SparseFile::loadIntoMemory(path);
    REQUIRE(loaded);
    CHECK((*loaded)->size() == 1 * MiB);
    CHECK((*loaded)->sectorSize() == 4096);
    auto mid = (*loaded)->read(512 * KiB, 6);
    CHECK(std::string(reinterpret_cast<const char*>(mid->data()), 6) == "middle");
    MemoryDevice small(8 * KiB, 512);
    CHECK(SparseFile::apply(*captured, small).error().category() == ErrorCategory::OutOfRange);
    CHECK(SparseFile::read(dir / "nope.sparse").error().category() == ErrorCategory::NotFound);
    std::filesystem::remove_all(dir);
}

TEST_CASE("OverlayDevice: copy-on-write, dirty regions, commit") {
    auto base = std::make_shared<MemoryDevice>(64 * KiB, 512);
    std::fill(base->bytes().begin(), base->bytes().end(), std::byte{0x11});
    auto ov = OverlayDevice::create(base, 4096);
    CHECK(!ov->hasChanges());
    CHECK(ov->size() == 64 * KiB);
    // Read-through.
    auto r = ov->read(10000, 16);
    REQUIRE(r);
    CHECK(r->at(0) == std::byte{0x11});
    // Write straddling two overlay blocks; base must stay untouched.
    CHECK(ov->writeAt(4096 - 3, bytesOf("abcdef")));
    CHECK(base->bytes()[4095] == std::byte{0x11});
    auto back = ov->read(4096 - 3, 6);
    CHECK(std::string(reinterpret_cast<const char*>(back->data()), 6) == "abcdef");
    // Untouched bytes inside the dirty blocks still read from the base copy.
    CHECK(ov->read(100, 1)->at(0) == std::byte{0x11});
    auto dirty = ov->dirtyRegions();
    REQUIRE(dirty.size() == 1);
    CHECK(dirty[0] == Region{0, 8192});
    CHECK(ov->dirtyBytes() == 8192);
    CHECK(ov->discard(60 * KiB, 4096));
    CHECK(ov->dirtyRegions().size() == 2);
    CHECK(ov->read(60 * KiB, 1)->at(0) == std::byte{0});
    ov->discardChanges();
    CHECK(!ov->hasChanges());
    CHECK(ov->read(4096 - 3, 1)->at(0) == std::byte{0x11});
    // Commit applies to the base.
    CHECK(ov->writeAt(500, bytesOf("Z")));
    REQUIRE(ov->commit());
    CHECK(base->bytes()[500] == std::byte{'Z'});
    CHECK(!ov->hasChanges());
    CHECK(ov->read(70 * KiB, 1).error().category() == ErrorCategory::OutOfRange);
}

TEST_CASE("ConcatDevice: parts laid end to end") {
    auto a = std::make_shared<MemoryDevice>(4096);
    auto b = std::make_shared<MemoryDevice>(1024);
    auto c = std::make_shared<MemoryDevice>(700);   // last part may be ragged
    std::fill(a->bytes().begin(), a->bytes().end(), std::byte{'A'});
    std::fill(b->bytes().begin(), b->bytes().end(), std::byte{'B'});
    std::fill(c->bytes().begin(), c->bytes().end(), std::byte{'C'});
    auto cat = ConcatDevice::create({a, b, c});
    REQUIRE(cat);
    CHECK((*cat)->size() == 4096 + 1024 + 700);
    CHECK((*cat)->sectorSize() == 512);
    auto r = (*cat)->read(4090, 1030 + 6);
    REQUIRE(r);
    CHECK(r->at(0) == std::byte{'A'});
    CHECK(r->at(5) == std::byte{'A'});
    CHECK(r->at(6) == std::byte{'B'});
    CHECK(r->at(6 + 1023) == std::byte{'B'});
    CHECK(r->at(6 + 1024) == std::byte{'C'});
    CHECK(r->back() == std::byte{'C'});
    // Write straddling all three parts.
    std::vector<std::byte> w(4096 - 4000 + 1024 + 10, std::byte{'x'});
    REQUIRE((*cat)->writeAt(4000, w));
    CHECK(a->bytes()[4000] == std::byte{'x'});
    CHECK(b->bytes()[0] == std::byte{'x'});
    CHECK(b->bytes()[1023] == std::byte{'x'});
    CHECK(c->bytes()[9] == std::byte{'x'});
    CHECK(c->bytes()[10] == std::byte{'C'});
    CHECK((*cat)->read(5820, 1).error().category() == ErrorCategory::OutOfRange);
    CHECK((*cat)->locate(4096) == std::pair<std::size_t, ByteCount>{1, 0});
    // A ragged middle part is refused.
    CHECK_FALSE(ConcatDevice::create({c, a}));
    CHECK_FALSE(ConcatDevice::create({}));
}
