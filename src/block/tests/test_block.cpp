// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/block/file_device.hpp"
#include "stein/block/memory_device.hpp"
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
