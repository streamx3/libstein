// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/block/file_device.hpp"
#include "stein/block/concat_device.hpp"
#include "stein/block/memory_device.hpp"
#include "stein/block/overlay_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/block/sparse_file.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>

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

TEST_CASE("zeroRange: guaranteed zeros on memory, file (holes), slice and concat devices, ragged ends included") {
    // Memory: unaligned range, neighbours untouched.
    MemoryDevice mem(1 * MiB, 512);
    std::fill(mem.bytes().begin(), mem.bytes().end(), std::byte{0x5A});
    REQUIRE(mem.zeroRange(1000, 70000));
    CHECK(mem.bytes()[999] == std::byte{0x5A});
    CHECK(mem.bytes()[1000] == std::byte{0});
    CHECK(mem.bytes()[70999] == std::byte{0});
    CHECK(mem.bytes()[71000] == std::byte{0x5A});
    CHECK(mem.zeroRange(1 * MiB - 10, 20).error().category() == ErrorCategory::OutOfRange);

    // File: a hole where the filesystem allows, zeros otherwise; the content is the same either way.
    auto dir = std::filesystem::temp_directory_path() / "stein_test_zero";
    std::filesystem::create_directories(dir);
    auto path = dir / "holes.img";
    {
        auto dev = FileDevice::create(path, 16 * MiB, 512);
        REQUIRE(dev);
        std::vector<std::byte> fill(4 * MiB, std::byte{0xAA});
        REQUIRE((*dev)->writeAt(1 * MiB, fill));
        REQUIRE((*dev)->zeroRange(1 * MiB + 100, 3 * MiB));   // 100 B past a block edge, ends mid-block
        REQUIRE((*dev)->flush());
        auto before = (*dev)->read(1 * MiB, 100);
        REQUIRE(before);
        CHECK(std::all_of(before->begin(), before->end(), [](std::byte b) { return b == std::byte{0xAA}; }));
        auto zeroed = (*dev)->read(1 * MiB + 100, 3 * MiB);
        REQUIRE(zeroed);
        CHECK(std::all_of(zeroed->begin(), zeroed->end(), [](std::byte b) { return b == std::byte{0}; }));
        auto after = (*dev)->read(4 * MiB + 100, 1 * MiB - 100);
        REQUIRE(after);
        CHECK(std::all_of(after->begin(), after->end(), [](std::byte b) { return b == std::byte{0xAA}; }));
        // A later write through the stream must not resurrect anything.
        REQUIRE((*dev)->writeAt(2 * MiB, bytesOf("x")));
        auto neighbour = (*dev)->read(2 * MiB + 1, 4095);
        REQUIRE(neighbour);
        CHECK(std::all_of(neighbour->begin(), neighbour->end(), [](std::byte b) { return b == std::byte{0}; }));
    }
    {
        auto dev = FileDevice::open(path, FileDevice::Mode::ReadOnly);
        REQUIRE(dev);
        CHECK((*dev)->zeroRange(0, 4096).error().category() == ErrorCategory::Permission);
        // Everything in the zeroed range is still zero on disk, except the "x" written afterwards.
        auto zeroed = (*dev)->read(1 * MiB + 100, 3 * MiB);
        REQUIRE(zeroed);
        std::size_t nonZero = 0, xAt = 0;
        for (std::size_t i = 0; i < zeroed->size(); ++i)
            if ((*zeroed)[i] != std::byte{0}) {
                ++nonZero;
                xAt = i;
            }
        CHECK(nonZero == 1);
        CHECK(xAt == 1 * MiB - 100);
        CHECK((*zeroed)[xAt] == std::byte{'x'});
    }
    std::filesystem::remove_all(dir);

    // Slice: forwards into its window only.
    auto parent = std::make_shared<MemoryDevice>(1 * MiB, 512);
    std::fill(parent->bytes().begin(), parent->bytes().end(), std::byte{0x77});
    auto slice = SliceDevice::create(parent, Region{256 * KiB, 256 * KiB}, "s");
    REQUIRE(slice);
    REQUIRE((*slice)->zeroRange(0, 256 * KiB));
    CHECK(parent->bytes()[256 * KiB - 1] == std::byte{0x77});
    CHECK(parent->bytes()[256 * KiB] == std::byte{0});
    CHECK(parent->bytes()[512 * KiB - 1] == std::byte{0});
    CHECK(parent->bytes()[512 * KiB] == std::byte{0x77});
    CHECK((*slice)->zeroRange(0, 256 * KiB + 1).error().category() == ErrorCategory::OutOfRange);

    // Concat: a range across two parts reaches both.
    auto a = std::make_shared<MemoryDevice>(64 * KiB, 512);
    auto b = std::make_shared<MemoryDevice>(64 * KiB, 512);
    std::fill(a->bytes().begin(), a->bytes().end(), std::byte{1});
    std::fill(b->bytes().begin(), b->bytes().end(), std::byte{2});
    auto cat = ConcatDevice::create({a, b}, "cat");
    REQUIRE(cat);
    REQUIRE((*cat)->zeroRange(60 * KiB, 8 * KiB));
    CHECK(a->bytes()[60 * KiB - 1] == std::byte{1});
    CHECK(a->bytes()[60 * KiB] == std::byte{0});
    CHECK(b->bytes()[4 * KiB - 1] == std::byte{0});
    CHECK(b->bytes()[4 * KiB] == std::byte{2});
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

TEST_CASE("SparseFile: encrypted pieces round-trip, refuse without or with a wrong passphrase, detect tampering") {
    auto dir = std::filesystem::temp_directory_path() / "stein_test_piece_enc";
    std::filesystem::create_directories(dir);
    auto dev = std::make_shared<MemoryDevice>(1 * MiB);
    for (std::size_t i = 0; i < 4096; ++i) dev->bytes()[i] = static_cast<std::byte>(i);
    for (std::size_t i = 0; i < 512; ++i) dev->bytes()[700 * 1024 + i] = std::byte{0xAB};
    auto piece = SparseFile::capture(*dev, {Region{0, 4096}, Region{700 * 1024, 512}});
    REQUIRE(piece);
    const auto path = dir / "p.piece";
    REQUIRE(SparseFile::write(path, *piece, "pw", KdfParams::fast()));
    CHECK(SparseFile::isEncrypted(path));
    CHECK(SparseFile::read(path).error().category() == ErrorCategory::Permission);
    CHECK(SparseFile::read(path, "wrong").error().category() == ErrorCategory::Integrity);
    auto back = SparseFile::read(path, "pw");
    REQUIRE(back);
    CHECK(back->totalSize == 1 * MiB);
    REQUIRE(back->runs.size() == 2);
    CHECK(back->runs[1].offset == 700 * 1024);
    CHECK(back->runs[0].bytes == piece->runs[0].bytes);
    // The plaintext does not appear in the file.
    {
        std::ifstream in(path, std::ios::binary);
        std::string all((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(all.find("STEINSPARSE1") == std::string::npos);
        CHECK(all.find("STEINPIECE1E") == 0);
        CHECK(all.find("chacha20-poly1305") != std::string::npos);
        // Tamper with the last byte of the ciphertext.
        all.back() = static_cast<char>(all.back() ^ 1);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(all.data(), static_cast<std::streamsize>(all.size()));
    }
    CHECK(SparseFile::read(path, "pw").error().category() == ErrorCategory::Integrity);
    // Plain pieces still read as before.
    REQUIRE(SparseFile::write(dir / "plain.sparse", *piece));
    CHECK_FALSE(SparseFile::isEncrypted(dir / "plain.sparse"));
    CHECK(SparseFile::read(dir / "plain.sparse")->runs.size() == 2);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
