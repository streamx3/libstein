// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/block/file_device.hpp"
#include "stein/block/cached_device.hpp"
#include "stein/block/concat_device.hpp"
#include "stein/block/memory_device.hpp"
#include "stein/block/overlay_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/block/sparse_file.hpp"
#include "stein/core/endian.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

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

namespace {

// A device whose byte at i is a function of i, so any read can be checked without a reference copy.
std::byte pattern(ByteCount i) { return std::byte((i * 131 + (i >> 8) * 7 + 3) & 0xff); }
std::shared_ptr<MemoryDevice> patternDevice(ByteCount size) {
    auto dev = std::make_shared<MemoryDevice>(size, 512);
    auto b = dev->bytes();
    for (ByteCount i = 0; i < size; ++i) b[i] = pattern(i);
    return dev;
}
bool matches(std::span<const std::byte> got, ByteCount offset) {
    for (std::size_t i = 0; i < got.size(); ++i)
        if (got[i] != pattern(offset + i)) return false;
    return true;
}

// MemoryDevice is not thread-safe; the real inner devices (FileDevice, a decrypting payload) take a
// lock, so the concurrency test wraps it in one and counts the reads that reach it.
class LockedDevice final : public BlockDevice {
public:
    explicit LockedDevice(std::shared_ptr<MemoryDevice> inner) : m_inner(std::move(inner)) {}
    std::string name() const override { return "locked"; }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        std::lock_guard lock(m_mutex);
        ++reads;
        return m_inner->readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        std::lock_guard lock(m_mutex);
        return m_inner->writeAt(offset, src);
    }
    Expected<void> flush() override { return {}; }
    std::uint64_t reads = 0;

private:
    std::shared_ptr<MemoryDevice> m_inner;
    std::mutex m_mutex;
};

// A device with one unreadable sector: every read touching it fails, every other read succeeds.
class BadSectorDevice final : public BlockDevice {
public:
    BadSectorDevice(std::shared_ptr<MemoryDevice> inner, ByteCount badOffset) : m_inner(std::move(inner)), m_bad(badOffset) {}
    std::string name() const override { return "bad-sector"; }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        ++reads;
        if (offset < m_bad + 512 && offset + dst.size() > m_bad) return fail(ErrorCategory::Io, "unreadable sector " + std::to_string(m_bad / 512));
        return m_inner->readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override { return fail(ErrorCategory::Permission, "read-only"); }
    Expected<void> flush() override { return {}; }
    std::uint64_t reads = 0;

private:
    std::shared_ptr<MemoryDevice> m_inner;
    ByteCount m_bad;
};

} // namespace

TEST_CASE("CachedDevice: hits and misses, LRU eviction within the budget, partial reads across chunks, forwarding") {
    auto inner = patternDevice(64 * KiB);
    auto cache = CachedDevice::create(inner, {4096, 16 * KiB});   // room for four chunks
    CHECK(cache->options().chunkSize == 4096);
    CHECK(cache->options().budget == 16 * KiB);
    CHECK(cache->name() == inner->name());
    CHECK(cache->size() == 64 * KiB);
    CHECK(cache->sectorSize() == 512);
    CHECK(cache->parent() == inner);
    CHECK(cache->extentsOnParent() == std::vector<Region>{Region{0, 64 * KiB}});
    CHECK_FALSE(cache->isReadOnly());
    CHECK(cache->flush());
    auto s = cache->stats();
    CHECK(s.hits == 0);
    CHECK(s.misses == 0);
    CHECK(s.chunks == 0);

    // The first read of a chunk misses and fills the whole chunk; the next read inside it hits.
    auto r = cache->read(100, 50);
    REQUIRE(r);
    CHECK(matches(*r, 100));
    s = cache->stats();
    CHECK(s.misses == 1);
    CHECK(s.hits == 0);
    CHECK(s.chunks == 1);
    CHECK(s.cachedBytes == 4096);
    r = cache->read(4000, 90);
    REQUIRE(r);
    CHECK(matches(*r, 4000));
    s = cache->stats();
    CHECK(s.misses == 1);
    CHECK(s.hits == 1);
    // Chunks 1, 2, 3 fill the budget.
    for (ByteCount c = 1; c <= 3; ++c) {
        r = cache->read(c * 4096 + 1, 10);
        REQUIRE(r);
        CHECK(matches(*r, c * 4096 + 1));
    }
    s = cache->stats();
    CHECK(s.misses == 4);
    CHECK(s.chunks == 4);
    CHECK(s.cachedBytes == 16 * KiB);
    CHECK(s.evictions == 0);
    // Chunk 4 evicts the least recently used one, chunk 0 ...
    r = cache->read(4 * 4096, 4096);
    REQUIRE(r);
    CHECK(matches(*r, 4 * 4096));
    s = cache->stats();
    CHECK(s.chunks == 4);
    CHECK(s.cachedBytes == 16 * KiB);
    CHECK(s.evictions == 1);
    // ... so chunk 0 misses again and pushes out chunk 1 (now the oldest); chunk 2 is still there
    // and its hit moves it to the front; chunk 1 misses and pushes out chunk 3.
    REQUIRE(cache->read(0, 1));
    REQUIRE(cache->read(8192, 1));
    REQUIRE(cache->read(4096, 1));
    s = cache->stats();
    CHECK(s.misses == 7);
    CHECK(s.hits == 2);
    CHECK(s.evictions == 3);
    CHECK(s.chunks == 4);

    // A read spanning chunk boundaries is one lookup per chunk and byte-exact.
    r = cache->read(4096 - 10, 20);
    REQUIRE(r);
    CHECK(matches(*r, 4096 - 10));
    const auto before = cache->stats();
    r = cache->read(4000, 9000);   // chunks 0 to 3
    REQUIRE(r);
    CHECK(matches(*r, 4000));
    s = cache->stats();
    CHECK(s.hits + s.misses == before.hits + before.misses + 4);
    // Whole-device read through the small cache: correct, and the cache never exceeds the budget.
    r = cache->read(0, 64 * KiB);
    REQUIRE(r);
    CHECK(matches(*r, 0));
    s = cache->stats();
    CHECK(s.cachedBytes <= 16 * KiB);
    CHECK(s.chunks == 4);
    CHECK(cache->read(64 * KiB - 1, 2).error().category() == ErrorCategory::OutOfRange);
    CHECK(cache->read(64 * KiB, 0));
}

TEST_CASE("CachedDevice: writes pass through and drop the chunks they touch; discard and zeroRange too; invalidate() for changes behind its back") {
    auto inner = patternDevice(32 * KiB);
    auto cache = CachedDevice::create(inner, {4096, 64 * KiB});
    REQUIRE(cache->read(0, 32 * KiB));   // everything cached
    CHECK(cache->stats().chunks == 8);
    REQUIRE(cache->writeAt(4096 - 2, bytesOf("WXYZ")));   // straddles chunks 0 and 1
    auto s = cache->stats();
    CHECK(s.chunks == 6);
    CHECK(s.cachedBytes == 6 * 4096);
    CHECK(s.evictions == 0);
    CHECK(inner->bytes()[4094] == std::byte{'W'});
    CHECK(inner->bytes()[4097] == std::byte{'Z'});
    auto r = cache->read(4096 - 2, 4);
    REQUIRE(r);
    CHECK(std::string(reinterpret_cast<const char*>(r->data()), 4) == "WXYZ");
    CHECK(cache->stats().misses == 8 + 2);
    CHECK(cache->stats().chunks == 8);
    // An untouched chunk is still served from the cache and still right.
    r = cache->read(8192, 16);
    REQUIRE(r);
    CHECK(matches(*r, 8192));
    CHECK(cache->stats().hits == 1);
    // zeroRange and discard go to the inner device and drop their chunks.
    REQUIRE(cache->zeroRange(8192, 100));
    CHECK(cache->stats().chunks == 7);
    r = cache->read(8192, 101);
    REQUIRE(r);
    CHECK(r->at(99) == std::byte{0});
    CHECK(r->at(100) == pattern(8292));
    REQUIRE(cache->discard(16384, 4096));
    CHECK(cache->read(16384, 1)->at(0) == std::byte{0});
    // A change that bypasses the cache (chunk 5 is still held from the first read) is not seen until invalidate().
    inner->bytes()[24000] = std::byte{0xEE};
    CHECK(cache->read(24000, 1)->at(0) == pattern(24000));
    cache->invalidate();
    CHECK(cache->stats().chunks == 0);
    CHECK(cache->read(24000, 1)->at(0) == std::byte{0xEE});
    // Read-only inner: the cache is read-only and refuses writes before touching anything.
    inner->setReadOnly(true);
    CHECK(cache->isReadOnly());
    REQUIRE(cache->read(0, 4096));
    CHECK(cache->writeAt(0, bytesOf("x")).error().category() == ErrorCategory::Permission);
    CHECK(cache->writeAt(40 * KiB, bytesOf("x")).error().category() == ErrorCategory::OutOfRange);
    CHECK(cache->read(0, 1)->at(0) == pattern(0));
}

TEST_CASE("CachedDevice: a size that is not a multiple of the chunk size, and a budget below one chunk") {
    auto inner = patternDevice(10000);
    auto cache = CachedDevice::create(inner, {4096, 0});
    CHECK(cache->options().budget == 4096);   // raised to one chunk
    auto r = cache->read(9000, 1000);
    REQUIRE(r);
    CHECK(matches(*r, 9000));
    auto s = cache->stats();
    CHECK(s.chunks == 1);
    CHECK(s.cachedBytes == 10000 - 8192);   // the ragged last chunk
    CHECK(cache->read(9999, 1));
    CHECK(cache->read(9999, 2).error().category() == ErrorCategory::OutOfRange);
    CHECK(cache->read(10000, 0));
    // The whole device through a one-chunk cache: every chunk evicts the previous one, bytes exact.
    r = cache->read(0, 10000);
    REQUIRE(r);
    CHECK(matches(*r, 0));
    s = cache->stats();
    CHECK(s.chunks == 1);
    CHECK(s.misses == 4);
    CHECK(s.evictions == 3);
    CHECK(s.cachedBytes == 10000 - 8192);
    // A zero chunk size takes the default.
    CHECK(CachedDevice::create(inner, {0, 0})->options().chunkSize == 256 * KiB);
    CHECK(CachedDevice::create(inner)->options().budget == 64 * MiB);
}

TEST_CASE("CachedDevice: concurrent readers and a writer see consistent bytes while chunks churn") {
    auto memory = patternDevice(1 * MiB);
    auto inner = std::make_shared<LockedDevice>(memory);
    auto cache = CachedDevice::create(inner, {8 * KiB, 64 * KiB});   // eight chunks: constant eviction
    std::atomic<int> failures{0};
    constexpr int kReads = 3000;
    auto reader = [&](std::uint64_t seed) {
        std::uint64_t s = seed;
        std::vector<std::byte> buf;
        for (int i = 0; i < kReads; ++i) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            const ByteCount len = 1 + s % 20000;
            const ByteCount off = (s >> 20) % (1 * MiB - len);
            buf.resize(static_cast<std::size_t>(len));
            if (!cache->readAt(off, buf) || !matches(buf, off)) ++failures;
        }
    };
    // The writer rewrites ranges with the bytes they already hold, so the pattern stays true for
    // every reader while the invalidation path runs against them.
    auto writer = [&] {
        std::vector<std::byte> v(3000);
        for (int i = 0; i < 1000; ++i) {
            const ByteCount off = (i * 7919ull) % (1 * MiB - v.size());
            for (std::size_t j = 0; j < v.size(); ++j) v[j] = pattern(off + j);
            if (!cache->writeAt(off, v)) ++failures;
        }
    };
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) threads.emplace_back(reader, 0x1234567ull + static_cast<std::uint64_t>(t));
    threads.emplace_back(writer);
    for (auto& t : threads) t.join();
    CHECK(failures == 0);
    auto s = cache->stats();
    CHECK(s.hits + s.misses >= 4 * kReads);
    CHECK(s.hits > 0);
    CHECK(s.cachedBytes <= 64 * KiB);
    CHECK(s.chunks <= 8);
    CHECK(inner->reads == s.misses);   // every inner read is a counted miss
    // After the churn a single-threaded pass is still exact.
    auto r = cache->read(0, 1 * MiB);
    REQUIRE(r);
    CHECK(matches(*r, 0));
}

TEST_CASE("RunListDevice: a piece as a device that holds only its runs; zeros in the gaps, read-only, overlaps resolve like apply()") {
    // A table piece from a 2 TiB disk: three small runs, nothing else allocated.
    SparseFile::Contents c;
    c.totalSize = 2 * TiB;
    c.sectorSize = 4096;
    std::vector<std::byte> mbr(512, std::byte{0x55});
    std::vector<std::byte> hdr(4096);
    for (std::size_t i = 0; i < hdr.size(); ++i) hdr[i] = std::byte(i & 0xff);
    c.runs.push_back({0, mbr});
    c.runs.push_back({1 * MiB, hdr});
    c.runs.push_back({2 * TiB - 4096, hdr});   // the backup header at the very end
    auto dev = RunListDevice::create(c, "disk.sparse");
    REQUIRE(dev);
    CHECK((*dev)->name() == "disk.sparse");
    CHECK((*dev)->size() == 2 * TiB);
    CHECK((*dev)->sectorSize() == 4096);
    CHECK((*dev)->isReadOnly());
    CHECK((*dev)->storedBytes() == 512 + 2 * 4096);
    CHECK((*dev)->runs().size() == 3);
    CHECK((*dev)->flush());
    // Inside a run: the run's bytes.
    auto r = (*dev)->read(1 * MiB + 100, 16);
    REQUIRE(r);
    for (std::size_t i = 0; i < 16; ++i) CHECK(r->at(i) == std::byte((100 + i) & 0xff));
    // Across a run's end: bytes, then zeros.
    r = (*dev)->read(500, 24);
    REQUIRE(r);
    CHECK(r->at(11) == std::byte{0x55});
    CHECK(r->at(12) == std::byte{0});
    CHECK(r->at(23) == std::byte{0});
    // A gap, far from any run, and a read spanning a gap between two runs.
    r = (*dev)->read(1 * GiB, 8192);
    REQUIRE(r);
    CHECK(std::all_of(r->begin(), r->end(), [](std::byte b) { return b == std::byte{0}; }));
    r = (*dev)->read(0, 1 * MiB + 4096);
    REQUIRE(r);
    CHECK(r->at(511) == std::byte{0x55});
    CHECK(r->at(512) == std::byte{0});
    CHECK(r->at(1 * MiB - 1) == std::byte{0});
    CHECK(r->at(1 * MiB) == std::byte{0});
    CHECK(r->at(1 * MiB + 4095) == std::byte{0xff});
    // The last sector, the end, and past the end.
    r = (*dev)->readSectors(2 * TiB / 4096 - 1, 1);
    REQUIRE(r);
    CHECK(r->at(0) == std::byte{0});
    CHECK(r->at(4095) == std::byte{0xff});
    CHECK((*dev)->read(2 * TiB, 0));
    CHECK((*dev)->read(2 * TiB - 1, 2).error().category() == ErrorCategory::OutOfRange);
    CHECK((*dev)->read(3 * TiB, 1).error().category() == ErrorCategory::OutOfRange);
    // Writes of every kind are refused before anything happens.
    CHECK((*dev)->writeAt(0, bytesOf("x")).error().category() == ErrorCategory::Permission);
    CHECK((*dev)->zeroRange(0, 512).error().category() == ErrorCategory::Permission);
    CHECK((*dev)->discard(0, 512).error().category() == ErrorCategory::Permission);
    CHECK((*dev)->read(0, 1)->at(0) == std::byte{0x55});

    // Overlapping runs: the later run in the piece wins, as when apply() writes them in order.
    SparseFile::Contents o;
    o.totalSize = 4096;
    o.runs.push_back({0, std::vector<std::byte>(1000, std::byte{'X'})});
    o.runs.push_back({400, std::vector<std::byte>(100, std::byte{'Y'})});     // inside X
    o.runs.push_back({900, std::vector<std::byte>(300, std::byte{'Z'})});     // over X's tail
    o.runs.push_back({1100, std::vector<std::byte>(50, std::byte{'W'})});     // inside Z
    o.runs.push_back({2000, {}});                                              // empty: dropped
    auto odev = RunListDevice::create(o);
    REQUIRE(odev);
    auto mem = std::make_shared<MemoryDevice>(o.totalSize, o.sectorSize);
    REQUIRE(SparseFile::apply(o, *mem));
    auto whole = (*odev)->read(0, o.totalSize);
    REQUIRE(whole);
    CHECK(*whole == std::vector<std::byte>(mem->bytes().begin(), mem->bytes().end()));
    CHECK(whole->at(399) == std::byte{'X'});
    CHECK(whole->at(400) == std::byte{'Y'});
    CHECK(whole->at(500) == std::byte{'X'});
    CHECK(whole->at(999) == std::byte{'Z'});
    CHECK(whole->at(1100) == std::byte{'W'});
    CHECK(whole->at(1150) == std::byte{'Z'});
    CHECK(whole->at(1200) == std::byte{0});
    CHECK((*odev)->storedBytes() == 1200);
    for (std::size_t i = 1; i < (*odev)->runs().size(); ++i)
        CHECK((*odev)->runs()[i - 1].offset + (*odev)->runs()[i - 1].bytes.size() <= (*odev)->runs()[i].offset);
    // Every short read agrees with the memory copy too.
    for (ByteCount off = 0; off < o.totalSize; off += 37) {
        const ByteCount len = std::min<ByteCount>(53, o.totalSize - off);
        auto a = (*odev)->read(off, len);
        auto b = mem->read(off, len);
        REQUIRE(a);
        REQUIRE(b);
        CHECK(*a == *b);
    }

    // Runs that do not fit, and a bad sector size.
    SparseFile::Contents bad;
    bad.totalSize = 1024;
    bad.runs.push_back({1000, std::vector<std::byte>(100)});
    CHECK(RunListDevice::create(bad).error().category() == ErrorCategory::OutOfRange);
    bad.runs.clear();
    bad.sectorSize = 0;
    CHECK(RunListDevice::create(bad).error().category() == ErrorCategory::InvalidArgument);
}

TEST_CASE("SparseFile::openAsDevice: a fixture piece reads byte for byte like its in-memory copy, encrypted pieces included") {
    const std::string fixture = std::string(STEIN_FIXTURE_DIR) + "/pt/gpt_basic.sparse";
    auto piece = SparseFile::read(fixture);
    REQUIRE(piece);
    auto mem = SparseFile::loadIntoMemory(fixture);
    REQUIRE(mem);
    auto dev = SparseFile::openAsDevice(fixture);
    REQUIRE(dev);
    CHECK((*dev)->name() == "gpt_basic.sparse");
    CHECK((*dev)->size() == piece->totalSize);
    CHECK((*dev)->sectorSize() == piece->sectorSize);
    CHECK((*dev)->isReadOnly());
    auto all = (*dev)->read(0, (*dev)->size());
    REQUIRE(all);
    CHECK(*all == std::vector<std::byte>((*mem)->bytes().begin(), (*mem)->bytes().end()));
    // The same piece encrypted: the passphrase is required and then the bytes are the same.
    auto dir = std::filesystem::temp_directory_path() / "stein_test_runlist";
    std::filesystem::create_directories(dir);
    const auto path = dir / "table.piece";
    REQUIRE(SparseFile::write(path, *piece, "pw", KdfParams::pbkdf2()));
    CHECK(SparseFile::openAsDevice(path).error().category() == ErrorCategory::Permission);
    CHECK(SparseFile::openAsDevice(path, "wrong").error().category() == ErrorCategory::Integrity);
    auto enc = SparseFile::openAsDevice(path, "pw");
    REQUIRE(enc);
    CHECK((*enc)->name() == "table.piece");
    auto encAll = (*enc)->read(0, (*enc)->size());
    REQUIRE(encAll);
    CHECK(*encAll == *all);
    CHECK(SparseFile::openAsDevice(dir / "missing.sparse").error().category() == ErrorCategory::NotFound);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("CachedDevice: one unreadable sector costs only the reads that touch it, not the whole chunk around it") {
    // A disk with a single bad sector: the chunk read that would fill the cache fails, but the
    // bytes the caller asked for may be perfectly readable. They are served with an uncached read of
    // exactly that window; only a window touching the bad sector gets the inner device's error.
    auto inner = std::make_shared<BadSectorDevice>(patternDevice(64 * KiB), 5 * 512);   // sector 5, in chunk 0
    auto cache = CachedDevice::create(inner, {4096, 16 * KiB});
    auto r = cache->read(0, 512);
    REQUIRE(r);
    CHECK(matches(*r, 0));
    auto s = cache->stats();
    CHECK(s.misses == 1);
    CHECK(s.chunks == 0);   // an incomplete chunk is not kept
    r = cache->read(6 * 512 + 100, 500);   // still inside chunk 0
    REQUIRE(r);
    CHECK(matches(*r, 6 * 512 + 100));
    CHECK(cache->stats().chunks == 0);
    CHECK(cache->stats().misses == 2);
    // The bad sector itself, and a window straddling into it: the inner device's error as is.
    auto bad = cache->read(5 * 512, 512);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().category() == ErrorCategory::Io);
    CHECK_FALSE(cache->read(4 * 512 + 100, 1024));
    CHECK(cache->stats().chunks == 0);
    // A read running from the bad chunk into the next one: both halves right, the next chunk cached.
    r = cache->read(6 * 512, 4096);
    REQUIRE(r);
    CHECK(matches(*r, 6 * 512));
    CHECK(cache->stats().chunks == 1);
    // Every other chunk behaves as always.
    r = cache->read(8192, 100);
    REQUIRE(r);
    CHECK(matches(*r, 8192));
    CHECK(cache->stats().chunks == 2);
    REQUIRE(cache->read(8192, 100));
    CHECK(cache->stats().hits == 1);
}

TEST_CASE("SparseFile::parse: a run length near 2^64 is an InvalidFormat error, not a wrapped range") {
    // A run header saying "len = 2^64 - 16" wraps pos + len below data.size() and offset + len below
    // totalSize, and assign() then gets a reversed range (std::length_error, which nothing catches:
    // every read-only command on such a file aborted). The checks must be overflow-free.
    auto piece = [](ByteCount offset, std::uint64_t len, std::size_t payload) {
        std::vector<std::byte> buf(24 + 16 + payload);
        std::memcpy(buf.data(), SparseFile::kMagic, 12);
        storeLe64(buf.data() + 12, 1 * MiB);
        storeLe32(buf.data() + 20, 512);
        storeLe64(buf.data() + 24, offset);
        storeLe64(buf.data() + 32, len);
        return buf;
    };
    const auto huge = piece(16, ~std::uint64_t{0} - 15, 16);   // 40 + len wraps to 24; 16 + len wraps to 0
    auto r = SparseFile::parse(huge, "crafted");
    REQUIRE_FALSE(r);
    CHECK(r.error().category() == ErrorCategory::InvalidFormat);
    // offset + len wraps to 8, below totalSize, while the 16 payload bytes satisfy the length check.
    r = SparseFile::parse(piece(~std::uint64_t{0} - 7, 16, 16), "crafted");
    REQUIRE_FALSE(r);
    CHECK(r.error().category() == ErrorCategory::InvalidFormat);
    // A run merely reaching past the buffer or the piece is the same error; a well-formed one parses.
    CHECK(SparseFile::parse(piece(0, 17, 16), "crafted").error().category() == ErrorCategory::InvalidFormat);
    CHECK(SparseFile::parse(piece(1 * MiB - 8, 16, 16), "crafted").error().category() == ErrorCategory::InvalidFormat);
    auto ok = SparseFile::parse(piece(512, 16, 16), "crafted");
    REQUIRE(ok);
    CHECK(ok->runs.size() == 1);
    CHECK(ok->runs[0].offset == 512);
    CHECK(ok->runs[0].bytes.size() == 16);
    // The same crafted piece on disk, opened the way the CLI opens one.
    auto dir = std::filesystem::temp_directory_path() / "stein_test_sparse_overflow";
    std::filesystem::create_directories(dir);
    const auto path = dir / "huge.sparse";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(huge.data()), static_cast<std::streamsize>(huge.size()));
    }
    auto dev = SparseFile::openAsDevice(path);
    REQUIRE_FALSE(dev);
    CHECK(dev.error().category() == ErrorCategory::InvalidFormat);
    CHECK(SparseFile::read(path).error().category() == ErrorCategory::InvalidFormat);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
