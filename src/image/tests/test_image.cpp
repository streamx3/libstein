// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/hash.hpp"
#include "stein/image/operations.hpp"
#include "stein/image/stein_format.hpp"
#include "stein/probe/topology.hpp"

#include <filesystem>
#include <fstream>
#include <random>

using namespace stein;
using namespace stein::image;
using stein::test::loadSparseFixture;

namespace {

struct Sink : ProgressSink {
    int updates = 0;
    std::vector<std::string> messages;
    void onProgress(const ProgressSnapshot&) override { ++updates; }
    void onMessage(std::string_view m) override { messages.emplace_back(m); }
};

std::filesystem::path tmpDir(const char* name) {
    auto d = std::filesystem::temp_directory_path() / name;
    stein::test::removeTree(d);
    std::filesystem::create_directories(d);
    return d;
}

// A 16 MiB source: GPT fixture with a FAT12 fs in partition 1, random data in partition 3, zeros elsewhere.
std::shared_ptr<MemoryDevice> makeSource() {
    auto disk = loadSparseFixture("pt/gpt_basic.sparse");
    auto fat = loadSparseFixture("fs/fat12.sparse");
    std::copy_n(fat->bytes().begin(), 64 * 1024, disk->bytes().begin() + 2048 * 512);
    std::mt19937 rng(7);
    for (ByteCount off = 14336 * 512; off < 14336 * 512 + 3 * MiB; ++off) disk->bytes()[off] = std::byte(static_cast<unsigned char>(rng()));
    return disk;
}

std::string sha256Of(BlockDevice& dev) {
    auto h = Hasher::create(HashAlgorithm::Sha256);
    std::vector<std::byte> buf(1 * MiB);
    for (ByteCount off = 0; off < dev.size(); off += buf.size()) {
        const auto len = std::min<ByteCount>(buf.size(), dev.size() - off);
        REQUIRE(dev.readAt(off, std::span<std::byte>(buf).first(len)));
        h->update(std::span<const std::byte>(buf).first(len));
    }
    return Hasher::hex(h->finish());
}

} // namespace

TEST_CASE("stein image: create, info, open as device, probe through it, verify, restore") {
    auto dir = tmpDir("stein_test_image");
    auto src = makeSource();
    const std::string srcHash = sha256Of(*src);
    Sink sink;
    Progress progress(sink);
    CreateOptions co;
    co.chunkSize = 1 * MiB;
    co.compression = Compression::Lz4;
    auto created = createImage(src, dir / "disk.stein", co, progress);
    REQUIRE_MESSAGE(created.has_value(), (created ? std::string() : created.error().toString()));
    CHECK(created->files.size() == 1);
    CHECK(created->stats.chunks == 16);
    CHECK(created->stats.zeroChunks >= 8);          // most of the 16 MiB is empty
    CHECK(created->storedBytes < 4 * MiB);           // 3 MiB random + small metadata, zeros omitted
    CHECK(created->imageHashHex == srcHash);
    CHECK(sink.updates > 0);

    auto info = imageInfo(dir / "disk.stein");
    REQUIRE(info);
    CHECK(info->complete);
    CHECK(info->chunksTotal == 16);
    CHECK(info->chunksStored < 16);
    CHECK(info->header.totalSize == 16 * MiB);
    CHECK(info->manifest.get("layout").get("compression").asString() == "lz4");
    CHECK(info->manifest.get("source").get("size").asUInt() == 16 * MiB);
    CHECK(info->manifest.get("topology").get("table").get("type").asString() == "gpt");
    CHECK(info->manifest.get("topology").get("children").size() == 3);
    CHECK(info->manifest.get("topology").get("children").at(0).get("content").get("type").asString() == "vfat");
    CHECK(*info->imageHashHex == srcHash);

    // Images are devices: probe the image exactly like a disk.
    auto dev = openImage(dir / "disk.stein");
    REQUIRE(dev);
    CHECK((*dev)->size() == 16 * MiB);
    CHECK((*dev)->isReadOnly());
    CHECK(sha256Of(**dev) == srcHash);
    auto tree = probe::probe(*dev);
    REQUIRE(tree);
    REQUIRE(tree->table);
    CHECK(tree->table->type() == pt::TableType::Gpt);
    CHECK(tree->children[0].content->type() == fs::FsType::Fat12);
    // Random access across chunk boundaries.
    auto cross = (*dev)->read(1 * MiB - 100, 200);
    REQUIRE(cross);
    auto orig = src->read(1 * MiB - 100, 200);
    CHECK(*cross == *orig);

    for (int level : {1, 2, 3}) {
        auto v = verifyImage(dir / "disk.stein", level, progress);
        REQUIRE(v);
        CHECK(v->structureOk);
        CHECK(v->complete);
        CHECK(v->chunksBad == 0);
        if (level == 3) {
            CHECK(v->imageHashChecked);
            CHECK(v->imageHashOk);
        }
    }

    // Restore to a dirty target of the same size: result must equal the source.
    auto target = std::make_shared<MemoryDevice>(16 * MiB, 512);
    std::fill(target->bytes().begin(), target->bytes().end(), std::byte{0xAB});
    auto restored = restoreImage(dir / "disk.stein", *target, RestoreOptions{.verifyPayloadFirst = true}, progress);
    REQUIRE(restored);
    CHECK(sha256Of(*target) == srcHash);
    CHECK(!restored->targetLarger);
    // Larger target: fine, flagged. Smaller: refused unless allowed.
    MemoryDevice big(20 * MiB, 512);
    auto r2 = restoreImage(dir / "disk.stein", big, RestoreOptions{}, progress);
    REQUIRE(r2);
    CHECK(r2->targetLarger);
    MemoryDevice small(8 * MiB, 512);
    CHECK(restoreImage(dir / "disk.stein", small, RestoreOptions{}, progress).error().category() == ErrorCategory::OutOfRange);
    auto r3 = restoreImage(dir / "disk.stein", small, RestoreOptions{.allowSmallerTarget = true}, progress);
    REQUIRE(r3);
    CHECK(r3->targetSmaller);
    CHECK(*small.read(0, 512) == *src->read(0, 512));
    if (dev) dev->reset();
    stein::test::removeTree(dir);
}

TEST_CASE("stein image: split segments, uncompressed, corruption detection, recovery without trailer") {
    auto dir = tmpDir("stein_test_image_split");
    auto src = makeSource();
    const std::string srcHash = sha256Of(*src);
    Sink sink;
    Progress progress(sink);
    CreateOptions co;
    co.chunkSize = 512 * KiB;
    co.compression = Compression::None;
    co.splitSize = 2 * MiB + 512 * KiB;   // forces several segments for the 3 MiB of random data
    auto created = createImage(src, dir / "s.stein", co, progress);
    REQUIRE_MESSAGE(created.has_value(), (created ? std::string() : created.error().toString()));
    CHECK(created->files.size() >= 2);
    for (const auto& f : created->files) CHECK(std::filesystem::file_size(f) <= co.splitSize);
    auto dev = openImage(dir / "s.stein");
    REQUIRE(dev);
    CHECK(sha256Of(**dev) == srcHash);
    auto info = imageInfo(dir / "s.stein");
    REQUIRE(info);
    CHECK(info->segments.size() == created->files.size());
    CHECK(info->complete);

    // Flip a payload byte in the last segment: verification must catch it and name the chunk.
    {
        const auto& seg = info->segments.back();
        std::fstream f(seg.path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(static_cast<std::streamoff>(SegmentHeader::kSize + ChunkRecord::kHeaderSize + 10));
        char c;
        f.seekg(static_cast<std::streamoff>(SegmentHeader::kSize + ChunkRecord::kHeaderSize + 10));
        f.get(c);
        f.seekp(static_cast<std::streamoff>(SegmentHeader::kSize + ChunkRecord::kHeaderSize + 10));
        f.put(static_cast<char>(c ^ 0x5A));
    }
    auto v2 = verifyImage(dir / "s.stein", 2, progress);
    REQUIRE(v2);
    CHECK(v2->chunksBad == 1);
    auto v3 = verifyImage(dir / "s.stein", 3, progress);
    REQUIRE(v3);
    CHECK(v3->chunksBad == 1);
    CHECK(!v3->imageHashOk);
    auto badDev = openImage(dir / "s.stein");
    REQUIRE(badDev);
    const std::uint64_t badChunk = v2->badChunks.at(0);
    auto rd = (*badDev)->read(badChunk * co.chunkSize, 4096);
    CHECK(!rd);
    CHECK(rd.error().category() == ErrorCategory::Integrity);

    // Truncate segment 0 so it has no trailer: the reader recovers by scanning records.
    {
        auto fresh = createImage(src, dir / "t.stein", co, progress);
        REQUIRE(fresh);
        const auto first = fresh->files.front();
        const auto size = std::filesystem::file_size(first);
        std::filesystem::resize_file(first, size - 200);   // chops the trailer and part of the index
        // Remove the following segments so the image is "crashed mid-write".
        for (std::size_t i = 1; i < fresh->files.size(); ++i) std::filesystem::remove(fresh->files[i]);
    }
    auto rec = imageInfo(dir / "t.stein");
    REQUIRE(rec);
    CHECK(!rec->complete);
    CHECK(rec->segments.size() == 1);
    CHECK(!rec->segments[0].trailer.has_value());
    CHECK(rec->segments[0].records > 0);
    CHECK(rec->chunksStored == rec->segments[0].records);
    auto recDev = openImage(dir / "t.stein");
    REQUIRE(recDev);
    // The first chunk (GPT + FAT) was in segment 0 and must read back intact.
    auto head = (*recDev)->read(0, 64 * 1024);
    REQUIRE(head);
    CHECK(*head == *src->read(0, 64 * 1024));
    if (dev) dev->reset();
    if (badDev) badDev->reset();
    if (recDev) recDev->reset();
    stein::test::removeTree(dir);
}

TEST_CASE("copy engine: bad sector policy") {
    // A device that fails reads inside one sector.
    class Flaky final : public BlockDevice {
    public:
        explicit Flaky(std::shared_ptr<MemoryDevice> inner) : m_inner(std::move(inner)) {}
        std::string name() const override { return "flaky"; }
        Geometry geometry() const override { return m_inner->geometry(); }
        bool isReadOnly() const override { return true; }
        Expected<void> readAt(ByteCount off, std::span<std::byte> dst) override {
            if (Region{off, dst.size()}.overlaps(Region{5000, 512})) return fail(ErrorCategory::Io, "simulated media error", 5);
            return m_inner->readAt(off, dst);
        }
        Expected<void> writeAt(ByteCount, std::span<const std::byte>) override { return fail(ErrorCategory::Permission, "ro"); }
        Expected<void> flush() override { return {}; }

    private:
        std::shared_ptr<MemoryDevice> m_inner;
    };
    auto inner = std::make_shared<MemoryDevice>(1 * MiB, 512);
    std::fill(inner->bytes().begin(), inner->bytes().end(), std::byte{0x11});
    Flaky flaky(inner);
    MemoryDevice target(1 * MiB, 512);
    Sink sink;
    Progress progress(sink);
    CopyOptions fail_;
    fail_.chunkSize = 64 * KiB;
    CHECK(copyDevice(flaky, target, fail_, progress).error().category() == ErrorCategory::Io);
    CopyOptions skip = fail_;
    skip.badSectors = BadSectorPolicy::SkipZero;
    auto st = copyDevice(flaky, target, skip, progress);
    REQUIRE(st);
    CHECK(st->unreadableSectors == 2);   // the bad 512-byte range at 5000 straddles two sectors (4608..5119, 5120..5631)
    CHECK(st->badRegions.size() == 1);
    CHECK(st->badRegions[0].offset == 4608);
    CHECK(st->badRegions[0].length == 1024);
    CHECK(target.bytes()[4607] == std::byte{0x11});
    CHECK(target.bytes()[4608] == std::byte{0});
    CHECK(target.bytes()[5631] == std::byte{0});
    CHECK(target.bytes()[5632] == std::byte{0x11});
}

TEST_CASE("split raw image set opens as one device") {
    auto dir = tmpDir("stein_test_splitraw");
    auto disk = loadSparseFixture("pt/gpt_basic.sparse");
    const ByteCount piece = 6 * MiB;
    std::vector<std::filesystem::path> files;
    for (ByteCount off = 0, i = 0; off < disk->size(); off += piece, ++i) {
        char suffix[8];
        std::snprintf(suffix, sizeof suffix, ".%03llu", static_cast<unsigned long long>(i));
        auto path = dir / ("disk.img" + std::string(suffix));
        const ByteCount n = std::min(piece, disk->size() - off);
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(disk->bytes().data() + off), static_cast<std::streamsize>(n));
        files.push_back(path);
    }
    REQUIRE(files.size() == 3);
    auto set = image::findSplitRaw(dir / "disk.img");
    REQUIRE(set);
    CHECK(set->members.size() == 3);
    CHECK(set->totalBytes == disk->size());
    CHECK(image::findSplitRaw(dir / "disk.img.001"));
    CHECK_FALSE(image::findSplitRaw(dir / "other.img"));
    auto dev = image::openSplitRaw(dir / "disk.img.000", false);
    REQUIRE(dev);
    CHECK((*dev)->size() == disk->size());
    auto table = pt::PartitionTable::read(*dev);
    REQUIRE(table);
    CHECK((*table)->type() == pt::TableType::Gpt);
    CHECK((*table)->partitions().size() == 3);
    CHECK((*table)->health() == layout::Validity::Ok);
    // Whole-image comparison across the piece boundaries.
    auto all = (*dev)->read(0, (*dev)->size());
    REQUIRE(all);
    CHECK(std::equal(all->begin(), all->end(), disk->bytes().begin()));
    if (dev) dev->reset();
    stein::test::removeTree(dir);
}
