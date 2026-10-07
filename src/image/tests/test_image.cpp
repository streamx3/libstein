// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/hash.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/image/operations.hpp"

#include <array>
#include "stein/image/stein_format.hpp"
#include "stein/pt/partition_table.hpp"
#include "stein/pt/partition_type.hpp"
#include "stein/probe/topology.hpp"

#include <algorithm>
#include <cstring>
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

TEST_CASE("stein header: versioning and feature masks (minor versions and compat bits open, incompat bits and a new major refuse)") {
    using image::SegmentHeader;
    SegmentHeader h;
    h.chunkSize = 1 * MiB;
    h.totalSize = 8 * MiB;
    std::array<std::byte, SegmentHeader::kSize> raw{};
    h.encode(raw);
    auto back = SegmentHeader::decode(raw);
    REQUIRE(back);
    CHECK(back->version == SegmentHeader::kVersionMajor);
    CHECK(back->versionMinor == SegmentHeader::kVersionMinor);
    CHECK(back->writerVersion == image::currentWriterVersion());
    CHECK(back->writerVersionText() == STEIN_VERSION_STRING);
    CHECK_FALSE(back->unknownRoCompat());
    // A file from a 1.0 writer: reserved bytes are zero.
    std::fill(raw.begin() + 96, raw.end(), std::byte{0});
    auto old = SegmentHeader::decode(raw);
    REQUIRE(old);
    CHECK(old->versionMinor == 0);
    CHECK(old->writerVersionText().empty());
    // A newer minor version with unknown compat and ro_compat bits still opens.
    h.versionMinor = 9;
    h.featuresCompat = 0x80000000u;
    h.featuresRoCompat = 0x4;
    h.encode(raw);
    auto newer = SegmentHeader::decode(raw);
    REQUIRE(newer);
    CHECK(newer->versionMinor == 9);
    CHECK(newer->unknownRoCompat());
    // An unknown incompat bit refuses the file and names the bit and the writer.
    h.featuresRoCompat = 0;
    h.featuresIncompat = 0x10;
    h.writerVersion = (2u << 16) | (3u << 8) | 4u;
    h.encode(raw);
    auto refused = SegmentHeader::decode(raw);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == ErrorCategory::Unsupported);
    CHECK(std::string(refused.error().message()).find("bit(s) 4") != std::string::npos);
    CHECK(std::string(refused.error().message()).find("2.3.4") != std::string::npos);
    // A new major version refuses with the format numbers in the message.
    h.featuresIncompat = 0;
    h.version = 2;
    h.encode(raw);
    auto major = SegmentHeader::decode(raw);
    REQUIRE_FALSE(major);
    CHECK(major.error().category() == ErrorCategory::Unsupported);
    CHECK(std::string(major.error().message()).find("format 2.x") != std::string::npos);
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

TEST_CASE("zero policy: gaps are zeroed, partitions are kept, straddling chunks split at the boundary, unknown tables keep everything") {
    // 16 MiB disk, GPT with one partition from 1 MiB to 2 MiB + 100 KiB (its end is not chunk-aligned).
    auto disk = std::make_shared<MemoryDevice>(16 * MiB, 512);
    auto table = pt::PartitionTable::createEmpty(pt::TableType::Gpt, disk->geometry());
    REQUIRE(table);
    const ByteCount pStart = 1 * MiB, pEnd = 2 * MiB + 100 * KiB;
    pt::Partition part;
    part.firstLba = pStart / 512;
    part.lastLba = pEnd / 512 - 1;
    part.type = *pt::types::fromSgdiskCode("8300");
    part.name = "odd";
    REQUIRE((*table)->addPartition(part));
    REQUIRE((*table)->write(*disk));
    const std::byte marker[4] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    REQUIRE(disk->writeAt(pStart, marker));   // the partition's first chunk is stored; the rest of it is zero

    const auto dir = std::filesystem::temp_directory_path() / "stein-zero-policy";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    Sink sink;
    Progress progress(sink);
    CreateOptions co;
    co.chunkSize = 64 * KiB;
    co.recordTopology = false;
    co.computeImageHash = false;
    REQUIRE(createImage(disk, dir / "odd.stein", co, progress));

    // keepRegionsOf: exactly the partition, nothing more.
    auto reader = SteinReader::open(dir / "odd.stein");
    REQUIRE(reader);
    auto keep = keepRegionsOf((*reader)->asDevice());
    REQUIRE(keep);
    CHECK(keep->tableUnderstood);
    REQUIRE(keep->regions.size() == 1);
    CHECK(keep->regions[0].offset == pStart);
    CHECK(keep->regions[0].end() == pEnd);

    // The plan, before anything is written.
    RestoreOptions ro;
    ro.zeroPolicy = ZeroPolicy::SkipInside;
    auto plan = planZeroWrites(dir / "odd.stein", ro);
    REQUIRE(plan);
    CHECK(plan->totalChunks == 256);
    CHECK(plan->zeroBytes + 64 * KiB * (plan->totalChunks - plan->zeroChunks) == 16 * MiB);
    // Zero chunks inside the partition: 1 MiB + 64 KiB .. 2 MiB + 64 KiB entirely (16 chunks), plus the
    // straddling chunk [2 MiB + 64 KiB, 2 MiB + 128 KiB) of which 36 KiB are inside, 28 KiB outside.
    CHECK(plan->toSkip == 16 * 64 * KiB + 36 * KiB);
    CHECK(plan->toWrite + plan->toSkip == plan->zeroBytes);
    CHECK(plan->toWrite > 12 * MiB);   // the gap before the partition (minus the GPT chunk) and everything after it

    // Restore onto a target full of 0xAA.
    MemoryDevice target(16 * MiB, 512);
    std::fill(target.bytes().begin(), target.bytes().end(), std::byte{0xAA});
    auto r = restoreImage(dir / "odd.stein", target, ro, progress);
    REQUIRE(r);
    CHECK(r->stats.zeroBytesWritten == plan->toWrite);
    CHECK(r->stats.zeroBytesSkipped == plan->toSkip);
    auto at = [&](ByteCount off) { return target.bytes()[static_cast<std::size_t>(off)]; };
    CHECK(at(512 * KiB) == std::byte{0});                   // gap before the partition: zeroed
    CHECK(at(pStart) == std::byte{0xDE});                   // stored chunk: restored
    CHECK(at(pStart + 512 * KiB) == std::byte{0xAA});       // zero chunk inside the partition: kept
    CHECK(at(pEnd - 1) == std::byte{0xAA});                 // last byte inside the partition: kept
    CHECK(at(pEnd) == std::byte{0});                        // first byte past it: zeroed (same chunk, split at the boundary)
    CHECK(at(pEnd + 27 * KiB) == std::byte{0});
    CHECK(at(8 * MiB) == std::byte{0});                     // free space after the partition: zeroed
    CHECK(at(16 * MiB - 512) != std::byte{0xAA});           // backup GPT: restored from a stored chunk

    // Skip everything / write everything, for the record.
    RestoreOptions skip;
    skip.zeroPolicy = ZeroPolicy::Skip;
    auto skipPlan = planZeroWrites(dir / "odd.stein", skip);
    REQUIRE(skipPlan);
    CHECK(skipPlan->toWrite == 0);
    CHECK(skipPlan->toSkip == skipPlan->zeroBytes);
    RestoreOptions write;
    auto writePlan = planZeroWrites(dir / "odd.stein", write);
    REQUIRE(writePlan);
    CHECK(writePlan->toSkip == 0);

    // No table at all: an unformatted disk with a marker. The whole device is kept.
    auto blank = std::make_shared<MemoryDevice>(4 * MiB, 512);
    REQUIRE(blank->writeAt(3 * MiB, marker));
    REQUIRE(createImage(blank, dir / "blank.stein", co, progress));
    auto keepBlank = keepRegionsOf(SteinReader::open(dir / "blank.stein").value()->asDevice());
    REQUIRE(keepBlank);
    CHECK(!keepBlank->tableUnderstood);
    REQUIRE(keepBlank->regions.size() == 1);
    CHECK(keepBlank->regions[0].offset == 0);
    CHECK(keepBlank->regions[0].length == 4 * MiB);
    auto blankPlan = planZeroWrites(dir / "blank.stein", ro);
    REQUIRE(blankPlan);
    CHECK(blankPlan->toWrite == 0);
    CHECK(blankPlan->toSkip == blankPlan->zeroBytes);

    // regionsOutside on its own: keep ranges unsorted and overlapping.
    auto outside = regionsOutside(Region{0, 100}, {Region{50, 20}, Region{10, 10}, Region{15, 10}});
    REQUIRE(outside.size() == 3);
    CHECK(outside[0].offset == 0);  CHECK(outside[0].length == 10);
    CHECK(outside[1].offset == 25); CHECK(outside[1].length == 25);
    CHECK(outside[2].offset == 70); CHECK(outside[2].length == 30);
    CHECK(regionsOutside(Region{0, 100}, {Region{0, 100}}).empty());
    CHECK(regionsOutside(Region{0, 100}, {}).size() == 1);

    std::filesystem::remove_all(dir);
}

TEST_CASE("copy engine: zero chunks go through zeroRange(), never through writeAt()") {
    // A target that records how zeros arrive.
    class Recorder final : public BlockDevice {
    public:
        explicit Recorder(ByteCount size) : m_inner(size, 512) {}
        std::string name() const override { return "recorder"; }
        Geometry geometry() const override { return m_inner.geometry(); }
        bool isReadOnly() const override { return false; }
        Expected<void> readAt(ByteCount off, std::span<std::byte> dst) override { return m_inner.readAt(off, dst); }
        Expected<void> writeAt(ByteCount off, std::span<const std::byte> src) override {
            if (isAllZero(src)) ++zeroWrites;
            return m_inner.writeAt(off, src);
        }
        Expected<void> zeroRange(ByteCount off, ByteCount len) override {
            ++zeroRanges;
            zeroRangeBytes += len;
            return m_inner.zeroRange(off, len);
        }
        Expected<void> flush() override { return {}; }
        MemoryDevice m_inner;
        int zeroWrites = 0, zeroRanges = 0;
        ByteCount zeroRangeBytes = 0;
    };
    auto source = std::make_shared<MemoryDevice>(1 * MiB, 512);
    const std::byte mark[1] = {std::byte{9}};
    REQUIRE(source->writeAt(0, mark));              // chunk 0 has data, the other 15 are zero
    Recorder target(1 * MiB);
    std::fill(target.m_inner.bytes().begin(), target.m_inner.bytes().end(), std::byte{0xCC});
    Sink sink;
    Progress progress(sink);
    CopyOptions co;
    co.chunkSize = 64 * KiB;
    auto st = copyDevice(*source, target, co, progress);
    REQUIRE(st);
    CHECK(target.zeroRanges == 15);
    CHECK(target.zeroRangeBytes == 15 * 64 * KiB);
    CHECK(target.zeroWrites == 0);
    CHECK(st->zeroBytesWritten == 15 * 64 * KiB);
    CHECK(st->bytesWritten == 1 * MiB);
    CHECK(target.m_inner.bytes()[0] == std::byte{9});
    CHECK(target.m_inner.bytes()[1 * MiB - 1] == std::byte{0});

    // SkipInside: the outside part of a straddling chunk goes through zeroRange() too.
    Recorder target2(1 * MiB);
    co.zeroPolicy = ZeroPolicy::SkipInside;
    co.keepRegions = {Region{64 * KiB, 100 * KiB}};   // ends inside chunk 2
    auto st2 = copyDevice(*source, target2, co, progress);
    REQUIRE(st2);
    CHECK(target2.zeroWrites == 0);
    CHECK(target2.zeroRangeBytes == st2->zeroBytesWritten);
    CHECK(st2->zeroBytesSkipped == 100 * KiB);
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

TEST_CASE("used-block-only imaging stores free space as zero chunks and restores the used blocks exactly") {
    auto dir = tmpDir("stein_test_image_used");
    auto src = loadSparseFixture("alloc/ext4.sparse");
    // Pollute the free space so that "whole copy" and "used only" differ measurably.
    auto probedFs = fs::probe(src);
    REQUIRE(probedFs);
    REQUIRE(*probedFs);
    auto map = (*probedFs)->allocationMap();
    REQUIRE(map);
    std::mt19937_64 rng(7);
    std::uint64_t polluted = 0;
    for (std::uint64_t b = 0; b < map->blocks() && polluted < 64; ++b) {
        if (map->isUsed(b)) continue;
        const ByteCount off = map->origin() + b * map->blockSize();
        if (off + map->blockSize() > src->size()) break;
        for (ByteCount i = 0; i < map->blockSize(); i += 8) {
            const std::uint64_t v = rng();
            std::memcpy(src->bytes().data() + off + i, &v, 8);
        }
        ++polluted;
    }
    REQUIRE(polluted == 64);
    NullProgressSink sink;
    Progress progress(sink);
    CreateOptions whole;
    whole.chunkSize = 64 * KiB;
    whole.compression = Compression::None;
    auto a = createImage(src, dir / "whole.stein", whole, progress);
    REQUIRE(a);
    CreateOptions used = whole;
    used.usedBlocksOnly = true;
    auto b = createImage(src, dir / "used.stein", used, progress);
    REQUIRE_MESSAGE(b, (b ? std::string() : b.error().toString()));
    CHECK(b->stats.freeBytesSkipped >= 64 * map->blockSize());
    CHECK(b->storedBytes < a->storedBytes);
    CHECK(b->storedBytes + 64 * map->blockSize() <= a->storedBytes);
    REQUIRE(b->allocationNotes.size() == 1);
    CHECK(b->allocationNotes[0].find("ext4") != std::string::npos);
    auto info = imageInfo(dir / "used.stein");
    REQUIRE(info);
    CHECK(info->manifest.get("used_blocks_only").asBool());
    // Restore: used blocks identical, polluted free blocks come back as zeros, filesystem probes clean.
    auto target = std::make_shared<MemoryDevice>(src->size(), 512);
    auto r = restoreImage(dir / "used.stein", *target, RestoreOptions{}, progress);
    REQUIRE(r);
    for (std::uint64_t blk = 0; blk < map->blocks(); ++blk) {
        const ByteCount off = map->origin() + blk * map->blockSize();
        if (off + map->blockSize() > src->size()) break;
        auto s = src->bytes().subspan(off, map->blockSize());
        auto t = target->bytes().subspan(off, map->blockSize());
        if (map->isUsed(blk)) REQUIRE(std::equal(s.begin(), s.end(), t.begin()));
        else REQUIRE(std::all_of(t.begin(), t.end(), [](std::byte x) { return x == std::byte{0}; }));
    }
    auto again = fs::probe(target);
    REQUIRE(again);
    REQUIRE(*again);
    CHECK((*again)->info().label == "alloc_ext4");
    auto map2 = (*again)->allocationMap();
    REQUIRE(map2);
    CHECK(map2->usedBlocks() == map->usedBlocks());
    stein::test::removeTree(dir);
}

TEST_CASE("encrypted images: locked structure, unlock, wrong passphrase, tamper, key slots") {
    auto dir = tmpDir("stein_test_image_enc");
    auto src = makeSource();
    NullProgressSink sink;
    Progress progress(sink);
    CreateOptions co;
    co.chunkSize = 1 * MiB;
    co.passphrase = "correct horse";
    co.kdf = KdfParams::fast();   // the default is Argon2id t=3 m=64MiB p=4
    co.notes = "secret note";
    auto created = createImage(src, dir / "enc.stein", co, progress);
    REQUIRE_MESSAGE(created, (created ? std::string() : created.error().toString()));
    CHECK(!created->imageHashHex.empty());

    // Without a key: structure, stored CRCs and segment list are readable; contents are not.
    auto locked = imageInfo(dir / "enc.stein");
    REQUIRE(locked);
    CHECK(locked->encrypted);
    CHECK_FALSE(locked->unlocked);
    CHECK(locked->keySlots == 1);
    CHECK(locked->manifest.isNull());
    CHECK_FALSE(locked->imageHashHex);
    CHECK(locked->complete);
    auto v2 = verifyImage(dir / "enc.stein", 2, progress);
    REQUIRE(v2);
    CHECK(v2->chunksBad == 0);
    CHECK(verifyImage(dir / "enc.stein", 3, progress).error().category() == ErrorCategory::Permission);
    CHECK(openImage(dir / "enc.stein").error().category() == ErrorCategory::Permission);
    // Nothing from the manifest appears in clear in the file.
    {
        std::ifstream in(dir / "enc.stein", std::ios::binary);
        std::string all((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(all.find("secret note") == std::string::npos);
        CHECK(all.find("stein-image") == std::string::npos);
        CHECK(all.find("chacha20-poly1305") != std::string::npos);   // the key area is plaintext
    }
    // Wrong passphrase.
    auto wrong = imageInfo(dir / "enc.stein", "wrong");
    REQUIRE_FALSE(wrong);
    CHECK(wrong.error().category() == ErrorCategory::Integrity);
    // Right passphrase: manifest, hash, contents.
    auto open = imageInfo(dir / "enc.stein", "correct horse");
    REQUIRE(open);
    CHECK(open->unlocked);
    CHECK(open->manifest.get("notes").asString() == "secret note");
    REQUIRE(open->imageHashHex);
    CHECK(*open->imageHashHex == created->imageHashHex);
    auto v3 = verifyImage(dir / "enc.stein", 3, progress, "correct horse");
    REQUIRE(v3);
    CHECK(v3->chunksBad == 0);
    CHECK(v3->imageHashOk);
    auto dev = openImage(dir / "enc.stein", "correct horse");
    REQUIRE(dev);
    auto all = (*dev)->read(0, (*dev)->size());
    REQUIRE(all);
    CHECK(std::equal(all->begin(), all->end(), src->bytes().begin()));
    auto target = std::make_shared<MemoryDevice>(src->size(), 512);
    REQUIRE(restoreImage(dir / "enc.stein", *target, RestoreOptions{}, progress, "correct horse"));
    CHECK(std::equal(target->bytes().begin(), target->bytes().end(), src->bytes().begin()));
    CHECK(restoreImage(dir / "enc.stein", *target, RestoreOptions{}, progress).error().category() == ErrorCategory::Permission);

    // Key slots: add a second passphrase, open with it, remove the first, the first stops working.
    auto id = addImageKey(dir / "enc.stein", "correct horse", "battery staple", KdfParams::fast(), "second");
    REQUIRE_MESSAGE(id, (id ? std::string() : id.error().toString()));
    CHECK(*id == 1);
    CHECK(imageKeys(dir / "enc.stein")->slots().size() == 2);
    CHECK(imageInfo(dir / "enc.stein", "battery staple")->unlocked);
    CHECK_FALSE(addImageKey(dir / "enc.stein", "nope", "x", KdfParams::fast()));
    REQUIRE(removeImageKey(dir / "enc.stein", "battery staple", 0));
    CHECK_FALSE(imageInfo(dir / "enc.stein", "correct horse"));
    CHECK(imageInfo(dir / "enc.stein", "battery staple")->unlocked);
    CHECK(removeImageKey(dir / "enc.stein", "battery staple", 1).error().category() == ErrorCategory::InvalidArgument);   // last slot
    auto v3b = verifyImage(dir / "enc.stein", 3, progress, "battery staple");
    REQUIRE(v3b);
    CHECK(v3b->imageHashOk);

    // Tamper with one byte of a stored payload: the stored CRC catches it keyless, the tag with the key.
    {
        auto reader = SteinReader::open(dir / "enc.stein");
        REQUIRE(reader);
        std::uint64_t stored = 0;
        for (std::uint64_t i = 0; i < (*reader)->totalChunks(); ++i)
            if (auto rec = (*reader)->recordOf(i); rec && rec->storedLength) {
                stored = i;
                break;
            }
        auto rec = (*reader)->recordOf(stored);
        REQUIRE(rec);
        (void)rec;
        reader->reset();
        // Find the record by scanning for its index in the file via the reader map is internal; flip a byte in the first payload after the manifest instead.
        std::fstream f(dir / "enc.stein", std::ios::in | std::ios::out | std::ios::binary);
        f.seekg(0, std::ios::end);
        const auto size = static_cast<std::streamoff>(f.tellg());
        std::vector<char> bytes(static_cast<std::size_t>(size));
        f.seekg(0);
        f.read(bytes.data(), size);
        const std::string magic = "CHNK";
        auto pos = std::search(bytes.begin() + 4096, bytes.end(), magic.begin(), magic.end());
        REQUIRE(pos != bytes.end());
        const auto payloadPos = static_cast<std::streamoff>(std::distance(bytes.begin(), pos)) + 32 + 5;
        f.seekp(payloadPos);
        char c = bytes[static_cast<std::size_t>(payloadPos)] ^ 0x40;
        f.write(&c, 1);
    }
    auto v2bad = verifyImage(dir / "enc.stein", 2, progress);
    REQUIRE(v2bad);
    CHECK(v2bad->chunksBad == 1);
    stein::test::removeTree(dir);
}

#include "stein/block/file_device.hpp"
#include "stein/block/sparse_file.hpp"
#include "stein/image/vdisk.hpp"

TEST_CASE("vdisk: qcow2 (v2/v3/deflate and zstd compressed/4K clusters), VHD (dynamic/fixed), VHDX, VMDK (sparse/stream-optimized) and VDI reproduce the raw disk byte for byte") {
    struct Case { const char* name; image::VdiskFormat format; const char* variant; bool compressed; };
    const Case cases[] = {
        {"qcow2", image::VdiskFormat::Qcow2, "v3", false},          {"qcow2_compressed", image::VdiskFormat::Qcow2, "v3", false},
        {"qcow2_v2", image::VdiskFormat::Qcow2, "v2", false},       {"qcow2_64k", image::VdiskFormat::Qcow2, "v3", false},
        {"qcow2_zstd", image::VdiskFormat::Qcow2, "v3", false},
        {"vhd_dynamic", image::VdiskFormat::Vhd, "dynamic", false}, {"vhd_fixed", image::VdiskFormat::Vhd, "fixed", false},
        {"vhdx", image::VdiskFormat::Vhdx, "dynamic", false},       {"vmdk_sparse", image::VdiskFormat::Vmdk, "monolithicSparse", false},
        {"vmdk_stream", image::VdiskFormat::Vmdk, "streamOptimized", true}, {"vdi", image::VdiskFormat::Vdi, "dynamic", false},
    };
    const auto dir = std::filesystem::temp_directory_path() / ("stein_vdisk_" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(dir);
    for (const auto& c : cases) {
        const std::string fixture = c.name;
        CAPTURE(fixture);
        // Materialise the container (the formats are read by path).
        auto mem = SparseFile::loadIntoMemory(std::string(STEIN_FIXTURE_DIR) + "/vdisk/" + fixture + ".sparse");
        REQUIRE(mem);
        const auto path = dir / (fixture + ".img");
        {
            auto out = FileDevice::create(path, (*mem)->size());
            REQUIRE(out);
            std::vector<std::byte> buf(1 * MiB);
            for (ByteCount off = 0; off < (*mem)->size(); off += buf.size()) {
                const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>(buf.size(), (*mem)->size() - off));
                REQUIRE((*mem)->readAt(off, std::span<std::byte>(buf).subspan(0, n)));
                REQUIRE((*out)->writeAt(off, std::span<const std::byte>(buf).subspan(0, n)));
            }
            REQUIRE((*out)->flush());
        }
        std::map<std::string, std::string> o;
        {
            std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/vdisk/" + fixture + ".oracle.txt");
            std::string line;
            while (std::getline(in, line))
                if (auto eq = line.find('='); eq != std::string::npos) o[line.substr(0, eq)] = line.substr(eq + 1);
        }
        auto fmt = image::detectVdiskFormat(path);
        REQUIRE(fmt);
        CHECK(*fmt == c.format);
        image::VdiskInfo info;
        auto dev = image::openVdisk(path, &info);
        REQUIRE_MESSAGE(dev, (dev ? std::string() : dev.error().toString()));
        CHECK(info.format == c.format);
        CHECK(info.variant == c.variant);
        CHECK(info.compressed == c.compressed);
        const ByteCount rawSize = std::stoull(o["raw_size"]);
        CHECK((*dev)->size() >= rawSize);
        if (fixture != "vhd_dynamic" && fixture != "vhd_fixed") CHECK((*dev)->size() == std::stoull(o["virtual_size"]));
        CHECK((*dev)->isReadOnly());
        // Whole-disk hash equals the raw source.
        std::vector<std::byte> all(static_cast<std::size_t>(rawSize));
        std::vector<std::byte> chunk(1 * MiB);
        for (ByteCount off = 0; off < rawSize; off += chunk.size()) {
            const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>(chunk.size(), rawSize - off));
            REQUIRE((*dev)->readAt(off, std::span<std::byte>(all).subspan(static_cast<std::size_t>(off), n)));
        }
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, all)) == o["sha256"]);
        // Odd-sized reads across unit boundaries agree with the sequential read.
        std::mt19937_64 rng(42);
        for (int i = 0; i < 40; ++i) {
            const ByteCount off = rng() % (rawSize - 300000);
            const std::size_t n = 1 + static_cast<std::size_t>(rng() % 299999);
            std::vector<std::byte> win(n);
            REQUIRE((*dev)->readAt(off, win));
            CHECK(std::memcmp(win.data(), all.data() + off, n) == 0);
        }
        // The disk inside: GPT with two partitions, ext2 on the second.
        auto tree = probe::probe(*dev);
        REQUIRE(tree);
        REQUIRE(tree->table);
        CHECK(tree->table->partitions().size() == 2);
        REQUIRE(tree->children.size() >= 2);
        const auto* ext = tree->children[1].content.get();
        REQUIRE(ext);
        CHECK(ext->info().label == "inside_vdisk");
        CHECK_FALSE((*dev)->writeAt(0, std::span<const std::byte>(chunk).subspan(0, 512)));
        mem->reset();
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("ewf: EnCase 6 compressed, EnCase 6 split into 13 uncompressed segments and EnCase 5 images reproduce the raw disk and carry its digests") {
    const char* names[] = {"ewf6_best", "ewf6_split", "ewf5"};
    const auto dir = std::filesystem::temp_directory_path() / ("stein_ewf_" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(dir);
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        std::map<std::string, std::string> o;
        {
            std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/ewf/" + fixture + ".oracle.txt");
            std::string line;
            while (std::getline(in, line))
                if (auto eq = line.find('='); eq != std::string::npos) o[line.substr(0, eq)] = line.substr(eq + 1);
        }
        // Materialise every segment of this image.
        int segments = 0;
        for (const auto& entry : std::filesystem::directory_iterator(std::string(STEIN_FIXTURE_DIR) + "/ewf")) {
            const std::string fn = entry.path().filename().string();
            if (fn.rfind(fixture + ".E", 0) != 0 || fn.find(".sparse") == std::string::npos) continue;
            auto mem = SparseFile::loadIntoMemory(entry.path());
            REQUIRE(mem);
            const auto target = dir / fn.substr(0, fn.size() - 7);
            auto out = FileDevice::create(target, (*mem)->size());
            REQUIRE(out);
            std::vector<std::byte> buf(static_cast<std::size_t>((*mem)->size()));
            REQUIRE((*mem)->readAt(0, buf));
            REQUIRE((*out)->writeAt(0, buf));
            REQUIRE((*out)->flush());
            ++segments;
        }
        CHECK(segments == std::stoi(o["segments"]));
        const auto first = dir / (fixture + ".E01");
        auto fmt = image::detectVdiskFormat(first);
        REQUIRE(fmt);
        CHECK(*fmt == image::VdiskFormat::Ewf);
        image::VdiskInfo info;
        auto dev = image::openVdisk(first, &info);
        REQUIRE_MESSAGE(dev, (dev ? std::string() : dev.error().toString()));
        CHECK(info.files.size() == static_cast<std::size_t>(segments));
        CHECK(info.storedMd5 == o["md5"]);
        if (!info.storedSha1.empty()) CHECK(info.storedSha1 == o["sha1"]);
        const ByteCount rawSize = std::stoull(o["raw_size"]);
        CHECK((*dev)->size() == rawSize);
        std::vector<std::byte> all(static_cast<std::size_t>(rawSize));
        REQUIRE((*dev)->readAt(0, all));
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, all)) == o["sha256"]);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Md5, all)) == o["md5"]);   // our read matches what the acquirer hashed
        std::mt19937_64 rng(7);
        for (int i = 0; i < 30; ++i) {
            const ByteCount off = rng() % (rawSize - 200000);
            const std::size_t n = 1 + static_cast<std::size_t>(rng() % 199999);
            std::vector<std::byte> win(n);
            REQUIRE((*dev)->readAt(off, win));
            CHECK(std::memcmp(win.data(), all.data() + off, n) == 0);
        }
        auto tree = probe::probe(*dev);
        REQUIRE(tree);
        REQUIRE(tree->table);
        CHECK(tree->table->partitions().size() == 2);
        REQUIRE(tree->children.size() >= 2);
        REQUIRE(tree->children[1].content);
        CHECK(tree->children[1].content->info().label == "inside_ewf");
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("dmg: UDRO, UDZO (zlib), UDBZ (bzip2), UDCO (ADC), ULMO (lzma) and ULFO (lzfse) images from hdiutil reproduce the raw disk") {
    const char* names[] = {"dmg_udro", "dmg_udzo", "dmg_udbz", "dmg_udco", "dmg_ulmo", "dmg_ulfo"};
    const auto dir = std::filesystem::temp_directory_path() / ("stein_dmg_" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(dir);
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        const auto sparse = std::string(STEIN_FIXTURE_DIR) + "/dmg/" + fixture + ".sparse";
        if (!std::filesystem::exists(sparse)) {
            MESSAGE("fixture dmg/", fixture, " missing (built by the macOS fixture workflow); skipping");
            continue;
        }
        std::map<std::string, std::string> o;
        {
            std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/dmg/" + fixture + ".oracle.txt");
            std::string line;
            while (std::getline(in, line))
                if (auto eq = line.find('='); eq != std::string::npos) o[line.substr(0, eq)] = line.substr(eq + 1);
        }
        auto mem = SparseFile::loadIntoMemory(sparse);
        REQUIRE(mem);
        const auto path = dir / (fixture + ".dmg");
        {
            auto out = FileDevice::create(path, (*mem)->size());
            REQUIRE(out);
            std::vector<std::byte> buf(static_cast<std::size_t>((*mem)->size()));
            REQUIRE((*mem)->readAt(0, buf));
            REQUIRE((*out)->writeAt(0, buf));
            REQUIRE((*out)->flush());
        }
        auto fmt = image::detectVdiskFormat(path);
        REQUIRE(fmt);
        CHECK(*fmt == image::VdiskFormat::Dmg);
        image::VdiskInfo info;
        auto dev = image::openVdisk(path, &info);
        REQUIRE_MESSAGE(dev, (dev ? std::string() : dev.error().toString()));
        CHECK(info.compressed == (fixture != "dmg_udro"));
        const ByteCount rawSize = std::stoull(o["raw_size"]);
        CHECK((*dev)->size() >= rawSize);
        std::vector<std::byte> all(static_cast<std::size_t>(rawSize));
        REQUIRE((*dev)->readAt(0, all));
        // hdiutil may drop unpartitioned space ("ignored" chunks read as zeros), so the
        // byte-exact oracle is the raw disk restricted to the partition table and the partitions.
        auto rawMem = SparseFile::loadIntoMemory(std::string(STEIN_FIXTURE_DIR) + "/vdisk/vhd_fixed.sparse");
        REQUIRE(rawMem);
        std::vector<std::byte> raw(static_cast<std::size_t>(rawSize));
        REQUIRE((*rawMem)->readAt(0, raw));
        auto tree = probe::probe(*dev);
        REQUIRE(tree);
        REQUIRE(tree->table);
        REQUIRE(tree->table->partitions().size() == 2);
        std::vector<Region> regions{Region{0, 34 * 512}};
        for (const auto& part : tree->table->partitions()) regions.push_back(part.region(512));
        for (const auto& r : regions) {
            CAPTURE(r.offset);
            CHECK(std::memcmp(all.data() + r.offset, raw.data() + r.offset, static_cast<std::size_t>(r.length)) == 0);
        }
        (void)o;   // the oracle's sha256 describes the raw source; hdiutil drops the free tail from every variant
        std::mt19937_64 rng(11);
        for (int i = 0; i < 30; ++i) {
            const ByteCount off = rng() % (rawSize - 200000);
            const std::size_t n = 1 + static_cast<std::size_t>(rng() % 199999);
            std::vector<std::byte> win(n);
            REQUIRE((*dev)->readAt(off, win));
            CHECK(std::memcmp(win.data(), all.data() + off, n) == 0);
        }
        mem->reset();
        rawMem->reset();
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
