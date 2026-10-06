// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/block/memory_device.hpp"
#include "stein/ops/stack.hpp"
#include "stein/pt/gpt_table.hpp"

#include <algorithm>

using namespace stein;
using stein::test::loadSparseFixture;

namespace {

pt::Partition linuxPart(std::uint32_t index, Lba first, Lba last, std::string name = {}) {
    pt::Partition p;
    p.index = index;
    p.firstLba = first;
    p.lastLba = last;
    p.type = *pt::types::fromSgdiskCode("8300");
    p.name = std::move(name);
    return p;
}

bool allZero(std::span<const std::byte> s) {
    return std::all_of(s.begin(), s.end(), [](std::byte b) { return b == std::byte{0}; });
}

} // namespace

TEST_CASE("ops: create GPT on a blank disk, add and delete partitions, apply") {
    auto disk = std::make_shared<MemoryDevice>(32 * MiB);
    ops::OperationStack stack(disk);
    CHECK(stack.empty());
    CHECK_FALSE(stack.base().table);   // blank disk: no table node

    REQUIRE(stack.push(std::make_unique<ops::CreateTable>(pt::TableType::Gpt)));
    CHECK(stack.pending().size() == 1);
    CHECK(stack.destructive());
    REQUIRE(stack.preview().table);
    CHECK(stack.preview().table->type() == pt::TableType::Gpt);
    // The base device is untouched until apply().
    CHECK(allZero(disk->bytes().subspan(0, 2 * 512)));
    CHECK_FALSE(stack.base().table);

    REQUIRE(stack.push(std::make_unique<ops::AddPartition>(linuxPart(0, 2048, 2048 + 8192 - 1, "root"))));
    REQUIRE(stack.push(std::make_unique<ops::AddPartition>(linuxPart(0, 2048 + 8192, 2048 + 16384 - 1, "home"))));
    CHECK(stack.pending().size() == 3);
    CHECK(stack.preview().table->partitions().size() == 2);
    CHECK(stack.preview().table->partitions()[1].name == "home");

    // Overlapping partition fails validation and leaves the stack unchanged.
    auto bad = stack.push(std::make_unique<ops::AddPartition>(linuxPart(0, 4096, 4096 + 100, "overlap")));
    CHECK_FALSE(bad);
    CHECK(stack.pending().size() == 3);
    CHECK(stack.preview().table->partitions().size() == 2);

    REQUIRE(stack.push(std::make_unique<ops::DeletePartition>(1)));
    CHECK(stack.preview().table->partitions().size() == 1);
    CHECK(stack.preview().table->partitions()[0].index == 2);

    // Undo the delete.
    REQUIRE(stack.pop());
    CHECK(stack.pending().size() == 3);
    CHECK(stack.preview().table->partitions().size() == 2);

    auto text = ops::describe(stack);
    CHECK(text.find("Create GPT partition table") != std::string::npos);
    CHECK(text.find("[DESTRUCTIVE]") != std::string::npos);
    CHECK(text.find("gpt table") != std::string::npos);

    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE_MESSAGE(applied, (applied ? std::string() : applied.error().toString()));
    CHECK(applied->postconditionOk);
    CHECK(applied->report.status() == ReportStatus::Success);
    CHECK(stack.empty());
    CHECK(stack.changedBytes() == 0);

    auto table = pt::PartitionTable::read(disk);
    REQUIRE(table);
    CHECK((*table)->type() == pt::TableType::Gpt);
    REQUIRE((*table)->partitions().size() == 2);
    CHECK((*table)->partitions()[0].name == "root");
    CHECK((*table)->partitions()[1].firstLba == 2048 + 8192);
    CHECK((*table)->health() == layout::Validity::Ok);
}

TEST_CASE("ops: creating a table wipes old signatures and nothing more") {
    auto disk = loadSparseFixture("pt/gpt_basic.sparse");
    // Put a marker deep inside partition 2 (sector 7000) that must survive.
    auto marker = disk->bytes().subspan(7000 * 512, 16);
    std::fill(marker.begin(), marker.end(), std::byte{0xA5});

    ops::OperationStack stack(disk);
    REQUIRE(stack.base().table->type() == pt::TableType::Gpt);
    REQUIRE(stack.push(std::make_unique<ops::CreateTable>(pt::TableType::Mbr)));
    CHECK(stack.preview().table->type() == pt::TableType::Mbr);
    CHECK(stack.preview().table->partitions().empty());
    // Both GPT copies are in the changed set.
    auto regions = stack.changedRegions();
    bool head = false, tail = false;
    for (const auto& r : regions) {
        if (r.contains(ByteCount{512})) head = true;
        if (r.contains(disk->size() - 512)) tail = true;
    }
    CHECK(head);
    CHECK(tail);

    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE(applied);
    CHECK(applied->postconditionOk);
    CHECK(std::all_of(marker.begin(), marker.end(), [](std::byte b) { return b == std::byte{0xA5}; }));
    auto table = pt::PartitionTable::read(disk);
    REQUIRE(table);
    CHECK((*table)->type() == pt::TableType::Mbr);
    // The old GPT headers must be gone, not just shadowed by a PMBR.
    CHECK(allZero(disk->bytes().subspan(512, 512)));
    CHECK(allZero(disk->bytes().subspan(disk->size() - 512, 512)));
}

TEST_CASE("ops: update partition type and name") {
    auto disk = loadSparseFixture("pt/gpt_basic.sparse");
    ops::OperationStack stack(disk);
    auto p = *stack.base().table->find(3);
    p.name = "renamed";
    p.type = *pt::types::fromSgdiskCode("8302");
    REQUIRE(stack.push(std::make_unique<ops::UpdatePartition>(p)));
    CHECK_FALSE(stack.destructive());
    CHECK(stack.preview().table->find(3)->name == "renamed");
    // Moving the partition onto its neighbour is rejected.
    auto q = p;
    q.firstLba = 6000;
    CHECK_FALSE(stack.push(std::make_unique<ops::UpdatePartition>(q)));
    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE(applied);
    CHECK(applied->postconditionOk);
    auto table = pt::PartitionTable::read(disk);
    REQUIRE(table);
    CHECK((*table)->find(3)->name == "renamed");
    CHECK(pt::types::name((*table)->find(3)->type) == "Linux /home");
}

TEST_CASE("ops: repair a broken GPT through the stack") {
    auto disk = loadSparseFixture("pt/gpt_broken_primary.sparse");
    ops::OperationStack stack(disk);
    REQUIRE(stack.base().table);
    CHECK(stack.base().table->health() != layout::Validity::Ok);
    REQUIRE(stack.push(std::make_unique<ops::RepairTable>()));
    CHECK(stack.preview().table->health() == layout::Validity::Ok);
    // Nothing left to repair in the preview -> a second repair is rejected.
    CHECK_FALSE(stack.push(std::make_unique<ops::RepairTable>()));
    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE(applied);
    CHECK(applied->postconditionOk);
    auto table = pt::PartitionTable::read(disk);
    REQUIRE(table);
    CHECK((*table)->health() == layout::Validity::Ok);
    CHECK((*table)->partitions().size() == 3);
}

TEST_CASE("ops: wipe signatures of a whole-device filesystem") {
    auto disk = loadSparseFixture("fs/ext4.sparse");
    ops::OperationStack stack(disk);
    REQUIRE(stack.base().content);
    REQUIRE(stack.push(std::make_unique<ops::WipeSignatures>(Region{0, disk->size()})));
    CHECK_FALSE(stack.preview().content);
    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE(applied);
    CHECK(applied->postconditionOk);
    auto probed = probe::probe(disk);
    REQUIRE(probed);
    CHECK_FALSE(probed->content);
}

TEST_CASE("ops: read-only device refuses apply, clear() drops everything") {
    auto disk = std::make_shared<MemoryDevice>(16 * MiB);
    disk->setReadOnly(true);
    ops::OperationStack stack(disk);
    REQUIRE(stack.push(std::make_unique<ops::CreateTable>(pt::TableType::Gpt)));
    NullProgressSink sink;
    Progress progress(sink);
    auto applied = stack.apply(progress);
    REQUIRE_FALSE(applied);
    CHECK(applied.error().category() == ErrorCategory::Permission);
    CHECK(stack.pending().size() == 1);
    stack.clear();
    CHECK(stack.empty());
    CHECK(stack.changedBytes() == 0);
    CHECK_FALSE(stack.preview().table);
    CHECK_FALSE(stack.pop());
}

#include "stein/ops/media_test.hpp"

namespace {
// A "32 GiB" stick with 8 MiB of real flash: addresses wrap modulo the real capacity.
class FakeFlash final : public BlockDevice {
public:
    FakeFlash(ByteCount claimed, ByteCount real) : m_claimed(claimed), m_real(real), m_cells(real) {}
    std::string name() const override { return "fake-flash"; }
    Geometry geometry() const override {
        Geometry g;
        g.sizeBytes = m_claimed;
        return g;
    }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        for (std::size_t i = 0; i < dst.size(); ++i) dst[i] = m_cells[(offset + i) % m_real];
        return {};
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        if (auto r = checkRange(offset, src.size()); !r) return r;
        for (std::size_t i = 0; i < src.size(); ++i) m_cells[(offset + i) % m_real] = src[i];
        return {};
    }
    Expected<void> flush() override { return {}; }

private:
    ByteCount m_claimed, m_real;
    std::vector<std::byte> m_cells;
};

// Reads fail inside one sector.
class BadSectorDevice final : public BlockDevice {
public:
    explicit BadSectorDevice(ByteCount size, ByteCount badOffset) : m_mem(size), m_bad(badOffset) {}
    std::string name() const override { return "bad-sector"; }
    Geometry geometry() const override { return m_mem.geometry(); }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (offset <= m_bad && m_bad < offset + dst.size()) return fail(ErrorCategory::Io, "medium error");
        return m_mem.readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override { return m_mem.writeAt(offset, src); }
    Expected<void> flush() override { return {}; }

private:
    MemoryDevice m_mem;
    ByteCount m_bad;
};
} // namespace

TEST_CASE("media: capacity test detects fake flash and reports the real capacity") {
    FakeFlash fake(64 * MiB, 8 * MiB);
    NullProgressSink sink;
    Progress progress(sink);
    Report report("capacity");
    ops::CapacityTestOptions o;
    o.chunkSize = 1 * MiB;
    o.seed = 42;
    auto r = ops::capacityTest(fake, o, progress, report);
    REQUIRE(r);
    CHECK_FALSE(r->healthy());
    REQUIRE(r->firstMismatch);
    CHECK(*r->firstMismatch == 0);   // low addresses were overwritten by the wrapped high writes
    CHECK(r->wraparound);
    REQUIRE(r->realCapacityEstimate);
    CHECK(*r->realCapacityEstimate == 8 * MiB);
    CHECK(r->chunksTested == 64);
    CHECK(r->chunksBad == 56);   // only the last 8 MiB written survives
    CHECK(report.toText().find("FAKE CAPACITY") != std::string::npos);

    // Quick mode: every 4th chunk plus the tail still finds it.
    FakeFlash fake2(64 * MiB, 8 * MiB);
    Report report2("quick");
    o.quickStride = 4;
    auto q = ops::capacityTest(fake2, o, progress, report2);
    REQUIRE(q);
    CHECK(q->chunksTested < 64);
    REQUIRE(q->realCapacityEstimate);
    CHECK(*q->realCapacityEstimate == 8 * MiB);

    // A genuine device passes and is left zeroed.
    auto good = std::make_shared<MemoryDevice>(16 * MiB);
    Report report3("good");
    o.quickStride = 0;
    auto g = ops::capacityTest(*good, o, progress, report3);
    REQUIRE(g);
    CHECK(g->healthy());
    CHECK(g->bytesVerified == 16 * MiB);
    CHECK(std::all_of(good->bytes().begin(), good->bytes().end(), [](std::byte b) { return b == std::byte{0}; }));
    o.keepPattern = true;
    REQUIRE(ops::capacityTest(*good, o, progress, report3));
    CHECK_FALSE(std::all_of(good->bytes().begin(), good->bytes().end(), [](std::byte b) { return b == std::byte{0}; }));
    // The pattern is deterministic per (seed, offset) and differs between offsets.
    std::vector<std::byte> a(4096), b(4096), c(4096);
    ops::fillPattern(42, 0, a);
    ops::fillPattern(42, 0, b);
    ops::fillPattern(42, 4096, c);
    CHECK(a == b);
    CHECK(a != c);
}

namespace {
// A stick that silently drops writes beyond its real capacity and reads zeros there.
class DroppingFlash final : public BlockDevice {
public:
    DroppingFlash(ByteCount claimed, ByteCount real) : m_claimed(claimed), m_real(real), m_cells(real) {}
    std::string name() const override { return "dropping-flash"; }
    Geometry geometry() const override {
        Geometry g;
        g.sizeBytes = m_claimed;
        return g;
    }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        for (std::size_t i = 0; i < dst.size(); ++i) dst[i] = offset + i < m_real ? m_cells[offset + i] : std::byte{0};
        return {};
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        if (auto r = checkRange(offset, src.size()); !r) return r;
        for (std::size_t i = 0; i < src.size() && offset + i < m_real; ++i) m_cells[offset + i] = src[i];
        return {};
    }
    Expected<void> flush() override { return {}; }

private:
    ByteCount m_claimed, m_real;
    std::vector<std::byte> m_cells;
};
} // namespace

TEST_CASE("media: capacity test on a stick that drops writes beyond its real size") {
    DroppingFlash dev(32 * MiB, 12 * MiB);
    NullProgressSink sink;
    Progress progress(sink);
    Report report("drop");
    ops::CapacityTestOptions o;
    o.chunkSize = 1 * MiB;
    o.seed = 7;
    auto r = ops::capacityTest(dev, o, progress, report);
    REQUIRE(r);
    CHECK_FALSE(r->wraparound);
    REQUIRE(r->firstMismatch);
    CHECK(*r->firstMismatch == 12 * MiB);
    REQUIRE(r->realCapacityEstimate);
    CHECK(*r->realCapacityEstimate == 12 * MiB);
    CHECK(r->bytesVerified == 12 * MiB);
}

TEST_CASE("media: surface scan lists unreadable sectors without writing") {
    BadSectorDevice dev(8 * MiB, 3 * MiB + 1536);
    NullProgressSink sink;
    Progress progress(sink);
    Report report("scan");
    auto r = ops::surfaceScan(dev, progress, report);
    REQUIRE(r);
    CHECK_FALSE(r->healthy());
    CHECK(r->unreadableSectors == 1);
    REQUIRE(r->badRegions.size() == 1);
    CHECK(r->badRegions[0].offset == 3 * MiB + 1536);
    CHECK(r->badRegions[0].length == 512);
    CHECK(r->bytesRead == 8 * MiB);
    MemoryDevice ok(4 * MiB);
    Report report2("scan2");
    auto s = ops::surfaceScan(ok, progress, report2);
    REQUIRE(s);
    CHECK(s->healthy());
}
