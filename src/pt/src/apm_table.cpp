// SPDX-License-Identifier: MIT
#include "stein/pt/apm_table.hpp"

#include "stein/core/strings.hpp"
#include "stein/layout/gen/apm.hpp"

#include <algorithm>

namespace stein::pt {

using layout::Validity;
namespace gen = layout::gen;

namespace {
bool isMapEntry(std::string_view type) { return type == "Apple_partition_map"; }
bool isFree(std::string_view type) { return type == "Apple_Free" || type == "Apple_Void"; }
} // namespace

Expected<std::unique_ptr<ApmTable>> ApmTable::read(BlockDevicePtr device) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    const Geometry geo = device->geometry();
    auto b0 = device->read(0, 512);
    if (!b0) return fail(b0.error());
    gen::ApmBlock0 block0(*b0);
    std::uint32_t bs = geo.logicalSectorSize ? geo.logicalSectorSize : 512;
    bool haveBlock0 = block0.sbSig() == "ER";
    if (haveBlock0) {
        const std::uint16_t sbs = block0.sbBlkSize();
        if (sbs == 512 || sbs == 1024 || sbs == 2048 || sbs == 4096) bs = sbs;
    }
    // Entry 1 must be a map entry (some maps lack Block0 — e.g. images made by old tools — so try both).
    auto e1 = device->read(bs, 512);
    if (!e1) return fail(e1.error());
    gen::ApmEntry first(*e1);
    if (first.pmSig() != "PM") {
        if (!haveBlock0 && bs != 512) return fail(ErrorCategory::NotFound, "no APM signatures");
        return fail(ErrorCategory::NotFound, haveBlock0 ? "Block0 found but no partition map entry" : "no APM signatures");
    }
    const std::uint32_t count = first.pmMapBlkCnt();
    if (count == 0 || count > 1024) return fail(ErrorCategory::InvalidFormat, "implausible APM entry count " + std::to_string(count));

    auto t = std::unique_ptr<ApmTable>(new ApmTable());
    t->m_geometry = geo;
    t->m_blockSize = bs;
    t->m_mapEntries = count;
    t->m_mapBlocks = count;
    t->m_block0 = *b0;
    if (!haveBlock0) t->addDiagnostic(Validity::Warning, "apm.no_block0", "no driver descriptor map (Block0) at sector 0", Region{0, 512});
    else if (block0.sbBlkCount() && static_cast<ByteCount>(block0.sbBlkCount()) * bs != geo.sizeBytes)
        t->addDiagnostic(Validity::Info, "apm.block0_count", "Block0 block count (" + std::to_string(block0.sbBlkCount()) + ") does not match the device size");
    if (bs != geo.logicalSectorSize)
        t->addDiagnostic(Validity::Warning, "apm.block_size", "map block size " + std::to_string(bs) + " differs from the device sector size " + std::to_string(geo.logicalSectorSize));

    bool sawMapEntry = false;
    for (std::uint32_t i = 1; i <= count; ++i) {
        auto raw = device->read(static_cast<ByteCount>(i) * bs, 512);
        if (!raw) {
            t->addDiagnostic(Validity::Error, "apm.entry_unreadable", "map entry " + std::to_string(i) + " is unreadable");
            break;
        }
        gen::ApmEntry e(*raw);
        t->m_entriesRaw.push_back(*raw);
        if (e.pmSig() != "PM") {
            t->addDiagnostic(Validity::Error, "apm.entry_signature", "map entry " + std::to_string(i) + " has no PM signature", Region{static_cast<ByteCount>(i) * bs, 512});
            continue;
        }
        if (e.pmMapBlkCnt() != count)
            t->addDiagnostic(Validity::Warning, "apm.count_mismatch", "map entry " + std::to_string(i) + " says the map has " + std::to_string(e.pmMapBlkCnt()) + " entries, entry 1 says " + std::to_string(count));
        const std::string type = e.pmParType();
        if (isMapEntry(type)) {
            sawMapEntry = true;
            if (e.pmPyPartStart() != 1) t->addDiagnostic(Validity::Warning, "apm.map_start", "partition map entry does not start at block 1");
            if (e.pmPartBlkCnt() >= count) t->m_mapBlocks = e.pmPartBlkCnt();
            continue;
        }
        if (isFree(type)) continue;
        Partition p;
        p.index = i;
        p.firstLba = static_cast<Lba>(e.pmPyPartStart()) * bs / geo.logicalSectorSize;
        p.lastLba = (static_cast<Lba>(e.pmPyPartStart()) + e.pmPartBlkCnt()) * bs / geo.logicalSectorSize - 1;
        p.type = PartitionType::apm(type);
        p.name = e.pmPartName();
        p.attributes = e.pmPartStatus();
        t->m_partitions.push_back(std::move(p));
        t->m_entryStatus.push_back(e.pmPartStatus());
    }
    if (!sawMapEntry) t->addDiagnostic(Validity::Warning, "apm.no_self_entry", "the map does not describe itself (no Apple_partition_map entry)");
    // Overlaps / bounds.
    const std::uint32_t ss = geo.logicalSectorSize;
    for (std::size_t i = 0; i < t->m_partitions.size(); ++i) {
        const auto& p = t->m_partitions[i];
        if (p.lastLba >= geo.sectors()) t->addDiagnostic(Validity::Error, "apm.out_of_range", "partition " + std::to_string(p.index) + " extends past the end of the device", p.region(ss));
        for (std::size_t j = i + 1; j < t->m_partitions.size(); ++j)
            if (p.overlaps(t->m_partitions[j]))
                t->addDiagnostic(Validity::Error, "apm.overlap", "partitions " + std::to_string(p.index) + " and " + std::to_string(t->m_partitions[j].index) + " overlap", p.region(ss));
    }
    return t;
}

void ApmTable::addDiagnostic(Validity sev, std::string code, std::string message, std::optional<Region> region) {
    m_diagnostics.push_back(Diagnostic{sev, std::move(code), std::move(message), region, false});
}

std::unique_ptr<ApmTable> ApmTable::createEmpty(const Geometry& geometry, std::uint32_t mapEntries) {
    auto t = std::unique_ptr<ApmTable>(new ApmTable());
    t->m_geometry = geometry;
    t->m_blockSize = geometry.logicalSectorSize ? geometry.logicalSectorSize : 512;
    t->m_mapEntries = std::max<std::uint32_t>(mapEntries, 2);
    t->m_mapBlocks = t->m_mapEntries;
    return t;
}

Limits ApmTable::limits() const {
    return Limits{.maxPartitions = m_mapEntries - 1, .supportsNames = true, .supportsUuids = false,
                  .supportsAttributes = true, .supportsLogical = false, .maxNameUnits = 32};
}

Lba ApmTable::lastUsableLba() const { return m_geometry.sectors() ? m_geometry.sectors() - 1 : 0; }

std::vector<Region> ApmTable::metadataRegions() const {
    return {Region{0, static_cast<ByteCount>(1 + m_mapBlocks) * m_blockSize}};
}

Expected<void> ApmTable::addPartition(const Partition& in) {
    Partition p = in;
    if (p.type.scheme != TableType::Apm) return fail(ErrorCategory::InvalidArgument, "partition type is not an APM type");
    if (p.type.apmType.empty() || isMapEntry(p.type.apmType) || isFree(p.type.apmType))
        return fail(ErrorCategory::InvalidArgument, "APM type must be a real partition type (e.g. Apple_HFS)");
    if (p.name.size() > 32) return fail(ErrorCategory::InvalidArgument, "APM names are at most 32 bytes");
    if (p.index == 0) {
        for (std::uint32_t i = 2; i <= m_mapEntries; ++i)
            if (!find(i)) {
                p.index = i;
                break;
            }
        if (p.index == 0) return fail(ErrorCategory::OutOfRange, "partition map is full");
    } else if (p.index < 2 || p.index > m_mapEntries || find(p.index)) {
        return fail(ErrorCategory::InvalidArgument, "invalid or busy map slot (1 is the map itself)");
    }
    if (p.attributes == 0) p.attributes = kDefaultStatus;
    if (auto r = validatePlacement(p, std::nullopt); !r) return r;
    m_partitions.push_back(std::move(p));
    std::sort(m_partitions.begin(), m_partitions.end(), [](const Partition& a, const Partition& b) { return a.index < b.index; });
    return {};
}

Expected<void> ApmTable::removePartition(std::uint32_t index) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(index));
    m_partitions.erase(it);
    return {};
}

Expected<void> ApmTable::updatePartition(const Partition& in) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == in.index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(in.index));
    if (in.type.scheme != TableType::Apm || in.type.apmType.empty()) return fail(ErrorCategory::InvalidArgument, "partition type is not an APM type");
    if (in.name.size() > 32) return fail(ErrorCategory::InvalidArgument, "APM names are at most 32 bytes");
    if (auto r = validatePlacement(in, in.index); !r) return r;
    *it = in;
    return {};
}

Expected<void> ApmTable::write(BlockDevice& device) const {
    const Geometry geo = device.geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    const std::uint32_t bs = m_blockSize;
    if (bs % ss != 0 && ss % bs != 0) return fail(ErrorCategory::InvalidArgument, "map block size and device sector size are incompatible");
    for (const auto& p : m_partitions)
        if (p.lastLba >= geo.sectors()) return fail(ErrorCategory::OutOfRange, "partition " + std::to_string(p.index) + " does not fit on the target device");
    // Block0.
    std::vector<std::byte> b0(bs, std::byte{0});
    if (m_block0.size() >= 512) std::copy_n(m_block0.begin(), std::min<std::size_t>(512, bs), b0.begin());
    gen::ApmBlock0::setSbSig(b0, "ER");
    gen::ApmBlock0::setSbBlkSize(b0, static_cast<std::uint16_t>(bs));
    gen::ApmBlock0::setSbBlkCount(b0, static_cast<std::uint32_t>(std::min<ByteCount>(geo.sizeBytes / bs, 0xFFFFFFFFull)));
    if (auto r = device.writeAt(0, b0); !r) return r;

    auto makeEntry = [&](std::string_view type, std::string_view name, std::uint32_t start, std::uint32_t blocks, std::uint32_t status) {
        std::vector<std::byte> e(bs, std::byte{0});
        gen::ApmEntry::setPmSig(e, "PM");
        gen::ApmEntry::setPmMapBlkCnt(e, m_mapEntries);
        gen::ApmEntry::setPmPyPartStart(e, start);
        gen::ApmEntry::setPmPartBlkCnt(e, blocks);
        gen::ApmEntry::setPmPartName(e, name);
        gen::ApmEntry::setPmParType(e, type);
        gen::ApmEntry::setPmLgDataStart(e, 0);
        gen::ApmEntry::setPmDataCnt(e, blocks);
        gen::ApmEntry::setPmPartStatus(e, status);
        return e;
    };
    // Entry 1: the map itself. Then real partitions in their slots; empty slots become Apple_Free
    // covering the gaps (sorted by position), remaining slots Apple_Void.
    std::vector<std::vector<std::byte>> entries(m_mapEntries);
    entries[0] = makeEntry("Apple_partition_map", "Apple", 1, m_mapBlocks, 0x3);
    std::vector<const Partition*> sorted;
    for (const auto& p : m_partitions) {
        const std::uint32_t start = static_cast<std::uint32_t>(p.firstLba * ss / bs);
        const std::uint32_t blocks = static_cast<std::uint32_t>(p.sectors() * ss / bs);
        if (p.index < 2 || p.index > m_mapEntries) return fail(ErrorCategory::InvalidArgument, "partition slot out of range");
        entries[p.index - 1] = makeEntry(p.type.apmType, p.name, start, blocks, p.attributes ? static_cast<std::uint32_t>(p.attributes) : kDefaultStatus);
        sorted.push_back(&p);
    }
    std::sort(sorted.begin(), sorted.end(), [](const Partition* a, const Partition* b) { return a->firstLba < b->firstLba; });
    // Free gaps.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> gaps;
    std::uint32_t cursor = 1 + m_mapBlocks;
    const std::uint32_t total = static_cast<std::uint32_t>(std::min<ByteCount>(geo.sizeBytes / bs, 0xFFFFFFFFull));
    for (const auto* p : sorted) {
        const std::uint32_t start = static_cast<std::uint32_t>(p->firstLba * ss / bs);
        if (start > cursor) gaps.emplace_back(cursor, start - cursor);
        cursor = std::max(cursor, static_cast<std::uint32_t>((p->lastLba + 1) * ss / bs));
    }
    if (total > cursor) gaps.emplace_back(cursor, total - cursor);
    std::size_t slot = 1;
    for (const auto& g : gaps) {
        while (slot < entries.size() && !entries[slot].empty()) ++slot;
        if (slot >= entries.size()) break;
        entries[slot] = makeEntry("Apple_Free", "Extra", g.first, g.second, 0);
    }
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].empty()) entries[i] = makeEntry("Apple_Void", "", 0, 0, 0);
        if (auto r = device.writeAt(static_cast<ByteCount>(i + 1) * bs, entries[i]); !r) return r;
    }
    return device.flush();
}

layout::Node ApmTable::describe() const {
    layout::Node root;
    root.name = "Apple Partition Map";
    root.isStruct = true;
    root.size = m_geometry.sizeBytes;
    if (m_block0.size() >= 32) {
        auto n = gen::ApmBlock0(m_block0).describe(0);
        n.name = "Block0 (driver descriptor map)";
        root.addChild(std::move(n));
    }
    for (std::size_t i = 0; i < m_entriesRaw.size(); ++i) {
        auto n = gen::ApmEntry(m_entriesRaw[i]).describe(static_cast<ByteCount>(i + 1) * m_blockSize);
        n.name = "map entry " + std::to_string(i + 1);
        if (auto* t = n.child("pm_par_type")) {
            const std::string type = t->value;
            if (isMapEntry(type)) t->pretty = "the partition map itself";
            else if (isFree(type)) t->pretty = "free space";
        }
        root.addChild(std::move(n));
    }
    for (const auto& d : m_diagnostics)
        if (d.severity >= Validity::Warning) root.flag(d.severity, d.message);
    return root;
}

} // namespace stein::pt
