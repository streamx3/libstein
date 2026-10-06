// SPDX-License-Identifier: MIT
#include "stein/pt/partition_table.hpp"

#include "stein/pt/apm_table.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/mbr_table.hpp"

#include <algorithm>

namespace stein::pt {

using layout::Validity;

Expected<void> PartitionTable::repair(BlockDevice&, const RepairOptions&) {
    return fail(ErrorCategory::Unsupported, std::string("repair is not implemented for ") + std::string(toString(type())));
}

Validity PartitionTable::health() const {
    Validity worst = Validity::Ok;
    for (const auto& d : diagnostics())
        if (d.severity > worst) worst = d.severity;
    return worst;
}

const Partition* PartitionTable::find(std::uint32_t index) const {
    for (const auto& p : partitions())
        if (p.index == index) return &p;
    return nullptr;
}

std::vector<FreeRegion> PartitionTable::freeRegions(SectorCount minSectors) const {
    std::vector<const Partition*> used;
    for (const auto& p : partitions())
        if (!p.isExtended) used.push_back(&p);   // the extended container is free space until logicals fill it
    std::sort(used.begin(), used.end(), [](const Partition* a, const Partition* b) { return a->firstLba < b->firstLba; });
    std::vector<FreeRegion> out;
    Lba cursor = firstUsableLba();
    const Lba last = lastUsableLba();
    for (const auto* p : used) {
        if (p->firstLba > cursor && p->firstLba - cursor >= minSectors) out.push_back({cursor, p->firstLba - 1});
        cursor = std::max(cursor, p->lastLba + 1);
    }
    if (last >= cursor && last - cursor + 1 >= minSectors) out.push_back({cursor, last});
    return out;
}

Expected<void> PartitionTable::validatePlacement(const Partition& c, std::optional<std::uint32_t> ignoreIndex) const {
    if (c.lastLba < c.firstLba) return fail(ErrorCategory::InvalidArgument, "partition ends before it starts");
    if (c.firstLba < firstUsableLba() || c.lastLba > lastUsableLba())
        return fail(ErrorCategory::OutOfRange, "partition [" + std::to_string(c.firstLba) + ", " + std::to_string(c.lastLba) +
                                                   "] is outside the usable range [" + std::to_string(firstUsableLba()) + ", " +
                                                   std::to_string(lastUsableLba()) + "]");
    for (const auto& p : partitions()) {
        if (ignoreIndex && p.index == *ignoreIndex) continue;
        // MBR: a logical must sit inside the extended container; that is not an overlap.
        if ((c.isLogical && p.isExtended) || (c.isExtended && p.isLogical)) {
            const Partition& ext = c.isExtended ? c : p;
            const Partition& log = c.isLogical ? c : p;
            if (log.firstLba < ext.firstLba || log.lastLba > ext.lastLba)
                return fail(ErrorCategory::InvalidArgument, "logical partition " + std::to_string(log.index) + " would lie outside the extended partition");
            continue;
        }
        if (c.overlaps(p))
            return fail(ErrorCategory::InvalidArgument, "overlaps partition " + std::to_string(p.index) + " [" + std::to_string(p.firstLba) +
                                                            ", " + std::to_string(p.lastLba) + "]");
    }
    return {};
}

Expected<std::unique_ptr<PartitionTable>> PartitionTable::read(BlockDevicePtr device, ReadOptions options) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    std::string notes;
    if (options.tryGpt) {
        auto gpt = GptTable::read(device);
        if (gpt) return std::unique_ptr<PartitionTable>(std::move(*gpt));
        if (gpt.error().category() != ErrorCategory::NotFound) return fail(gpt.error());
        notes += "gpt: " + gpt.error().message() + "; ";
    }
    if (options.tryApm) {
        auto apm = ApmTable::read(device);
        if (apm) return std::unique_ptr<PartitionTable>(std::move(*apm));
        if (apm.error().category() != ErrorCategory::NotFound) return fail(apm.error());
        notes += "apm: " + apm.error().message() + "; ";
    }
    if (options.tryMbr) {
        auto mbr = MbrTable::read(device);
        if (mbr) return std::unique_ptr<PartitionTable>(std::move(*mbr));
        if (mbr.error().category() != ErrorCategory::NotFound) return fail(mbr.error());
        notes += "mbr: " + mbr.error().message();
    }
    return std::unique_ptr<PartitionTable>(std::make_unique<NoPartitionTable>(device->geometry(), notes));
}

Expected<std::unique_ptr<PartitionTable>> PartitionTable::createEmpty(TableType type, const Geometry& geometry) {
    switch (type) {
    case TableType::Gpt: return std::unique_ptr<PartitionTable>(GptTable::createEmpty(geometry));
    case TableType::Mbr: return std::unique_ptr<PartitionTable>(MbrTable::createEmpty(geometry));
    case TableType::Apm: return std::unique_ptr<PartitionTable>(ApmTable::createEmpty(geometry));
    case TableType::None: return std::unique_ptr<PartitionTable>(std::make_unique<NoPartitionTable>(geometry));
    default: return fail(ErrorCategory::Unsupported, std::string("cannot create a ") + std::string(toString(type)) + " table yet");
    }
}

// ----------------------------------------------------------------------------- NoPartitionTable

NoPartitionTable::NoPartitionTable(const Geometry& geometry, std::string note) : m_geometry(geometry) {
    m_diagnostics.push_back(Diagnostic{Validity::Info, "pt.none",
                                       note.empty() ? "no partition table" : "no partition table (" + note + ")", {}, false});
}

layout::Node NoPartitionTable::describe() const {
    layout::Node n;
    n.name = "no partition table";
    n.isStruct = true;
    n.size = m_geometry.sizeBytes;
    n.flag(Validity::Info, m_diagnostics.front().message);
    return n;
}

Expected<void> NoPartitionTable::addPartition(const Partition&) {
    return fail(ErrorCategory::Unsupported, "device has no partition table; create one first");
}
Expected<void> NoPartitionTable::removePartition(std::uint32_t) {
    return fail(ErrorCategory::Unsupported, "device has no partition table");
}
Expected<void> NoPartitionTable::updatePartition(const Partition&) {
    return fail(ErrorCategory::Unsupported, "device has no partition table");
}

} // namespace stein::pt
