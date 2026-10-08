// SPDX-License-Identifier: MIT
// Apple Partition Map: Block0 (driver descriptor map) + one map entry per
// block starting at block 1. The map describes itself; Apple_Free entries
// mark unallocated space explicitly.
#pragma once

#include "stein/pt/partition_table.hpp"

namespace stein::pt {

// One slot of the map as read, including the Apple_partition_map entry and the
// Apple_Free slots that partitions() leaves out. The OS exposes every slot as a
// block device (Linux: sda1 is the map itself, an Apple_Free slot is sdaN too).
struct ApmSlot {
    std::uint32_t slot = 0;        // 1-based
    std::string type;              // pm_par_type
    std::string name;              // pm_part_name
    Lba firstLba = 0, lastLba = 0; // in device sectors, inclusive
    bool isMap = false, isFree = false;
};

class ApmTable final : public PartitionTable {
public:
    static Expected<std::unique_ptr<ApmTable>> read(BlockDevicePtr device);
    static std::unique_ptr<ApmTable> createEmpty(const Geometry& geometry, std::uint32_t mapEntries = 63);

    TableType type() const override { return TableType::Apm; }
    const Geometry& geometry() const override { return m_geometry; }
    std::span<const Partition> partitions() const override { return m_partitions; }
    std::span<const Diagnostic> diagnostics() const override { return m_diagnostics; }
    Limits limits() const override;
    Lba firstUsableLba() const override { return (1 + static_cast<Lba>(m_mapBlocks)) * m_blockSize / m_geometry.logicalSectorSize; }   // after Block0 and the map area
    Lba lastUsableLba() const override;
    std::vector<Region> metadataRegions() const override;
    layout::Node describe() const override;
    Expected<void> write(BlockDevice& device) const override;
    Expected<void> addPartition(const Partition& partition) override;
    Expected<void> removePartition(std::uint32_t index) override;
    Expected<void> updatePartition(const Partition& partition) override;
    std::unique_ptr<PartitionTable> clone() const override { return std::make_unique<ApmTable>(*this); }

    // Block size the map is written in (Block0.sbBlkSize); normally the device's sector size.
    std::uint32_t mapBlockSize() const { return m_blockSize; }
    std::uint32_t mapEntries() const { return m_mapEntries; }
    // Blocks reserved for the map (the Apple_partition_map entry's size); >= mapEntries.
    std::uint32_t mapBlocks() const { return m_mapBlocks; }
    // Every slot with a PM signature, in map order, as read (not maintained by edits).
    std::span<const ApmSlot> slots() const { return m_slots; }
    // Apple_Free entries are kept out of partitions(); they are reported as free regions.
    static constexpr std::uint32_t kDefaultStatus = 0x3F;   // valid|allocated|in_use|boot_info|readable|writable

private:
    ApmTable() = default;
    void addDiagnostic(layout::Validity sev, std::string code, std::string message, std::optional<Region> region = {});

    Geometry m_geometry;
    std::uint32_t m_blockSize = 512;
    std::uint32_t m_mapEntries = 0;         // pm_map_blk_cnt
    std::uint32_t m_mapBlocks = 0;          // size of the Apple_partition_map partition in blocks
    std::vector<Partition> m_partitions;    // real partitions (not map, not free), index = map slot (1-based)
    std::vector<Diagnostic> m_diagnostics;
    std::vector<std::byte> m_block0;        // as read
    std::vector<std::vector<std::byte>> m_entriesRaw;   // all map entries as read, for describe()
    std::vector<std::uint32_t> m_entryStatus;           // per real partition, parallel to m_partitions
    std::vector<ApmSlot> m_slots;                       // all slots as read, see slots()
};

} // namespace stein::pt
