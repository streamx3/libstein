// SPDX-License-Identifier: MIT
// PartitionTable: abstract base for every partitioning scheme. Reading never
// writes; editing happens in memory; write() and repair() are explicit.
// See doc/design/12-class-hierarchies.md §2.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/units.hpp"
#include "stein/layout/node.hpp"
#include "stein/pt/partition_type.hpp"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace stein::pt {

struct Partition {
    std::uint32_t index = 0;          // 1-based slot: GPT entry number, MBR 1-4, logicals 5+
    Lba firstLba = 0;
    Lba lastLba = 0;                  // inclusive
    PartitionType type;
    std::string name;                 // GPT / APM name, UTF-8
    Uuid uuid;                        // GPT unique partition GUID
    std::uint64_t attributes = 0;     // GPT attribute bits; MBR: kMbrBootable
    bool isExtended = false;          // MBR extended container
    bool isLogical = false;           // MBR logical inside the extended container
    std::optional<Lba> ebrLba;        // MBR logical: where its EBR sector lives

    static constexpr std::uint64_t kMbrBootable = 1;

    SectorCount sectors() const { return lastLba >= firstLba ? lastLba - firstLba + 1 : 0; }
    Region region(std::uint32_t sectorSize) const { return {firstLba * sectorSize, sectors() * sectorSize}; }
    bool overlaps(const Partition& o) const { return firstLba <= o.lastLba && o.firstLba <= lastLba; }
};

struct FreeRegion {
    Lba firstLba = 0;
    Lba lastLba = 0;                  // inclusive
    SectorCount sectors() const { return lastLba >= firstLba ? lastLba - firstLba + 1 : 0; }
};

struct Diagnostic {
    layout::Validity severity = layout::Validity::Info;
    std::string code;                 // stable identifier, e.g. "gpt.primary_header"
    std::string message;              // human text
    std::optional<Region> region;     // bytes on the device the diagnostic refers to
    bool repairable = false;          // repair() can fix it
};

struct Limits {
    std::uint32_t maxPartitions = 0;
    bool supportsNames = false;
    bool supportsUuids = false;
    bool supportsAttributes = false;
    bool supportsLogical = false;     // MBR extended/logical
    std::uint32_t maxNameUnits = 0;   // UTF-16 units for GPT, bytes for APM
};

struct RepairOptions {
    bool rebuildPrimary = true;
    bool rebuildBackup = true;
    bool relocateBackup = true;       // move the backup to the end of a grown disk
    bool fixProtectiveMbr = true;     // only when the MBR is not a hybrid
};

struct ReadOptions {
    bool tryGpt = true;
    bool tryMbr = true;
};

class PartitionTable {
public:
    virtual ~PartitionTable() = default;

    virtual TableType type() const = 0;
    virtual const Geometry& geometry() const = 0;
    virtual std::span<const Partition> partitions() const = 0;
    virtual std::span<const Diagnostic> diagnostics() const = 0;
    virtual Limits limits() const = 0;
    virtual Lba firstUsableLba() const = 0;
    virtual Lba lastUsableLba() const = 0;
    // Byte ranges holding the table's own metadata (for dump/restore of the "table piece").
    virtual std::vector<Region> metadataRegions() const = 0;
    // Hexinator-style tree of every metadata structure with validity.
    virtual layout::Node describe() const = 0;

    // Write the whole table to `device` (ordered, CRCs recomputed). The device
    // may differ from the one the table was read from (restore to another disk).
    virtual Expected<void> write(BlockDevice& device) const = 0;
    // Fix repairable diagnostics in place. Default: unsupported.
    virtual Expected<void> repair(BlockDevice& device, const RepairOptions& options);

    // In-memory editing. index 0 in addPartition = pick the first free slot.
    virtual Expected<void> addPartition(const Partition& partition) = 0;
    virtual Expected<void> removePartition(std::uint32_t index) = 0;
    virtual Expected<void> updatePartition(const Partition& partition) = 0;   // matched by index
    virtual std::unique_ptr<PartitionTable> clone() const = 0;

    // ---- non-virtual helpers ---------------------------------------------------
    layout::Validity health() const;
    const Partition* find(std::uint32_t index) const;
    // Gaps inside the usable range not covered by any (non-extended) partition.
    std::vector<FreeRegion> freeRegions(SectorCount minSectors = 1) const;
    // Bounds and overlap validation shared by schemes.
    Expected<void> validatePlacement(const Partition& candidate, std::optional<std::uint32_t> ignoreIndex) const;

    // Detects the scheme and parses it. Never fails for "no table": that returns
    // a NoPartitionTable. Fails only on I/O errors.
    static Expected<std::unique_ptr<PartitionTable>> read(BlockDevicePtr device, ReadOptions options = {});
    static Expected<std::unique_ptr<PartitionTable>> createEmpty(TableType type, const Geometry& geometry);
};

// The "loop" case: a device without a partition table (whole-device filesystem or blank).
class NoPartitionTable final : public PartitionTable {
public:
    explicit NoPartitionTable(const Geometry& geometry, std::string note = {});
    TableType type() const override { return TableType::None; }
    const Geometry& geometry() const override { return m_geometry; }
    std::span<const Partition> partitions() const override { return {}; }
    std::span<const Diagnostic> diagnostics() const override { return m_diagnostics; }
    Limits limits() const override { return {}; }
    Lba firstUsableLba() const override { return 0; }
    Lba lastUsableLba() const override { return m_geometry.sectors() ? m_geometry.sectors() - 1 : 0; }
    std::vector<Region> metadataRegions() const override { return {}; }
    layout::Node describe() const override;
    Expected<void> write(BlockDevice&) const override { return {}; }
    Expected<void> addPartition(const Partition&) override;
    Expected<void> removePartition(std::uint32_t) override;
    Expected<void> updatePartition(const Partition&) override;
    std::unique_ptr<PartitionTable> clone() const override { return std::make_unique<NoPartitionTable>(*this); }

private:
    Geometry m_geometry;
    std::vector<Diagnostic> m_diagnostics;
};

} // namespace stein::pt
