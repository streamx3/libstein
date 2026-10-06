// SPDX-License-Identifier: MIT
// DOS/MBR partition table with the EBR chain for logical partitions.
#pragma once

#include "stein/pt/partition_table.hpp"

namespace stein::pt {

class MbrTable final : public PartitionTable {
public:
    // NotFound if LBA 0 is not an MBR (bad signature, or a filesystem boot sector).
    static Expected<std::unique_ptr<MbrTable>> read(BlockDevicePtr device);
    static std::unique_ptr<MbrTable> createEmpty(const Geometry& geometry);

    TableType type() const override { return TableType::Mbr; }
    const Geometry& geometry() const override { return m_geometry; }
    std::span<const Partition> partitions() const override { return m_partitions; }
    std::span<const Diagnostic> diagnostics() const override { return m_diagnostics; }
    Limits limits() const override;
    Lba firstUsableLba() const override { return 1; }
    Lba lastUsableLba() const override;
    std::vector<Region> metadataRegions() const override;
    layout::Node describe() const override;
    Expected<void> write(BlockDevice& device) const override;
    Expected<void> addPartition(const Partition& partition) override;
    Expected<void> removePartition(std::uint32_t index) override;
    Expected<void> updatePartition(const Partition& partition) override;
    std::unique_ptr<PartitionTable> clone() const override { return std::make_unique<MbrTable>(*this); }

    std::uint32_t diskSignature() const { return m_diskSignature; }
    void setDiskSignature(std::uint32_t s) { m_diskSignature = s; }
    const Partition* extendedPartition() const;
    // Sectors between an EBR and its logical partition's data when we place EBRs ourselves.
    static constexpr Lba kDefaultEbrGap = 2048;

private:
    MbrTable() = default;
    void addDiagnostic(layout::Validity sev, std::string code, std::string message, std::optional<Region> region = {});
    void validate();
    std::vector<std::byte> serializeEntry(const Partition& p, Lba relativeTo) const;

    Geometry m_geometry;
    std::uint32_t m_diskSignature = 0;
    std::vector<std::byte> m_bootstrap;              // 440 bytes of LBA 0, preserved on write
    std::vector<Partition> m_partitions;             // primaries (1-4) then logicals (5+), sorted by index
    std::vector<Diagnostic> m_diagnostics;
    std::vector<std::byte> m_sector0;                // as read, for describe()
    std::vector<std::pair<Lba, std::vector<std::byte>>> m_ebrs;   // EBR sectors as read
};

} // namespace stein::pt
