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
    // Rewrites the EBR chain from the logicals held, after looking behind a broken link for
    // EBR sectors the walk could no longer reach (believed only when a filesystem sits where
    // they say) and for the filesystem of the logical the lost EBR itself described. Refuses
    // to replace a chain it could not read with an empty one, and to close the chain over a
    // logical it cannot rebuild.
    Expected<void> repair(BlockDevice& device, const RepairOptions& options) override;
    Expected<void> addPartition(const Partition& partition) override;
    Expected<void> removePartition(std::uint32_t index) override;
    Expected<void> updatePartition(const Partition& partition) override;
    std::unique_ptr<PartitionTable> clone() const override { return std::make_unique<MbrTable>(*this); }

    std::uint32_t diskSignature() const { return m_diskSignature; }
    void setDiskSignature(std::uint32_t s) { m_diskSignature = s; }
    std::uint16_t copyProtected() const { return m_copyProtected; }
    const Partition* extendedPartition() const;
    // Sectors between an EBR and its logical partition's data when we place EBRs ourselves.
    static constexpr Lba kDefaultEbrGap = 2048;
    // Upper bound on what the orphaned-EBR scan of repair() reads, split evenly between its
    // two passes (the 1 MiB grid and the track grid behind the break).
    static constexpr ByteCount kRecoveryScanBudget = 64 * MiB;

private:
    // How the EBR walk of read() ended.
    enum class ChainEnd : std::uint8_t {
        None,         // no extended partition
        Empty,        // first EBR sector is all zero: an extended partition without logicals yet
        Terminated,   // an EBR without a link
        Unreadable,   // I/O error on an EBR
        Unsigned,     // an EBR without the 0xAA55 signature
        Outside,      // a link pointing outside the extended partition or the device
        Loop,         // a link back to a visited EBR, or more than 128 links
        Wiped,        // first EBR sector is all zero but EBRs or filesystems lie behind it
    };
    bool chainBroken() const { return m_chainEnd >= ChainEnd::Unreadable; }
    // What the scan behind a broken chain turned up.
    struct Recovery {
        std::vector<Partition> logicals;
        bool lostAtBreak = false;   // the EBR at the break described a logical nothing could rebuild
    };

    MbrTable() = default;
    void addDiagnostic(layout::Validity sev, std::string code, std::string message, std::optional<Region> region = {},
                       bool repairable = false);
    void validate();
    std::vector<std::byte> serializeEntry(const Partition& p, Lba relativeTo) const;
    Recovery recoverLogicals(BlockDevice& device, const Partition& ext) const;

    Geometry m_geometry;
    std::uint32_t m_diskSignature = 0;
    std::uint16_t m_copyProtected = 0;               // 0x1BC of LBA 0, preserved on write
    std::vector<std::byte> m_bootstrap;              // 440 bytes of LBA 0, preserved on write
    std::vector<Partition> m_partitions;             // primaries (1-4) then logicals (5+), sorted by index
    std::vector<Diagnostic> m_diagnostics;
    std::vector<std::byte> m_sector0;                // as read, for describe()
    std::vector<std::pair<Lba, std::vector<std::byte>>> m_ebrs;   // EBR sectors as read
    ChainEnd m_chainEnd = ChainEnd::None;
    std::optional<Lba> m_chainBreakLba;              // where the walk stopped when chainBroken()
};

} // namespace stein::pt
