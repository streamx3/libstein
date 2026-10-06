// SPDX-License-Identifier: MIT
// GUID Partition Table (UEFI 2.10 §5.3) with explicit primary/backup state,
// CRC verification, diagnostics and repair.
#pragma once

#include "stein/pt/partition_table.hpp"

#include <array>

namespace stein::pt {

class GptTable final : public PartitionTable {
public:
    struct HeaderState {
        bool present = false;        // bytes could be read
        bool signatureOk = false;
        bool headerCrcOk = false;
        bool selfLbaOk = false;      // my_lba points at where we read it
        bool entriesCrcOk = false;   // its entry array matched its CRC
        Lba lba = 0;
        std::string problem;         // first failure, human text
        bool valid() const { return present && signatureOk && headerCrcOk && selfLbaOk; }
    };

    // NotFound if the device carries no GPT (neither header valid and no protective MBR).
    static Expected<std::unique_ptr<GptTable>> read(BlockDevicePtr device);
    static std::unique_ptr<GptTable> createEmpty(const Geometry& geometry, std::uint32_t entryCount = 128);

    TableType type() const override { return TableType::Gpt; }
    const Geometry& geometry() const override { return m_geometry; }
    std::span<const Partition> partitions() const override { return m_partitions; }
    std::span<const Diagnostic> diagnostics() const override { return m_diagnostics; }
    Limits limits() const override;
    Lba firstUsableLba() const override { return m_firstUsable; }
    Lba lastUsableLba() const override { return m_lastUsable; }
    std::vector<Region> metadataRegions() const override;
    layout::Node describe() const override;
    Expected<void> write(BlockDevice& device) const override;
    Expected<void> repair(BlockDevice& device, const RepairOptions& options) override;
    Expected<void> addPartition(const Partition& partition) override;
    Expected<void> removePartition(std::uint32_t index) override;
    Expected<void> updatePartition(const Partition& partition) override;
    std::unique_ptr<PartitionTable> clone() const override { return std::make_unique<GptTable>(*this); }

    const Uuid& diskGuid() const { return m_diskGuid; }
    void setDiskGuid(const Uuid& g) { m_diskGuid = g; }
    std::uint32_t entryCount() const { return m_entryCount; }
    std::uint32_t entrySize() const { return m_entrySize; }
    const HeaderState& primaryState() const { return m_primary; }
    const HeaderState& backupState() const { return m_backup; }
    bool hasProtectiveMbr() const { return m_hasProtectiveMbr; }
    bool isHybridMbr() const { return m_isHybridMbr; }
    // Where the backup header *should* be on a device of `sectors` sectors.
    static Lba expectedBackupLba(SectorCount sectors) { return sectors ? sectors - 1 : 0; }
    SectorCount entryArraySectors() const;

private:
    GptTable() = default;
    void addDiagnostic(layout::Validity sev, std::string code, std::string message, std::optional<Region> region = {},
                       bool repairable = false);
    void validateEntries();
    std::vector<std::byte> serializeEntries() const;
    std::vector<std::byte> serializeHeader(Lba myLba, Lba alternateLba, Lba entriesLba, Lba lastUsable,
                                           std::uint32_t entriesCrc) const;
    std::vector<std::byte> buildProtectiveMbr(SectorCount sectors) const;

    Geometry m_geometry;
    Uuid m_diskGuid;
    Lba m_firstUsable = 0, m_lastUsable = 0;
    Lba m_primaryEntriesLba = 2, m_backupEntriesLba = 0, m_alternateLba = 0;
    std::uint32_t m_entryCount = 128, m_entrySize = 128;
    std::vector<Partition> m_partitions;
    std::vector<Diagnostic> m_diagnostics;
    HeaderState m_primary, m_backup;
    bool m_hasProtectiveMbr = false, m_isHybridMbr = false;
    std::vector<std::byte> m_mbrSector;       // LBA 0 as read (bootstrap preserved on write)
    std::vector<std::byte> m_primaryHeaderRaw, m_backupHeaderRaw;   // for describe()
    std::vector<std::byte> m_entriesRaw;                            // the array we loaded
    bool m_loadedFromBackup = false;
};

} // namespace stein::pt
