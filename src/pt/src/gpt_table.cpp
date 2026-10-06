// SPDX-License-Identifier: MIT
#include "stein/pt/gpt_table.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/gpt.hpp"
#include "stein/layout/gen/mbr.hpp"

#include <algorithm>

namespace stein::pt {

using layout::Validity;
namespace gen = layout::gen;

namespace {

constexpr std::uint32_t kHeaderSize = gen::GptHeader::kSize;   // 92
constexpr std::uint8_t kProtectiveType = 0xEE;

std::uint32_t headerCrc(std::span<const std::byte> header, std::uint32_t headerSize) {
    std::vector<std::byte> copy(header.begin(), header.begin() + headerSize);
    gen::GptHeader::setHeaderCrc32(copy, 0);
    return Crc32::compute(copy);
}

} // namespace

// ----------------------------------------------------------------------------- reading

Expected<std::unique_ptr<GptTable>> GptTable::read(BlockDevicePtr device) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    const Geometry geo = device->geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    const SectorCount sectors = geo.sectors();
    if (sectors < 3) return fail(ErrorCategory::NotFound, "device too small for a GPT");

    auto t = std::unique_ptr<GptTable>(new GptTable());
    t->m_geometry = geo;

    // LBA 0: protective / hybrid MBR?
    auto lba0 = device->readSectors(0, 1);
    if (!lba0) return fail(lba0.error());
    t->m_mbrSector = std::move(*lba0);
    {
        gen::MbrSector mbr(t->m_mbrSector);
        if (mbr.bootSignature() == 0xAA55) {
            int protective = 0, other = 0;
            for (int i = 0; i < 4; ++i) {
                gen::MbrEntry e(mbr.entries().subspan(static_cast<std::size_t>(i) * 16, 16));
                if (e.type() == kProtectiveType) ++protective;
                else if (e.type() != 0) ++other;
            }
            t->m_hasProtectiveMbr = protective > 0;
            t->m_isHybridMbr = protective > 0 && other > 0;
        }
    }

    // Read a header at `lba`, validate it, and (if valid) its entry array.
    auto loadHeader = [&](Lba lba, HeaderState& st, std::vector<std::byte>& raw,
                          std::vector<std::byte>& entries) -> bool {
        st.lba = lba;
        auto hdr = device->readSectors(lba, 1);
        if (!hdr) {
            st.problem = "unreadable: " + hdr.error().message();
            return false;
        }
        raw = std::move(*hdr);
        st.present = true;
        gen::GptHeader h(raw);
        if (h.signature() != "EFI PART") {
            st.problem = "bad signature";
            return false;
        }
        st.signatureOk = true;
        const std::uint32_t hs = h.headerSize();
        if (hs < kHeaderSize || hs > ss) {
            st.problem = "implausible header_size " + std::to_string(hs);
            return false;
        }
        if (headerCrc(raw, hs) != h.headerCrc32()) {
            st.problem = "header CRC mismatch";
            return false;
        }
        st.headerCrcOk = true;
        if (h.myLba() != lba) {
            st.problem = "my_lba is " + std::to_string(h.myLba()) + ", header read from " + std::to_string(lba);
            return false;
        }
        st.selfLbaOk = true;
        const std::uint64_t n = h.numberOfPartitionEntries(), es = h.sizeOfPartitionEntry();
        if (n == 0 || n > 4096 || es < gen::GptEntry::kSize || (es & (es - 1)) != 0 || n * es > 16 * MiB) {
            st.problem = "implausible entry array (" + std::to_string(n) + " x " + std::to_string(es) + ")";
            return false;
        }
        const ByteCount bytes = n * es;
        auto arr = device->read(h.partitionEntriesLba() * ss, bytes);
        if (!arr) {
            st.problem = "entry array unreadable: " + arr.error().message();
            return true;   // header itself is fine
        }
        st.entriesCrcOk = Crc32::compute(*arr) == h.partitionEntriesCrc32();
        if (!st.entriesCrcOk) st.problem = "entry array CRC mismatch";
        entries = std::move(*arr);
        return true;
    };

    std::vector<std::byte> primaryEntries, backupEntries;
    const bool primaryOk = loadHeader(1, t->m_primary, t->m_primaryHeaderRaw, primaryEntries);
    // Backup: prefer where the primary says it is, else the last sector.
    Lba backupLba = expectedBackupLba(sectors);
    if (primaryOk) {
        const Lba alt = gen::GptHeader(t->m_primaryHeaderRaw).alternateLba();
        if (alt > 1 && alt < sectors) backupLba = alt;
    }
    bool backupOk = loadHeader(backupLba, t->m_backup, t->m_backupHeaderRaw, backupEntries);
    if (!backupOk && backupLba != expectedBackupLba(sectors)) {
        // The primary pointed somewhere wrong; try the end of the disk too.
        HeaderState alt;
        std::vector<std::byte> altRaw, altEntries;
        if (loadHeader(expectedBackupLba(sectors), alt, altRaw, altEntries)) {
            t->m_backup = alt;
            t->m_backupHeaderRaw = std::move(altRaw);
            backupEntries = std::move(altEntries);
            backupOk = true;
        }
    }

    const bool primaryUsable = primaryOk && t->m_primary.entriesCrcOk;
    const bool backupUsable = backupOk && t->m_backup.entriesCrcOk;
    if (!primaryOk && !backupOk && !t->m_hasProtectiveMbr)
        return fail(ErrorCategory::NotFound, "no GPT header found");

    // Choose the source of truth.
    const std::vector<std::byte>* hdrRaw = nullptr;
    if (primaryUsable) {
        hdrRaw = &t->m_primaryHeaderRaw;
        t->m_entriesRaw = std::move(primaryEntries);
    } else if (backupUsable) {
        hdrRaw = &t->m_backupHeaderRaw;
        t->m_entriesRaw = std::move(backupEntries);
        t->m_loadedFromBackup = true;
    } else if (primaryOk) {   // header fine, entries corrupt: still describe the header
        hdrRaw = &t->m_primaryHeaderRaw;
        t->m_entriesRaw = std::move(primaryEntries);
    } else if (backupOk) {
        hdrRaw = &t->m_backupHeaderRaw;
        t->m_entriesRaw = std::move(backupEntries);
        t->m_loadedFromBackup = true;
    }

    if (hdrRaw) {
        gen::GptHeader h(*hdrRaw);
        t->m_diskGuid = h.diskGuid();
        t->m_firstUsable = h.firstUsableLba();
        t->m_lastUsable = h.lastUsableLba();
        t->m_entryCount = h.numberOfPartitionEntries();
        t->m_entrySize = h.sizeOfPartitionEntry();
        if (t->m_loadedFromBackup) {
            t->m_alternateLba = h.myLba();
            t->m_backupEntriesLba = h.partitionEntriesLba();
            t->m_primaryEntriesLba = 2;
        } else {
            t->m_alternateLba = h.alternateLba();
            t->m_primaryEntriesLba = h.partitionEntriesLba();
            t->m_backupEntriesLba = backupOk ? gen::GptHeader(t->m_backupHeaderRaw).partitionEntriesLba()
                                             : t->m_alternateLba - t->entryArraySectors();
        }
        // Decode entries.
        if ((primaryUsable || backupUsable) && t->m_entriesRaw.size() >= static_cast<std::size_t>(t->m_entryCount) * t->m_entrySize) {
            for (std::uint32_t i = 0; i < t->m_entryCount; ++i) {
                gen::GptEntry e(std::span<const std::byte>(t->m_entriesRaw).subspan(static_cast<std::size_t>(i) * t->m_entrySize, gen::GptEntry::kSize));
                const Uuid typeGuid = e.partitionTypeGuid();
                if (typeGuid.isNil()) continue;
                Partition p;
                p.index = i + 1;
                p.firstLba = e.startingLba();
                p.lastLba = e.endingLba();
                p.type = PartitionType::gpt(typeGuid);
                p.uuid = e.uniquePartitionGuid();
                p.attributes = e.attributes();
                p.name = e.partitionName();
                t->m_partitions.push_back(std::move(p));
            }
        }
    } else {
        // Protective MBR but no readable header at all.
        t->m_firstUsable = 34;
        t->m_lastUsable = sectors > 34 ? sectors - 34 : 0;
        t->m_alternateLba = expectedBackupLba(sectors);
        t->m_backupEntriesLba = t->m_alternateLba - 32;
    }

    // ---- diagnostics -----------------------------------------------------------
    const Region primaryRegion{ss, static_cast<ByteCount>(ss) * (1 + t->entryArraySectors())};
    const Region backupRegion{t->m_backupEntriesLba * ss, static_cast<ByteCount>(ss) * (1 + t->entryArraySectors())};
    if (!t->m_primary.valid())
        t->addDiagnostic(Validity::Error, "gpt.primary_header", "primary GPT header is invalid: " + t->m_primary.problem,
                         Region{ss, ss}, backupUsable);
    else if (!t->m_primary.entriesCrcOk)
        t->addDiagnostic(Validity::Error, "gpt.primary_entries", "primary partition entry array is corrupt (CRC mismatch)",
                         primaryRegion, backupUsable);
    if (!t->m_backup.valid())
        t->addDiagnostic(Validity::Error, "gpt.backup_header", "backup GPT header is invalid: " + t->m_backup.problem,
                         Region{t->m_backup.lba * ss, ss}, primaryUsable);
    else if (!t->m_backup.entriesCrcOk)
        t->addDiagnostic(Validity::Error, "gpt.backup_entries", "backup partition entry array is corrupt (CRC mismatch)",
                         backupRegion, primaryUsable);
    if (!primaryUsable && !backupUsable)
        t->addDiagnostic(Validity::Error, "gpt.unrecoverable", "neither GPT copy is usable; partition list is empty", {}, false);
    if (t->m_loadedFromBackup)
        t->addDiagnostic(Validity::Warning, "gpt.loaded_from_backup", "partition list was loaded from the backup copy", {}, true);
    if (primaryOk && backupOk) {
        gen::GptHeader p(t->m_primaryHeaderRaw), b(t->m_backupHeaderRaw);
        if (p.diskGuid() != b.diskGuid() || p.firstUsableLba() != b.firstUsableLba() ||
            p.lastUsableLba() != b.lastUsableLba() || p.partitionEntriesCrc32() != b.partitionEntriesCrc32())
            t->addDiagnostic(Validity::Warning, "gpt.headers_disagree", "primary and backup headers describe different tables", {}, true);
        if (p.alternateLba() != b.myLba() || b.alternateLba() != p.myLba())
            t->addDiagnostic(Validity::Warning, "gpt.alternate_mismatch", "headers do not point at each other", {}, true);
    }
    if (t->m_alternateLba != expectedBackupLba(sectors))
        t->addDiagnostic(Validity::Warning, "gpt.backup_not_at_end",
                         "backup header is at LBA " + std::to_string(t->m_alternateLba) + " but the device ends at LBA " +
                             std::to_string(expectedBackupLba(sectors)) + " (disk grown or image truncated)",
                         {}, true);
    if (!t->m_hasProtectiveMbr)
        t->addDiagnostic(Validity::Warning, "gpt.pmbr_missing", "no protective MBR at LBA 0", Region{0, ss}, true);
    else if (t->m_isHybridMbr)
        t->addDiagnostic(Validity::Info, "gpt.pmbr_hybrid", "hybrid MBR present (left untouched by repair)", Region{0, ss});
    t->validateEntries();
    return t;
}

void GptTable::validateEntries() {
    const auto& parts = m_partitions;
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    const Lba alignSectors = std::max<Lba>(1, MiB / ss);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const auto& p = parts[i];
        if (p.lastLba < p.firstLba)
            addDiagnostic(Validity::Error, "gpt.entry_inverted", "partition " + std::to_string(p.index) + " ends before it starts");
        else if (p.firstLba < m_firstUsable || p.lastLba > m_lastUsable)
            addDiagnostic(Validity::Error, "gpt.out_of_range", "partition " + std::to_string(p.index) + " lies outside the usable range",
                          p.region(ss));
        if (p.firstLba % alignSectors != 0)
            addDiagnostic(Validity::Info, "gpt.unaligned", "partition " + std::to_string(p.index) + " does not start on a 1 MiB boundary",
                          p.region(ss));
        for (std::size_t j = i + 1; j < parts.size(); ++j)
            if (p.overlaps(parts[j]))
                addDiagnostic(Validity::Error, "gpt.overlap",
                              "partitions " + std::to_string(p.index) + " and " + std::to_string(parts[j].index) + " overlap",
                              p.region(ss));
    }
}

void GptTable::addDiagnostic(Validity sev, std::string code, std::string message, std::optional<Region> region, bool repairable) {
    m_diagnostics.push_back(Diagnostic{sev, std::move(code), std::move(message), region, repairable});
}

std::unique_ptr<GptTable> GptTable::createEmpty(const Geometry& geometry, std::uint32_t entryCount) {
    auto t = std::unique_ptr<GptTable>(new GptTable());
    t->m_geometry = geometry;
    t->m_entryCount = std::max<std::uint32_t>(entryCount, 1);
    t->m_entrySize = 128;
    const SectorCount sectors = geometry.sectors();
    const SectorCount arr = t->entryArraySectors();
    t->m_primaryEntriesLba = 2;
    t->m_firstUsable = 2 + arr;
    t->m_alternateLba = expectedBackupLba(sectors);
    t->m_backupEntriesLba = t->m_alternateLba > arr ? t->m_alternateLba - arr : 0;
    t->m_lastUsable = t->m_backupEntriesLba > 0 ? t->m_backupEntriesLba - 1 : 0;
    // A random-looking disk GUID from the geometry would be deterministic; callers set a real one.
    t->m_hasProtectiveMbr = true;
    return t;
}

SectorCount GptTable::entryArraySectors() const {
    const ByteCount bytes = static_cast<ByteCount>(m_entryCount) * m_entrySize;
    const std::uint32_t ss = m_geometry.logicalSectorSize ? m_geometry.logicalSectorSize : 512;
    return (bytes + ss - 1) / ss;
}

Limits GptTable::limits() const {
    return Limits{.maxPartitions = m_entryCount, .supportsNames = true, .supportsUuids = true,
                  .supportsAttributes = true, .supportsLogical = false, .maxNameUnits = 36};
}

std::vector<Region> GptTable::metadataRegions() const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    const SectorCount arr = entryArraySectors();
    return {Region{0, ss},                                                // protective MBR
            Region{ss, ss},                                               // primary header
            Region{m_primaryEntriesLba * ss, arr * ss},                   // primary entries
            Region{m_backupEntriesLba * ss, arr * ss},                    // backup entries
            Region{m_alternateLba * ss, ss}};                             // backup header
}

// ----------------------------------------------------------------------------- editing

Expected<void> GptTable::addPartition(const Partition& in) {
    Partition p = in;
    if (p.type.scheme != TableType::Gpt) return fail(ErrorCategory::InvalidArgument, "partition type is not a GPT type");
    if (p.isExtended || p.isLogical) return fail(ErrorCategory::InvalidArgument, "GPT has no extended/logical partitions");
    if (p.index == 0) {
        for (std::uint32_t i = 1; i <= m_entryCount; ++i)
            if (!find(i)) {
                p.index = i;
                break;
            }
        if (p.index == 0) return fail(ErrorCategory::OutOfRange, "all " + std::to_string(m_entryCount) + " entries are in use");
    } else if (p.index > m_entryCount) {
        return fail(ErrorCategory::OutOfRange, "entry index exceeds table size");
    } else if (find(p.index)) {
        return fail(ErrorCategory::InvalidArgument, "entry " + std::to_string(p.index) + " is already in use");
    }
    if (utf16Length(p.name) > 36) return fail(ErrorCategory::InvalidArgument, "name longer than 36 UTF-16 units");
    if (auto r = validatePlacement(p, std::nullopt); !r) return r;
    m_partitions.push_back(std::move(p));
    std::sort(m_partitions.begin(), m_partitions.end(), [](const Partition& a, const Partition& b) { return a.firstLba < b.firstLba; });
    return {};
}

Expected<void> GptTable::removePartition(std::uint32_t index) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(index));
    m_partitions.erase(it);
    return {};
}

Expected<void> GptTable::updatePartition(const Partition& in) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == in.index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(in.index));
    if (in.type.scheme != TableType::Gpt) return fail(ErrorCategory::InvalidArgument, "partition type is not a GPT type");
    if (utf16Length(in.name) > 36) return fail(ErrorCategory::InvalidArgument, "name longer than 36 UTF-16 units");
    if (auto r = validatePlacement(in, in.index); !r) return r;
    *it = in;
    std::sort(m_partitions.begin(), m_partitions.end(), [](const Partition& a, const Partition& b) { return a.firstLba < b.firstLba; });
    return {};
}

// ----------------------------------------------------------------------------- writing

std::vector<std::byte> GptTable::serializeEntries() const {
    std::vector<std::byte> arr(static_cast<std::size_t>(m_entryCount) * m_entrySize, std::byte{0});
    for (const auto& p : m_partitions) {
        if (p.index == 0 || p.index > m_entryCount) continue;
        auto e = std::span<std::byte>(arr).subspan(static_cast<std::size_t>(p.index - 1) * m_entrySize, gen::GptEntry::kSize);
        gen::GptEntry::setPartitionTypeGuid(e, p.type.gptGuid);
        gen::GptEntry::setUniquePartitionGuid(e, p.uuid);
        gen::GptEntry::setStartingLba(e, p.firstLba);
        gen::GptEntry::setEndingLba(e, p.lastLba);
        gen::GptEntry::setAttributes(e, p.attributes);
        gen::GptEntry::setPartitionName(e, p.name);
    }
    return arr;
}

std::vector<std::byte> GptTable::serializeHeader(Lba myLba, Lba alternateLba, Lba entriesLba, Lba lastUsable,
                                                 std::uint32_t entriesCrc) const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    std::vector<std::byte> h(ss, std::byte{0});
    gen::GptHeader::setSignature(h, "EFI PART");
    gen::GptHeader::setRevision(h, 0x00010000);
    gen::GptHeader::setHeaderSize(h, kHeaderSize);
    gen::GptHeader::setMyLba(h, myLba);
    gen::GptHeader::setAlternateLba(h, alternateLba);
    gen::GptHeader::setFirstUsableLba(h, m_firstUsable);
    gen::GptHeader::setLastUsableLba(h, lastUsable);
    gen::GptHeader::setDiskGuid(h, m_diskGuid);
    gen::GptHeader::setPartitionEntriesLba(h, entriesLba);
    gen::GptHeader::setNumberOfPartitionEntries(h, m_entryCount);
    gen::GptHeader::setSizeOfPartitionEntry(h, m_entrySize);
    gen::GptHeader::setPartitionEntriesCrc32(h, entriesCrc);
    gen::GptHeader::setHeaderCrc32(h, headerCrc(h, kHeaderSize));
    return h;
}

std::vector<std::byte> GptTable::buildProtectiveMbr(SectorCount sectors) const {
    std::vector<std::byte> s(512, std::byte{0});
    // Keep existing boot code if the old LBA 0 was already a protective MBR.
    if (m_mbrSector.size() >= 512 && m_hasProtectiveMbr)
        std::copy_n(m_mbrSector.begin(), 440, s.begin());
    auto e = std::span<std::byte>(s).subspan(gen::MbrSector::kEntriesOffset, 16);
    gen::MbrEntry::setStatus(e, 0);
    gen::MbrEntry::setFirstChs(e, layout::chsFromLba(1));
    gen::MbrEntry::setType(e, kProtectiveType);
    gen::MbrEntry::setLastChs(e, layout::chsFromLba(sectors > 1 ? sectors - 1 : 0));
    gen::MbrEntry::setFirstLba(e, 1);
    const std::uint64_t count = sectors > 1 ? sectors - 1 : 0;
    gen::MbrEntry::setSectorCount(e, static_cast<std::uint32_t>(std::min<std::uint64_t>(count, 0xFFFFFFFFull)));
    gen::MbrSector::setBootSignature(s, 0xAA55);
    return s;
}

Expected<void> GptTable::write(BlockDevice& device) const {
    const Geometry geo = device.geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    if (ss != m_geometry.logicalSectorSize)
        return fail(ErrorCategory::InvalidArgument, "table was built for " + std::to_string(m_geometry.logicalSectorSize) +
                                                        "-byte sectors, device has " + std::to_string(ss));
    const SectorCount sectors = geo.sectors();
    const SectorCount arr = entryArraySectors();
    if (sectors < 2 + 2 * arr + 2) return fail(ErrorCategory::OutOfRange, "device too small for the GPT layout");
    // Backup placement always follows the *target* device; this is what relocates a backup after growth.
    const Lba backupLba = expectedBackupLba(sectors);
    const Lba backupEntriesLba = backupLba - arr;
    const Lba lastUsable = backupEntriesLba - 1;
    for (const auto& p : m_partitions)
        if (p.lastLba > lastUsable || p.firstLba < m_firstUsable)
            return fail(ErrorCategory::OutOfRange, "partition " + std::to_string(p.index) + " does not fit on the target device");

    const auto entries = serializeEntries();
    const std::uint32_t entriesCrc = Crc32::compute(entries);
    const auto primary = serializeHeader(1, backupLba, 2, lastUsable, entriesCrc);
    const auto backup = serializeHeader(backupLba, 1, backupEntriesLba, lastUsable, entriesCrc);

    // Order: backup entries, backup header, primary entries, primary header, protective MBR.
    if (auto r = device.writeAt(backupEntriesLba * ss, entries); !r) return r;
    if (auto r = device.writeAt(backupLba * ss, backup); !r) return r;
    if (auto r = device.writeAt(2 * ss, entries); !r) return r;
    if (auto r = device.writeAt(1 * ss, primary); !r) return r;
    if (!m_isHybridMbr) {
        auto pmbr = buildProtectiveMbr(sectors);
        if (ss > 512) pmbr.resize(ss, std::byte{0});
        if (auto r = device.writeAt(0, pmbr); !r) return r;
    }
    return device.flush();
}

Expected<void> GptTable::repair(BlockDevice& device, const RepairOptions& options) {
    bool anything = false;
    const Diagnostic* firstError = nullptr;
    for (const auto& d : m_diagnostics) {
        anything = anything || d.repairable;
        if (!firstError && d.severity == Validity::Error) firstError = &d;
    }
    if (!anything) {
        if (firstError) return fail(ErrorCategory::InvalidFormat, "nothing repairable: " + firstError->message);
        return {};
    }
    if (m_partitions.empty() && !m_primary.entriesCrcOk && !m_backup.entriesCrcOk)
        return fail(ErrorCategory::InvalidFormat, "no intact copy of the partition entries; refusing to write an empty table");
    if (!options.rebuildPrimary && !m_primary.valid()) return fail(ErrorCategory::InvalidArgument, "primary rebuild disabled");
    if (!options.rebuildBackup && !m_backup.valid()) return fail(ErrorCategory::InvalidArgument, "backup rebuild disabled");
    if (!options.relocateBackup && m_alternateLba != expectedBackupLba(device.geometry().sectors()))
        return fail(ErrorCategory::InvalidArgument, "backup relocation disabled");
    const bool hybrid = m_isHybridMbr;
    if (!options.fixProtectiveMbr) m_isHybridMbr = true;   // write() skips LBA 0 when "hybrid"
    auto r = write(device);
    m_isHybridMbr = hybrid;
    if (!r) return r;
    // Re-read to refresh state and diagnostics.
    auto fresh = GptTable::read(std::shared_ptr<BlockDevice>(&device, [](BlockDevice*) {}));
    if (!fresh) return fail(fresh.error());
    *this = std::move(**fresh);
    return {};
}

// ----------------------------------------------------------------------------- describe

layout::Node GptTable::describe() const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    layout::Node root;
    root.name = "GPT partition table";
    root.isStruct = true;
    root.absOffset = 0;
    root.size = m_geometry.sizeBytes;

    if (m_mbrSector.size() >= 512) {
        auto mbr = gen::MbrSector(m_mbrSector).describe(0);
        mbr.name = m_isHybridMbr ? "hybrid MBR" : (m_hasProtectiveMbr ? "protective MBR" : "MBR (not protective)");
        if (auto* entries = mbr.child("entries")) {
            entries->isStruct = true;
            for (int i = 0; i < 4; ++i) {
                gen::MbrEntry e(std::span<const std::byte>(m_mbrSector).subspan(gen::MbrSector::kEntriesOffset + static_cast<std::size_t>(i) * 16, 16));
                if (e.type() == 0 && e.sectorCount() == 0) continue;
                auto n = e.describe(gen::MbrSector::kEntriesOffset + static_cast<std::uint64_t>(i) * 16);
                n.name = "entry " + std::to_string(i + 1);
                if (auto* t = n.child("type")) t->pretty = types::name(PartitionType::mbr(e.type()));
                entries->addChild(std::move(n));
            }
        }
        if (!m_hasProtectiveMbr) mbr.flag(Validity::Warning, "no 0xEE protective entry");
        root.addChild(std::move(mbr));
    }

    auto describeHeader = [&](const std::vector<std::byte>& raw, const HeaderState& st, const char* title) {
        layout::Node n;
        if (raw.size() < kHeaderSize) {
            n.name = title;
            n.isStruct = true;
            n.absOffset = st.lba * ss;
            n.size = ss;
            n.flag(Validity::Error, st.problem.empty() ? "missing" : st.problem);
            return n;
        }
        n = gen::GptHeader(raw).describe(st.lba * ss);
        n.name = title;
        if (auto* c = n.child("header_crc32")) {
            c->validity = Validity::Ok;
            c->message.clear();
            if (!st.headerCrcOk) c->flag(Validity::Error, "mismatch; computed " + toHex(headerCrc(raw, std::min<std::uint32_t>(gen::GptHeader(raw).headerSize(), ss)), 8));
        }
        if (auto* c = n.child("partition_entries_crc32")) {
            c->validity = Validity::Ok;
            c->message.clear();
            if (!st.entriesCrcOk) c->flag(Validity::Error, "entry array does not match");
        }
        if (auto* c = n.child("my_lba"); c && !st.selfLbaOk && st.signatureOk) c->flag(Validity::Error, "does not match the header's location");
        if (auto* c = n.child("alternate_lba"); c && gen::GptHeader(raw).alternateLba() != (st.lba == 1 ? expectedBackupLba(m_geometry.sectors()) : 1))
            c->flag(Validity::Warning, "does not point at the expected location");
        if (!st.valid()) n.flag(Validity::Error, st.problem);
        return n;
    };
    root.addChild(describeHeader(m_primaryHeaderRaw, m_primary, "primary GPT header"));

    auto describeEntries = [&](Lba lba, const char* title) {
        layout::Node n;
        n.name = title;
        n.isStruct = true;
        n.absOffset = lba * ss;
        n.size = entryArraySectors() * ss;
        for (const auto& p : m_partitions) {
            std::size_t off = static_cast<std::size_t>(p.index - 1) * m_entrySize;
            if (off + gen::GptEntry::kSize > m_entriesRaw.size()) break;
            auto e = gen::GptEntry(std::span<const std::byte>(m_entriesRaw).subspan(off, gen::GptEntry::kSize)).describe(lba * ss + off);
            e.name = "entry " + std::to_string(p.index);
            if (auto* t = e.child("partition_type_guid")) t->pretty = types::name(p.type);
            n.addChild(std::move(e));
        }
        return n;
    };
    root.addChild(describeEntries(m_primaryEntriesLba, "primary partition entries"));
    root.addChild(describeEntries(m_backupEntriesLba, "backup partition entries"));
    root.addChild(describeHeader(m_backupHeaderRaw, m_backup, "backup GPT header"));

    for (const auto& d : m_diagnostics)
        if (d.severity >= Validity::Warning) root.flag(d.severity, d.message);
    return root;
}

} // namespace stein::pt
