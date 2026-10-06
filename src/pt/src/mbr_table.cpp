// SPDX-License-Identifier: MIT
#include "stein/pt/mbr_table.hpp"

#include "stein/core/strings.hpp"
#include "stein/layout/gen/mbr.hpp"

#include <algorithm>
#include <set>

namespace stein::pt {

using layout::Validity;
namespace gen = layout::gen;

namespace {

constexpr std::uint32_t kEntriesOffset = gen::MbrSector::kEntriesOffset;   // 0x1BE

bool isExtendedType(std::uint8_t t) { return t == 0x05 || t == 0x0F || t == 0x85; }

struct RawEntry {
    std::uint8_t status, type;
    std::uint32_t firstLba, count;
};

RawEntry rawEntry(std::span<const std::byte> sector, int i) {
    gen::MbrEntry e(sector.subspan(kEntriesOffset + static_cast<std::size_t>(i) * 16, 16));
    return RawEntry{e.status(), e.type(), e.firstLba(), e.sectorCount()};
}

} // namespace

// ----------------------------------------------------------------------------- reading

Expected<std::unique_ptr<MbrTable>> MbrTable::read(BlockDevicePtr device) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    const Geometry geo = device->geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    const SectorCount sectors = geo.sectors();
    if (sectors < 1 || ss < 512) return fail(ErrorCategory::NotFound, "device too small for an MBR");

    auto s0 = device->readSectors(0, 1);
    if (!s0) return fail(s0.error());
    gen::MbrSector mbr(*s0);
    if (mbr.bootSignature() != 0xAA55) return fail(ErrorCategory::NotFound, "no 0x55AA boot signature");

    // Distinguish an MBR from a filesystem boot sector that also ends in 0x55AA.
    bool allEmpty = true, plausible = true;
    for (int i = 0; i < 4; ++i) {
        RawEntry e = rawEntry(*s0, i);
        if (e.status != 0x00 && e.status != 0x80) plausible = false;
        if (e.type != 0 || e.count != 0 || e.firstLba != 0) allEmpty = false;
        if (e.type != 0 && e.count == 0) plausible = false;
    }
    const auto b0 = std::to_integer<unsigned>((*s0)[0]);
    const bool looksLikeFatJump = b0 == 0xEB || b0 == 0xE9;
    if (!plausible) return fail(ErrorCategory::NotFound, "entries do not look like MBR partition entries");
    if (allEmpty && looksLikeFatJump) return fail(ErrorCategory::NotFound, "boot sector of a filesystem, not an MBR");

    auto t = std::unique_ptr<MbrTable>(new MbrTable());
    t->m_geometry = geo;
    t->m_sector0 = *s0;
    t->m_bootstrap.assign(s0->begin(), s0->begin() + 440);
    t->m_diskSignature = mbr.diskSignature();

    for (int i = 0; i < 4; ++i) {
        RawEntry e = rawEntry(*s0, i);
        if (e.type == 0) continue;
        Partition p;
        p.index = static_cast<std::uint32_t>(i + 1);
        p.firstLba = e.firstLba;
        p.lastLba = static_cast<Lba>(e.firstLba) + e.count - 1;
        p.type = PartitionType::mbr(e.type);
        p.attributes = (e.status & 0x80) ? Partition::kMbrBootable : 0;
        p.isExtended = isExtendedType(e.type);
        t->m_partitions.push_back(p);
    }

    // Walk the EBR chain of the (first) extended partition.
    const Partition* extPtr = t->extendedPartition();
    if (extPtr) {
        const Partition extCopy = *extPtr;   // m_partitions reallocates below; never keep the pointer
        const Partition* ext = &extCopy;
        std::set<Lba> visited;
        Lba ebr = ext->firstLba;
        std::uint32_t index = 5;
        while (ebr >= ext->firstLba && ebr <= ext->lastLba && !visited.count(ebr) && ebr < sectors && index < 5 + 128) {
            visited.insert(ebr);
            auto sec = device->readSectors(ebr, 1);
            if (!sec) {
                t->addDiagnostic(Validity::Error, "mbr.ebr_unreadable", "EBR at LBA " + std::to_string(ebr) + " is unreadable", Region{ebr * ss, ss});
                break;
            }
            t->m_ebrs.emplace_back(ebr, *sec);
            if (gen::MbrSector(*sec).bootSignature() != 0xAA55) {
                t->addDiagnostic(Validity::Error, "mbr.ebr_chain_broken", "EBR at LBA " + std::to_string(ebr) + " has no boot signature", Region{ebr * ss, ss});
                break;
            }
            RawEntry first = rawEntry(*sec, 0), next = rawEntry(*sec, 1);
            if (first.type != 0 && first.count != 0) {
                Partition p;
                p.index = index++;
                p.firstLba = ebr + first.firstLba;
                p.lastLba = p.firstLba + first.count - 1;
                p.type = PartitionType::mbr(first.type);
                p.attributes = (first.status & 0x80) ? Partition::kMbrBootable : 0;
                p.isLogical = true;
                p.ebrLba = ebr;
                t->m_partitions.push_back(p);
            }
            if (next.type == 0 || next.count == 0) break;
            if (!isExtendedType(next.type))
                t->addDiagnostic(Validity::Warning, "mbr.ebr_link_type", "EBR link entry at LBA " + std::to_string(ebr) + " has type " + toHex(next.type, 2) + " instead of an extended type");
            ebr = ext->firstLba + next.firstLba;
        }
        if (visited.size() >= 128) t->addDiagnostic(Validity::Error, "mbr.ebr_chain_loop", "EBR chain too long or looping");
    }
    t->validate();
    return t;
}

void MbrTable::validate() {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    const SectorCount sectors = m_geometry.sectors();
    const Partition* ext = extendedPartition();
    int extendedCount = 0, bootable = 0;
    for (const auto& p : m_partitions) {
        if (p.isExtended) ++extendedCount;
        if (p.attributes & Partition::kMbrBootable) ++bootable;
        if (p.lastLba >= sectors)
            addDiagnostic(Validity::Error, "mbr.out_of_range", "partition " + std::to_string(p.index) + " extends past the end of the device", p.region(ss));
        if (p.isLogical && ext && (p.firstLba < ext->firstLba || p.lastLba > ext->lastLba))
            addDiagnostic(Validity::Error, "mbr.logical_outside_extended", "logical partition " + std::to_string(p.index) + " lies outside the extended partition", p.region(ss));
        if (p.type.mbrId == 0xEE)
            addDiagnostic(Validity::Warning, "mbr.protective_entry", "entry " + std::to_string(p.index) + " is a GPT protective entry but no valid GPT was found");
        if (p.firstLba % std::max<Lba>(1, MiB / ss) != 0)
            addDiagnostic(Validity::Info, "mbr.unaligned", "partition " + std::to_string(p.index) + " does not start on a 1 MiB boundary", p.region(ss));
    }
    if (extendedCount > 1) addDiagnostic(Validity::Error, "mbr.multiple_extended", "more than one extended partition");
    if (bootable > 1) addDiagnostic(Validity::Warning, "mbr.multiple_bootable", "more than one partition is marked bootable");
    for (std::size_t i = 0; i < m_partitions.size(); ++i)
        for (std::size_t j = i + 1; j < m_partitions.size(); ++j) {
            const auto& a = m_partitions[i];
            const auto& b = m_partitions[j];
            // A logical inside its extended container is expected to "overlap" it.
            if ((a.isExtended && b.isLogical) || (b.isExtended && a.isLogical)) continue;
            if (a.overlaps(b))
                addDiagnostic(Validity::Error, "mbr.overlap", "partitions " + std::to_string(a.index) + " and " + std::to_string(b.index) + " overlap", a.region(ss));
        }
}

void MbrTable::addDiagnostic(Validity sev, std::string code, std::string message, std::optional<Region> region) {
    m_diagnostics.push_back(Diagnostic{sev, std::move(code), std::move(message), region, false});
}

std::unique_ptr<MbrTable> MbrTable::createEmpty(const Geometry& geometry) {
    auto t = std::unique_ptr<MbrTable>(new MbrTable());
    t->m_geometry = geometry;
    t->m_bootstrap.assign(440, std::byte{0});
    return t;
}

Limits MbrTable::limits() const {
    return Limits{.maxPartitions = 4 + 128, .supportsNames = false, .supportsUuids = false,
                  .supportsAttributes = true, .supportsLogical = true, .maxNameUnits = 0};
}

Lba MbrTable::lastUsableLba() const {
    const SectorCount sectors = m_geometry.sectors();
    // 32-bit LBA + count fields cap addressing at 2^32 sectors.
    return std::min<Lba>(sectors ? sectors - 1 : 0, 0xFFFFFFFFull);
}

std::vector<Region> MbrTable::metadataRegions() const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    std::vector<Region> r{Region{0, ss}};
    for (const auto& p : m_partitions)
        if (p.isLogical && p.ebrLba) r.push_back(Region{*p.ebrLba * ss, ss});
    return r;
}

const Partition* MbrTable::extendedPartition() const {
    for (const auto& p : m_partitions)
        if (p.isExtended) return &p;
    return nullptr;
}

// ----------------------------------------------------------------------------- editing

Expected<void> MbrTable::addPartition(const Partition& in) {
    Partition p = in;
    if (p.type.scheme != TableType::Mbr) return fail(ErrorCategory::InvalidArgument, "partition type is not an MBR type");
    if (!p.name.empty()) return fail(ErrorCategory::InvalidArgument, "MBR partitions have no names");
    p.isExtended = isExtendedType(p.type.mbrId);
    if (p.lastLba > 0xFFFFFFFFull || p.sectors() > 0xFFFFFFFFull)
        return fail(ErrorCategory::OutOfRange, "MBR cannot address beyond 2^32 sectors");
    if (p.isLogical) {
        const Partition* ext = extendedPartition();
        if (!ext) return fail(ErrorCategory::InvalidArgument, "no extended partition to hold a logical partition");
        if (p.isExtended) return fail(ErrorCategory::InvalidArgument, "a logical partition cannot be extended");
        if (p.firstLba <= ext->firstLba || p.lastLba > ext->lastLba)
            return fail(ErrorCategory::OutOfRange, "logical partition must lie inside the extended partition, after its first sector");
        if (!p.ebrLba) {
            // Place the EBR at the start of the slot: one alignment unit before the data, but after the extended start.
            Lba ebr = p.firstLba >= kDefaultEbrGap ? p.firstLba - kDefaultEbrGap : 0;
            if (ebr < ext->firstLba) ebr = ext->firstLba;
            // The very first logical's EBR must be the extended partition's first sector.
            bool firstLogical = std::none_of(m_partitions.begin(), m_partitions.end(), [](const Partition& q) { return q.isLogical; });
            if (firstLogical) ebr = ext->firstLba;
            p.ebrLba = ebr;
        }
        if (*p.ebrLba < ext->firstLba || *p.ebrLba >= p.firstLba)
            return fail(ErrorCategory::InvalidArgument, "EBR must lie inside the extended partition and before the logical's data");
        if (p.index == 0) {
            p.index = 5;
            for (const auto& q : m_partitions)
                if (q.isLogical) p.index = std::max(p.index, q.index + 1);
        } else if (p.index < 5 || find(p.index)) {
            return fail(ErrorCategory::InvalidArgument, "invalid or busy logical index");
        }
    } else {
        if (p.isExtended && extendedPartition()) return fail(ErrorCategory::InvalidArgument, "only one extended partition is allowed");
        if (p.index == 0) {
            for (std::uint32_t i = 1; i <= 4; ++i)
                if (!find(i)) {
                    p.index = i;
                    break;
                }
            if (p.index == 0) return fail(ErrorCategory::OutOfRange, "all four primary slots are in use");
        } else if (p.index > 4) {
            return fail(ErrorCategory::InvalidArgument, "primary index must be 1-4 (set isLogical for 5+)");
        } else if (find(p.index)) {
            return fail(ErrorCategory::InvalidArgument, "slot " + std::to_string(p.index) + " is already in use");
        }
    }
    if (auto r = validatePlacement(p, std::nullopt); !r) return r;
    m_partitions.push_back(std::move(p));
    std::sort(m_partitions.begin(), m_partitions.end(), [](const Partition& a, const Partition& b) { return a.index < b.index; });
    return {};
}

Expected<void> MbrTable::removePartition(std::uint32_t index) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(index));
    if (it->isExtended && std::any_of(m_partitions.begin(), m_partitions.end(), [](const Partition& p) { return p.isLogical; }))
        return fail(ErrorCategory::Busy, "extended partition still contains logical partitions");
    m_partitions.erase(it);
    return {};
}

Expected<void> MbrTable::updatePartition(const Partition& in) {
    auto it = std::find_if(m_partitions.begin(), m_partitions.end(), [&](const Partition& p) { return p.index == in.index; });
    if (it == m_partitions.end()) return fail(ErrorCategory::NotFound, "no partition " + std::to_string(in.index));
    if (in.type.scheme != TableType::Mbr) return fail(ErrorCategory::InvalidArgument, "partition type is not an MBR type");
    if (in.isLogical != it->isLogical) return fail(ErrorCategory::InvalidArgument, "cannot change a partition between primary and logical");
    if (auto r = validatePlacement(in, in.index); !r) return r;
    Partition p = in;
    p.isExtended = isExtendedType(p.type.mbrId);
    *it = p;
    return {};
}

// ----------------------------------------------------------------------------- writing

std::vector<std::byte> MbrTable::serializeEntry(const Partition& p, Lba relativeTo) const {
    std::vector<std::byte> e(16, std::byte{0});
    gen::MbrEntry::setStatus(e, (p.attributes & Partition::kMbrBootable) ? 0x80 : 0x00);
    gen::MbrEntry::setType(e, p.type.mbrId);
    gen::MbrEntry::setFirstChs(e, layout::chsFromLba(p.firstLba));
    gen::MbrEntry::setLastChs(e, layout::chsFromLba(p.lastLba));
    gen::MbrEntry::setFirstLba(e, static_cast<std::uint32_t>(p.firstLba - relativeTo));
    gen::MbrEntry::setSectorCount(e, static_cast<std::uint32_t>(p.sectors()));
    return e;
}

Expected<void> MbrTable::write(BlockDevice& device) const {
    const Geometry geo = device.geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    if (ss < 512) return fail(ErrorCategory::InvalidArgument, "sector size below 512");
    for (const auto& p : m_partitions)
        if (p.lastLba >= geo.sectors()) return fail(ErrorCategory::OutOfRange, "partition " + std::to_string(p.index) + " does not fit on the target device");

    std::vector<std::byte> s(ss, std::byte{0});
    std::copy_n(m_bootstrap.begin(), std::min<std::size_t>(440, m_bootstrap.size()), s.begin());
    gen::MbrSector::setDiskSignature(s, m_diskSignature);
    gen::MbrSector::setBootSignature(s, 0xAA55);
    for (const auto& p : m_partitions) {
        if (p.isLogical || p.index < 1 || p.index > 4) continue;
        auto e = serializeEntry(p, 0);
        std::copy(e.begin(), e.end(), s.begin() + kEntriesOffset + static_cast<std::ptrdiff_t>(p.index - 1) * 16);
    }

    // EBR chain: logicals sorted by position; each EBR points at its data and at the next EBR.
    std::vector<const Partition*> logicals;
    for (const auto& p : m_partitions)
        if (p.isLogical) logicals.push_back(&p);
    std::sort(logicals.begin(), logicals.end(), [](const Partition* a, const Partition* b) { return a->firstLba < b->firstLba; });
    const Partition* ext = extendedPartition();
    if (!logicals.empty() && !ext) return fail(ErrorCategory::InvalidArgument, "logical partitions without an extended partition");
    std::vector<std::pair<Lba, std::vector<std::byte>>> ebrs;
    for (std::size_t i = 0; i < logicals.size(); ++i) {
        const Partition& p = *logicals[i];
        if (!p.ebrLba) return fail(ErrorCategory::InvalidArgument, "logical partition " + std::to_string(p.index) + " has no EBR location");
        std::vector<std::byte> ebr(ss, std::byte{0});
        gen::MbrSector::setBootSignature(ebr, 0xAA55);
        auto e0 = serializeEntry(p, *p.ebrLba);
        std::copy(e0.begin(), e0.end(), ebr.begin() + kEntriesOffset);
        if (i + 1 < logicals.size()) {
            const Partition& n = *logicals[i + 1];
            if (!n.ebrLba) return fail(ErrorCategory::InvalidArgument, "logical partition " + std::to_string(n.index) + " has no EBR location");
            Partition link;
            link.type = PartitionType::mbr(0x05);
            link.firstLba = *n.ebrLba;
            link.lastLba = n.lastLba;
            auto e1 = serializeEntry(link, ext->firstLba);
            std::copy(e1.begin(), e1.end(), ebr.begin() + kEntriesOffset + 16);
        }
        ebrs.emplace_back(*p.ebrLba, std::move(ebr));
    }

    for (const auto& [lba, bytes] : ebrs)
        if (auto r = device.writeAt(lba * ss, bytes); !r) return r;
    if (auto r = device.writeAt(0, s); !r) return r;
    return device.flush();
}

// ----------------------------------------------------------------------------- describe

layout::Node MbrTable::describe() const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    layout::Node root;
    root.name = "MBR partition table";
    root.isStruct = true;
    root.size = m_geometry.sizeBytes;

    auto describeSector = [&](std::span<const std::byte> sec, Lba lba, const std::string& title, bool isEbr) {
        auto n = gen::MbrSector(sec).describe(lba * ss);
        n.name = title;
        if (auto* entries = n.child("entries")) {
            entries->isStruct = true;
            for (int i = 0; i < 4; ++i) {
                RawEntry raw = rawEntry(sec, i);
                if (raw.type == 0 && raw.count == 0) continue;
                auto e = gen::MbrEntry(sec.subspan(kEntriesOffset + static_cast<std::size_t>(i) * 16, 16)).describe(lba * ss + kEntriesOffset + static_cast<std::uint64_t>(i) * 16);
                e.name = isEbr ? (i == 0 ? "logical partition" : "next EBR link") : "entry " + std::to_string(i + 1);
                if (auto* t = e.child("type")) t->pretty = types::name(PartitionType::mbr(raw.type));
                if (auto* f = e.child("first_lba"); f && isEbr) f->pretty = "absolute LBA " + std::to_string((i == 0 ? lba : extendedPartition()->firstLba) + raw.firstLba);
                entries->addChild(std::move(e));
            }
        }
        return n;
    };
    if (m_sector0.size() >= 512) root.addChild(describeSector(m_sector0, 0, "MBR sector", false));
    for (const auto& [lba, bytes] : m_ebrs) root.addChild(describeSector(bytes, lba, "EBR @ LBA " + std::to_string(lba), true));
    for (const auto& d : m_diagnostics)
        if (d.severity >= Validity::Warning) root.flag(d.severity, d.message);
    return root;
}

} // namespace stein::pt
