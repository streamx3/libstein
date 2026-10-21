// SPDX-License-Identifier: MIT
#include "stein/pt/mbr_table.hpp"

#include "stein/core/crypto.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/mbr.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <set>

namespace stein::pt {

using layout::Validity;
namespace gen = layout::gen;

namespace {

constexpr std::uint32_t kEntriesOffset = gen::MbrSector::kEntriesOffset;   // 0x1BE

bool isExtendedType(std::uint8_t t) { return t == 0x05 || t == 0x0F || t == 0x85; }
bool statusIsStandard(std::uint8_t s) { return s == 0x00 || s == 0x80; }

struct RawEntry {
    std::uint8_t status, type;
    std::uint32_t firstLba, count;
};

RawEntry rawEntry(std::span<const std::byte> sector, int i) {
    gen::MbrEntry e(sector.subspan(kEntriesOffset + static_cast<std::size_t>(i) * 16, 16));
    return RawEntry{e.status(), e.type(), e.firstLba(), e.sectorCount()};
}

std::span<const std::byte> entryBytes(std::span<const std::byte> sector, int i) {
    return sector.subspan(kEntriesOffset + static_cast<std::size_t>(i) * 16, 16);
}

bool allZero(std::span<const std::byte> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](std::byte b) { return b == std::byte{0}; });
}

// Windows identifies disks by this word; zero means "unset" and makes Windows rewrite it,
// so a fresh table gets a random one.
std::uint32_t randomDiskSignature() {
    std::array<std::uint8_t, 4> b{};
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (!crypto::randomBytes(b)) break;
        const std::uint32_t v = static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8) |
                                (static_cast<std::uint32_t>(b[2]) << 16) | (static_cast<std::uint32_t>(b[3]) << 24);
        if (v != 0) return v;
    }
    // No OS randomness: a clock-derived value still beats the "unset" zero.
    const auto t = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto v = static_cast<std::uint32_t>(t ^ (t >> 32));
    return v ? v : 0x5EED5EEDu;
}

// A logical partition and the onward link found in one orphaned EBR sector.
struct OrphanEbr {
    Partition logical;
    std::optional<Lba> link;
};

// Decides whether `sec` at `lba` is an EBR of the extended partition `ext` that the chain lost.
// A grid candidate must look exactly like what every partitioner writes: signature, zero disk
// signature (copies of an MBR, such as a disk image stored inside a filesystem, carry one), the
// logical in entry 1, an extended link or nothing in entry 2, entries 3 and 4 blank. A sector a
// readable link points at gets the same scrutiny of its entries but is accepted without the
// signature: those two bytes are the usual casualty, and the link vouches for the location.
std::optional<OrphanEbr> parseOrphanEbr(std::span<const std::byte> sec, Lba lba, const Partition& ext, Lba extLast, bool linkTarget) {
    gen::MbrSector s(sec);
    if (!linkTarget && (s.bootSignature() != 0xAA55 || s.diskSignature() != 0 || s.copyProtected() != 0)) return std::nullopt;
    if (!allZero(entryBytes(sec, 2)) || !allZero(entryBytes(sec, 3))) return std::nullopt;
    const RawEntry first = rawEntry(sec, 0), next = rawEntry(sec, 1);
    if (first.type == 0 || first.count == 0 || first.firstLba == 0 || isExtendedType(first.type) || !statusIsStandard(first.status))
        return std::nullopt;
    const Lba dataFirst = lba + first.firstLba, dataLast = dataFirst + first.count - 1;
    if (dataLast > extLast) return std::nullopt;
    OrphanEbr o;
    if (!allZero(entryBytes(sec, 1))) {
        if (!isExtendedType(next.type) || next.count == 0 || next.status != 0) return std::nullopt;
        const Lba l = ext.firstLba + next.firstLba;
        if (l <= ext.firstLba || l > extLast || l == lba) return std::nullopt;
        o.link = l;
    }
    o.logical.firstLba = dataFirst;
    o.logical.lastLba = dataLast;
    o.logical.type = PartitionType::mbr(first.type);
    o.logical.attributes = (first.status & 0x80) ? Partition::kMbrBootable : 0;
    o.logical.isLogical = true;
    o.logical.ebrLba = lba;
    return o;
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

    // Distinguish an MBR from a filesystem boot sector that also ends in 0x55AA. Real tables
    // do turn up with one clobbered status byte, so an entry whose status is neither 0x00 nor
    // 0x80 is tolerated (and reported by validate()) as long as its other fields form an
    // in-range partition and at least one entry is beyond doubt; boot code at 0x1BE passes
    // neither test.
    bool allEmpty = true, anyCertain = false, anyDoubtful = false;
    for (int i = 0; i < 4; ++i) {
        RawEntry e = rawEntry(*s0, i);
        if (e.type != 0 || e.count != 0 || e.firstLba != 0) allEmpty = false;
        if (e.type != 0 && e.count == 0) return fail(ErrorCategory::NotFound, "entries do not look like MBR partition entries");
        if (statusIsStandard(e.status)) {
            if (e.type != 0) anyCertain = true;
            continue;
        }
        if (e.type != 0 && (e.firstLba == 0 || static_cast<std::uint64_t>(e.firstLba) + e.count > sectors))
            return fail(ErrorCategory::NotFound, "entries do not look like MBR partition entries");
        anyDoubtful = true;
    }
    if (anyDoubtful && !anyCertain) return fail(ErrorCategory::NotFound, "entries do not look like MBR partition entries");
    const auto b0 = std::to_integer<unsigned>((*s0)[0]);
    const bool looksLikeFatJump = b0 == 0xEB || b0 == 0xE9;
    if (allEmpty && looksLikeFatJump) return fail(ErrorCategory::NotFound, "boot sector of a filesystem, not an MBR");

    auto t = std::unique_ptr<MbrTable>(new MbrTable());
    t->m_geometry = geo;
    t->m_sector0 = *s0;
    t->m_bootstrap.assign(s0->begin(), s0->begin() + 440);
    t->m_diskSignature = mbr.diskSignature();
    t->m_copyProtected = mbr.copyProtected();

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
        const Partition ext = *extPtr;   // m_partitions reallocates below; never keep the pointer
        std::set<Lba> visited;
        Lba ebr = ext.firstLba;
        std::uint32_t index = 5;
        t->m_chainEnd = ChainEnd::Terminated;
        for (;;) {
            const std::string at = "LBA " + std::to_string(ebr);
            if (ebr < ext.firstLba || ebr > ext.lastLba || ebr >= sectors) {
                t->m_chainEnd = ChainEnd::Outside;
                t->m_chainBreakLba = ebr;
                t->addDiagnostic(Validity::Error, "mbr.ebr_link_outside", "EBR link points at " + at + ", outside the extended partition", {}, true);
                break;
            }
            if (visited.count(ebr) || visited.size() >= 128) {
                t->m_chainEnd = ChainEnd::Loop;
                t->m_chainBreakLba = ebr;
                t->addDiagnostic(Validity::Error, "mbr.ebr_chain_loop",
                                 visited.count(ebr) ? "EBR chain loops back to " + at : "EBR chain has more than 128 links", Region{ebr * ss, ss}, true);
                break;
            }
            visited.insert(ebr);
            auto sec = device->readSectors(ebr, 1);
            if (!sec) {
                t->m_chainEnd = ChainEnd::Unreadable;
                t->m_chainBreakLba = ebr;
                t->addDiagnostic(Validity::Error, "mbr.ebr_unreadable", "EBR at " + at + " is unreadable", Region{ebr * ss, ss}, true);
                break;
            }
            if (gen::MbrSector(*sec).bootSignature() != 0xAA55) {
                // Nothing was ever written at the start of a fresh extended partition.
                if (ebr == ext.firstLba && allZero(*sec)) {
                    t->m_chainEnd = ChainEnd::Empty;
                    break;
                }
                t->m_ebrs.emplace_back(ebr, *sec);
                t->m_chainEnd = ChainEnd::Unsigned;
                t->m_chainBreakLba = ebr;
                t->addDiagnostic(Validity::Error, "mbr.ebr_chain_broken", "EBR at " + at + " has no boot signature", Region{ebr * ss, ss}, true);
                break;
            }
            t->m_ebrs.emplace_back(ebr, *sec);
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
                t->addDiagnostic(Validity::Warning, "mbr.ebr_link_type",
                                 "EBR link entry at " + at + " has type " + toHex(next.type, 2) + " instead of an extended type",
                                 Region{ebr * ss + kEntriesOffset + 16, 16}, true);
            ebr = ext.firstLba + next.firstLba;
        }
        if (t->chainBroken())
            t->addDiagnostic(Validity::Warning, "mbr.logical_lost",
                             "the EBR chain stops at LBA " + std::to_string(*t->m_chainBreakLba) +
                                 " before its end; logical partitions behind that point are missing from the table",
                             {}, true);
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

    // Rules about the raw entries, which Partition does not carry. write() regenerates every
    // entry from the Partition list, so each of these is cured by a rewrite.
    auto checkEntries = [&](std::span<const std::byte> sec, Lba lba, bool isEbr) {
        if (sec.size() < 512) return;
        for (int i = 0; i < 4; ++i) {
            const auto bytes = entryBytes(sec, i);
            gen::MbrEntry e(bytes);
            const Region where{lba * ss + kEntriesOffset + static_cast<ByteCount>(i) * 16, 16};
            const std::string slot = (isEbr ? "EBR at LBA " + std::to_string(lba) + " entry " : "entry ") + std::to_string(i + 1);
            if (e.type() == 0) {
                if (!allZero(bytes))
                    addDiagnostic(Validity::Info, "mbr.entry_stale", slot + " has type 0 but other fields set (leftover of a deleted partition)", where, true);
                continue;
            }
            if (!statusIsStandard(e.status()))
                addDiagnostic(Validity::Warning, "mbr.entry_status", slot + ": status " + toHex(e.status(), 2) + " is neither 0x00 nor 0x80", where, true);
            if (e.firstChs().sector == 0 || e.lastChs().sector == 0)
                addDiagnostic(Validity::Warning, "mbr.chs_invalid", slot + ": CHS address has sector 0 (sectors count from 1)", where, true);
        }
    };
    checkEntries(m_sector0, 0, false);
    for (const auto& [lba, bytes] : m_ebrs) checkEntries(bytes, lba, true);
}

void MbrTable::addDiagnostic(Validity sev, std::string code, std::string message, std::optional<Region> region, bool repairable) {
    m_diagnostics.push_back(Diagnostic{sev, std::move(code), std::move(message), region, repairable});
}

std::unique_ptr<MbrTable> MbrTable::createEmpty(const Geometry& geometry) {
    auto t = std::unique_ptr<MbrTable>(new MbrTable());
    t->m_geometry = geometry;
    t->m_bootstrap.assign(440, std::byte{0});
    t->m_diskSignature = randomDiskSignature();
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
    gen::MbrSector::setCopyProtected(s, m_copyProtected);
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
    // The kernel starts the walk at the extended partition's first sector, so the lowest logical
    // owns that EBR whatever its entry recorded (a recovered chain may have lost its head). Every
    // other EBR keeps its place when it still sits between its predecessor and its own data.
    std::vector<Lba> ebrAt(logicals.size());
    for (std::size_t i = 0; i < logicals.size(); ++i) {
        const Partition& p = *logicals[i];
        if (i == 0) {
            ebrAt[i] = ext->firstLba;
        } else {
            const Lba prevEnd = logicals[i - 1]->lastLba;
            if (p.ebrLba && *p.ebrLba > prevEnd && *p.ebrLba < p.firstLba) {
                ebrAt[i] = *p.ebrLba;
            } else {
                const Lba wanted = p.firstLba >= kDefaultEbrGap ? p.firstLba - kDefaultEbrGap : 0;
                ebrAt[i] = std::max(wanted, prevEnd + 1);
            }
        }
        if (ebrAt[i] >= p.firstLba || ebrAt[i] < ext->firstLba)
            return fail(ErrorCategory::InvalidArgument, "no room for an EBR before logical partition " + std::to_string(p.index));
    }
    std::vector<std::pair<Lba, std::vector<std::byte>>> ebrs;
    for (std::size_t i = 0; i < logicals.size(); ++i) {
        const Partition& p = *logicals[i];
        std::vector<std::byte> ebr(ss, std::byte{0});
        gen::MbrSector::setBootSignature(ebr, 0xAA55);
        auto e0 = serializeEntry(p, ebrAt[i]);
        std::copy(e0.begin(), e0.end(), ebr.begin() + kEntriesOffset);
        if (i + 1 < logicals.size()) {
            const Partition& n = *logicals[i + 1];
            Partition link;
            link.type = PartitionType::mbr(0x05);
            link.firstLba = ebrAt[i + 1];
            link.lastLba = n.lastLba;
            auto e1 = serializeEntry(link, ext->firstLba);
            std::copy(e1.begin(), e1.end(), ebr.begin() + kEntriesOffset + 16);
        }
        ebrs.emplace_back(ebrAt[i], std::move(ebr));
    }

    for (const auto& [lba, bytes] : ebrs)
        if (auto r = device.writeAt(lba * ss, bytes); !r) return r;
    if (auto r = device.writeAt(0, s); !r) return r;
    return device.flush();
}

// ----------------------------------------------------------------------------- repair

std::vector<Partition> MbrTable::recoverLogicals(BlockDevice& device, const Partition& ext) const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    const SectorCount sectors = std::min(m_geometry.sectors(), device.geometry().sectors());
    if (sectors == 0 || ext.firstLba >= sectors) return {};
    const Lba extLast = std::min(ext.lastLba, sectors - 1);
    std::vector<Partition> found;
    ByteCount budget = kRecoveryScanBudget;
    // Sectors the walk already read; the one it broke on is examined again (a read may succeed
    // on retry, and a signature-less EBR is only accepted through the link that reached it).
    std::set<Lba> seen;
    for (const auto& [lba, bytes] : m_ebrs)
        if (!m_chainBreakLba || lba != *m_chainBreakLba) seen.insert(lba);

    auto insideData = [&](Lba lba) {
        for (const auto& p : m_partitions)
            if (!p.isExtended && lba >= p.firstLba && lba <= p.lastLba) return true;
        for (const auto& f : found)
            if (lba >= f.firstLba && lba <= f.lastLba) return true;
        return false;
    };
    auto overlapsKnown = [&](const Partition& c) {
        for (const auto& p : m_partitions)
            if (!p.isExtended && c.overlaps(p)) return true;
        for (const auto& f : found)
            if (c.overlaps(f)) return true;
        return false;
    };
    // Examines one sector; returns the onward link of an accepted EBR so a whole chain behind
    // the break is picked up from its first sector.
    auto examine = [&](Lba lba, bool linkTarget) -> std::optional<Lba> {
        if (lba < ext.firstLba || lba > extLast || seen.count(lba) || insideData(lba) || budget < ss) return std::nullopt;
        seen.insert(lba);
        budget -= ss;
        auto sec = device.readSectors(lba, 1);
        if (!sec) return std::nullopt;
        auto o = parseOrphanEbr(*sec, lba, ext, extLast, linkTarget);
        if (!o || overlapsKnown(o->logical)) return std::nullopt;
        found.push_back(std::move(o->logical));
        return o->link;
    };
    auto followFrom = [&](std::optional<Lba> lba, bool linkTarget) {
        while (lba) {
            lba = examine(*lba, linkTarget);
            linkTarget = true;   // an accepted EBR vouches for whatever it links to
        }
    };

    followFrom(m_chainBreakLba, true);
    // Where partitioners put EBRs: the 1 MiB grid (fdisk, sfdisk, parted since 2.x) and the
    // 63-sector track grid of the CHS era. Each hit may lead a chain of its own.
    for (const Lba step : {std::max<Lba>(1, MiB / ss), Lba{63}}) {
        const Lba first = ((ext.firstLba + step - 1) / step) * step;
        for (Lba lba = first; lba <= extLast && budget >= ss; lba += step) followFrom(lba, false);
    }
    std::sort(found.begin(), found.end(), [](const Partition& a, const Partition& b) { return a.firstLba < b.firstLba; });
    return found;
}

Expected<void> MbrTable::repair(BlockDevice& device, const RepairOptions&) {
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
    if (device.geometry().logicalSectorSize != m_geometry.logicalSectorSize)
        return fail(ErrorCategory::InvalidArgument, "table was read from a device with " + std::to_string(m_geometry.logicalSectorSize) +
                                                        "-byte sectors, this one has " + std::to_string(device.geometry().logicalSectorSize));
    if (const Partition* extPtr = extendedPartition(); extPtr && chainBroken()) {
        const Partition ext = *extPtr;   // m_partitions grows below
        for (auto& p : recoverLogicals(device, ext)) m_partitions.push_back(std::move(p));
        std::vector<Partition*> logicals;
        for (auto& p : m_partitions)
            if (p.isLogical) logicals.push_back(&p);
        if (logicals.empty())
            return fail(ErrorCategory::InvalidFormat, "the EBR chain breaks at LBA " + std::to_string(*m_chainBreakLba) +
                                                          " and no logical partition was found behind it; refusing to write an empty chain over it");
        // Chain order is disk order, and read() numbers logicals along the chain.
        std::sort(logicals.begin(), logicals.end(), [](const Partition* a, const Partition* b) { return a->firstLba < b->firstLba; });
        std::uint32_t index = 5;
        for (auto* p : logicals) p->index = index++;
        std::sort(m_partitions.begin(), m_partitions.end(), [](const Partition& a, const Partition& b) { return a.index < b.index; });
    }
    if (auto r = write(device); !r) return r;
    // Re-read to refresh state and diagnostics.
    auto fresh = MbrTable::read(std::shared_ptr<BlockDevice>(&device, [](BlockDevice*) {}));
    if (!fresh) return fail(fresh.error());
    *this = std::move(**fresh);
    return {};
}

// ----------------------------------------------------------------------------- describe

layout::Node MbrTable::describe() const {
    const std::uint32_t ss = m_geometry.logicalSectorSize;
    layout::Node root;
    root.name = "MBR partition table";
    root.isStruct = true;
    root.size = m_geometry.sizeBytes;

    // Diagnostics name the bytes they are about: a whole sector or one 16-byte entry.
    auto flagByRegion = [&](layout::Node& n) {
        for (const auto& d : m_diagnostics)
            if (d.region && d.region->offset == n.absOffset && (d.region->length == n.size || d.region->length == ss))
                n.flag(d.severity, d.message);
    };
    auto describeSector = [&](std::span<const std::byte> sec, Lba lba, const std::string& title, bool isEbr) {
        auto n = gen::MbrSector(sec).describe(lba * ss);
        n.name = title;
        if (auto* entries = n.child("entries")) {
            entries->isStruct = true;
            for (int i = 0; i < 4; ++i) {
                RawEntry raw = rawEntry(sec, i);
                if (allZero(entryBytes(sec, i))) continue;
                auto e = gen::MbrEntry(entryBytes(sec, i)).describe(lba * ss + kEntriesOffset + static_cast<std::uint64_t>(i) * 16);
                e.name = isEbr ? (i == 0 ? "logical partition" : "next EBR link") : "entry " + std::to_string(i + 1);
                if (auto* t = e.child("type")) t->pretty = types::name(PartitionType::mbr(raw.type));
                if (auto* f = e.child("first_lba"); f && isEbr) f->pretty = "absolute LBA " + std::to_string((i == 0 ? lba : extendedPartition()->firstLba) + raw.firstLba);
                flagByRegion(e);
                entries->addChild(std::move(e));
            }
        }
        flagByRegion(n);
        return n;
    };
    if (m_sector0.size() >= 512) root.addChild(describeSector(m_sector0, 0, "MBR sector", false));
    for (const auto& [lba, bytes] : m_ebrs) root.addChild(describeSector(bytes, lba, "EBR @ LBA " + std::to_string(lba), true));
    if (m_chainEnd == ChainEnd::Unreadable && m_chainBreakLba) {
        layout::Node n;
        n.name = "EBR @ LBA " + std::to_string(*m_chainBreakLba);
        n.isStruct = true;
        n.absOffset = *m_chainBreakLba * ss;
        n.size = ss;
        flagByRegion(n);
        root.addChild(std::move(n));
    }
    for (const auto& d : m_diagnostics)
        if (d.severity >= Validity::Warning) root.flag(d.severity, d.message);
    return root;
}

} // namespace stein::pt
