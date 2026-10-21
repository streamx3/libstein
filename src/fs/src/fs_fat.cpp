// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/exfat.hpp"
#include "stein/fs/exfat_reader.hpp"
#include "stein/fs/fat_reader.hpp"
#include "stein/layout/gen/fat.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

namespace {

bool isPow2(std::uint32_t v) { return v && (v & (v - 1)) == 0; }

// Scan a directory region for the volume label entry (attribute 0x08, not deleted, not LFN);
// returns its offset inside the region.
std::optional<std::size_t> fatDirLabelAt(std::span<const std::byte> dir) {
    for (std::size_t off = 0; off + 32 <= dir.size(); off += 32) {
        const auto first = std::to_integer<std::uint8_t>(dir[off]);
        if (first == 0x00) break;        // end of directory
        if (first == 0xE5) continue;     // deleted
        const auto attr = std::to_integer<std::uint8_t>(dir[off + 11]);
        if (attr == 0x0F) continue;      // long-name fragment
        if (attr & 0x08) return off;
    }
    return std::nullopt;
}

} // namespace

// FAT: a cluster is used when its FAT entry is non-zero.
class FatAllocation final : public AllocationSource {
public:
    std::uint32_t bps = 0, spc = 0, bits = 16;
    ByteCount fatOffset = 0, fatBytes = 0, dataOffset = 0;
    std::uint64_t clusters = 0;

    Expected<AllocationMap> load(BlockDevice& dev) const override {
        auto fat = dev.read(fatOffset, std::min<ByteCount>(fatBytes, 1 * GiB));
        if (!fat) return fail(fat.error());
        AllocationMap map(dataOffset, ByteCount{bps} * spc, clusters, true);
        const std::byte* f = fat->data();
        for (std::uint64_t c = 0; c < clusters; ++c) {
            const std::uint64_t n = c + 2;
            std::uint32_t entry = 0;
            if (bits == 12) {
                const std::size_t pos = static_cast<std::size_t>(n + n / 2);
                if (pos + 1 >= fat->size()) break;
                const std::uint16_t v = loadLe16(f + pos);
                entry = (n & 1) ? (v >> 4) : (v & 0x0FFF);
            } else if (bits == 16) {
                if ((n + 1) * 2 > fat->size()) break;
                entry = loadLe16(f + n * 2);
            } else {
                if ((n + 1) * 4 > fat->size()) break;
                entry = loadLe32(f + n * 4) & 0x0FFFFFFFu;
            }
            if (entry == 0) map.set(c, false);
        }
        return map;
    }
};

// exFAT: the allocation bitmap file, found through the root directory (entry type 0x81).
class ExfatAllocation final : public AllocationSource {
public:
    ByteCount bps = 0, cluster = 0, fatOffset = 0, heapOffset = 0;
    std::uint32_t clusterCount = 0, rootCluster = 0;

    Expected<std::uint32_t> next(BlockDevice& dev, std::uint32_t c) const {
        auto e = dev.read(fatOffset + ByteCount{c} * 4, 4);
        if (!e) return fail(e.error());
        return loadLe32(e->data());
    }
    ByteCount clusterOffset(std::uint32_t c) const { return heapOffset + ByteCount{c - 2} * cluster; }

    Expected<AllocationMap> load(BlockDevice& dev) const override {
        // Walk the root directory chain looking for the bitmap entry.
        std::uint32_t c = rootCluster;
        std::uint32_t bitmapFirst = 0;
        std::uint64_t bitmapLen = 0;
        for (int hops = 0; hops < 1024 && c >= 2 && c - 2 < clusterCount && !bitmapFirst; ++hops) {
            auto dir = dev.read(clusterOffset(c), cluster);
            if (!dir) return fail(dir.error());
            for (std::size_t e = 0; e + 32 <= dir->size(); e += 32) {
                const auto type = std::to_integer<std::uint8_t>((*dir)[e]);
                if (type == 0x00) break;
                if (type == 0x81) {
                    bitmapFirst = loadLe32(dir->data() + e + 20);
                    bitmapLen = loadLe64(dir->data() + e + 24);
                    break;
                }
            }
            auto n = next(dev, c);
            if (!n) return fail(n.error());
            c = *n;
        }
        if (!bitmapFirst) return fail(ErrorCategory::InvalidFormat, "exFAT root directory has no allocation bitmap entry");
        AllocationMap map(heapOffset, cluster, clusterCount, true);
        const std::uint64_t needed = (std::uint64_t{clusterCount} + 7) / 8;
        if (bitmapLen < needed) return fail(ErrorCategory::InvalidFormat, "exFAT allocation bitmap is too short");
        std::vector<std::byte> bits;
        bits.reserve(static_cast<std::size_t>(needed));
        c = bitmapFirst;
        for (int hops = 0; hops < 1 << 20 && bits.size() < needed && c >= 2 && c - 2 < clusterCount; ++hops) {
            auto part = dev.read(clusterOffset(c), std::min<ByteCount>(cluster, needed - bits.size()));
            if (!part) return fail(part.error());
            bits.insert(bits.end(), part->begin(), part->end());
            auto n = next(dev, c);
            if (!n) return fail(n.error());
            c = *n;
        }
        if (bits.size() < needed) return fail(ErrorCategory::InvalidFormat, "exFAT allocation bitmap chain is broken");
        map.importBitmap(0, clusterCount, bits);
        return map;
    }
};

Result detectFat(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 512);
    if (!raw) return fail(raw.error());
    std::span<const std::byte> s(*raw);
    if (loadLe16(s.data() + 510) != 0xAA55) return notMine("no boot signature");
    gen::FatBpb bpb(s);
    const auto jump = std::to_integer<std::uint8_t>(s[0]);
    if (jump != 0xEB && jump != 0xE9 && jump != 0x49 /* some exotic */) return notMine("no jump");
    const std::uint32_t bps = bpb.bytesPerSector(), spc = bpb.sectorsPerCluster(), reserved = bpb.reservedSectors(),
                        fats = bpb.numFats();
    if (!(bps == 512 || bps == 1024 || bps == 2048 || bps == 4096) || !isPow2(spc) || reserved == 0 || fats == 0 || fats > 2)
        return notMine("BPB fields implausible");
    gen::Fat16Ebpb e16(s.subspan(36, gen::Fat16Ebpb::kSize));
    gen::Fat32Ebpb e32(s.subspan(36, gen::Fat32Ebpb::kSize));
    const std::uint32_t totalSectors = bpb.totalSectors16() ? bpb.totalSectors16() : bpb.totalSectors32();
    const std::uint32_t fatSectors = bpb.sectorsPerFat16() ? bpb.sectorsPerFat16() : e32.sectorsPerFat32();
    if (totalSectors == 0 || fatSectors == 0) return notMine("no sector counts");
    const std::uint32_t rootDirSectors = (bpb.rootEntries() * 32u + bps - 1) / bps;
    const std::uint64_t dataStart = ByteCount{reserved} + ByteCount{fats} * fatSectors + rootDirSectors;
    if (dataStart >= totalSectors) return notMine("data area outside volume");
    const std::uint64_t clusters = (totalSectors - dataStart) / spc;
    const bool isFat32 = bpb.sectorsPerFat16() == 0 && bpb.rootEntries() == 0;

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    if (isFat32) info.type = FsType::Fat32;
    else if (clusters < 4085) info.type = FsType::Fat12;
    else if (clusters < 65525) info.type = FsType::Fat16;
    else info.type = FsType::Fat32;
    if (isFat32 && clusters < 65525) fs->diag(Validity::Info, "fat.small_fat32", "FAT32 layout with fewer than 65525 clusters");
    info.version = std::string(displayName(info.type));
    info.blockSize = ByteCount{bps} * spc;
    info.totalBytes = ByteCount{totalSectors} * bps;

    std::string bootLabel;
    std::uint32_t serial = 0;
    std::uint8_t dirtyFlags = 0;
    if (isFat32) {
        if (e32.bootSignature() == 0x29 || e32.bootSignature() == 0x28) {
            bootLabel = e32.volumeLabel();
            serial = e32.volumeId();
        }
        dirtyFlags = e32.reserved1();
    } else {
        if (e16.bootSignature() == 0x29 || e16.bootSignature() == 0x28) {
            bootLabel = e16.volumeLabel();
            serial = e16.volumeId();
        }
        dirtyFlags = e16.reserved1();
    }
    // The root directory's label entry is authoritative (this is what blkid reports as LABEL).
    std::string dirLabel;
    std::optional<ByteCount> labelEntryOffset;   // where that entry lies, for describe()
    std::vector<std::byte> labelEntry;
    auto takeLabel = [&](const std::vector<std::byte>& dir, ByteCount dirOffset) {
        if (auto at = fatDirLabelAt(dir)) {
            dirLabel = asciiField(std::span<const std::byte>(dir).subspan(*at, 11));
            labelEntryOffset = dirOffset + *at;
            labelEntry.assign(dir.begin() + static_cast<std::ptrdiff_t>(*at), dir.begin() + static_cast<std::ptrdiff_t>(*at + 32));
        }
    };
    if (isFat32) {
        const std::uint32_t root = e32.rootCluster();
        if (root >= 2 && root - 2 < clusters) {
            const ByteCount off = (dataStart + ByteCount{root - 2} * spc) * bps;
            if (auto dir = dev->read(off, ByteCount{spc} * bps)) takeLabel(*dir, off);
        }
    } else {
        const ByteCount off = (ByteCount{reserved} + ByteCount{fats} * fatSectors) * bps;
        const ByteCount len = std::min<ByteCount>(ByteCount{rootDirSectors} * bps, 64 * KiB);
        if (len && off + len <= dev->size())
            if (auto dir = dev->read(off, len)) takeLabel(*dir, off);
    }
    info.label = !dirLabel.empty() ? dirLabel : (bootLabel == "NO NAME" ? "" : bootLabel);
    if (serial) info.uuid = serialHex(serial);
    info.clean = !(dirtyFlags & 0x01);
    if (dirtyFlags & 0x01) fs->diag(Validity::Warning, "fat.dirty", "volume is marked dirty (needs chkdsk)");
    if (!bootLabel.empty() && bootLabel != "NO NAME") info.extra = "boot-sector label: " + bootLabel;

    fs->setTreeName(info.version + " filesystem");
    auto tree = bpb.describe(0);
    tree.name = "boot sector BPB";
    fs->addNode(std::move(tree));
    if (isFat32) {
        auto t = e32.describe(36);
        t.name = "FAT32 extended BPB";
        fs->addNode(std::move(t));
        fs->addRegion(Region{0, ByteCount{reserved} * bps});   // boot sector, FSInfo, backup boot sector
        const std::uint32_t fsinfo = e32.fsinfoSector();
        if (fsinfo && fsinfo < reserved) {
            if (auto fi = dev->read(ByteCount{fsinfo} * bps, 512)) {
                auto n = gen::Fat32Fsinfo(*fi).describe(ByteCount{fsinfo} * bps);
                n.name = "FSInfo sector";
                gen::Fat32Fsinfo f(*fi);
                if (f.freeCount() != 0xFFFFFFFFu && f.freeCount() <= clusters)
                    info.usedBytes = (clusters - f.freeCount()) * ByteCount{spc} * bps;
                fs->addNode(std::move(n));
            }
        }
        // The backup boot sector (usually 6) is what a repair tool restores from; show it and say
        // when it has drifted from the live one (a label edited in one sector only, for instance).
        const std::uint32_t backup = e32.backupBootSector();
        if (backup && backup < reserved) {
            if (auto bb = dev->read(ByteCount{backup} * bps, 512)) {
                std::span<const std::byte> b(*bb);
                auto n = gen::FatBpb(b).describe(ByteCount{backup} * bps);
                n.name = "backup boot sector BPB";
                fs->addNode(std::move(n));
                auto n2 = gen::Fat32Ebpb(b.subspan(36, gen::Fat32Ebpb::kSize)).describe(ByteCount{backup} * bps + 36);
                n2.name = "backup FAT32 extended BPB";
                fs->addNode(std::move(n2));
                if (!std::equal(b.begin(), b.begin() + 90, s.begin()))
                    fs->diag(Validity::Warning, "fat.backup_boot_mismatch", "backup boot sector (sector " + std::to_string(backup) + ") differs from the boot sector");
            }
        }
    } else {
        auto t = e16.describe(36);
        t.name = "FAT12/16 extended BPB";
        fs->addNode(std::move(t));
        fs->addRegion(Region{0, ByteCount{reserved} * bps});
    }
    // The label the OS shows lives in the root directory, not in the boot sector.
    if (labelEntryOffset) {
        auto n = gen::FatDirEntry(labelEntry).describe(*labelEntryOffset);
        n.name = "root directory volume label entry";
        fs->addNode(std::move(n));
    }
    if (!dirLabel.empty() && !bootLabel.empty() && bootLabel != "NO NAME" && bootLabel != dirLabel)
        fs->diag(Validity::Info, "fat.label_mismatch", "boot-sector label \"" + bootLabel + "\" differs from the root directory label \"" + dirLabel + "\", which is the one the OS shows");
    {
        auto alloc = std::make_unique<FatAllocation>();
        alloc->bps = bps;
        alloc->spc = spc;
        alloc->bits = info.type == FsType::Fat12 ? 12 : info.type == FsType::Fat16 ? 16 : 32;
        alloc->fatOffset = ByteCount{reserved} * bps;
        alloc->fatBytes = ByteCount{fatSectors} * bps;
        alloc->dataOffset = dataStart * bps;
        alloc->clusters = clusters;
        fs->setAllocationSource(std::move(alloc));
        fs->setReaderSource(makeFatReaderSource());
    }
    // FATs and (FAT12/16) root directory are metadata too.
    fs->addRegion(Region{ByteCount{reserved} * bps, ByteCount{fats} * fatSectors * bps});
    if (rootDirSectors) fs->addRegion(Region{(ByteCount{reserved} + ByteCount{fats} * fatSectors) * bps, ByteCount{rootDirSectors} * bps});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

namespace {
// exFAT specification §3.4: the boot checksum runs over the first eleven sectors of a
// boot region, skipping VolumeFlags (bytes 106-107) and PercentInUse (112) of the boot
// sector; the twelfth sector repeats the 32-bit result until it is full.
std::uint32_t exfatBootChecksum(std::span<const std::byte> sectors) {
    std::uint32_t c = 0;
    for (std::size_t i = 0; i < sectors.size(); ++i) {
        if (i == 106 || i == 107 || i == 112) continue;
        c = ((c & 1u) ? 0x80000000u : 0u) + (c >> 1) + std::to_integer<std::uint32_t>(sectors[i]);
    }
    return c;
}

// exFAT §7.2.3 / §6.4: the table checksum (no skips) and the 16-bit entry-set checksum
// (bytes 2-3 of the primary entry skipped) use the same rotate-and-add recurrence.
std::uint32_t exfatTableChecksum(std::span<const std::byte> bytes) {
    std::uint32_t c = 0;
    for (const auto b : bytes) c = ((c & 1u) ? 0x80000000u : 0u) + (c >> 1) + std::to_integer<std::uint32_t>(b);
    return c;
}
std::uint16_t exfatEntrySetChecksum(std::span<const std::byte> entries) {
    std::uint16_t c = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (i == 2 || i == 3) continue;
        c = static_cast<std::uint16_t>(((c & 1u) ? 0x8000u : 0u) + (c >> 1) + std::to_integer<std::uint16_t>(entries[i]));
    }
    return c;
}

constexpr const char* kExfatFlashParametersGuid = "0A0C7E46-3399-4021-90C8-FA6D389C4BA2";

// One boot region (main at sector 0, backup at sector 12) as a tree: the boot sector, the
// eight extended boot sectors, the OEM parameters and the checksum sector that seals them.
// The checksum is one field as wide as the sector, so a hex editor that refills it writes
// the repeated value the specification asks for.
layout::Node describeExfatBootRegion(std::span<const std::byte> bytes, ByteCount base, std::size_t bps, const char* title,
                                     bool& checksumOk, bool& checksumRepeated) {
    layout::Node region;
    region.name = title;
    region.isStruct = true;
    region.absOffset = base;
    region.size = 12 * bps;
    auto boot = gen::ExfatBootSector(bytes.first(gen::ExfatBootSector::kSize)).describe(base);
    boot.name = "boot sector";
    region.addChild(std::move(boot));

    // Sectors 1-8: boot code of the implementation's choosing, each ending in 0xAA550000.
    layout::Node extended;
    extended.name = "extended boot sectors";
    extended.isStruct = true;
    extended.absOffset = base + bps;
    extended.size = 8 * bps;
    for (std::size_t i = 1; i <= 8; ++i) {
        layout::Node sector;
        sector.name = "extended boot sector " + std::to_string(i);
        sector.isStruct = true;
        sector.absOffset = base + i * bps;
        sector.size = bps;
        layout::Node code;
        code.name = "boot_code";
        code.type = layout::FieldType::Bytes;
        code.absOffset = sector.absOffset;
        code.size = bps - 4;
        code.value = "<" + std::to_string(bps - 4) + " bytes>";
        sector.addChild(std::move(code));
        layout::Node sig;
        sig.name = "extended_boot_signature";
        sig.type = layout::FieldType::U32;
        sig.absOffset = sector.absOffset + bps - 4;
        sig.size = 4;
        const std::uint32_t v = loadLe32(bytes.data() + i * bps + bps - 4);
        sig.value = std::to_string(v);
        sig.pretty = toHex(v, 8);
        sig.doc = "Must be 0xAA550000";
        if (v != 0xAA550000u) sig.flag(Validity::Error, "expected 0xAA550000");
        sector.addChild(std::move(sig));
        extended.addChild(std::move(sector));
    }
    region.addChild(std::move(extended));

    // Sector 9: ten OEM parameter slots; the flash parameters record is the one defined so far.
    layout::Node oem;
    oem.name = "OEM parameters";
    oem.isStruct = true;
    oem.absOffset = base + 9 * bps;
    oem.size = bps;
    for (std::size_t i = 0; i < 10 && (i + 1) * 48 <= bps; ++i) {
        const auto slot = bytes.subspan(9 * bps + i * 48, 48);
        const Uuid guid = gen::ExfatOemParameter(slot).parametersGuid();
        if (guid.isNil()) continue;
        layout::Node n;
        if (guid.toString() == kExfatFlashParametersGuid) {
            n = gen::ExfatFlashParameters(slot).describe(oem.absOffset + i * 48);
            n.name = "flash parameters";
        } else {
            n = gen::ExfatOemParameter(slot).describe(oem.absOffset + i * 48);
            n.name = "OEM parameter " + std::to_string(i + 1);
        }
        oem.addChild(std::move(n));
    }
    if (oem.children.empty()) oem.doc = "all ten slots unused";
    region.addChild(std::move(oem));

    layout::Node sector;
    sector.name = "boot checksum";
    sector.isStruct = true;
    sector.absOffset = base + 11 * bps;
    sector.size = bps;
    const auto ck = bytes.subspan(11 * bps, bps);
    const std::uint32_t stored = loadLe32(ck.data());
    const std::uint32_t computed = exfatBootChecksum(bytes.first(11 * bps));
    checksumRepeated = true;
    for (std::size_t i = 4; i + 4 <= ck.size(); i += 4)
        if (loadLe32(ck.data() + i) != stored) {
            checksumRepeated = false;
            break;
        }
    checksumOk = stored == computed;
    layout::Node f;
    f.name = "checksum";
    f.type = layout::FieldType::Crc32;
    f.absOffset = sector.absOffset;
    f.size = bps;
    f.value = toHex(stored, 8);
    f.doc = "Boot checksum over the eleven sectors before it (VolumeFlags and PercentInUse excluded), repeated to fill the sector";
    if (!checksumOk) f.flag(Validity::Error, "mismatch; computed " + toHex(computed, 8));
    else if (!checksumRepeated) f.flag(Validity::Warning, "not repeated through the sector; computed " + toHex(computed, 8));
    sector.addChild(std::move(f));
    region.addChild(std::move(sector));
    return region;
}

// Repair policy for the two boot regions, the one fsck.exfat follows: a region whose
// checksum holds is sound. Backup damaged or drifted -> copy the main region over it.
// Main damaged, backup sound -> restore the main region from the backup. Both damaged ->
// nothing to copy from; recompute each checksum over what is there. Only sectors that
// change are written; the FAT and the cluster heap are never touched.
Expected<void> repairExfatBootRegions(BlockDevice& target, ByteCount bps) {
    const std::size_t bpsz = static_cast<std::size_t>(bps);
    auto regions = target.read(0, 24 * bps);
    if (!regions) return fail(regions.error());
    if (regions->size() != 24 * bpsz) return fail(ErrorCategory::InvalidFormat, "device too short for the exFAT boot regions");
    std::vector<std::byte> all = std::move(*regions);
    const std::vector<std::byte> before = all;
    auto region = [&](std::size_t which) { return std::span<std::byte>(all).subspan(which * 12 * bpsz, 12 * bpsz); };
    auto checksumHolds = [&](std::span<const std::byte> r) {
        const std::uint32_t computed = exfatBootChecksum(r.first(11 * bpsz));
        for (std::size_t i = 0; i + 4 <= bpsz; i += 4)
            if (loadLe32(r.data() + 11 * bpsz + i) != computed) return false;
        return true;
    };
    auto seal = [&](std::span<std::byte> r) {
        const std::uint32_t computed = exfatBootChecksum(r.first(11 * bpsz));
        for (std::size_t i = 0; i + 4 <= bpsz; i += 4) storeLe32(r.data() + 11 * bpsz + i, computed);
    };
    auto sameBoot = [&] {
        for (std::size_t i = 0; i < 512; ++i) {
            if (i == 106 || i == 107 || i == 112) continue;
            if (all[i] != all[12 * bpsz + i]) return false;
        }
        return true;
    };
    // Copy the eleven sealed sectors of one region over the other, keeping the destination's
    // VolumeFlags and PercentInUse: the specification lets the copies differ there.
    auto copyRegion = [&](std::size_t from, std::size_t to) {
        const std::byte keep106 = region(to)[106], keep107 = region(to)[107], keep112 = region(to)[112];
        std::copy_n(region(from).begin(), 11 * bpsz, region(to).begin());
        region(to)[106] = keep106;
        region(to)[107] = keep107;
        region(to)[112] = keep112;
        seal(region(to));
    };
    const bool mainOk = checksumHolds(region(0)), backupOk = checksumHolds(region(1));
    if (mainOk) {
        if (!backupOk || !sameBoot()) copyRegion(0, 1);
    } else if (backupOk) {
        copyRegion(1, 0);
    } else {
        seal(region(0));
        seal(region(1));
    }
    for (std::size_t sector = 0; sector < 24; ++sector) {
        const auto from = sector * bpsz;
        if (std::equal(all.begin() + from, all.begin() + from + bpsz, before.begin() + from)) continue;
        if (auto w = target.writeAt(sector * bps, std::span<const std::byte>(all).subspan(from, bpsz)); !w) return w;
    }
    return target.flush();
}

// Both boot regions, each sealed by its checksum sector. A device too short for them
// (never a real volume) falls back to the bare boot sector.
void describeExfatBootRegions(const Dev& dev, SimpleFileSystem& fs, const gen::ExfatBootSector& b, ByteCount bps) {
    const std::size_t bpsz = static_cast<std::size_t>(bps);
    auto regions = dev->read(0, 24 * bps);
    if (!regions || regions->size() != 24 * bpsz) {
        auto tree = b.describe(0);
        tree.name = "main boot sector";
        fs.addNode(std::move(tree));
        return;
    }
    std::span<const std::byte> all(*regions);
    bool mainOk = false, mainRepeated = false, backupOk = false, backupRepeated = false;
    fs.addNode(describeExfatBootRegion(all.first(12 * bpsz), 0, bpsz, "main boot region", mainOk, mainRepeated));
    fs.addNode(describeExfatBootRegion(all.subspan(12 * bpsz, 12 * bpsz), 12 * bps, bpsz, "backup boot region", backupOk, backupRepeated));
    if (!mainOk) fs.diag(Validity::Error, "exfat.boot_checksum", "main boot region checksum (sector 11) does not match its sectors", true);
    else if (!mainRepeated) fs.diag(Validity::Warning, "exfat.boot_checksum_partial", "main boot checksum is not repeated through sector 11", true);
    if (!backupOk) fs.diag(Validity::Warning, "exfat.backup_boot_checksum", "backup boot region checksum (sector 23) does not match its sectors", true);
    else if (!backupRepeated) fs.diag(Validity::Warning, "exfat.backup_boot_checksum_partial", "backup boot checksum is not repeated through sector 23", true);
    // The backup copy is what a repair restores from; say when it has drifted. VolumeFlags
    // and PercentInUse may legitimately differ between the two copies.
    bool same = true;
    for (std::size_t i = 0; i < 512 && same; ++i) {
        if (i == 106 || i == 107 || i == 112) continue;
        same = all[i] == all[12 * bpsz + i];
    }
    if (!same) fs.diag(Validity::Warning, "exfat.backup_boot_mismatch", "backup boot sector (sector 12) differs from the main boot sector", true);
    fs.setRepair([bps](BlockDevice& target) { return repairExfatBootRegions(target, bps); });
    for (std::size_t i = 1; i <= 8; ++i)
        if (loadLe32(all.data() + i * bpsz + bpsz - 4) != 0xAA550000u) {
            fs.diag(Validity::Warning, "exfat.extended_boot_signature", "extended boot sector " + std::to_string(i) + " lacks the 0xAA550000 signature");
            break;
        }
}

// The root directory's volume-wide entries: allocation bitmap, up-case table (its checksum
// verified over the stored table), volume label and volume GUID. First cluster only.
void describeExfatRootEntries(const Dev& dev, SimpleFileSystem& fs, const gen::ExfatBootSector& b, ByteCount bps, ByteCount cluster) {
    const std::uint32_t root = b.firstClusterOfRoot();
    const std::uint32_t clusters = b.clusterCount();
    if (root < 2 || root - 2 >= clusters) return;
    const ByteCount heap = ByteCount{b.clusterHeapOffset()} * bps;
    const ByteCount off = heap + ByteCount{root - 2} * cluster;
    auto dir = dev->read(off, std::min<ByteCount>(cluster, 64 * KiB));
    if (!dir) return;
    layout::Node rootNode;
    rootNode.name = "root directory";
    rootNode.isStruct = true;
    rootNode.absOffset = off;
    rootNode.size = dir->size();
    rootNode.doc = "First cluster of the root directory: the entries that describe the volume itself";
    fs.addRegion(Region{off, static_cast<ByteCount>(dir->size())});
    auto inHeap = [&](std::uint32_t first, std::uint64_t length) {
        return first >= 2 && first - 2 < clusters && length <= (ByteCount{clusters - (first - 2)}) * cluster;
    };
    // Is the run first..first+n-1 contiguous as the FAT sees it (entries unset, sequential, or EOC last)?
    auto contiguous = [&](std::uint32_t first, std::uint64_t length) {
        const std::uint64_t n = (length + cluster - 1) / cluster;
        auto fat = dev->read(ByteCount{b.fatOffset()} * bps + ByteCount{first} * 4, n * 4);
        if (!fat) return false;
        for (std::uint64_t i = 0; i < n; ++i) {
            const std::uint32_t e = loadLe32(fat->data() + i * 4);
            const bool last = i + 1 == n;
            if (e == 0 || (!last && e == first + i + 1) || (last && e == 0xFFFFFFFFu)) continue;
            return false;
        }
        return true;
    };
    for (std::size_t e = 0; e + 32 <= dir->size(); e += 32) {
        const auto entry = std::span<const std::byte>(*dir).subspan(e, 32);
        const auto type = std::to_integer<std::uint8_t>(entry[0]);
        if (type == 0x00) break;
        const ByteCount at = off + e;
        if (type == 0x81) {
            auto n = gen::ExfatBitmapEntry(entry).describe(at);
            n.name = "allocation bitmap entry";
            gen::ExfatBitmapEntry v(entry);
            const std::uint64_t expected = (std::uint64_t{clusters} + 7) / 8;
            if (auto* c = n.child("data_length"); c && v.dataLength() != expected)
                c->flag(Validity::Warning, "expected " + std::to_string(expected) + " bytes for " + std::to_string(clusters) + " clusters");
            if (auto* c = n.child("first_cluster"); c && !inHeap(v.firstCluster(), v.dataLength())) c->flag(Validity::Error, "outside the cluster heap");
            else if (inHeap(v.firstCluster(), v.dataLength())) fs.addRegion(Region{heap + ByteCount{v.firstCluster() - 2} * cluster, v.dataLength()});
            rootNode.addChild(std::move(n));
        } else if (type == 0x82) {
            auto n = gen::ExfatUpcaseEntry(entry).describe(at);
            n.name = "up-case table entry";
            gen::ExfatUpcaseEntry v(entry);
            const bool plausible = inHeap(v.firstCluster(), v.dataLength()) && v.dataLength() >= 2 && v.dataLength() <= 128 * KiB + 2;
            if (auto* c = n.child("first_cluster"); c && !inHeap(v.firstCluster(), v.dataLength())) c->flag(Validity::Error, "outside the cluster heap");
            if (auto* c = n.child("table_checksum")) {
                c->validity = Validity::Ok;
                c->message.clear();
                if (plausible && contiguous(v.firstCluster(), v.dataLength())) {
                    const ByteCount tableAt = heap + ByteCount{v.firstCluster() - 2} * cluster;
                    fs.addRegion(Region{tableAt, v.dataLength()});
                    if (auto table = dev->read(tableAt, v.dataLength())) {
                        const std::uint32_t computed = exfatTableChecksum(*table);
                        if (computed != v.tableChecksum()) {
                            c->flag(Validity::Error, "mismatch; computed " + toHex(computed, 8));
                            fs.diag(Validity::Error, "exfat.upcase_checksum", "up-case table checksum does not match the table");
                        }
                    }
                } else if (plausible) {
                    c->flag(Validity::Info, "not verified: the table is fragmented");
                }
            }
            rootNode.addChild(std::move(n));
        } else if (type == 0x83 || type == 0x03) {
            auto n = gen::ExfatLabelEntry(entry).describe(at);
            n.name = "volume label entry";
            rootNode.addChild(std::move(n));
        } else if (type == 0xA0) {
            auto n = gen::ExfatVolumeGuidEntry(entry).describe(at);
            n.name = "volume GUID entry";
            gen::ExfatVolumeGuidEntry v(entry);
            if (auto* c = n.child("set_checksum")) {
                const std::uint16_t computed = exfatEntrySetChecksum(entry);
                if (computed != v.setChecksum()) c->flag(Validity::Error, "mismatch; computed " + toHex(computed, 4));
            }
            if (auto* c = n.child("general_primary_flags"); c && (v.generalPrimaryFlags() & 0x3)) c->flag(Validity::Warning, "must be zero for this entry");
            rootNode.addChild(std::move(n));
        }
    }
    if (!rootNode.children.empty()) fs.addNode(std::move(rootNode));
}
} // namespace

Result detectExFat(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 512);
    if (!raw) return fail(raw.error());
    std::span<const std::byte> s(*raw);
    gen::ExfatBootSector b(s);
    if (b.fsName() != "EXFAT") return notMine("no EXFAT name");
    if (loadLe16(s.data() + 510) != 0xAA55) return notMine("no boot signature");
    const std::uint8_t bpsShift = b.bytesPerSectorShift(), spcShift = b.sectorsPerClusterShift();
    if (bpsShift < 9 || bpsShift > 12 || spcShift > 25) return notMine("implausible shifts");
    const ByteCount bps = ByteCount{1} << bpsShift;
    const ByteCount cluster = bps << spcShift;

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::ExFat;
    info.version = std::to_string(b.fsRevision() >> 8) + "." + std::to_string(b.fsRevision() & 0xFF);
    info.uuid = serialHex(b.volumeSerialNumber());
    info.blockSize = cluster;
    info.totalBytes = b.volumeLength() * bps;
    info.clean = !(b.volumeFlags() & 0x2);
    if (b.volumeFlags() & 0x2) fs->diag(Validity::Warning, "exfat.dirty", "volume is marked dirty");
    if (b.volumeFlags() & 0x4) fs->diag(Validity::Warning, "exfat.media_failure", "media failure flag set");
    if (b.percentInUse() <= 100) info.usedBytes = *info.totalBytes * b.percentInUse() / 100;

    // Volume label: directory entry type 0x83 in the root directory (first cluster only at L0).
    const std::uint32_t root = b.firstClusterOfRoot();
    if (root >= 2 && root - 2 < b.clusterCount()) {
        const ByteCount off = ByteCount{b.clusterHeapOffset()} * bps + ByteCount{root - 2} * cluster;
        if (auto dir = dev->read(off, std::min<ByteCount>(cluster, 64 * KiB))) {
            for (std::size_t e = 0; e + 32 <= dir->size(); e += 32) {
                const auto type = std::to_integer<std::uint8_t>((*dir)[e]);
                if (type == 0x00) break;
                if (type == 0x83) {
                    const auto count = std::min<std::size_t>(std::to_integer<std::uint8_t>((*dir)[e + 1]), 11);
                    info.label = utf16leToUtf8(std::span<const std::byte>(*dir).subspan(e + 2, count * 2), false);
                    break;
                }
            }
        }
    }
    {
        auto alloc = std::make_unique<ExfatAllocation>();
        alloc->bps = bps;
        alloc->cluster = cluster;
        alloc->fatOffset = ByteCount{b.fatOffset()} * bps;
        alloc->heapOffset = ByteCount{b.clusterHeapOffset()} * bps;
        alloc->clusterCount = b.clusterCount();
        alloc->rootCluster = root;
        fs->setAllocationSource(std::move(alloc));
        fs->setReaderSource(makeExfatReaderSource());
    }
    fs->setTreeName("exFAT filesystem");
    describeExfatBootRegions(dev, *fs, b, bps);
    describeExfatRootEntries(dev, *fs, b, bps, cluster);
    fs->addRegion(Region{0, 12 * bps});                 // main boot region
    fs->addRegion(Region{12 * bps, 12 * bps});          // backup boot region
    fs->addRegion(Region{ByteCount{b.fatOffset()} * bps, ByteCount{b.fatLength()} * bps * b.numberOfFats()});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
