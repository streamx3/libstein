// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/exfat.hpp"
#include "stein/fs/exfat_reader.hpp"
#include "stein/fs/fat_reader.hpp"
#include "stein/layout/gen/fat.hpp"

#include <bit>

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

// The generated structs tile the 512-byte boot sector; describeFatBootSector() relies on it.
static_assert(gen::FatBpb::kSize + gen::Fat16Ebpb::kSize + gen::Fat16BootTail::kSize == 512);
static_assert(gen::FatBpb::kSize + gen::Fat32Ebpb::kSize + gen::Fat32BootTail::kSize == 512);

namespace {

bool isPow2(std::uint32_t v) { return v && (v & (v - 1)) == 0; }

// "3 MiB", "512 KiB", "67108864 bytes": for messages, whole units only.
std::string humanBytes(ByteCount n) {
    if (n >= GiB && n % GiB == 0) return std::to_string(n / GiB) + " GiB";
    if (n >= MiB && n % MiB == 0) return std::to_string(n / MiB) + " MiB";
    if (n >= KiB && n % KiB == 0) return std::to_string(n / KiB) + " KiB";
    return std::to_string(n) + " bytes";
}

// FAT copies are compared this far at most: 64 MiB of FAT32 entries is 16 Mi clusters, a
// 64 GiB volume at 4 KiB per cluster. Beyond that a probe would read for seconds.
constexpr ByteCount kFatCompareLimit = 64 * MiB;
constexpr ByteCount kFatChunk = 1 * MiB;
// An allocation bitmap this size (64 Mi clusters) is counted bit by bit at probe time.
constexpr ByteCount kExfatBitmapCountLimit = 8 * MiB;

// Byte offset of the first difference between [a, a+length) and [b, b+length), read in
// chunks; nullopt when equal. A read error ends the comparison (a truncated device has
// already been reported as such).
Expected<std::optional<ByteCount>> firstDifference(BlockDevice& dev, ByteCount a, ByteCount b, ByteCount length) {
    for (ByteCount done = 0; done < length; done += kFatChunk) {
        const ByteCount n = std::min(kFatChunk, length - done);
        auto x = dev.read(a + done, n);
        if (!x) return fail(x.error());
        auto y = dev.read(b + done, n);
        if (!y) return fail(y.error());
        const auto [ix, iy] = std::mismatch(x->begin(), x->end(), y->begin());
        if (ix != x->end()) return std::optional<ByteCount>(done + static_cast<ByteCount>(ix - x->begin()));
    }
    return std::optional<ByteCount>();
}

// Make [to, to+length) equal to [from, from+length), writing only the sectors that differ.
Expected<void> copyChangedSectors(BlockDevice& dev, ByteCount from, ByteCount to, ByteCount length, ByteCount sector) {
    for (ByteCount done = 0; done < length; done += kFatChunk) {
        const ByteCount n = std::min(kFatChunk, length - done);
        auto src = dev.read(from + done, n);
        if (!src) return fail(src.error());
        auto dst = dev.read(to + done, n);
        if (!dst) return fail(dst.error());
        for (ByteCount s = 0; s < n; s += sector) {
            const ByteCount len = std::min(sector, n - s);
            if (std::equal(src->begin() + s, src->begin() + s + len, dst->begin() + s)) continue;
            if (auto w = dev.writeAt(to + done + s, std::span<const std::byte>(*src).subspan(s, len)); !w) return w;
        }
    }
    return {};
}

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

// Bytes of FAT that entries 0..clusters+1 occupy.
ByteCount fatBytesNeeded(int bits, std::uint64_t clusters) {
    const std::uint64_t entries = clusters + 2;
    if (bits == 12) return (entries * 3 + 1) / 2;
    return entries * static_cast<std::uint64_t>(bits / 8);
}

// The partition's start LBA when `dev` is a slice of a larger device, looked through wrappers
// that only view their parent whole (extent {0, parent size}). Nothing for a whole device.
std::optional<std::uint64_t> partitionStartLba(const BlockDevice& dev) {
    const BlockDevice* d = &dev;
    std::shared_ptr<BlockDevice> keep;
    for (int hops = 0; hops < 8; ++hops) {
        const auto ext = d->extentsOnParent();
        auto parent = d->parent();
        if (ext.size() != 1 || !parent) return std::nullopt;
        if (ext.front().offset == 0 && ext.front().length == parent->size()) {
            keep = parent;
            d = keep.get();
            continue;
        }
        return ext.front().offset / dev.sectorSize();
    }
    return std::nullopt;
}

// The boot sector as one node spanning all 512 bytes: the common BPB, the extended BPB of the
// FAT type, then the boot code and the 0xAA55 signature directly under the sector (the shape
// exFAT's boot sector has). The FAT32 backup copy goes through the same function.
layout::Node describeFatBootSector(std::span<const std::byte> s, ByteCount base, bool fat32Layout, const char* title) {
    layout::Node sector;
    sector.name = title;
    sector.isStruct = true;
    sector.absOffset = base;
    sector.size = 512;
    auto bpb = gen::FatBpb(s).describe(base);
    bpb.name = "BPB";
    sector.addChild(std::move(bpb));
    layout::Node tail;
    if (fat32Layout) {
        auto e = gen::Fat32Ebpb(s.subspan(36, gen::Fat32Ebpb::kSize)).describe(base + 36);
        e.name = "FAT32 extended BPB";
        sector.addChild(std::move(e));
        tail = gen::Fat32BootTail(s.subspan(90, gen::Fat32BootTail::kSize)).describe(base + 90);
    } else {
        auto e = gen::Fat16Ebpb(s.subspan(36, gen::Fat16Ebpb::kSize)).describe(base + 36);
        e.name = "FAT12/16 extended BPB";
        sector.addChild(std::move(e));
        tail = gen::Fat16BootTail(s.subspan(62, gen::Fat16BootTail::kSize)).describe(base + 62);
    }
    for (auto& c : tail.children) sector.addChild(std::move(c));
    return sector;
}

// What repair() puts right on a FAT volume, all of it copies of metadata that exists elsewhere:
// the FAT32 backup boot sector and backup FSInfo sector are rewritten from the live ones, and
// with mirroring on every other FAT is rewritten from the active one. Only sectors that differ
// are written; directories and file data are never touched. Unlike exFAT's VolumeFlags and
// PercentInUse, no byte of a FAT boot sector may legitimately differ between the copies.
struct FatRepairPlan {
    ByteCount bps = 0;
    std::uint32_t reserved = 0, fats = 0, fatSectors = 0, activeFat = 0;
    bool mirroring = true;
    std::uint32_t backupSector = 0, fsinfoSector = 0;   // 0 = no copy to keep in sync
    ByteCount fatBytesInUse = 0;                        // entries 0..clusters+1, whole sectors
};

Expected<void> repairFat(BlockDevice& target, const FatRepairPlan& p) {
    if (p.backupSector) {
        if (auto r = copyChangedSectors(target, 0, ByteCount{p.backupSector} * p.bps, p.bps, p.bps); !r) return r;
        if (p.fsinfoSector)
            if (auto r = copyChangedSectors(target, ByteCount{p.fsinfoSector} * p.bps, ByteCount{p.backupSector + 1} * p.bps, p.bps, p.bps); !r) return r;
    }
    if (p.mirroring && p.fats >= 2) {
        const ByteCount active = (ByteCount{p.reserved} + ByteCount{p.activeFat} * p.fatSectors) * p.bps;
        for (std::uint32_t i = 0; i < p.fats; ++i) {
            if (i == p.activeFat) continue;
            const ByteCount other = (ByteCount{p.reserved} + ByteCount{i} * p.fatSectors) * p.bps;
            if (auto r = copyChangedSectors(target, active, other, p.fatBytesInUse, p.bps); !r) return r;
        }
    }
    return target.flush();
}

} // namespace

// FAT: a cluster is used when its entry in the active FAT is non-zero.
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

// exFAT: the allocation bitmap file, found through the root directory (entry type 0x81). On a
// TexFAT volume (two FATs) there are two bitmaps and volume_flags bit 0 says which pair is live.
class ExfatAllocation final : public AllocationSource {
public:
    ByteCount bps = 0, cluster = 0, fatOffset = 0, heapOffset = 0;
    std::uint32_t clusterCount = 0, rootCluster = 0;
    bool secondBitmap = false;

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
                    const bool second = (std::to_integer<std::uint8_t>((*dir)[e + 1]) & 0x01) != 0;
                    if (second != secondBitmap && bitmapFirst) continue;   // the other pair's bitmap
                    bitmapFirst = loadLe32(dir->data() + e + 20);
                    bitmapLen = loadLe64(dir->data() + e + 24);
                    if (second == secondBitmap) break;
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
    gen::Fat16Ebpb e16(s.subspan(36, gen::Fat16Ebpb::kSize));
    gen::Fat32Ebpb e32(s.subspan(36, gen::Fat32Ebpb::kSize));
    const std::uint32_t bps = bpb.bytesPerSector(), spc = bpb.sectorsPerCluster(), reserved = bpb.reservedSectors(),
                        fats = bpb.numFats();
    // sectors_per_fat16 == 0 marks the FAT32 layout; the type then follows from it, else from
    // the cluster count (fat_reader.hpp, shared with the reader).
    const bool fat32Layout = bpb.sectorsPerFat16() == 0;
    const std::uint32_t totalSectors = bpb.totalSectors16() ? bpb.totalSectors16() : bpb.totalSectors32();
    const std::uint32_t fatSectors = fat32Layout ? e32.sectorsPerFat32() : bpb.sectorsPerFat16();

    // Geometry the probe cannot proceed without. A boot sector that calls itself FAT (extended
    // boot signature or fs_type string) and still gets these wrong is a broken FAT volume and is
    // reported as one, with the sector described; anything else is simply not FAT.
    std::vector<std::string> fatal;
    if (!(bps == 512 || bps == 1024 || bps == 2048 || bps == 4096)) fatal.push_back("bytes_per_sector " + std::to_string(bps) + " is not 512, 1024, 2048 or 4096");
    if (!isPow2(spc) || spc > 128) fatal.push_back("sectors_per_cluster " + std::to_string(spc) + " is not a power of two up to 128");
    if (reserved == 0) fatal.push_back("reserved_sectors is 0");
    if (fats == 0) fatal.push_back("num_fats is 0");
    if (totalSectors == 0) fatal.push_back("total sectors is 0");
    if (fatSectors == 0) fatal.push_back("sectors per FAT is 0");
    const std::uint32_t rootDirSectors = bps ? (bpb.rootEntries() * 32u + bps - 1) / bps : 0;
    const std::uint64_t dataStart = ByteCount{reserved} + ByteCount{fats} * fatSectors + rootDirSectors;
    if (fatal.empty() && dataStart >= totalSectors)
        fatal.push_back("reserved area, FATs and root directory take " + std::to_string(dataStart) + " of " + std::to_string(totalSectors) + " sectors: no data area");
    const auto extended = [](std::uint8_t sig) { return sig == 0x29 || sig == 0x28; };
    const auto saysFat = [](const std::string& fsType) { return fsType.rfind("FAT", 0) == 0; };
    const bool callsItselfFat = fat32Layout ? (extended(e32.bootSignature()) || saysFat(e32.fsType()))
                                            : (extended(e16.bootSignature()) || saysFat(e16.fsType()));
    if (!fatal.empty() && !callsItselfFat) return notMine("BPB fields implausible");
    if (fats > 2 && !callsItselfFat) return notMine("more than two FATs");

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    if (!fatal.empty()) {
        // Enough to name the type and show the sector; there are no clusters to count and
        // nothing the reader could trust.
        info.type = fat32Layout ? FsType::Fat32 : e16.fsType() == "FAT12" ? FsType::Fat12 : FsType::Fat16;
        info.version = std::string(displayName(info.type));
        std::string why;
        for (const auto& f : fatal) why += (why.empty() ? "" : "; ") + f;
        fs->diag(Validity::Error, "fat.bpb_geometry", why);
        fs->setTreeName(info.version + " filesystem");
        fs->addNode(describeFatBootSector(s, 0, fat32Layout, "boot sector"));
        fs->addRegion(Region{0, 512});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }

    const std::uint64_t clusters = (totalSectors - dataStart) / spc;
    const int bits = fatBitsFor(fat32Layout, clusters);
    info.type = bits == 12 ? FsType::Fat12 : bits == 16 ? FsType::Fat16 : FsType::Fat32;
    info.version = std::string(displayName(info.type));
    const ByteCount clusterBytes = ByteCount{bps} * spc;
    info.blockSize = clusterBytes;
    info.totalBytes = ByteCount{totalSectors} * bps;

    // --- BPB sanity the per-field rules of the tree cannot express ---
    if (fat32Layout && clusters <= kFat16MaxClusters) fs->diag(Validity::Info, "fat.small_fat32", "FAT32 layout with fewer than 65525 clusters");
    if (!fat32Layout && clusters > kFat16MaxClusters)
        fs->diag(Validity::Error, "fat.bpb_geometry", "FAT16 cannot address " + std::to_string(clusters) + " clusters (at most 65524); read as FAT16 anyway");
    if (fat32Layout && clusters > kFat32MaxClusters)
        fs->diag(Validity::Error, "fat.bpb_geometry", "FAT32 cannot address " + std::to_string(clusters) + " clusters (at most " + std::to_string(kFat32MaxClusters) + ")");
    if (!fat32Layout && bpb.rootEntries() == 0) fs->diag(Validity::Error, "fat.bpb_geometry", "root_entries is 0 on a FAT12/16 volume: there is no root directory");
    else if (!fat32Layout && (bpb.rootEntries() * 32u) % bps != 0)
        fs->diag(Validity::Warning, "fat.root_entries_unaligned", "root_entries " + std::to_string(bpb.rootEntries()) + " * 32 bytes is not a multiple of the " + std::to_string(bps) + "-byte sector");
    if (fat32Layout && bpb.rootEntries() != 0) fs->diag(Validity::Warning, "fat.bpb_geometry", "root_entries must be 0 on FAT32 (is " + std::to_string(bpb.rootEntries()) + ")");
    if (fats > 2) fs->diag(Validity::Warning, "fat.bpb_geometry", "num_fats " + std::to_string(fats) + ": 1 or 2 expected");
    if (*info.totalBytes > dev->size())
        fs->diag(Validity::Warning, "fat.truncated", "BPB counts " + std::to_string(totalSectors) + " sectors (" + humanBytes(*info.totalBytes) + ") but the device holds " + humanBytes(dev->size()) + ": the volume is truncated");
    const ByteCount fatBytes = ByteCount{fatSectors} * bps;
    const ByteCount fatNeeded = fatBytesNeeded(bits, clusters);
    if (fatNeeded > fatBytes)
        fs->diag(Validity::Error, "fat.fat_too_small", "each FAT has " + std::to_string(fatBytes) + " bytes; " + std::to_string(fatNeeded) + " are needed for " + std::to_string(clusters) + " clusters");

    // --- which FAT is live (FAT32 ext_flags; always FAT 0 with mirroring) ---
    const std::uint16_t extFlags = fat32Layout ? e32.extFlags() : 0;
    const bool mirroring = !fat32Layout || fatMirroring(extFlags);
    const std::uint32_t activeFat = fat32Layout ? fatActiveIndex(extFlags, fats) : 0;
    if (!mirroring && (extFlags & 0x0F) >= fats)
        fs->diag(Validity::Error, "fat.active_fat_out_of_range", "ext_flags names FAT " + std::to_string(extFlags & 0x0F) + " as the active copy but the volume has " + std::to_string(fats) + "; FAT 0 is read");
    const ByteCount fatOffset = (ByteCount{reserved} + ByteCount{activeFat} * fatSectors) * bps;

    // --- FAT[0] and FAT[1] of the active FAT ---
    // FAT[0]'s low byte repeats the media byte; FAT[1] carries the clean-shutdown (set = clean)
    // and hard-error (set = no error) bits on FAT16/32. FAT12 has neither.
    std::optional<bool> fatClean, fatNoHardError;
    if (auto head = dev->read(fatOffset, 8)) {
        const auto media0 = std::to_integer<std::uint8_t>((*head)[0]);
        if (media0 != bpb.media())
            fs->diag(Validity::Warning, "fat.media_mismatch", "FAT[0] low byte " + toHex(media0, 2) + " does not repeat the BPB media byte " + toHex(bpb.media(), 2));
        if (bits == 16) {
            const std::uint16_t e1 = loadLe16(head->data() + 2);
            fatClean = (e1 & 0x8000) != 0;
            fatNoHardError = (e1 & 0x4000) != 0;
        } else if (bits == 32) {
            const std::uint32_t e1 = loadLe32(head->data() + 4) & 0x0FFFFFFFu;
            fatClean = (e1 & 0x08000000u) != 0;
            fatNoHardError = (e1 & 0x04000000u) != 0;
        }
    }

    // --- volume state: one answer from two flags ---
    // Two places record an unclean unmount: the extended BPB's reserved1 bit 0 (what Windows
    // NT onwards and Linux set at mount and clear at unmount) and FAT[1]'s clean-shutdown bit
    // (the DOS / Windows 9x convention, which Windows still maintains). Either one saying
    // "dirty" makes info.clean false and raises one fat.dirty naming the flag(s);
    // allocationMap() then refuses to trust the FAT.
    const std::uint8_t state = fat32Layout ? e32.reserved1() : e16.reserved1();
    std::string dirtyBy;
    if (state & 0x01) dirtyBy = "boot sector state flag";
    if (fatClean && !*fatClean) dirtyBy += std::string(dirtyBy.empty() ? "" : " and ") + "FAT[1] clean-shutdown bit";
    info.clean = dirtyBy.empty();
    if (!dirtyBy.empty()) fs->diag(Validity::Warning, "fat.dirty", "volume was not cleanly unmounted (" + dirtyBy + "); needs chkdsk / fsck.fat");
    if (fatNoHardError && !*fatNoHardError)
        fs->diag(Validity::Warning, "fat.hard_error", "FAT[1] hard-error bit: the driver met disk I/O errors the last time the volume was mounted");

    std::string bootLabel;
    std::uint32_t serial = 0;
    if (fat32Layout) {
        if (extended(e32.bootSignature())) {
            bootLabel = e32.volumeLabel();
            serial = e32.volumeId();
        }
    } else if (extended(e16.bootSignature())) {
        bootLabel = e16.volumeLabel();
        serial = e16.volumeId();
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
    if (fat32Layout) {
        const std::uint32_t root = e32.rootCluster();
        if (root >= 2 && root - 2 < clusters) {
            const ByteCount off = (dataStart + ByteCount{root - 2} * spc) * bps;
            if (auto dir = dev->read(off, clusterBytes)) takeLabel(*dir, off);
        }
    } else {
        const ByteCount off = (ByteCount{reserved} + ByteCount{fats} * fatSectors) * bps;
        const ByteCount len = std::min<ByteCount>(ByteCount{rootDirSectors} * bps, 64 * KiB);
        if (len && off + len <= dev->size())
            if (auto dir = dev->read(off, len)) takeLabel(*dir, off);
    }
    info.label = !dirLabel.empty() ? dirLabel : (bootLabel == "NO NAME" ? "" : bootLabel);
    if (serial) info.uuid = serialHex(serial);
    if (!bootLabel.empty() && bootLabel != "NO NAME") info.extra = "boot-sector label: " + bootLabel;

    fs->setTreeName(info.version + " filesystem");
    fs->addNode(describeFatBootSector(s, 0, fat32Layout, "boot sector"));
    fs->addRegion(Region{0, ByteCount{reserved} * bps});   // boot sector; on FAT32 also FSInfo and the backup copies
    FatRepairPlan plan;
    plan.bps = bps;
    plan.reserved = reserved;
    plan.fats = fats;
    plan.fatSectors = fatSectors;
    plan.activeFat = activeFat;
    plan.mirroring = mirroring;
    if (fat32Layout) {
        // FSInfo: Linux reads sector 1 when the BPB says 0, so do we.
        const std::uint32_t fsinfo = e32.fsinfoSector() ? e32.fsinfoSector() : 1;
        std::vector<std::byte> fsinfoSector;
        if (fsinfo >= reserved) {
            fs->diag(Validity::Warning, "fat.fsinfo_bad", "FSInfo sector " + std::to_string(fsinfo) + " lies outside the " + std::to_string(reserved) + " reserved sectors");
        } else if (auto fi = dev->read(ByteCount{fsinfo} * bps, bps)) {
            fsinfoSector = *fi;
            gen::Fat32Fsinfo f(*fi);
            auto n = f.describe(ByteCount{fsinfo} * bps);
            n.name = "FSInfo sector";
            fs->addNode(std::move(n));
            std::string bad;
            if (f.leadSignature() != 0x41615252u) bad = "lead";
            if (f.structSignature() != 0x61417272u) bad += std::string(bad.empty() ? "" : ", ") + "struct";
            if (f.trailSignature() != 0xAA550000u) bad += std::string(bad.empty() ? "" : ", ") + "trail";
            if (!bad.empty()) {
                fs->diag(Validity::Warning, "fat.fsinfo_bad", "FSInfo sector " + std::to_string(fsinfo) + ": " + bad + " signature wrong; its free-cluster hint is not trusted");
            } else {
                if (f.freeCount() != 0xFFFFFFFFu) {
                    if (f.freeCount() > clusters)
                        fs->diag(Validity::Warning, "fat.fsinfo_free_count", "FSInfo free_count " + std::to_string(f.freeCount()) + " exceeds the " + std::to_string(clusters) + " clusters of the volume");
                    else info.usedBytes = (clusters - f.freeCount()) * clusterBytes;
                }
                if (f.nextFree() != 0xFFFFFFFFu && (f.nextFree() < 2 || f.nextFree() >= clusters + 2))
                    fs->diag(Validity::Info, "fat.fsinfo_next_free", "FSInfo next_free " + std::to_string(f.nextFree()) + " is not a cluster number (2.." + std::to_string(clusters + 1) + ")");
            }
        }
        // The backup boot sector (usually 6) is what a repair tool restores from; show it and say
        // when it has drifted from the live one (a label edited in one sector only, for instance).
        // Its FSInfo copy follows it in the next sector.
        const std::uint32_t backup = e32.backupBootSector();
        if (backup && backup < reserved && backup != fsinfo) {
            auto live = dev->read(0, bps);
            if (auto bb = dev->read(ByteCount{backup} * bps, bps); bb && live) {
                fs->addNode(describeFatBootSector(*bb, ByteCount{backup} * bps, true, "backup boot sector"));
                if (!std::equal(bb->begin(), bb->end(), live->begin()))
                    fs->diag(Validity::Warning, "fat.backup_boot_mismatch", "backup boot sector (sector " + std::to_string(backup) + ") differs from the boot sector", true);
                plan.backupSector = backup;
            }
            if (!fsinfoSector.empty() && backup + 1 < reserved && backup + 1 != fsinfo) {
                if (auto bf = dev->read(ByteCount{backup + 1} * bps, bps)) {
                    auto n = gen::Fat32Fsinfo(*bf).describe(ByteCount{backup + 1} * bps);
                    n.name = "backup FSInfo sector";
                    fs->addNode(std::move(n));
                    if (!std::equal(bf->begin(), bf->end(), fsinfoSector.begin()))
                        fs->diag(Validity::Info, "fat.backup_fsinfo_mismatch", "backup FSInfo sector (sector " + std::to_string(backup + 1) + ") differs from the FSInfo sector", true);
                    plan.fsinfoSector = fsinfo;
                }
            }
        }
    }
    // The label the OS shows lives in the root directory, not in the boot sector.
    if (labelEntryOffset) {
        auto n = gen::FatDirEntry(labelEntry).describe(*labelEntryOffset);
        n.name = "root directory volume label entry";
        fs->addNode(std::move(n));
    }
    if (!dirLabel.empty() && !bootLabel.empty() && bootLabel != "NO NAME" && bootLabel != dirLabel)
        fs->diag(Validity::Info, "fat.label_mismatch", "boot-sector label \"" + bootLabel + "\" differs from the root directory label \"" + dirLabel + "\", which is the one the OS shows");

    // --- FAT copies ---
    // With mirroring on every FAT is a copy of the active one. Compared over the entries in use
    // (0..clusters+1) up to the 64 MiB limit; a FAT bigger than that is said to be only partly
    // compared. The repair rewrites the differing sectors of the other copies from the active one.
    const ByteCount fatInUse = std::min(fatBytes, alignUp(fatNeeded, bps));
    plan.fatBytesInUse = fatInUse;
    if (fats >= 2 && mirroring) {
        const ByteCount compared = std::min(fatInUse, kFatCompareLimit);
        for (std::uint32_t i = 0; i < fats; ++i) {
            if (i == activeFat) continue;
            const ByteCount other = (ByteCount{reserved} + ByteCount{i} * fatSectors) * bps;
            auto diff = firstDifference(*dev, fatOffset, other, compared);
            if (!diff) break;   // beyond the device: fat.truncated has said so
            if (*diff)
                fs->diag(Validity::Warning, "fat.fat_copies_differ", "FAT " + std::to_string(i) + " differs from FAT " + std::to_string(activeFat) + " (first difference at FAT byte " + std::to_string(**diff) + ")", true);
        }
        if (fatInUse > kFatCompareLimit)
            fs->diag(Validity::Info, "fat.fat_copies_not_compared", "FAT copies compared over their first 64 MiB only; each FAT holds " + humanBytes(fatInUse) + " of entries");
    }

    // --- where the volume sits ---
    // hidden_sectors is the partition's start LBA as the formatter saw it. Probing a slice of a
    // larger device, the two should agree; a moved or re-imaged volume shows up here.
    if (auto start = partitionStartLba(*dev); start && *start != bpb.hiddenSectors())
        fs->diag(Validity::Info, "fat.hidden_sectors_mismatch", "hidden_sectors is " + std::to_string(bpb.hiddenSectors()) + " but the volume starts at LBA " + std::to_string(*start) + " of its parent device");

    {
        auto alloc = std::make_unique<FatAllocation>();
        alloc->bps = bps;
        alloc->spc = spc;
        alloc->bits = static_cast<std::uint32_t>(bits);
        alloc->fatOffset = fatOffset;
        alloc->fatBytes = fatBytes;
        alloc->dataOffset = dataStart * bps;
        alloc->clusters = clusters;
        fs->setAllocationSource(std::move(alloc));
        fs->setReaderSource(makeFatReaderSource());
    }
    if (plan.backupSector || (fats >= 2 && mirroring)) fs->setRepair([plan](BlockDevice& target) { return repairFat(target, plan); });
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

// The root directory's volume-wide entries: allocation bitmap (its set bits counted for the
// exact used space), up-case table (its checksum verified over the stored table), volume label
// and volume GUID. First cluster only.
void describeExfatRootEntries(const Dev& dev, SimpleFileSystem& fs, const gen::ExfatBootSector& b, ByteCount bps, ByteCount cluster) {
    const std::uint32_t root = b.firstClusterOfRoot();
    const std::uint32_t clusters = b.clusterCount();
    if (root < 2 || root - 2 >= clusters) return;
    const ByteCount heap = ByteCount{b.clusterHeapOffset()} * bps;
    // TexFAT keeps two FAT/bitmap pairs; volume_flags bit 0 names the live one.
    const bool secondPair = b.numberOfFats() == 2 && (b.volumeFlags() & 0x1);
    const ByteCount fatOffset = (ByteCount{b.fatOffset()} + (secondPair ? ByteCount{b.fatLength()} : 0)) * bps;
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
        auto fat = dev->read(fatOffset + ByteCount{first} * 4, n * 4);
        if (!fat) return false;
        for (std::uint64_t i = 0; i < n; ++i) {
            const std::uint32_t e = loadLe32(fat->data() + i * 4);
            const bool last = i + 1 == n;
            if (e == 0 || (!last && e == first + i + 1) || (last && e == 0xFFFFFFFFu)) continue;
            return false;
        }
        return true;
    };
    // The bytes of a root-directory file, following its FAT chain (an unset entry means "next
    // cluster", as the formatters that skip FAT entries for these files intend).
    auto readChain = [&](std::uint32_t first, std::uint64_t length) -> std::optional<std::vector<std::byte>> {
        std::vector<std::byte> out;
        out.reserve(static_cast<std::size_t>(length));
        std::uint32_t c = first;
        while (out.size() < length) {
            if (c < 2 || c - 2 >= clusters) return std::nullopt;
            auto part = dev->read(heap + ByteCount{c - 2} * cluster, std::min<ByteCount>(cluster, length - out.size()));
            if (!part) return std::nullopt;
            out.insert(out.end(), part->begin(), part->end());
            auto e = dev->read(fatOffset + ByteCount{c} * 4, 4);
            if (!e) return std::nullopt;
            const std::uint32_t n = loadLe32(e->data());
            c = n == 0 ? c + 1 : n;
        }
        return out;
    };
    // Which bitmap entry is the live one: the one flagged for the live pair, or the only one
    // there (the allocation source falls back the same way).
    bool haveLiveBitmap = false;
    for (std::size_t e = 0; e + 32 <= dir->size(); e += 32) {
        const auto type = std::to_integer<std::uint8_t>((*dir)[e]);
        if (type == 0x00) break;
        if (type == 0x81 && ((std::to_integer<std::uint8_t>((*dir)[e + 1]) & 0x1) != 0) == secondPair) haveLiveBitmap = true;
    }
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
            // Used space: percent_in_use is a 1 % figure and is what detectExFat() filled in.
            // When the live bitmap is at most 8 MiB (64 Mi clusters) its set bits give the exact
            // count instead; bigger bitmaps keep the percentage so probing stays bounded.
            const bool live = !haveLiveBitmap || ((v.bitmapFlags() & 0x1) != 0) == secondPair;
            if (live && inHeap(v.firstCluster(), v.dataLength()) && v.dataLength() >= expected && v.dataLength() <= kExfatBitmapCountLimit) {
                if (auto bits = readChain(v.firstCluster(), expected)) {
                    std::uint64_t used = 0;
                    for (const auto byte : *bits) used += static_cast<std::uint64_t>(std::popcount(std::to_integer<unsigned>(byte)));
                    // Bits past cluster_count in the last byte are padding.
                    if (const unsigned tail = clusters % 8) used -= static_cast<std::uint64_t>(std::popcount(std::to_integer<unsigned>(bits->back()) >> tail));
                    fs.mutableInfo().usedBytes = used * cluster;
                }
            }
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
    // 1 % granularity; describeExfatRootEntries() replaces it with the bitmap's exact count.
    if (b.percentInUse() <= 100) info.usedBytes = *info.totalBytes * b.percentInUse() / 100;

    // --- geometry (§3.1): Error where the layout is impossible, Warning where it is merely
    // inconsistent with the volume length ---
    const std::uint64_t fatEnd = ByteCount{b.fatOffset()} + ByteCount{b.fatLength()} * b.numberOfFats();
    const std::uint64_t heapEnd = ByteCount{b.clusterHeapOffset()} + (ByteCount{b.clusterCount()} << spcShift);
    if (b.fatOffset() < 24)
        fs->diag(Validity::Error, "exfat.geometry", "fat_offset " + std::to_string(b.fatOffset()) + " lies inside the boot regions (sectors 0-23)");
    if (fatEnd > b.clusterHeapOffset())
        fs->diag(Validity::Error, "exfat.geometry", "the FAT" + std::string(b.numberOfFats() == 2 ? "s end" : " ends") + " at sector " + std::to_string(fatEnd) + ", past the cluster heap at " + std::to_string(b.clusterHeapOffset()));
    if (ByteCount{b.fatLength()} * bps < (ByteCount{b.clusterCount()} + 2) * 4)
        fs->diag(Validity::Error, "exfat.geometry", "fat_length " + std::to_string(b.fatLength()) + " sectors cannot hold entries for " + std::to_string(b.clusterCount()) + " clusters");
    if (b.clusterCount() > 0xFFFFFFF5u)
        fs->diag(Validity::Error, "exfat.geometry", "cluster_count " + std::to_string(b.clusterCount()) + " exceeds the 2^32 - 11 the FAT can address");
    if (heapEnd > b.volumeLength())
        fs->diag(Validity::Error, "exfat.geometry", "cluster heap ends at sector " + std::to_string(heapEnd) + ", beyond volume_length " + std::to_string(b.volumeLength()));
    else if (b.volumeLength() - heapEnd >= (ByteCount{1} << spcShift))
        fs->diag(Validity::Warning, "exfat.geometry", "cluster_count " + std::to_string(b.clusterCount()) + " leaves " + std::to_string(b.volumeLength() - heapEnd) + " sectors of the volume outside the heap");
    if (*info.totalBytes > dev->size())
        fs->diag(Validity::Warning, "exfat.truncated", "volume_length counts " + std::to_string(b.volumeLength()) + " sectors (" + humanBytes(*info.totalBytes) + ") but the device holds " + humanBytes(dev->size()) + ": the volume is truncated");
    if (b.firstClusterOfRoot() < 2 || b.firstClusterOfRoot() - 2 >= b.clusterCount())
        fs->diag(Validity::Error, "exfat.geometry", "first_cluster_of_root " + std::to_string(b.firstClusterOfRoot()) + " is outside the cluster heap (2.." + std::to_string(ByteCount{b.clusterCount()} + 1) + ")");
    // TexFAT: two FATs, the live one named by volume_flags bit 0. They are compared over the
    // entries in use, 64 MiB at most; nothing repairs them, as the two may legitimately be
    // mid-transaction on such a volume.
    const bool secondPair = b.numberOfFats() == 2 && (b.volumeFlags() & 0x1);
    if (b.numberOfFats() == 2) {
        const ByteCount inUse = std::min<ByteCount>(ByteCount{b.fatLength()} * bps, alignUp((ByteCount{b.clusterCount()} + 2) * 4, bps));
        const ByteCount first = ByteCount{b.fatOffset()} * bps, second = first + ByteCount{b.fatLength()} * bps;
        if (auto diff = firstDifference(*dev, first, second, std::min(inUse, kFatCompareLimit)); diff && *diff)
            fs->diag(Validity::Warning, "exfat.fat_copies_differ", "the second FAT differs from the first (first difference at FAT byte " + std::to_string(**diff) + ")");
        if (inUse > kFatCompareLimit)
            fs->diag(Validity::Info, "exfat.fat_copies_not_compared", "FAT copies compared over their first 64 MiB only; each FAT holds " + humanBytes(inUse) + " of entries");
    }

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
        alloc->fatOffset = (ByteCount{b.fatOffset()} + (secondPair ? ByteCount{b.fatLength()} : 0)) * bps;
        alloc->heapOffset = ByteCount{b.clusterHeapOffset()} * bps;
        alloc->clusterCount = b.clusterCount();
        alloc->rootCluster = root;
        alloc->secondBitmap = secondPair;
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
