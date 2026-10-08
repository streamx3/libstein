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
    auto tree = b.describe(0);
    tree.name = "main boot sector";
    fs->addNode(std::move(tree));
    fs->addRegion(Region{0, 12 * bps});                 // main boot region
    fs->addRegion(Region{12 * bps, 12 * bps});          // backup boot region
    fs->addRegion(Region{ByteCount{b.fatOffset()} * bps, ByteCount{b.fatLength()} * bps * b.numberOfFats()});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
