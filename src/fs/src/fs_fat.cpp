// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/exfat.hpp"
#include "stein/layout/gen/fat.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

namespace {

bool isPow2(std::uint32_t v) { return v && (v & (v - 1)) == 0; }

// Scan a directory region for the volume label entry (attribute 0x08, not deleted, not LFN).
std::string fatDirLabel(std::span<const std::byte> dir) {
    for (std::size_t off = 0; off + 32 <= dir.size(); off += 32) {
        const auto first = std::to_integer<std::uint8_t>(dir[off]);
        if (first == 0x00) break;        // end of directory
        if (first == 0xE5) continue;     // deleted
        const auto attr = std::to_integer<std::uint8_t>(dir[off + 11]);
        if (attr == 0x0F) continue;      // long-name fragment
        if (attr & 0x08) return asciiField(dir.subspan(off, 11));
    }
    return {};
}

} // namespace

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
    if (isFat32) {
        const std::uint32_t root = e32.rootCluster();
        if (root >= 2 && root - 2 < clusters) {
            const ByteCount off = (dataStart + ByteCount{root - 2} * spc) * bps;
            if (auto dir = dev->read(off, ByteCount{spc} * bps)) dirLabel = fatDirLabel(*dir);
        }
    } else {
        const ByteCount off = (ByteCount{reserved} + ByteCount{fats} * fatSectors) * bps;
        const ByteCount len = std::min<ByteCount>(ByteCount{rootDirSectors} * bps, 64 * KiB);
        if (len && off + len <= dev->size())
            if (auto dir = dev->read(off, len)) dirLabel = fatDirLabel(*dir);
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
    } else {
        auto t = e16.describe(36);
        t.name = "FAT12/16 extended BPB";
        fs->addNode(std::move(t));
        fs->addRegion(Region{0, ByteCount{reserved} * bps});
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
