// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/ntfs.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

namespace {

// Apply the update sequence array ("fixups") to a FILE record in place.
bool applyFixups(std::vector<std::byte>& rec, std::uint32_t sectorSize) {
    gen::NtfsMftRecordHeader h(rec);
    const std::uint16_t usaOff = h.usaOffset(), usaCount = h.usaCount();
    if (usaCount < 2 || usaOff + usaCount * 2u > rec.size()) return false;
    const std::uint16_t usn = loadLe16(rec.data() + usaOff);
    for (std::uint16_t i = 1; i < usaCount; ++i) {
        const std::size_t pos = static_cast<std::size_t>(i) * sectorSize - 2;
        if (pos + 2 > rec.size()) return false;
        if (loadLe16(rec.data() + pos) != usn) return false;   // torn record
        rec[pos] = rec[usaOff + i * 2];
        rec[pos + 1] = rec[usaOff + i * 2 + 1];
    }
    return true;
}

} // namespace

Result detectNtfs(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 512);
    if (!raw) return fail(raw.error());
    std::span<const std::byte> s(*raw);
    gen::NtfsBootSector b(s);
    if (b.oemId() != "NTFS") return notMine("no NTFS oem id");
    const std::uint32_t bps = b.bytesPerSector();
    if (!(bps == 512 || bps == 1024 || bps == 2048 || bps == 4096)) return notMine("bad sector size");
    const std::uint8_t spcRaw = b.sectorsPerCluster();
    const ByteCount spc = spcRaw > 0x80 ? (ByteCount{1} << (256 - spcRaw)) : spcRaw;
    if (spc == 0) return notMine("bad cluster size");
    const ByteCount cluster = bps * spc;
    const std::int8_t cpmr = b.clustersPerMftRecord();
    const ByteCount recSize = cpmr < 0 ? (ByteCount{1} << static_cast<unsigned>(-cpmr)) : ByteCount{static_cast<std::uint8_t>(cpmr)} * cluster;
    if (recSize < 256 || recSize > 64 * KiB) return notMine("bad MFT record size");

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Ntfs;
    info.uuid = hex64(b.volumeSerialNumber());
    info.blockSize = cluster;
    info.totalBytes = b.numberOfSectors() * bps;   // the backup boot sector sits one sector past this
    fs->setTreeName("NTFS filesystem");
    auto tree = b.describe(0);
    tree.name = "boot sector";
    fs->addNode(std::move(tree));
    fs->addRegion(Region{0, bps});
    const ByteCount backupBoot = b.numberOfSectors() * bps;
    if (backupBoot + bps <= dev->size()) fs->addRegion(Region{backupBoot, bps});
    const ByteCount mftOff = b.mftLcn() * cluster, mirrOff = b.mftmirrLcn() * cluster;
    if (mftOff + 16 * recSize <= dev->size()) fs->addRegion(Region{mftOff, 16 * recSize});
    if (mirrOff + 4 * recSize <= dev->size()) fs->addRegion(Region{mirrOff, 4 * recSize});

    // $Volume is MFT record 3: $VOLUME_NAME (0x60) and $VOLUME_INFORMATION (0x70).
    const ByteCount volOff = mftOff + 3 * recSize;
    if (volOff + recSize <= dev->size()) {
        auto rec = dev->read(volOff, recSize);
        if (rec && rec->size() >= 48 && std::string(reinterpret_cast<const char*>(rec->data()), 4) == "FILE") {
            if (!applyFixups(*rec, bps)) fs->diag(Validity::Warning, "ntfs.volume_fixup", "$Volume record has a torn update sequence");
            gen::NtfsMftRecordHeader h(*rec);
            auto recTree = h.describe(volOff);
            recTree.name = "$Volume MFT record";
            std::size_t pos = h.attrsOffset();
            while (pos + gen::NtfsAttrHeader::kSize <= rec->size()) {
                gen::NtfsAttrHeader a(std::span<const std::byte>(*rec).subspan(pos, gen::NtfsAttrHeader::kSize));
                if (a.type() == 0xFFFFFFFFu || a.length() < 16 || pos + a.length() > rec->size()) break;
                if (a.nonResident() == 0 && pos + 24 <= rec->size()) {
                    gen::NtfsAttrResident r(std::span<const std::byte>(*rec).subspan(pos + 16, 8));
                    const std::size_t vOff = pos + r.valueOffset(), vLen = r.valueLength();
                    if (vOff + vLen <= rec->size()) {
                        auto value = std::span<const std::byte>(*rec).subspan(vOff, vLen);
                        if (a.type() == 0x60) {
                            info.label = utf16leToUtf8(value, false);
                            auto n = a.describe(volOff + pos);
                            n.name = "$VOLUME_NAME attribute";
                            n.pretty = info.label;
                            recTree.addChild(std::move(n));
                        } else if (a.type() == 0x70 && vLen >= gen::NtfsVolumeInformation::kSize) {
                            gen::NtfsVolumeInformation vi(value);
                            info.version = std::to_string(vi.majorVersion()) + "." + std::to_string(vi.minorVersion());
                            info.clean = !(vi.flags() & 0x1);
                            if (vi.flags() & 0x1) fs->diag(Validity::Warning, "ntfs.dirty", "volume is marked dirty");
                            if (vi.flags() & 0x4000) fs->diag(Validity::Info, "ntfs.chkdsk_underway", "chkdsk was running");
                            auto n = vi.describe(volOff + vOff);
                            n.name = "$VOLUME_INFORMATION attribute";
                            recTree.addChild(std::move(n));
                        }
                    }
                }
                pos += a.length();
            }
            fs->addNode(std::move(recTree));
        } else {
            fs->diag(Validity::Warning, "ntfs.volume_record", "cannot read the $Volume MFT record");
        }
    }
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectReFs(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 512);
    if (!raw) return fail(raw.error());
    std::span<const std::byte> s(*raw);
    if (std::string(reinterpret_cast<const char*>(s.data() + 3), 4) != "ReFS") return notMine("no ReFS id");
    if (std::string(reinterpret_cast<const char*>(s.data() + 0x18), 4) != "FSRS") return notMine("no FSRS");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::ReFs;
    info.version = std::to_string(std::to_integer<unsigned>(s[0x1C])) + "." + std::to_string(std::to_integer<unsigned>(s[0x1D]));
    const std::uint32_t bps = loadLe32(s.data() + 0x20);
    const std::uint32_t cluster = loadLe32(s.data() + 0x24);
    if (bps) info.blockSize = ByteCount{bps} * (cluster ? cluster : 1);
    info.totalBytes = loadLe64(s.data() + 0x28) * (bps ? bps : 512);
    fs->setTreeName("ReFS volume (detection only)");
    fs->addRegion(Region{0, 512});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
