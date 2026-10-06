// SPDX-License-Identifier: MIT
// Content markers for containers and volume managers: LUKS, LVM2 PV, md RAID member,
// BitLocker; plus ZFS and UFS detection.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/luks.hpp"
#include "stein/layout/gen/lvm.hpp"
#include "stein/layout/gen/md.hpp"

#include <algorithm>
#include <array>

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

Result detectLuks(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 4096);
    if (!raw) return fail(raw.error());
    static constexpr std::uint8_t kMagic[6] = {'L', 'U', 'K', 'S', 0xBA, 0xBE};
    for (int i = 0; i < 6; ++i)
        if (std::to_integer<std::uint8_t>((*raw)[i]) != kMagic[i]) return notMine("no LUKS magic");
    const std::uint16_t version = loadBe16(raw->data() + 6);
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.usage = Usage::Crypto;
    if (version == 1) {
        gen::Luks1Phdr h(*raw);
        info.type = FsType::Luks1;
        info.version = "1";
        info.uuid = h.uuid();
        info.extra = h.cipherName() + "-" + h.cipherMode() + ", " + h.hashSpec() + ", " + std::to_string(h.keyBytes() * 8) + "-bit key";
        info.blockSize = 512;
        info.totalBytes = dev->size();
        int active = 0;
        for (int i = 0; i < 8; ++i) {
            gen::Luks1Keyslot ks(std::span<const std::byte>(*raw).subspan(0xD0 + i * 48, 48));
            if (ks.active() == 0x00AC71F3u) ++active;
        }
        info.features.push_back(std::to_string(active) + " active keyslot(s)");
        fs->setTreeName("LUKS1 encrypted volume");
        auto t = h.describe(0);
        for (int i = 0; i < 8; ++i) {
            gen::Luks1Keyslot ks(std::span<const std::byte>(*raw).subspan(0xD0 + i * 48, 48));
            auto n = ks.describe(0xD0 + static_cast<std::uint64_t>(i) * 48);
            n.name = "keyslot " + std::to_string(i);
            t.addChild(std::move(n));
        }
        fs->addNode(std::move(t));
        fs->addRegion(Region{0, std::min<ByteCount>(ByteCount{h.payloadOffset()} * 512, dev->size())});
    } else if (version == 2) {
        gen::Luks2Hdr h(*raw);
        info.type = FsType::Luks2;
        info.version = "2";
        info.uuid = h.uuid();
        info.label = h.label();
        info.extra = "header " + formatSize(h.hdrSize()) + ", seqid " + std::to_string(h.seqid()) + (h.subsystem().empty() ? "" : ", subsystem " + h.subsystem());
        info.blockSize = 512;
        info.totalBytes = dev->size();
        fs->setTreeName("LUKS2 encrypted volume");
        auto t = h.describe(0);
        t.name = "primary binary header";
        fs->addNode(std::move(t));
        const ByteCount hdrSize = h.hdrSize();
        if (hdrSize >= 16 * KiB && hdrSize <= 4 * MiB) {
            auto sec = readOrNotFound(*dev, hdrSize, 4096);
            if (sec) {
                gen::Luks2Hdr h2(*sec);
                auto t2 = h2.describe(hdrSize);
                t2.name = "secondary binary header";
                const std::string m2(reinterpret_cast<const char*>(sec->data()), 4);
                if (m2 != "SKUL") t2.flag(Validity::Error, "secondary header magic is not SKUL");
                else if (h2.seqid() != h.seqid()) t2.flag(Validity::Info, "seqid differs from the primary (" + std::to_string(h2.seqid()) + ")");
                fs->addNode(std::move(t2));
            }
            fs->addRegion(Region{0, std::min<ByteCount>(2 * hdrSize, dev->size())});
        } else {
            fs->diag(Validity::Error, "luks2.hdr_size", "implausible hdr_size " + std::to_string(hdrSize));
            fs->addRegion(Region{0, 4096});
        }
    } else {
        return notMine("unknown LUKS version");
    }
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectLvm(Dev dev) {
    for (ByteCount sector = 0; sector < 4; ++sector) {
        auto raw = readOrNotFound(*dev, sector * 512, 512);
        if (!raw) return fail(raw.error());
        gen::LvmLabelHeader lh(*raw);
        if (lh.id() != "LABELONE") continue;
        if (lh.type() != "LVM2 001") continue;
        if (lh.sector() != sector) continue;
        const std::uint32_t pvOff = lh.offset();
        if (pvOff + gen::LvmPvHeader::kSize > 512) continue;
        gen::LvmPvHeader pv(std::span<const std::byte>(*raw).subspan(pvOff, gen::LvmPvHeader::kSize));
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::Lvm2Pv;
        info.usage = Usage::Raid;
        info.version = "LVM2 001";
        info.uuid = hyphenateLvmUuid(pv.pvUuid());
        info.totalBytes = pv.deviceSize();
        info.blockSize = 512;
        fs->setTreeName("LVM2 physical volume");
        auto t = lh.describe(sector * 512);
        t.name = "label header";
        fs->addNode(std::move(t));
        auto tp = pv.describe(sector * 512 + pvOff);
        tp.name = "PV header";
        fs->addNode(std::move(tp));
        fs->addRegion(Region{0, 4 * 512});
        // Two zero-terminated lists of disk_locn follow: data areas, then metadata areas.
        std::size_t pos = pvOff + gen::LvmPvHeader::kSize;
        for (int list = 0; list < 2; ++list) {
            while (pos + 16 <= 512) {
                gen::LvmDiskLocn locn(std::span<const std::byte>(*raw).subspan(pos, 16));
                pos += 16;
                if (locn.offset() == 0 && locn.size() == 0) break;
                if (list == 1) {
                    const ByteCount len = locn.size() ? locn.size() : (dev->size() > locn.offset() ? dev->size() - locn.offset() : 0);
                    if (len && locn.offset() + len <= dev->size()) {
                        fs->addRegion(Region{locn.offset(), len});
                        if (auto mda = dev->read(locn.offset(), 512)) {
                            gen::LvmMdaHeader mh(*mda);
                            auto n = mh.describe(locn.offset());
                            n.name = "metadata area header";
                            fs->addNode(std::move(n));
                            // The first raw_locn tells where the live text metadata is.
                            gen::LvmRawLocn rl(std::span<const std::byte>(*mda).subspan(gen::LvmMdaHeader::kSize, 24));
                            if (rl.size() && rl.size() < 1 * MiB && locn.offset() + rl.offset() + rl.size() <= dev->size()) {
                                if (auto text = dev->read(locn.offset() + rl.offset(), std::min<ByteCount>(rl.size(), 4096))) {
                                    std::string s(reinterpret_cast<const char*>(text->data()), text->size());
                                    // VG name is the first token before " {".
                                    const auto brace = s.find(" {");
                                    if (brace != std::string::npos && brace < 128) info.label = std::string(trim(s.substr(0, brace)));
                                }
                            }
                        }
                    }
                } else if (list == 0 && locn.size() == 0) {
                    info.extra = "data area at " + formatSize(locn.offset());
                }
            }
        }
        if (!info.label.empty()) info.extra = "volume group " + info.label + (info.extra.empty() ? "" : "; " + info.extra);
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no LVM label");
}

Result detectMd(Dev dev) {
    const ByteCount size = dev->size();
    struct Candidate {
        ByteCount offset;
        const char* version;
    };
    std::vector<Candidate> candidates = {{4096, "1.2"}, {0, "1.1"}};
    if (size >= 16 * KiB) candidates.push_back({((size & ~ByteCount{4095}) - 8 * KiB), "1.0"});
    for (const auto& c : candidates) {
        auto raw = readOrNotFound(*dev, c.offset, 256 + 2);
        if (!raw) continue;
        gen::MdSuperblock1 sb(*raw);
        if (sb.magic() != 0xA92B4EFCu || sb.majorVersion() != 1) continue;
        if (sb.superOffset() != c.offset / 512) continue;
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::MdRaidMember;
        info.usage = Usage::Raid;
        info.version = c.version;
        info.label = sb.setName();
        info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::MdSuperblock1::kSetUuidOffset, 16));
        info.blockSize = 512;
        info.totalBytes = sb.dataSize() * 512;
        auto t = sb.describe(c.offset);
        if (auto* lvl = t.child("level")) info.extra = lvl->pretty + ", " + std::to_string(sb.raidDisks()) + " device(s), data at sector " + std::to_string(sb.dataOffset());
        fs->setTreeName("Linux RAID member (md " + info.version + ")");
        fs->addNode(std::move(t));
        fs->addRegion(Region{c.offset, 4096});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    // Version 0.90: superblock 64 KiB from the end, 64 KiB aligned.
    if (size >= 128 * KiB) {
        const ByteCount off = (size & ~ByteCount{65535}) - 65536;
        auto raw = readOrNotFound(*dev, off, 256);
        if (raw && loadLe32(raw->data()) == 0xA92B4EFCu && loadLe32(raw->data() + 4) == 0) {
            auto fs = std::make_unique<SimpleFileSystem>(dev);
            auto& info = fs->mutableInfo();
            info.type = FsType::MdRaidMember;
            info.usage = Usage::Raid;
            info.version = "0.90";
            // set_uuid0 @0x14, set_uuid1..3 @0x34..0x3C
            std::array<std::byte, 16> u{};
            std::copy_n(raw->begin() + 0x14, 4, u.begin());
            std::copy_n(raw->begin() + 0x34, 12, u.begin() + 4);
            info.uuid = uuidText(u);
            fs->setTreeName("Linux RAID member (md 0.90)");
            fs->addRegion(Region{off, 4096});
            return std::unique_ptr<FileSystem>(std::move(fs));
        }
    }
    return notMine("no md superblock");
}

Result detectBitLocker(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, 512);
    if (!raw) return fail(raw.error());
    const std::string id(reinterpret_cast<const char*>(raw->data()) + 3, 8);
    std::string version;
    if (id == "-FVE-FS-") version = "Vista+/Windows 7+";
    else if (id == "MSWIN4.1" && std::string(reinterpret_cast<const char*>(raw->data()) + 0x1F8, 8) == "-FVE-FS-") version = "Windows 7+ (FAT-styled)";
    else if (id == "NTFS    " && std::string(reinterpret_cast<const char*>(raw->data()) + 0x1F8, 8) == "-FVE-FS-") version = "Windows To Go";
    else return notMine("no BitLocker signature");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::BitLocker;
    info.usage = Usage::Crypto;
    info.version = version;
    info.totalBytes = dev->size();
    fs->setTreeName("BitLocker encrypted volume");
    fs->addRegion(Region{0, 512});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectZfs(Dev dev) {
    // Four vdev labels: two at the front (0, 256 KiB), two at the end. Each has 128 uberblocks from +128 KiB.
    const ByteCount size = dev->size();
    std::vector<ByteCount> labels = {0, 256 * KiB};
    if (size >= 1 * MiB) {
        labels.push_back(size - 512 * KiB);
        labels.push_back(size - 256 * KiB);
    }
    for (ByteCount label : labels) {
        if (label + 256 * KiB > size) continue;
        int found = 0;
        for (int i = 0; i < 128 && found < 4; ++i) {
            auto ub = dev->read(label + 128 * KiB + ByteCount{static_cast<std::uint64_t>(i)} * 1024, 8);
            if (!ub) break;
            const std::uint64_t le = loadLe64(ub->data()), be = loadBe64(ub->data());
            if (le == 0x00bab10cull || be == 0x00bab10cull) ++found;
        }
        if (found < 4) continue;
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::Zfs;
        info.usage = Usage::Raid;
        // XDR nvlist at label + 16 KiB: pool name and guid.
        if (auto nv = dev->read(label + 16 * KiB, 112 * KiB)) {
            const std::byte* p = nv->data();
            const std::byte* end = p + nv->size();
            auto rd32 = [&](const std::byte*& q) { std::uint32_t v = loadBe32(q); q += 4; return v; };
            if (end - p > 16) {
                p += 4;          // encoding + endian + reserved
                p += 8;          // nvl_version, nvflag
                while (end - p >= 16) {
                    const std::uint32_t encSize = rd32(p);
                    rd32(p);   // decoded size
                    if (encSize == 0) break;
                    const std::byte* pairEnd = p - 8 + encSize;
                    if (pairEnd > end) break;
                    const std::uint32_t nameLen = rd32(p);
                    if (nameLen > 256 || p + nameLen > end) break;
                    const std::string name(reinterpret_cast<const char*>(p), nameLen);
                    p += (nameLen + 3) & ~3u;
                    const std::uint32_t type = rd32(p);
                    rd32(p);   // nelem
                    if (type == 9 && name == "name") {            // string
                        const std::uint32_t len = rd32(p);
                        if (len < 256 && p + len <= end) info.label = std::string(reinterpret_cast<const char*>(p), len);
                    } else if (type == 8 && (name == "pool_guid" || name == "guid")) {   // uint64
                        if (p + 8 <= end) {
                            const std::uint64_t v = loadBe64(p);
                            if (name == "pool_guid") info.uuid = std::to_string(v);
                            else info.extra = "vdev guid " + std::to_string(v);
                        }
                    } else if (type == 8 && name == "version" && p + 8 <= end) {
                        info.version = std::to_string(loadBe64(p));
                    }
                    p = pairEnd;
                }
            }
        }
        fs->setTreeName("ZFS pool member");
        fs->addRegion(Region{label, 256 * KiB});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no ZFS uberblocks");
}

Result detectUfs(Dev dev) {
    for (ByteCount off : {ByteCount{65536}, ByteCount{8192}, ByteCount{262144}, ByteCount{0}}) {
        auto raw = readOrNotFound(*dev, off + 0x55C, 4);
        if (!raw) continue;
        const std::uint32_t le = loadLe32(raw->data()), be = loadBe32(raw->data());
        const char* version = nullptr;
        if (le == 0x00011954u || be == 0x00011954u) version = "1";
        else if (le == 0x19540119u || be == 0x19540119u) version = "2";
        if (!version) continue;
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::Ufs;
        info.version = version;
        info.extra = (le == 0x00011954u || le == 0x19540119u) ? "little-endian" : "big-endian";
        if (std::string(version) == "2") {
            if (auto name = dev->read(off + 0x2C0, 32)) info.label = asciiField(*name);   // fs_volname
        }
        fs->setTreeName("UFS filesystem (detection only)");
        fs->addRegion(Region{off, 1376});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no UFS magic");
}

} // namespace stein::fs::detail
