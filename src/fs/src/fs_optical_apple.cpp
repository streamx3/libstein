// SPDX-License-Identifier: MIT
// ISO 9660 (+Joliet), UDF, APFS container.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/iso9660.hpp"
#include "stein/layout/gen/misc_fs.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

namespace {
std::string utf16beToUtf8(std::span<const std::byte> in) {
    std::vector<std::byte> le(in.size());
    for (std::size_t i = 0; i + 1 < in.size(); i += 2) {
        le[i] = in[i + 1];
        le[i + 1] = in[i];
    }
    return utf16leToUtf8(le, true);
}
} // namespace

Result detectIso9660(Dev dev) {
    constexpr ByteCount kPvd = 32768;
    auto raw = readOrNotFound(*dev, kPvd, 2048);
    if (!raw) return fail(raw.error());
    gen::IsoPrimaryVolumeDescriptor pvd(*raw);
    if (pvd.standardId() != "CD001" || pvd.type() != 1) return notMine("no CD001 PVD");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Iso9660;
    info.label = std::string(trim(pvd.volumeId()));
    info.blockSize = pvd.logicalBlockSize() ? pvd.logicalBlockSize() : 2048;
    info.totalBytes = ByteCount{pvd.volumeSpaceSize()} * *info.blockSize;
    // UUID as blkid prints it: creation date YYYY-MM-DD-HH-MM-SS-cc.
    const std::string d = pvd.creationDate();
    if (d.size() >= 16 && d.substr(0, 16) != "0000000000000000")
        info.uuid = d.substr(0, 4) + "-" + d.substr(4, 2) + "-" + d.substr(6, 2) + "-" + d.substr(8, 2) + "-" + d.substr(10, 2) + "-" +
                    d.substr(12, 2) + "-" + d.substr(14, 2);
    fs->setTreeName("ISO 9660 filesystem");
    auto t = pvd.describe(kPvd);
    t.name = "primary volume descriptor";
    fs->addNode(std::move(t));
    ByteCount end = kPvd + 2048;
    // Walk the descriptor set for a Joliet SVD and the terminator.
    for (int i = 1; i < 16; ++i) {
        const ByteCount off = kPvd + ByteCount{static_cast<std::uint64_t>(i)} * 2048;
        auto d2 = readOrNotFound(*dev, off, 2048);
        if (!d2) break;
        gen::IsoPrimaryVolumeDescriptor vd(*d2);
        if (vd.standardId() != "CD001") break;
        end = off + 2048;
        if (vd.type() == 255) break;
        if (vd.type() == 2) {
            auto esc = vd.escapeSequences();
            if (esc.size() >= 3 && esc[0] == std::byte{0x25} && esc[1] == std::byte{0x2F}) {
                info.version = "Joliet Extension";
                std::string jl = std::string(trim(utf16beToUtf8(std::span<const std::byte>(*d2).subspan(0x28, 32))));
                if (!jl.empty() && info.label.size() <= jl.size()) info.label = jl;
                auto n = vd.describe(off);
                n.name = "Joliet supplementary volume descriptor";
                fs->addNode(std::move(n));
            }
        }
    }
    fs->addRegion(Region{kPvd, end - kPvd});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectUdf(Dev dev) {
    // Volume recognition sequence at 32 KiB: BEA01 ... NSR02/NSR03 ... TEA01, 2 KiB apart.
    bool nsr = false;
    for (int i = 0; i < 16 && !nsr; ++i) {
        auto d = readOrNotFound(*dev, 32768 + ByteCount{static_cast<std::uint64_t>(i)} * 2048, 7);
        if (!d) return notMine("too small for UDF");
        const std::string id(reinterpret_cast<const char*>(d->data()) + 1, 5);
        if (i == 0 && id != "BEA01") return notMine("no BEA01");
        if (id == "NSR02" || id == "NSR03") nsr = true;
        if (id == "TEA01") break;
    }
    if (!nsr) return notMine("no NSR descriptor");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Udf;
    fs->setTreeName("UDF filesystem");
    fs->addRegion(Region{32768, 6 * 2048});
    // Anchor at sector 256 for the common block sizes; then the main volume descriptor sequence.
    for (ByteCount bs : {ByteCount{2048}, ByteCount{512}, ByteCount{1024}, ByteCount{4096}}) {
        auto a = readOrNotFound(*dev, 256 * bs, gen::UdfAnchorDescriptor::kSize);
        if (!a) continue;
        gen::UdfAnchorDescriptor avdp(*a);
        if (avdp.tagId() != 2 || avdp.tagLocation() != 256) continue;
        info.blockSize = bs;
        fs->addNode(avdp.describe(256 * bs));
        fs->addRegion(Region{256 * bs, bs});
        const ByteCount vds = ByteCount{avdp.mainVdsLocation()} * bs;
        const std::uint32_t count = std::min<std::uint32_t>(avdp.mainVdsLength() / static_cast<std::uint32_t>(bs), 32);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto d = readOrNotFound(*dev, vds + ByteCount{i} * bs, bs);
            if (!d) break;
            const std::uint16_t tag = loadLe16(d->data());
            if (tag == 1) {   // Primary Volume Descriptor: volume identifier dstring @24 (32), volume set id @72 (128)
                auto dstring = [&](std::size_t off, std::size_t len) -> std::string {
                    auto f = std::span<const std::byte>(*d).subspan(off, len);
                    const auto n = std::min<std::size_t>(std::to_integer<std::uint8_t>(f[len - 1]), len - 1);
                    if (n == 0) return {};
                    const auto comp = std::to_integer<std::uint8_t>(f[0]);
                    if (comp == 8) return asciiField(f.subspan(1, n - 1));
                    if (comp == 16) return utf16beToUtf8(f.subspan(1, n - 1));
                    return {};
                };
                info.label = dstring(24, 32);
                const std::string set = dstring(72, 128);
                if (set.size() >= 16) info.uuid = toLower(set.substr(0, 16));
                else if (!set.empty()) info.uuid = set;
            } else if (tag == 6) {   // Logical Volume Descriptor: domain identifier @84 (32 bytes regid), suffix holds UDF revision
                auto regid = std::span<const std::byte>(*d).subspan(84, 32);
                if (asciiField(regid.subspan(1, 23)).starts_with("*OSTA UDF Compliant")) {
                    const std::uint16_t rev = loadLe16(regid.data() + 24);
                    char buf[16];
                    std::snprintf(buf, sizeof buf, "%x.%02x", rev >> 8, rev & 0xFF);
                    info.version = buf;
                }
                if (info.blockSize) info.blockSize = loadLe32(d->data() + 212);   // logical block size
            } else if (tag == 8) {   // terminating descriptor
                break;
            }
        }
        fs->addRegion(Region{vds, ByteCount{count} * bs});
        break;
    }
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectApfs(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, gen::ApfsNxSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::ApfsNxSuperblock nx(*raw);
    if (nx.nxMagic() != "NXSB") return notMine("no NXSB");
    if ((nx.oType() & 0xFFFF) != 1) return notMine("object is not an NX superblock");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Apfs;
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::ApfsNxSuperblock::kNxUuidOffset, 16));
    info.blockSize = nx.nxBlockSize();
    info.totalBytes = nx.nxBlockCount() * nx.nxBlockSize();
    info.extra = "container; up to " + std::to_string(nx.nxMaxFileSystems()) + " volumes";
    fs->setTreeName("APFS container");
    fs->addNode(nx.describe(0));
    fs->addRegion(Region{0, nx.nxBlockSize()});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
