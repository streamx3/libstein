// SPDX-License-Identifier: MIT
// Linux-native filesystems: XFS, btrfs, F2FS, JFS, ReiserFS, Reiser4, NILFS2, bcachefs, OCFS2,
// Minix, EROFS, SquashFS, swap.
#include "detectors.hpp"
#include "stein/fs/xfs_reader.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/btrfs.hpp"
#include "stein/layout/gen/f2fs.hpp"
#include "stein/layout/gen/misc_fs.hpp"
#include "stein/layout/gen/swap.hpp"
#include "stein/layout/gen/xfs.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

Result detectXfs(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, gen::XfsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::XfsSuperblock sb(*raw);
    if (sb.magicnum() != "XFSB") return notMine("no XFSB");
    if (sb.blocksize() < 512 || sb.agcount() == 0 || sb.agblocks() == 0) return notMine("bad XFS superblock");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Xfs;
    info.version = std::to_string(sb.versionnum() & 0xF);
    info.label = sb.fname();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::XfsSuperblock::kUuidOffset, 16));
    info.blockSize = sb.blocksize();
    info.totalBytes = sb.dblocks() * sb.blocksize();
    info.usedBytes = (sb.dblocks() - std::min(sb.fdblocks(), sb.dblocks())) * sb.blocksize();
    if (sb.inprogress()) fs->diag(Validity::Warning, "xfs.inprogress", "mkfs did not complete (inprogress flag set)");
    if ((sb.versionnum() & 0xF) == 5) info.features.push_back("crc");
    if (sb.featuresIncompat() & (1u << 4)) fs->diag(Validity::Warning, "xfs.needsrepair", "filesystem is marked NEEDSREPAIR");
    auto tree = sb.describe(0);
    if (auto* n = tree.child("features_incompat")) for (const auto& f : split(n->pretty, '|')) if (f != "none") info.features.push_back(f);
    fs->setTreeName("XFS filesystem");
    fs->addNode(std::move(tree));
    fs->setReaderSource(makeXfsReaderSource());
    for (std::uint32_t ag = 0; ag < sb.agcount() && ag < 4; ++ag) {
        const ByteCount off = ByteCount{ag} * sb.agblocks() * sb.blocksize();
        if (off + sb.sectsize() <= dev->size()) fs->addRegion(Region{off, std::max<ByteCount>(sb.sectsize(), 512)});
    }
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectBtrfs(Dev dev) {
    constexpr ByteCount kOff = 64 * KiB;
    auto raw = readOrNotFound(*dev, kOff, gen::BtrfsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::BtrfsSuperblock sb(*raw);
    if (sb.magic() != "_BHRfS_M") return notMine("no btrfs magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Btrfs;
    info.label = sb.label();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::BtrfsSuperblock::kFsidOffset, 16));
    info.blockSize = sb.sectorsize();
    info.totalBytes = sb.totalBytes();
    info.usedBytes = sb.bytesUsed();
    info.extra = "device uuid " + uuidText(sb.devItem().subspan(0x3B, 16)) + ", " + std::to_string(sb.numDevices()) + " device(s), nodesize " +
                 std::to_string(sb.nodesize());
    auto tree = sb.describe(kOff);
    if (auto* n = tree.child("incompat_flags")) for (const auto& f : split(n->pretty, '|')) if (f != "none") info.features.push_back(f);
    if (sb.bytenr() != kOff) fs->diag(Validity::Warning, "btrfs.bytenr", "superblock bytenr does not match its location");
    fs->setTreeName("btrfs filesystem");
    fs->addNode(std::move(tree));
    for (ByteCount copy : {ByteCount{64 * KiB}, ByteCount{64 * MiB}, ByteCount{256} * GiB})
        if (copy + 4096 <= dev->size()) fs->addRegion(Region{copy, 4096});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectF2fs(Dev dev) {
    constexpr ByteCount kOff = 1024;
    auto raw = readOrNotFound(*dev, kOff, gen::F2fsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::F2fsSuperblock sb(*raw);
    if (sb.magic() != 0xF2F52010u) return notMine("no f2fs magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::F2fs;
    info.version = std::to_string(sb.majorVer()) + "." + std::to_string(sb.minorVer());
    info.label = sb.volumeName();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::F2fsSuperblock::kUuidOffset, 16));
    info.blockSize = ByteCount{1} << sb.logBlocksize();
    info.totalBytes = sb.blockCount() * *info.blockSize;
    fs->setTreeName("F2FS filesystem");
    fs->addNode(sb.describe(kOff));
    fs->addRegion(Region{kOff, 4096});
    if (kOff + 4096 + 4096 <= dev->size()) fs->addRegion(Region{kOff + 4096, 4096});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectJfs(Dev dev) {
    constexpr ByteCount kOff = 32 * KiB;
    auto raw = readOrNotFound(*dev, kOff, 0xB8);
    if (!raw) return fail(raw.error());
    gen::JfsSuperblock sb(*raw);
    if (sb.magic() != "JFS1") return notMine("no JFS1");
    gen::JfsSuperblockTail tail(std::span<const std::byte>(*raw).subspan(0x98, 32));
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Jfs;
    info.version = std::to_string(sb.version());
    info.label = tail.label();
    if (info.label.empty()) info.label = sb.fpack();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::JfsSuperblock::kUuidOffset, 16));
    info.blockSize = sb.bsize();
    info.totalBytes = sb.size() * 512;
    info.clean = sb.state() == 0;
    if (sb.state() != 0) fs->diag(Validity::Warning, "jfs.state", "filesystem state is not clean");
    fs->setTreeName("JFS filesystem");
    fs->addNode(sb.describe(kOff));
    fs->addRegion(Region{kOff, 1024});
    if (60 * KiB + 1024 <= dev->size()) fs->addRegion(Region{60 * KiB, 1024});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectReiserFs(Dev dev) {
    for (ByteCount off : {ByteCount{64 * KiB}, ByteCount{8 * KiB}}) {
        auto raw = readOrNotFound(*dev, off, 0x74);
        if (!raw) continue;
        gen::ReiserfsSuperblock sb(*raw);
        const std::string magic = sb.magic();
        if (!startsWith(magic, "ReIsEr")) continue;
        if (magic != "ReIsErFs" && magic != "ReIsEr2Fs" && magic != "ReIsEr3Fs") continue;
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::ReiserFs;
        info.version = magic == "ReIsErFs" ? "3.5" : (sb.version() == 2 ? "3.6" : "3.5");
        info.label = gen::ReiserfsLabel(std::span<const std::byte>(*raw).subspan(0x64, 16)).label();
        info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::ReiserfsSuperblock::kUuidOffset, 16));
        info.blockSize = sb.blocksize();
        info.totalBytes = ByteCount{sb.blockCount()} * sb.blocksize();
        info.usedBytes = ByteCount{sb.blockCount() - std::min(sb.freeBlocks(), sb.blockCount())} * sb.blocksize();
        info.clean = sb.umountState() == 1;
        if (sb.umountState() != 1) fs->diag(Validity::Warning, "reiserfs.not_clean", "not cleanly unmounted");
        fs->setTreeName("ReiserFS filesystem");
        fs->addNode(sb.describe(off));
        fs->addRegion(Region{off, 1024});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no reiserfs magic");
}

Result detectReiser4(Dev dev) {
    constexpr ByteCount kOff = 64 * KiB;
    auto raw = readOrNotFound(*dev, kOff, 64);
    if (!raw) return fail(raw.error());
    if (std::string(reinterpret_cast<const char*>(raw->data()), 7) != "ReIsEr4") return notMine("no reiser4 magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Reiser4;
    info.blockSize = loadLe16(raw->data() + 16);
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(20, 16));
    info.label = asciiField(std::span<const std::byte>(*raw).subspan(36, 16));
    fs->setTreeName("Reiser4 filesystem (master superblock)");
    fs->addRegion(Region{kOff, 4096});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectNilfs2(Dev dev) {
    constexpr ByteCount kOff = 1024;
    auto raw = readOrNotFound(*dev, kOff, gen::Nilfs2Superblock::kSize);
    if (!raw) return fail(raw.error());
    gen::Nilfs2Superblock sb(*raw);
    if (sb.magic() != 0x3434) return notMine("no nilfs2 magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Nilfs2;
    info.version = std::to_string(sb.revLevel()) + (sb.minorRevLevel() ? "." + std::to_string(sb.minorRevLevel()) : "");
    info.label = sb.volumeName();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::Nilfs2Superblock::kUuidOffset, 16));
    info.blockSize = ByteCount{1024} << sb.logBlockSize();
    info.totalBytes = sb.devSize();
    info.clean = (sb.state() & 1) != 0;
    fs->setTreeName("NILFS2 filesystem");
    fs->addNode(sb.describe(kOff));
    fs->addRegion(Region{kOff, 1024});
    const ByteCount s2 = ((sb.devSize() >> 12) - 1) << 12;
    if (s2 > kOff && s2 + 1024 <= dev->size()) fs->addRegion(Region{s2, 1024});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectBcachefs(Dev dev) {
    constexpr ByteCount kOff = 4096;
    auto raw = readOrNotFound(*dev, kOff, gen::BcachefsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::BcachefsSuperblock sb(*raw);
    static constexpr std::uint8_t kMagic[16] = {0xc6, 0x85, 0x73, 0xf6, 0x66, 0xce, 0x90, 0xa9, 0xd9, 0x6a, 0x60, 0xcf, 0x80, 0x3d, 0xf7, 0xef};
    auto m = sb.magic();
    for (int i = 0; i < 16; ++i)
        if (std::to_integer<std::uint8_t>(m[i]) != kMagic[i]) return notMine("no bcachefs magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Bcachefs;
    info.version = std::to_string(sb.version() >> 10) + "." + std::to_string(sb.version() & 0x3FF);
    info.label = sb.label();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::BcachefsSuperblock::kUserUuidOffset, 16));
    info.extra = "internal uuid " + uuidText(std::span<const std::byte>(*raw).subspan(gen::BcachefsSuperblock::kUuidOffset, 16)) + ", " +
                 std::to_string(sb.nrDevices()) + " device(s)";
    info.blockSize = ByteCount{sb.blockSize()} * 512;
    fs->setTreeName("bcachefs filesystem");
    fs->addNode(sb.describe(kOff));
    fs->addRegion(Region{kOff, 4096});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectOcfs2(Dev dev) {
    for (ByteCount off : {ByteCount{1024}, ByteCount{2048}, ByteCount{4096}, ByteCount{8192}}) {
        auto raw = readOrNotFound(*dev, off, 0xC0 + gen::Ocfs2SuperBlockInfo::kSize);
        if (!raw) continue;
        gen::Ocfs2Superblock di(*raw);
        if (di.signature() != "OCFSV2") continue;
        gen::Ocfs2SuperBlockInfo sbi(std::span<const std::byte>(*raw).subspan(0xC0, gen::Ocfs2SuperBlockInfo::kSize));
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::Ocfs2;
        info.version = std::to_string(sbi.majorRevLevel()) + "." + std::to_string(sbi.minorRevLevel());
        info.label = sbi.label();
        info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(0xC0 + gen::Ocfs2SuperBlockInfo::kUuidOffset, 16));
        info.blockSize = ByteCount{1} << sbi.clustersizeBits();
        fs->setTreeName("OCFS2 filesystem");
        auto t = sbi.describe(off + 0xC0);
        fs->addNode(std::move(t));
        fs->addRegion(Region{off, ByteCount{1} << sbi.blocksizeBits()});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no OCFSV2 signature");
}

Result detectMinix(Dev dev) {
    constexpr ByteCount kOff = 1024;
    auto raw = readOrNotFound(*dev, kOff, 32);
    if (!raw) return fail(raw.error());
    gen::MinixSuperblock v12(*raw);
    gen::Minix3Superblock v3(*raw);
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Minix;
    const std::uint16_t m12 = v12.magic();
    if (m12 == 0x137F || m12 == 0x138F) {
        info.version = "1";
        info.blockSize = 1024;
        info.totalBytes = ByteCount{v12.nzones()} * 1024;
        fs->addNode(v12.describe(kOff));
    } else if (m12 == 0x2468 || m12 == 0x2478) {
        info.version = "2";
        info.blockSize = 1024;
        info.totalBytes = ByteCount{v12.zones()} * 1024;
        fs->addNode(v12.describe(kOff));
    } else if (v3.magic() == 0x4D5A) {
        info.version = "3";
        info.blockSize = v3.blocksize();
        info.totalBytes = ByteCount{v3.zones()} * v3.blocksize();
        fs->addNode(v3.describe(kOff));
    } else {
        return notMine("no minix magic");
    }
    fs->setTreeName("Minix filesystem");
    fs->addRegion(Region{kOff, 1024});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectErofs(Dev dev) {
    constexpr ByteCount kOff = 1024;
    auto raw = readOrNotFound(*dev, kOff, gen::ErofsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::ErofsSuperblock sb(*raw);
    if (sb.magic() != 0xE0F5E1E2u) return notMine("no erofs magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Erofs;
    info.label = sb.volumeName();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::ErofsSuperblock::kUuidOffset, 16));
    info.blockSize = ByteCount{1} << sb.blkszbits();
    info.totalBytes = ByteCount{sb.blocks()} << sb.blkszbits();
    fs->setTreeName("EROFS filesystem");
    fs->addNode(sb.describe(kOff));
    fs->addRegion(Region{kOff, 128});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectSquashFs(Dev dev) {
    auto raw = readOrNotFound(*dev, 0, gen::SquashfsSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::SquashfsSuperblock sb(*raw);
    if (sb.magic() != "hsqs") return notMine("no squashfs magic");
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::SquashFs;
    info.version = std::to_string(sb.versionMajor()) + "." + std::to_string(sb.versionMinor());
    info.blockSize = sb.blockSize();
    info.totalBytes = sb.bytesUsed();
    auto t = sb.describe(0);
    if (auto* c = t.child("compressor")) info.extra = "compressor " + c->pretty;
    fs->setTreeName("SquashFS image");
    fs->addNode(std::move(t));
    fs->addRegion(Region{0, 96});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

Result detectSwap(Dev dev) {
    for (ByteCount page : {ByteCount{4096}, ByteCount{8192}, ByteCount{16384}, ByteCount{65536}}) {
        auto sig = readOrNotFound(*dev, page - 10, 10);
        if (!sig) continue;
        const std::string s(reinterpret_cast<const char*>(sig->data()), 10);
        const bool v1 = s == "SWAPSPACE2", v0 = s == "SWAP-SPACE";
        const bool suspend = s == "S1SUSPEND\0" || startsWith(s, "S1SUSPEND") || startsWith(s, "S2SUSPEND") || startsWith(s, "ULSUSPEND") ||
                             startsWith(s, "LINHIB0001") || startsWith(s, "TUXONICE");
        if (!v1 && !v0 && !suspend) continue;
        auto fs = std::make_unique<SimpleFileSystem>(dev);
        auto& info = fs->mutableInfo();
        info.type = FsType::Swap;
        info.usage = Usage::Swap;
        info.blockSize = page;
        if (v1 || suspend) {
            auto raw = dev->read(1024, gen::SwapHeaderInfo::kSize);
            if (raw) {
                gen::SwapHeaderInfo h(*raw);
                info.version = std::to_string(h.version());
                info.label = h.volumeName();
                info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::SwapHeaderInfo::kUuidOffset, 16));
                info.totalBytes = (ByteCount{h.lastPage()} + 1) * page;
                if (h.nrBadpages()) fs->diag(Validity::Warning, "swap.badpages", std::to_string(h.nrBadpages()) + " bad pages recorded");
                fs->addNode(h.describe(1024));
            }
            if (suspend) info.extra = "contains a hibernation image (" + std::string(trim(std::string_view(s.c_str()))) + ")";
        } else {
            info.version = "0";
        }
        fs->setTreeName("Linux swap");
        fs->addRegion(Region{0, page});
        return std::unique_ptr<FileSystem>(std::move(fs));
    }
    return notMine("no swap signature");
}

} // namespace stein::fs::detail
