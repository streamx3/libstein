// SPDX-License-Identifier: MIT
// F2FS reader. Block addresses are absolute 4 KiB block numbers; node blocks
// are found through the NAT (two interleaved copies selected by the
// checkpoint's NAT bitmap) after the checkpoint's NAT journal; a file's
// blocks are addressed by the inode's slots, two direct nodes, two indirect
// nodes and one double indirect node.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/lz4.hpp"
#include "stein/core/lzo.hpp"
#include "stein/core/zstd.hpp"
#include "stein/fs/f2fs_reader.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint32_t kMagic = 0xF2F52010u;
constexpr std::uint32_t kNullAddr = 0, kNewAddr = 0xFFFFFFFFu, kCompressAddr = 0xFFFFFFFEu;
constexpr std::uint32_t kAddrsPerInode = 923, kAddrsPerBlock = 1018, kNatEntriesPerBlock = 455, kDentriesPerBlock = 214, kDentrySize = 11, kSlotLen = 8;
constexpr std::uint32_t kDefaultInlineXattrAddrs = 50;
constexpr std::size_t kNodeFooter = 4096 - 24;
// Superblock features.
constexpr std::uint32_t kFeatEncrypt = 0x1, kFeatExtraAttr = 0x8, kFeatFlexibleInlineXattr = 0x40, kFeatInodeCrtime = 0x100, kFeatCasefold = 0x1000, kFeatCompression = 0x2000;
// Checkpoint flags.
constexpr std::uint32_t kCpCompactSum = 0x4, kCpLargeNatBitmap = 0x400;
// i_inline.
constexpr std::uint8_t kInlineXattr = 0x01, kInlineData = 0x02, kInlineDentry = 0x04, kExtraAttr = 0x20, kCompressReleased = 0x80;
// i_flags and i_advise.
constexpr std::uint32_t kFlCompr = 0x4, kFlCasefold = 0x40000000u;
constexpr std::uint8_t kAdviseEncrypt = 0x04;
constexpr std::uint8_t kAlgLzo = 0, kAlgLz4 = 1, kAlgZstd = 2, kAlgLzoRle = 3;

// crc32_le as the kernel computes it for f2fs: seeded with the magic, no final inversion.
std::uint32_t f2fsCrc(std::span<const std::byte> data) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t crc = kMagic;
    for (std::byte b : data) crc = table[(crc ^ std::to_integer<std::uint32_t>(b)) & 0xFF] ^ (crc >> 8);
    return crc;
}

FileType modeType(std::uint16_t mode) {
    switch (mode & 0170000) {
    case 0040000: return FileType::Directory;
    case 0100000: return FileType::File;
    case 0120000: return FileType::Symlink;
    case 0020000: return FileType::CharDevice;
    case 0060000: return FileType::BlockDevice;
    case 0010000: return FileType::Fifo;
    case 0140000: return FileType::Socket;
    default: return FileType::Unknown;
    }
}

FileType dentryType(std::uint8_t t) {
    switch (t) {
    case 1: return FileType::File;
    case 2: return FileType::Directory;
    case 3: return FileType::CharDevice;
    case 4: return FileType::BlockDevice;
    case 5: return FileType::Fifo;
    case 6: return FileType::Socket;
    case 7: return FileType::Symlink;
    default: return FileType::Unknown;
    }
}
} // namespace

Expected<F2fsReader::Block> F2fsReader::readBlock(std::uint32_t addr) const {
    if (addr == kNullAddr || addr == kNewAddr || addr == kCompressAddr || (m_blockCount && addr >= m_blockCount))
        return fail(ErrorCategory::InvalidFormat, "F2FS block address " + std::to_string(addr) + " is not readable");
    auto b = m_device->read(std::uint64_t{addr} * m_blockSize, m_blockSize);
    if (!b) return fail(b.error());
    return std::make_shared<const std::vector<std::byte>>(std::move(*b));
}

Expected<std::unique_ptr<F2fsReader>> F2fsReader::open(std::shared_ptr<BlockDevice> device) {
    std::unique_ptr<F2fsReader> r(new F2fsReader());
    r->m_device = std::move(device);
    auto sbRaw = r->m_device->read(1024, 3072);
    if (!sbRaw) return fail(sbRaw.error());
    const std::byte* sb = sbRaw->data();
    if (loadLe32(sb) != kMagic) return fail(ErrorCategory::InvalidFormat, "no F2FS superblock");
    if (loadLe32(sb + 16) != 12) return fail(ErrorCategory::Unsupported, "F2FS block size other than 4 KiB");
    r->m_blocksPerSeg = 1u << loadLe32(sb + 20);
    r->m_blockCount = loadLe64(sb + 36);
    const std::uint32_t cpBlkaddr = loadLe32(sb + 76);
    r->m_natBlkaddr = loadLe32(sb + 84);
    r->m_rootIno = loadLe32(sb + 96);
    const std::uint32_t cpPayload = loadLe32(sb + 1664);
    r->m_feature = loadLe32(sb + 2180);

    // The newer of the two checkpoint packs whose header and footer agree (and whose CRC holds).
    struct Pack {
        std::uint32_t start = 0;
        std::uint64_t version = 0;
        Block header;
    } best;
    for (int i = 0; i < 2; ++i) {
        const std::uint32_t start = cpBlkaddr + static_cast<std::uint32_t>(i) * r->m_blocksPerSeg;
        auto head = r->readBlock(start);
        if (!head) continue;
        const std::byte* h = (*head)->data();
        const std::uint64_t ver = loadLe64(h);
        const std::uint32_t total = loadLe32(h + 136), crcOff = loadLe32(h + 164);
        if (total < 2 || total > 4 * r->m_blocksPerSeg) continue;
        if (crcOff >= 4 && crcOff + 4 <= 4096 && f2fsCrc(std::span<const std::byte>(h, crcOff)) != loadLe32(h + crcOff)) continue;
        auto foot = r->readBlock(start + total - 1);
        if (!foot || loadLe64((*foot)->data()) != ver) continue;
        if (!best.header || ver > best.version) best = Pack{start, ver, *head};
    }
    if (!best.header) return fail(ErrorCategory::InvalidFormat, "no valid F2FS checkpoint");
    const std::byte* cp = best.header->data();
    const std::uint32_t flags = loadLe32(cp + 132), startSum = loadLe32(cp + 140);
    const std::uint32_t sitBitmapBytes = loadLe32(cp + 156), natBitmapBytes = loadLe32(cp + 160);
    std::size_t natOff;
    if (flags & kCpLargeNatBitmap) natOff = 192 + 4;
    else if (cpPayload > 0) natOff = 192;
    else natOff = 192 + sitBitmapBytes;
    if (natOff + natBitmapBytes > 4096) return fail(ErrorCategory::InvalidFormat, "F2FS NAT bitmap outside the checkpoint block");
    r->m_natBitmap.resize(natBitmapBytes);
    for (std::size_t i = 0; i < natBitmapBytes; ++i) r->m_natBitmap[i] = std::to_integer<std::uint8_t>(cp[natOff + i]);
    // NAT journal: in the compacted summary block at offset 0, else at the end of the hot-data summary block.
    if (startSum && startSum < loadLe32(cp + 136)) {
        auto sum = r->readBlock(best.start + startSum);
        if (!sum) return fail(sum.error());
        const std::size_t joff = (flags & kCpCompactSum) ? 0 : 7 * 512;
        const std::byte* j = (*sum)->data() + joff;
        const std::uint16_t n = loadLe16(j);
        for (std::uint16_t k = 0; k < n && k < 38; ++k) {
            const std::byte* e = j + 2 + k * 13;
            r->m_natJournal[loadLe32(e)] = loadLe32(e + 9);
        }
    }
    auto root = r->inode(r->m_rootIno);
    if (!root) return fail(root.error());
    if (modeType((*root)->mode) != FileType::Directory) return fail(ErrorCategory::InvalidFormat, "F2FS root inode is not a directory");
    // Casefolding is per directory (chattr +F); the reader-wide answer follows the root directory,
    // and lookup() honours the flag on every directory it searches.
    r->m_casefold = (r->m_feature & kFeatCasefold) && ((*root)->flags & kFlCasefold);
    return r;
}

Expected<std::uint32_t> F2fsReader::nodeAddr(std::uint32_t nid) const {
    if (auto it = m_natJournal.find(nid); it != m_natJournal.end()) return it->second;
    const std::uint32_t blockOff = nid / kNatEntriesPerBlock, entry = nid % kNatEntriesPerBlock;
    std::uint32_t addr = m_natBlkaddr + 2 * blockOff - (blockOff & (m_blocksPerSeg - 1));
    if (blockOff / 8 < m_natBitmap.size() && (m_natBitmap[blockOff / 8] & (0x80u >> (blockOff % 8)))) addr += m_blocksPerSeg;
    auto blk = readBlock(addr);
    if (!blk) return fail(blk.error());
    return loadLe32((*blk)->data() + entry * 9 + 5);
}

Expected<F2fsReader::Block> F2fsReader::nodeBlock(std::uint32_t nid) const {
    if (auto it = m_nodeCache.find(nid); it != m_nodeCache.end()) return it->second;
    auto addr = nodeAddr(nid);
    if (!addr) return fail(addr.error());
    if (*addr == kNullAddr) return fail(ErrorCategory::NotFound, "F2FS node " + std::to_string(nid) + " is not allocated");
    auto blk = readBlock(*addr);
    if (!blk) return fail(blk.error());
    if (loadLe32((*blk)->data() + kNodeFooter) != nid) return fail(ErrorCategory::InvalidFormat, "F2FS node block for nid " + std::to_string(nid) + " carries nid " + std::to_string(loadLe32((*blk)->data() + kNodeFooter)));
    if (m_nodeCache.size() > 4096) m_nodeCache.clear();
    m_nodeCache[nid] = *blk;
    return *blk;
}

Expected<const F2fsReader::InodeRec*> F2fsReader::inode(std::uint64_t ino) {
    if (auto it = m_inodes.find(ino); it != m_inodes.end()) return &it->second;
    if (ino > 0xFFFFFFFFull) return fail(ErrorCategory::NotFound, "no F2FS inode " + std::to_string(ino));
    auto blk = nodeBlock(static_cast<std::uint32_t>(ino));
    if (!blk) return fail(blk.error());
    const std::byte* p = (*blk)->data();
    if (loadLe32(p + kNodeFooter + 4) != ino) return fail(ErrorCategory::InvalidFormat, "F2FS node " + std::to_string(ino) + " is not an inode block");
    InodeRec in;
    in.node = *blk;
    in.mode = loadLe16(p);
    in.advise = std::to_integer<std::uint8_t>(p[2]);
    in.inlineFlags = std::to_integer<std::uint8_t>(p[3]);
    in.uid = loadLe32(p + 4);
    in.gid = loadLe32(p + 8);
    in.links = loadLe32(p + 12);
    in.size = loadLe64(p + 16);
    in.blocks = loadLe64(p + 24);
    in.atime = static_cast<std::int64_t>(loadLe64(p + 32));
    in.ctime = static_cast<std::int64_t>(loadLe64(p + 40));
    in.mtime = static_cast<std::int64_t>(loadLe64(p + 48));
    in.flags = loadLe32(p + 80);
    if ((in.inlineFlags & kExtraAttr) && (m_feature & kFeatExtraAttr)) {
        in.extraIsize = loadLe16(p + 360);
        if (in.extraIsize > 4 * (kAddrsPerInode - 1) || in.extraIsize % 4) return fail(ErrorCategory::InvalidFormat, "bad F2FS i_extra_isize");
        if ((m_feature & kFeatInodeCrtime) && in.extraIsize >= 24) in.crtime = static_cast<std::int64_t>(loadLe64(p + 372));
        if ((m_feature & kFeatCompression) && (in.flags & kFlCompr) && in.extraIsize >= 36) {
            in.compressed = true;
            in.compressAlgorithm = std::to_integer<std::uint8_t>(p[392]);
            in.logClusterSize = std::to_integer<std::uint8_t>(p[393]);
        }
    }
    // The kernel's rule (do_read_inode): the flexible size when present, else the default when the
    // inode has an inline xattr area or inline dentries, else none.
    if ((in.inlineFlags & kExtraAttr) && (m_feature & kFeatFlexibleInlineXattr)) in.inlineXattrSlots = loadLe16(p + 362);
    else if (in.inlineFlags & (kInlineXattr | kInlineDentry)) in.inlineXattrSlots = kDefaultInlineXattrAddrs;
    if (in.inlineXattrSlots > kAddrsPerInode / 2) return fail(ErrorCategory::InvalidFormat, "bad F2FS inline xattr size");
    in.addrBase = 360 + in.extraIsize;
    in.addrsPerInode = kAddrsPerInode - in.extraIsize / 4 - in.inlineXattrSlots;
    if (in.compressed) {
        // Clusters never straddle a node: the kernel rounds both slot counts down to the cluster size.
        if (in.logClusterSize < 2 || in.logClusterSize > 8) return fail(ErrorCategory::InvalidFormat, "bad F2FS compression cluster size");
        const std::uint32_t cs = 1u << in.logClusterSize;
        in.addrsPerInode &= ~(cs - 1);
        in.addrsPerBlock = kAddrsPerBlock & ~(cs - 1);
    }
    static const bool debug = std::getenv("STEIN_F2FS_DEBUG") != nullptr;
    if (debug) std::fprintf(stderr, "f2fs inode %llu inline 0x%02x extra %u xattrsize@362 %u slots %u addrs %u size %llu nid0 %u\n", static_cast<unsigned long long>(ino), in.inlineFlags, in.extraIsize, loadLe16(p + 362), in.inlineXattrSlots, in.addrsPerInode, static_cast<unsigned long long>(in.size), loadLe32(p + 4052));
    auto [it, _] = m_inodes.emplace(ino, std::move(in));
    return &it->second;
}

Expected<std::uint32_t> F2fsReader::dataAddr(const InodeRec& in, std::uint64_t index) const {
    const std::byte* p = in.node->data();
    if (index < in.addrsPerInode) return loadLe32(p + in.addrBase + 4 * index);
    index -= in.addrsPerInode;
    auto nidAt = [&](int i) { return loadLe32(p + 4052 + 4 * i); };
    auto slot = [&](std::uint32_t nid, std::uint64_t i) -> Expected<std::uint32_t> {
        if (nid == 0) return kNullAddr;
        auto blk = nodeBlock(nid);
        if (!blk) return fail(blk.error());
        return loadLe32((*blk)->data() + 4 * i);
    };
    const std::uint64_t per = in.addrsPerBlock, nids = kAddrsPerBlock;
    if (index < 2 * per) return slot(nidAt(static_cast<int>(index / per)), index % per);
    index -= 2 * per;
    if (index < 2 * nids * per) {
        auto direct = slot(nidAt(2 + static_cast<int>(index / (nids * per))), (index / per) % nids);
        if (!direct) return direct;
        return slot(*direct, index % per);
    }
    index -= 2 * nids * per;
    if (index < nids * nids * per) {
        auto indirect = slot(nidAt(4), index / (nids * per));
        if (!indirect) return indirect;
        auto direct = slot(*indirect, (index / per) % nids);
        if (!direct) return direct;
        return slot(*direct, index % per);
    }
    return fail(ErrorCategory::OutOfRange, "F2FS file block index beyond the node tree");
}

Expected<std::vector<DirEntry>> F2fsReader::parseDentries(std::span<const std::byte> bitmap, std::size_t count, std::span<const std::byte> dentries, std::span<const std::byte> names) const {
    std::vector<DirEntry> out;
    for (std::size_t bit = 0; bit < count;) {
        if (!(std::to_integer<std::uint8_t>(bitmap[bit / 8]) & (1u << (bit % 8)))) {
            ++bit;
            continue;
        }
        const std::byte* d = dentries.data() + bit * kDentrySize;
        const std::uint32_t ino = loadLe32(d + 4);
        const std::uint16_t nameLen = loadLe16(d + 8);
        const std::uint8_t type = std::to_integer<std::uint8_t>(d[10]);
        const std::size_t slots = std::max<std::size_t>(1, (nameLen + kSlotLen - 1) / kSlotLen);
        if (nameLen == 0 || bit * kSlotLen + nameLen > names.size()) return fail(ErrorCategory::InvalidFormat, "bad F2FS directory entry");
        std::string name(reinterpret_cast<const char*>(names.data()) + bit * kSlotLen, nameLen);
        if (name != "." && name != "..") out.push_back(DirEntry{std::move(name), Inode{ino}, dentryType(type)});
        bit += slots;
    }
    return out;
}

Expected<std::vector<DirEntry>> F2fsReader::readdir(const Inode& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    auto inp = inode(dir.id);
    if (!inp) return fail(inp.error());
    const InodeRec& in = **inp;
    if (modeType(in.mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    static const bool debug = std::getenv("STEIN_F2FS_DEBUG") != nullptr;
    if (debug) std::fprintf(stderr, "f2fs readdir ino %llu size %llu inline 0x%02x extra %u slots %u addrBase %zu\n", static_cast<unsigned long long>(dir.id), static_cast<unsigned long long>(in.size), in.inlineFlags, in.extraIsize, in.inlineXattrSlots, in.addrBase);
    if (in.inlineFlags & kInlineDentry) {
        const std::size_t inlineSize = (in.addrsPerInode - 1) * 4;
        const std::size_t count = inlineSize * 8 / ((kDentrySize + kSlotLen) * 8 + 1);
        const std::size_t bitmapBytes = (count + 7) / 8, reserved = inlineSize - count * (kDentrySize + kSlotLen) - bitmapBytes;
        std::span<const std::byte> area(in.node->data() + in.addrBase + 4, inlineSize);
        auto e = parseDentries(area.first(bitmapBytes), count, area.subspan(bitmapBytes + reserved, count * kDentrySize), area.subspan(bitmapBytes + reserved + count * kDentrySize, count * kSlotLen));
        if (!e) return e;
        out = std::move(*e);
    } else {
        const std::uint64_t blocks = (in.size + m_blockSize - 1) / m_blockSize;
        for (std::uint64_t b = 0; b < blocks; ++b) {
            auto addr = dataAddr(in, b);
            if (!addr) return fail(addr.error());
            if (debug) std::fprintf(stderr, "  block %llu -> addr %u\n", static_cast<unsigned long long>(b), *addr);
            if (*addr == kNullAddr || *addr == kNewAddr) continue;
            auto blk = readBlock(*addr);
            if (!blk) return fail(blk.error());
            std::span<const std::byte> d(**blk);
            auto e = parseDentries(d.first(27), kDentriesPerBlock, d.subspan(30, kDentriesPerBlock * kDentrySize), d.subspan(30 + kDentriesPerBlock * kDentrySize, kDentriesPerBlock * kSlotLen));
            if (!e) return e;
            out.insert(out.end(), e->begin(), e->end());
        }
    }
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> F2fsReader::lookup(const Inode& dir, std::string_view name) {
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    auto inp = inode(dir.id);
    if (inp && (m_feature & kFeatCasefold) && ((*inp)->flags & kFlCasefold))
        for (const auto& e : *entries)
            if (e.name.size() == name.size() && std::equal(e.name.begin(), e.name.end(), name.begin(), [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); }))
                return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> F2fsReader::stat(const Inode& ino) {
    auto inp = inode(ino.id);
    if (!inp) return fail(inp.error());
    const InodeRec& in = **inp;
    Stat st;
    st.type = modeType(in.mode);
    st.mode = in.mode & 07777;
    st.nlink = in.links;
    st.uid = in.uid;
    st.gid = in.gid;
    st.size = in.size;
    st.allocatedBytes = in.blocks * m_blockSize;
    st.atime = in.atime;
    st.mtime = in.mtime;
    st.ctime = in.ctime;
    st.crtime = in.crtime;
    return st;
}

Expected<std::size_t> F2fsReader::readCluster(const InodeRec& in, std::uint64_t cluster, std::span<std::byte> out) {
    const std::uint64_t cs = 1ull << in.logClusterSize;
    auto first = dataAddr(in, cluster * cs);
    if (!first) return fail(first.error());
    if (*first != kCompressAddr) {
        // Plain cluster: block by block (holes stay zero).
        for (std::uint64_t i = 0; i < cs && i * m_blockSize < out.size(); ++i) {
            auto addr = i == 0 ? first : dataAddr(in, cluster * cs + i);
            if (!addr) return fail(addr.error());
            if (*addr == kNullAddr || *addr == kNewAddr) continue;
            auto blk = readBlock(*addr);
            if (!blk) return fail(blk.error());
            const std::size_t n = std::min<std::size_t>(m_blockSize, out.size() - i * m_blockSize);
            std::memcpy(out.data() + i * m_blockSize, (*blk)->data(), n);
        }
        return out.size();
    }
    std::vector<std::byte> packed;
    for (std::uint64_t i = 1; i < cs; ++i) {
        auto addr = dataAddr(in, cluster * cs + i);
        if (!addr) return fail(addr.error());
        if (*addr == kNullAddr || *addr == kNewAddr) continue;
        auto blk = readBlock(*addr);
        if (!blk) return fail(blk.error());
        packed.insert(packed.end(), (*blk)->begin(), (*blk)->end());
    }
    if (packed.size() < 24) return fail(ErrorCategory::InvalidFormat, "F2FS compressed cluster without a header");
    const std::uint32_t clen = loadLe32(packed.data());
    if (24 + static_cast<std::size_t>(clen) > packed.size()) return fail(ErrorCategory::InvalidFormat, "F2FS compressed cluster length exceeds its blocks");
    const std::span<const std::byte> input(packed.data() + 24, clen);
    std::vector<std::byte> decoded(cs * m_blockSize);
    Expected<std::size_t> n;
    switch (in.compressAlgorithm) {
    case kAlgLz4: {
        auto r = lz4::decompressUpTo(input, decoded);
        if (!r) return fail(r.error());
        n = *r;
        break;
    }
    case kAlgLzo: n = compress::lzo1xDecompress(input, decoded); break;
    case kAlgZstd: n = compress::zstdDecompress(input, decoded); break;
    case kAlgLzoRle: return fail(ErrorCategory::Unsupported, "F2FS lzo-rle compressed files are not supported yet");
    default: return fail(ErrorCategory::Unsupported, "unknown F2FS compression algorithm " + std::to_string(in.compressAlgorithm));
    }
    if (!n) return fail(n.error());
    if (*n < out.size()) return fail(ErrorCategory::InvalidFormat, "F2FS compressed cluster decoded short");
    std::memcpy(out.data(), decoded.data(), out.size());
    return out.size();
}

Expected<std::size_t> F2fsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto inp = inode(file.id);
    if (!inp) return fail(inp.error());
    const InodeRec& in = **inp;
    if (modeType(in.mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if ((in.advise & kAdviseEncrypt) && (m_feature & kFeatEncrypt)) return fail(ErrorCategory::Unsupported, "encrypted F2FS files are not supported");
    if (in.inlineFlags & kCompressReleased) return fail(ErrorCategory::Unsupported, "F2FS file whose compressed blocks were released");
    if (offset >= in.size) return 0;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size(), in.size - offset));
    std::memset(dst.data(), 0, n);
    if (in.inlineFlags & kInlineData) {
        const std::size_t inlineSize = (in.addrsPerInode - 1) * 4;
        const std::size_t avail = std::min<std::size_t>(in.size, inlineSize);
        if (offset < avail) std::memcpy(dst.data(), in.node->data() + in.addrBase + 4 + offset, std::min<std::size_t>(n, avail - offset));
        return n;
    }
    if (in.compressed) {
        const std::uint64_t cs = 1ull << in.logClusterSize, clusterBytes = cs * m_blockSize;
        std::vector<std::byte> buf(clusterBytes);
        for (std::uint64_t c = offset / clusterBytes; c * clusterBytes < offset + n; ++c) {
            const std::uint64_t cstart = c * clusterBytes;
            const std::size_t clen = static_cast<std::size_t>(std::min<std::uint64_t>(clusterBytes, in.size - cstart));
            if (auto r = readCluster(in, c, std::span<std::byte>(buf).first(clen)); !r) return fail(r.error());
            const std::uint64_t from = std::max(offset, cstart), to = std::min<std::uint64_t>(offset + n, cstart + clen);
            if (to > from) std::memcpy(dst.data() + (from - offset), buf.data() + (from - cstart), static_cast<std::size_t>(to - from));
        }
        return n;
    }
    for (std::uint64_t b = offset / m_blockSize; b * m_blockSize < offset + n; ++b) {
        auto addr = dataAddr(in, b);
        if (!addr) return fail(addr.error());
        if (*addr == kNullAddr || *addr == kNewAddr) continue;   // hole
        if (*addr == kCompressAddr) return fail(ErrorCategory::InvalidFormat, "F2FS compressed cluster in a file not marked compressed");
        auto blk = readBlock(*addr);
        if (!blk) return fail(blk.error());
        const std::uint64_t bstart = b * m_blockSize;
        const std::uint64_t from = std::max(offset, bstart), to = std::min<std::uint64_t>(offset + n, bstart + m_blockSize);
        std::memcpy(dst.data() + (from - offset), (*blk)->data() + (from - bstart), static_cast<std::size_t>(to - from));
    }
    return n;
}

Expected<std::string> F2fsReader::readlink(const Inode& link) {
    auto inp = inode(link.id);
    if (!inp) return fail(inp.error());
    const InodeRec& in = **inp;
    if (modeType(in.mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (in.size > 4096) return fail(ErrorCategory::InvalidFormat, "F2FS symlink longer than a block");
    std::vector<std::byte> buf(static_cast<std::size_t>(in.size));
    auto n = read(link, 0, buf);
    if (!n) return fail(n.error());
    std::string target(reinterpret_cast<const char*>(buf.data()), *n);
    while (!target.empty() && target.back() == '\0') target.pop_back();
    return target;
}

class F2fsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = F2fsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeF2fsReaderSource() { return std::make_unique<F2fsReaderSource>(); }

} // namespace stein::fs::detail
