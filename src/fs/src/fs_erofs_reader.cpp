// SPDX-License-Identifier: MIT
// EROFS reader. Compressed inodes follow the z_erofs mapping of erofs-utils:
// logical clusters (lclusters) described by full 8-byte indexes or compacted
// 2/4-byte packs, HEAD lclusters that start a physical cluster, NONHEAD ones
// that point back to it, big physical clusters whose size sits in the first
// NONHEAD index, tail data packed after the indexes, fragments stored in the
// packed inode, and dedupe references that need partial decoding.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/inflate.hpp"
#include "stein/core/lz4.hpp"
#include "stein/core/lzma.hpp"
#include "stein/core/zstd.hpp"
#include "stein/fs/erofs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint64_t kSuperOffset = 1024;
constexpr std::uint32_t kIncompatLz4ZeroPadding = 0x1, kIncompatComprCfgs = 0x2, kIncompat48Bit = 0x80, kIncompatMetabox = 0x100;
constexpr std::uint8_t kLayoutPlain = 0, kLayoutCompressedFull = 1, kLayoutInline = 2, kLayoutCompressedCompact = 3, kLayoutChunk = 4;
constexpr std::uint16_t kAdviseCompacted2B = 0x1, kAdviseExtents = 0x1, kAdviseBigPcluster1 = 0x2, kAdviseBigPcluster2 = 0x4, kAdviseInlinePcluster = 0x8,
                        kAdviseInterlaced = 0x10, kAdviseFragment = 0x20;
constexpr std::uint8_t kTypePlain = 0, kTypeHead1 = 1, kTypeNonhead = 2, kTypeHead2 = 3;
constexpr std::uint32_t kD0Cblkcnt = 1u << 11;
constexpr std::uint16_t kPartialRef = 1u << 15;
constexpr std::uint8_t kAlgLz4 = 0, kAlgLzma = 1, kAlgDeflate = 2, kAlgZstd = 3, kAlgShifted = 4, kAlgInterlaced = 5;
constexpr std::uint32_t kNullAddr = 0xFFFFFFFFu;

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

FileType direntType(std::uint8_t t) {
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

std::uint64_t roundUp(std::uint64_t v, std::uint64_t a) { return (v + a - 1) / a * a; }
} // namespace

Expected<std::vector<std::byte>> ErofsReader::readMeta(std::uint64_t offset, std::size_t n) const { return m_device->read(offset, n); }

Expected<std::unique_ptr<ErofsReader>> ErofsReader::open(std::shared_ptr<BlockDevice> device) {
    auto sb = device->read(kSuperOffset, 128);
    if (!sb) return fail(sb.error());
    const std::byte* s = sb->data();
    if (loadLe32(s) != 0xE0F5E1E2u) return fail(ErrorCategory::InvalidFormat, "no erofs magic");
    std::unique_ptr<ErofsReader> r(new ErofsReader());
    r->m_device = std::move(device);
    r->m_featureCompat = loadLe32(s + 8);
    r->m_blkszBits = std::to_integer<std::uint8_t>(s[12]);
    if (r->m_blkszBits < 9 || r->m_blkszBits > 16) return fail(ErrorCategory::InvalidFormat, "bad erofs block size");
    r->m_blockSize = 1u << r->m_blkszBits;
    r->m_featureIncompat = loadLe32(s + 80);
    if (r->m_featureIncompat & kIncompatMetabox) return fail(ErrorCategory::Unsupported, "erofs metabox images are not supported yet");
    r->m_rootNid = (r->m_featureIncompat & kIncompat48Bit) ? loadLe64(s + 112) : loadLe16(s + 14);
    r->m_epoch = loadLe64(s + 24);
    r->m_metaBlkAddr = loadLe32(s + 40);
    r->m_availableAlgs = (r->m_featureIncompat & kIncompatComprCfgs) ? loadLe16(s + 84) : 1;
    const std::uint8_t dirBits = std::to_integer<std::uint8_t>(s[90]);
    r->m_dirBlockSize = dirBits ? (1u << dirBits) : r->m_blockSize;
    r->m_packedNid = loadLe64(s + 96);
    if (loadLe16(s + 86) != 0) return fail(ErrorCategory::Unsupported, "multi-device erofs images are not supported");
    return r;
}

Expected<ErofsReader::InodeRec> ErofsReader::inode(std::uint64_t nid) {
    if (auto it = m_inodes.find(nid); it != m_inodes.end()) return it->second;
    InodeRec in;
    in.nid = nid;
    in.iloc = (m_metaBlkAddr << m_blkszBits) + nid * 32;
    auto raw = readMeta(in.iloc, 64);
    if (!raw) return fail(raw.error());
    const std::byte* p = raw->data();
    const std::uint16_t format = loadLe16(p);
    if (format & ~0x1Fu) return fail(ErrorCategory::Unsupported, "unsupported erofs inode format " + std::to_string(format));
    in.layout = static_cast<std::uint8_t>((format >> 1) & 7);
    if (in.layout > kLayoutChunk) return fail(ErrorCategory::InvalidFormat, "bad erofs data layout");
    const std::uint16_t xattrCount = loadLe16(p + 2);
    in.xattrSize = xattrCount ? 12 + 4 * (xattrCount - 1) : 0;
    in.mode = loadLe16(p + 4);
    const std::uint16_t nb = loadLe16(p + 6);
    std::uint32_t iu;
    std::uint64_t startHi = 0;
    if (format & 1) {   // extended
        in.inodeSize = 64;
        in.size = loadLe64(p + 8);
        iu = loadLe32(p + 16);
        in.ino = loadLe32(p + 20);
        in.uid = loadLe32(p + 24);
        in.gid = loadLe32(p + 28);
        in.mtime = loadLe64(p + 32);
        in.nlink = loadLe32(p + 44);
        startHi = nb;
    } else {
        in.inodeSize = 32;
        in.size = loadLe32(p + 8);
        in.mtime = m_epoch + loadLe32(p + 12);
        iu = loadLe32(p + 16);
        in.ino = loadLe32(p + 20);
        in.uid = loadLe16(p + 24);
        in.gid = loadLe16(p + 26);
        if (modeType(in.mode) != FileType::Directory && ((format >> 4) & 1)) {
            in.nlink = 1;
            startHi = nb;
        } else {
            in.nlink = nb;
        }
    }
    if (!(m_featureIncompat & kIncompat48Bit)) startHi = 0;
    if (in.layout == kLayoutPlain || in.layout == kLayoutInline) in.startBlock = iu | (startHi << 32);
    else if (in.layout == kLayoutChunk) in.chunkFormat = static_cast<std::uint16_t>(iu & 0xFFFF);
    m_inodes[nid] = in;
    return in;
}

// ---------------------------------------------------------------- uncompressed data

Expected<void> ErofsReader::readRaw(const InodeRec& in, std::uint64_t offset, std::span<std::byte> dst) {
    std::memset(dst.data(), 0, dst.size());
    if (in.layout == kLayoutPlain || in.layout == kLayoutInline) {
        const std::uint64_t fullBlocks = in.layout == kLayoutInline ? in.size >> m_blkszBits : (in.size + m_blockSize - 1) >> m_blkszBits;
        const std::uint64_t blockBytes = fullBlocks << m_blkszBits;
        std::uint64_t pos = offset;
        std::size_t done = 0;
        if (pos < blockBytes) {
            const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size(), blockBytes - pos));
            if (auto r = m_device->readAt((in.startBlock << m_blkszBits) + pos, dst.subspan(0, n)); !r) return fail(r.error());
            pos += n;
            done += n;
        }
        if (done < dst.size() && in.layout == kLayoutInline) {
            const std::uint64_t tailAt = in.iloc + in.inodeSize + in.xattrSize + (pos - blockBytes);
            if (auto r = m_device->readAt(tailAt, dst.subspan(done)); !r) return fail(r.error());
        }
        return {};
    }
    if (in.layout == kLayoutChunk) {
        const unsigned chunkBits = (in.chunkFormat & 0x1F) + m_blkszBits;
        const bool indexes = (in.chunkFormat & 0x20) != 0;
        const std::uint64_t chunkSize = std::uint64_t{1} << chunkBits;
        const std::size_t entrySize = indexes ? 8 : 4;
        const std::uint64_t chunks = (in.size + chunkSize - 1) >> chunkBits;
        auto table = readMeta(in.iloc + in.inodeSize + in.xattrSize, static_cast<std::size_t>(chunks * entrySize));
        if (!table) return fail(table.error());
        std::size_t done = 0;
        while (done < dst.size()) {
            const std::uint64_t pos = offset + done, ci = pos >> chunkBits, inChunk = pos & (chunkSize - 1);
            const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size() - done, chunkSize - inChunk));
            if (ci >= chunks) break;
            const std::byte* e = table->data() + ci * entrySize;
            std::uint64_t blk = indexes ? loadLe32(e + 4) : loadLe32(e);
            if (indexes && (m_featureIncompat & kIncompat48Bit)) blk |= std::uint64_t{loadLe16(e)} << 32;
            if (blk != kNullAddr) {
                if (auto r = m_device->readAt((blk << m_blkszBits) + inChunk, dst.subspan(done, n)); !r) return fail(r.error());
            }
            done += n;
        }
        return {};
    }
    return fail(ErrorCategory::InvalidFormat, "not an uncompressed erofs layout");
}

// ---------------------------------------------------------------- z_erofs mapping

Expected<void> ErofsReader::zInit(InodeRec& in) {
    if (in.zInit) return {};
    const std::uint64_t pos = roundUp(in.iloc + in.inodeSize + in.xattrSize, 8);
    auto h = readMeta(pos, 8);
    if (!h) return fail(h.error());
    const std::byte* p = h->data();
    const std::uint8_t clusterBits = std::to_integer<std::uint8_t>(p[7]);
    if (clusterBits >> 7) {
        in.zWholeInPacked = true;
        in.zAdvise = kAdviseFragment;
        in.zFragmentOff = loadLe64(p) ^ (std::uint64_t{1} << 63);
        in.zTailHeadLcn = 0;
        in.zInit = true;
        m_inodes[in.nid] = in;
        return {};
    }
    in.zAdvise = loadLe16(p + 4);
    in.zLclusterBits = static_cast<std::uint8_t>(m_blkszBits + (clusterBits & 15));
    if (in.layout == kLayoutCompressedFull && (in.zAdvise & kAdviseExtents)) return fail(ErrorCategory::Unsupported, "erofs extent-based compressed inodes (erofs-utils 1.9+) are not supported yet");
    const std::uint8_t at = std::to_integer<std::uint8_t>(p[6]);
    in.zAlg[0] = at & 15;
    in.zAlg[1] = at >> 4;
    if (in.zAdvise & kAdviseFragment) in.zFragmentOff = loadLe32(p);
    else if (in.zAdvise & kAdviseInlinePcluster) in.zIdataSize = loadLe16(p + 2);
    in.zInit = true;
    if (in.zIdataSize || (in.zAdvise & kAdviseFragment)) {
        auto tail = mapBlocks(in, 0, true);
        if (!tail) return fail(tail.error());
    }
    m_inodes[in.nid] = in;
    return {};
}

Expected<ErofsReader::Lcluster> ErofsReader::loadFullLcluster(const InodeRec& in, std::uint64_t lcn) {
    const std::uint64_t pos = roundUp(in.iloc + in.inodeSize + in.xattrSize, 8) + 8 + 8 + lcn * 8;
    auto d = readMeta(pos, 8);
    if (!d) return fail(d.error());
    const std::byte* p = d->data();
    Lcluster m;
    m.lcn = lcn;
    m.nextPackOff = pos + 8;
    const std::uint16_t advise = loadLe16(p);
    m.type = advise & 3;
    if (m.type == kTypeNonhead) {
        m.clusterOfs = 1u << in.zLclusterBits;
        m.delta[0] = loadLe16(p + 4);
        if (m.delta[0] & kD0Cblkcnt) {
            if (!(in.zAdvise & (kAdviseBigPcluster1 | kAdviseBigPcluster2))) return fail(ErrorCategory::InvalidFormat, "erofs CBLKCNT without big pcluster");
            m.compressedBlocks = m.delta[0] & ~kD0Cblkcnt;
            m.delta[0] = 1;
        }
        m.delta[1] = loadLe16(p + 6);
    } else {
        m.partialRef = (advise & kPartialRef) != 0;
        m.clusterOfs = loadLe16(p + 2);
        m.pblk = loadLe32(p + 4);
    }
    return m;
}

Expected<ErofsReader::Lcluster> ErofsReader::loadCompactLcluster(const InodeRec& in, std::uint64_t lcn, bool lookahead) {
    const std::uint64_t ebase = 8 + roundUp(in.iloc + in.inodeSize + in.xattrSize, 8);
    const unsigned lclusterBits = in.zLclusterBits;
    const std::uint64_t totalIdx = (in.size + m_blockSize - 1) >> m_blkszBits;
    if (lcn >= totalIdx || lclusterBits > 14) return fail(ErrorCategory::InvalidFormat, "erofs lcluster index out of range");
    const bool bigPcluster = (in.zAdvise & kAdviseBigPcluster1) != 0;
    Lcluster m;
    m.lcn = lcn;
    const std::uint64_t compacted4bInitial = ((32 - ebase % 32) / 4) & 7;
    std::uint64_t compacted2b = 0;
    if ((in.zAdvise & kAdviseCompacted2B) && compacted4bInitial < totalIdx) compacted2b = (totalIdx - compacted4bInitial) / 16 * 16;
    std::uint64_t pos = ebase;
    unsigned amortizedShift = 2;
    if (lcn >= compacted4bInitial) {
        pos += compacted4bInitial * 4;
        lcn -= compacted4bInitial;
        if (lcn < compacted2b) {
            amortizedShift = 1;
        } else {
            pos += compacted2b * 2;
            lcn -= compacted2b;
        }
    }
    pos += lcn << amortizedShift;
    unsigned vcnt;
    if (amortizedShift == 2 && lclusterBits <= 14) vcnt = 2;
    else if (amortizedShift == 1 && lclusterBits <= 12) vcnt = 16;
    else return fail(ErrorCategory::Unsupported, "erofs compacted index with unsupported lcluster size");
    const std::size_t packSize = vcnt << amortizedShift;
    m.nextPackOff = pos / packSize * packSize + packSize;
    const unsigned lobits = std::max<unsigned>(lclusterBits, 12), encodeBits = static_cast<unsigned>(((packSize - 4) * 8) / vcnt);
    const std::size_t bytes = pos & (packSize - 1);
    auto pack = readMeta(pos - bytes, packSize);
    if (!pack) return fail(pack.error());
    const std::uint8_t* inp = reinterpret_cast<const std::uint8_t*>(pack->data());
    auto decode = [&](unsigned idx, std::uint8_t& type) -> std::uint32_t {
        const unsigned bit = encodeBits * idx;
        std::uint32_t v = 0;
        for (unsigned b = 0; b < 4 && bit / 8 + b < packSize; ++b) v |= std::uint32_t{inp[bit / 8 + b]} << (8 * b);
        v >>= (bit & 7);
        type = static_cast<std::uint8_t>((v >> lobits) & 3);
        return v & ((1u << lobits) - 1);
    };
    int i = static_cast<int>(bytes >> amortizedShift);
    std::uint8_t type;
    std::uint32_t lo = decode(static_cast<unsigned>(i), type);
    m.type = type;
    if (type == kTypeNonhead) {
        m.clusterOfs = 1u << lclusterBits;
        if (lookahead) {
            unsigned d1 = 0;
            std::uint32_t llo = lo;
            std::uint8_t t;
            int j = i;
            bool ended = false;
            do {
                llo = decode(static_cast<unsigned>(j), t);
                if (t != kTypeNonhead) {
                    m.delta[1] = d1;
                    ended = true;
                    break;
                }
                ++d1;
            } while (++j < static_cast<int>(vcnt));
            if (!ended) {
                if (!(llo & kD0Cblkcnt)) d1 += llo - 1;
                m.delta[1] = d1;
            }
        }
        if (lo & kD0Cblkcnt) {
            if (!bigPcluster) return fail(ErrorCategory::InvalidFormat, "erofs CBLKCNT without big pcluster");
            m.compressedBlocks = lo & ~kD0Cblkcnt;
            m.delta[0] = 1;
            return m;
        }
        if (i + 1 != static_cast<int>(vcnt)) {
            m.delta[0] = lo;
            return m;
        }
        // The last lcluster of a pack stores delta[1] in lo; derive delta[0] from the previous one.
        lo = decode(static_cast<unsigned>(i - 1), type);
        if (type != kTypeNonhead) lo = 0;
        else if (lo & kD0Cblkcnt) lo = 1;
        m.delta[0] = lo + 1;
        return m;
    }
    m.clusterOfs = lo;
    m.delta[0] = 0;
    std::uint32_t nblk;
    if (!bigPcluster) {
        nblk = 1;
        while (i > 0) {
            --i;
            lo = decode(static_cast<unsigned>(i), type);
            if (type == kTypeNonhead) i -= static_cast<int>(lo);
            if (i >= 0) ++nblk;
        }
    } else {
        nblk = 0;
        while (i > 0) {
            --i;
            lo = decode(static_cast<unsigned>(i), type);
            if (type == kTypeNonhead) {
                if (lo & kD0Cblkcnt) {
                    --i;
                    nblk += lo & ~kD0Cblkcnt;
                    continue;
                }
                if (lo <= 1) return fail(ErrorCategory::InvalidFormat, "erofs big pcluster with a plain delta");
                i -= static_cast<int>(lo) - 2;
                continue;
            }
            ++nblk;
        }
    }
    m.pblk = loadLe32(pack->data() + packSize - 4) + nblk;
    return m;
}

Expected<ErofsReader::Lcluster> ErofsReader::loadLcluster(const InodeRec& in, std::uint64_t lcn, bool lookahead) {
    auto m = in.layout == kLayoutCompressedCompact ? loadCompactLcluster(in, lcn, lookahead) : loadFullLcluster(in, lcn);
    if (!m) return m;
    if (m->type != kTypeNonhead && m->clusterOfs >= (1u << in.zLclusterBits)) return fail(ErrorCategory::InvalidFormat, "erofs cluster offset beyond the lcluster");
    return m;
}

Expected<ErofsReader::Map> ErofsReader::mapBlocks(InodeRec& in, std::uint64_t la, bool findTail) {
    Map map;
    const bool fragment = (in.zAdvise & kAdviseFragment) != 0;
    const bool ztailpacking = in.zIdataSize != 0;
    const unsigned lclusterBits = in.zLclusterBits;
    const std::uint64_t ofs = findTail ? in.size - 1 : la;
    if (fragment && !findTail && in.zTailHeadLcn == 0 && !in.zWholeInPacked) {
        // Only reached for inodes whose whole content is a fragment; handled by the caller.
    }
    const std::uint64_t initialLcn = ofs >> lclusterBits;
    const std::uint32_t endoff = static_cast<std::uint32_t>(ofs & ((std::uint64_t{1} << lclusterBits) - 1));
    auto m = loadLcluster(in, initialLcn, false);
    if (!m) return fail(m.error());
    if (findTail && ztailpacking) in.zIdataPos = m->nextPackOff;
    map.mapped = map.encoded = true;
    std::uint64_t end = (m->lcn + 1) << lclusterBits;
    std::uint8_t headType = m->type;
    Lcluster head = *m;
    if (m->type == kTypePlain || m->type == kTypeHead1 || m->type == kTypeHead2) {
        if (endoff >= m->clusterOfs) {
            map.la = (m->lcn << lclusterBits) | m->clusterOfs;
            if (ztailpacking && end > in.size) end = in.size;
        } else {
            if (m->lcn == 0) return fail(ErrorCategory::InvalidFormat, "erofs lcluster 0 with a cluster offset");
            end = (m->lcn << lclusterBits) | m->clusterOfs;
            map.fullMapped = true;
            // look back one lcluster for the head
            std::uint32_t lookback = 1;
            for (;;) {
                if (head.lcn < lookback) return fail(ErrorCategory::InvalidFormat, "erofs lookback runs before the file");
                auto prev = loadLcluster(in, head.lcn - lookback, false);
                if (!prev) return fail(prev.error());
                head = *prev;
                if (head.type == kTypeNonhead) {
                    lookback = head.delta[0];
                    if (!lookback) return fail(ErrorCategory::InvalidFormat, "erofs zero lookback distance");
                    continue;
                }
                headType = head.type;
                map.la = (head.lcn << lclusterBits) | head.clusterOfs;
                break;
            }
        }
    } else if (m->type == kTypeNonhead) {
        std::uint32_t lookback = m->delta[0];
        for (;;) {
            if (!lookback || head.lcn < lookback) return fail(ErrorCategory::InvalidFormat, "erofs bogus lookback distance");
            auto prev = loadLcluster(in, head.lcn - lookback, false);
            if (!prev) return fail(prev.error());
            head = *prev;
            if (head.type == kTypeNonhead) {
                lookback = head.delta[0];
                continue;
            }
            headType = head.type;
            map.la = (head.lcn << lclusterBits) | head.clusterOfs;
            break;
        }
    } else {
        return fail(ErrorCategory::InvalidFormat, "unknown erofs lcluster type");
    }
    map.partialRef = head.partialRef;
    map.llen = end - map.la;
    if (findTail) {
        in.zTailHeadLcn = head.lcn;
        if (fragment && in.layout == kLayoutCompressedFull) in.zFragmentOff |= std::uint64_t{head.pblk} << 32;
    }
    if (ztailpacking && head.lcn == in.zTailHeadLcn) {
        map.meta = true;
        map.pa = in.zIdataPos;
        map.plen = in.zIdataSize;
    } else if (fragment && head.lcn == in.zTailHeadLcn) {
        map.fragment = true;
    } else {
        map.pa = std::uint64_t{head.pblk} << m_blkszBits;
        // compressed length: one block unless a CBLKCNT follows the head
        const bool bigpcl1 = (in.zAdvise & kAdviseBigPcluster1) != 0, bigpcl2 = (in.zAdvise & kAdviseBigPcluster2) != 0;
        std::uint32_t compressedBlocks = head.compressedBlocks;
        const std::uint64_t nextLcn = head.lcn + 1;
        if ((headType == kTypeHead1 && !bigpcl1) || ((headType == kTypePlain || headType == kTypeHead2) && !bigpcl2) || (nextLcn << lclusterBits) >= in.size)
            compressedBlocks = 1;
        if (!compressedBlocks) {
            auto next = loadLcluster(in, nextLcn, false);
            if (!next) return fail(next.error());
            if (next->type == kTypeNonhead) {
                if (next->delta[0] != 1) return fail(ErrorCategory::InvalidFormat, "erofs bogus CBLKCNT");
                compressedBlocks = next->compressedBlocks;
                if (!compressedBlocks) return fail(ErrorCategory::InvalidFormat, "erofs CBLKCNT not found");
            } else {
                compressedBlocks = 1;
            }
        }
        map.plen = std::uint64_t{compressedBlocks} << m_blkszBits;
    }
    if (headType == kTypePlain) {
        if (map.llen > map.plen) return fail(ErrorCategory::InvalidFormat, "erofs plain lcluster longer than its data");
        map.alg = (in.zAdvise & kAdviseInterlaced) ? kAlgInterlaced : kAlgShifted;
    } else if (headType == kTypeHead2) {
        map.alg = in.zAlg[1];
    } else {
        map.alg = in.zAlg[0];
    }
    // Decompressed length: walk forward to the next head lcluster.
    {
        std::uint64_t lcn = head.lcn;
        const std::uint64_t headLcn = map.la >> lclusterBits;
        std::uint32_t clusterOfs = 0;
        for (;;) {
            if ((lcn << lclusterBits) >= in.size) {
                map.llen = in.size - map.la;
                map.fullMapped = true;
                return map;
            }
            auto c = loadLcluster(in, lcn, true);
            if (!c) return fail(c.error());
            std::uint32_t step;
            if (c->type == kTypeNonhead) {
                step = c->delta[1] ? c->delta[1] : 1;
            } else {
                if (lcn != headLcn) {
                    clusterOfs = c->clusterOfs;
                    break;
                }
                step = 1;
            }
            lcn += step;
        }
        map.llen = (lcn << lclusterBits) + clusterOfs - map.la;
        map.fullMapped = true;
    }
    return map;
}

// ---------------------------------------------------------------- reads

Expected<void> ErofsReader::readCompressed(InodeRec& in, std::uint64_t offset, std::span<std::byte> dst, int depth) {
    if (auto r = zInit(in); !r) return r;
    in = m_inodes[in.nid];
    if (in.zWholeInPacked) {
        if (depth > 1 || m_packedNid == 0) return fail(ErrorCategory::InvalidFormat, "erofs fragment without a packed inode");
        auto packed = inode(m_packedNid);
        if (!packed) return fail(packed.error());
        return readData(*packed, in.zFragmentOff + offset, dst, depth + 1);
    }
    std::uint64_t end = offset + dst.size();
    std::vector<std::byte> raw, decoded;
    while (end > offset) {
        auto map = mapBlocks(in, end - 1, false);
        if (!map) return fail(map.error());
        bool trimmed = false;
        std::uint64_t length;
        if (end < map->la + map->llen) {
            length = end - map->la;
            trimmed = true;
        } else {
            length = map->llen;
        }
        std::uint64_t skip;
        if (map->la < offset) {
            skip = offset - map->la;
            end = offset;
        } else {
            skip = 0;
            end = map->la;
        }
        std::span<std::byte> out = dst.subspan(static_cast<std::size_t>(end - offset), static_cast<std::size_t>(length - skip));
        if (map->fragment) {
            if (depth > 1 || m_packedNid == 0) return fail(ErrorCategory::InvalidFormat, "erofs fragment without a packed inode");
            auto packed = inode(m_packedNid);
            if (!packed) return fail(packed.error());
            if (auto r = readData(*packed, in.zFragmentOff + skip, out, depth + 1); !r) return r;
            continue;
        }
        if (map->plen > (1u << 20) || length > (12u << 20)) return fail(ErrorCategory::InvalidFormat, "erofs pcluster larger than the format allows");
        raw.resize(static_cast<std::size_t>(map->plen));
        if (auto r = m_device->readAt(map->pa, raw); !r) return fail(r.error());
        // Without the LZ4_0PADDING feature the payload sits at the front of the pcluster with zero
        // padding after it, so lz4 must stop at the output size instead of the input end.
        const bool partial = trimmed || !map->fullMapped || map->partialRef || (map->alg == kAlgLz4 && !(m_featureIncompat & kIncompatLz4ZeroPadding));
        if (map->alg == kAlgShifted || map->alg == kAlgInterlaced) {
            if (length > map->plen) return fail(ErrorCategory::InvalidFormat, "erofs plain pcluster shorter than its data");
            const std::size_t count = static_cast<std::size_t>(length - skip);
            if (map->alg == kAlgShifted) {
                std::memcpy(out.data(), raw.data() + skip, count);
            } else {
                const std::uint64_t interlacedOff = map->la & (m_blockSize - 1);
                const std::size_t s = static_cast<std::size_t>((interlacedOff + skip) & (m_blockSize - 1));
                const std::size_t right = std::min<std::size_t>(m_blockSize - s, count);
                std::memcpy(out.data(), raw.data() + s, right);
                std::memcpy(out.data() + right, raw.data(), count - right);
            }
            continue;
        }
        if (map->alg < 4 && !(m_availableAlgs & (1u << map->alg))) return fail(ErrorCategory::InvalidFormat, "erofs inode uses an algorithm the image does not announce");
        std::size_t margin = 0;
        if (map->alg != kAlgLz4 || (m_featureIncompat & kIncompatLz4ZeroPadding))
            while (margin < raw.size() && raw[margin] == std::byte{0}) ++margin;
        if (margin >= raw.size()) return fail(ErrorCategory::InvalidFormat, "erofs pcluster is all padding");
        const std::span<const std::byte> input(raw.data() + margin, raw.size() - margin);
        decoded.resize(static_cast<std::size_t>(length));
        Expected<std::size_t> n;
        switch (map->alg) {
        case kAlgLz4: n = partial ? lz4::decompressPartial(input, decoded) : [&]() -> Expected<std::size_t> {
            auto r = lz4::decompress(input, decoded);
            if (!r) return fail(r.error());
            return decoded.size();
        }(); break;
        case kAlgLzma: n = compress::lzmaMicroDecompress(input, decoded, partial); break;
        case kAlgDeflate: n = partial ? compress::inflateRawPartial(input, decoded) : compress::inflateRaw(input, decoded); break;
        case kAlgZstd: n = compress::zstdDecompressFrame(input, decoded); break;
        default: return fail(ErrorCategory::Unsupported, "unknown erofs compression algorithm " + std::to_string(map->alg));
        }
        if (!n) return fail(ErrorCategory::InvalidFormat, "erofs pcluster: " + std::string(n.error().message()));
        if (*n != decoded.size()) return fail(ErrorCategory::InvalidFormat, "erofs pcluster decoded to " + std::to_string(*n) + " bytes, expected " + std::to_string(decoded.size()));
        std::memcpy(out.data(), decoded.data() + skip, static_cast<std::size_t>(length - skip));
    }
    return {};
}

Expected<void> ErofsReader::readData(InodeRec& in, std::uint64_t offset, std::span<std::byte> dst, int depth) {
    if (in.layout == kLayoutCompressedFull || in.layout == kLayoutCompressedCompact) return readCompressed(in, offset, dst, depth);
    return readRaw(in, offset, dst);
}

Expected<std::vector<DirEntry>> ErofsReader::readdir(const Inode& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    auto in = inode(dir.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    std::vector<std::byte> block(m_dirBlockSize);
    for (std::uint64_t pos = 0; pos < in->size; pos += m_dirBlockSize) {
        const std::size_t len = static_cast<std::size_t>(std::min<std::uint64_t>(m_dirBlockSize, in->size - pos));
        auto rd = readData(*in, pos, std::span<std::byte>(block).subspan(0, len), 0);
        if (!rd) return fail(rd.error());
        const std::byte* p = block.data();
        if (len < 12) break;
        const std::uint16_t nameOff0 = loadLe16(p + 8);
        if (nameOff0 < 12 || nameOff0 > len || nameOff0 % 12 != 0) return fail(ErrorCategory::InvalidFormat, "bad erofs directory block");
        const std::size_t count = nameOff0 / 12;
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint64_t nid = loadLe64(p + i * 12) & 0x7FFFFFFFFFFFFFFFull;
            const std::uint16_t nameOff = loadLe16(p + i * 12 + 8);
            const std::uint8_t type = std::to_integer<std::uint8_t>(p[i * 12 + 10]);
            std::size_t nameEnd = i + 1 < count ? loadLe16(p + (i + 1) * 12 + 8) : len;
            if (nameOff > len || nameEnd > len || nameEnd < nameOff) return fail(ErrorCategory::InvalidFormat, "bad erofs directory entry");
            std::string name(reinterpret_cast<const char*>(p) + nameOff, nameEnd - nameOff);
            if (i + 1 == count) name.resize(std::strlen(name.c_str()));   // the last name is NUL padded to the block end
            if (name == "." || name == "..") continue;
            out.push_back(DirEntry{std::move(name), Inode{nid}, direntType(type)});
        }
    }
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> ErofsReader::lookup(const Inode& dir, std::string_view name) {
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> ErofsReader::stat(const Inode& ino) {
    auto in = inode(ino.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = modeType(in->mode);
    st.mode = in->mode & 07777;
    st.nlink = in->nlink;
    st.uid = in->uid;
    st.gid = in->gid;
    st.size = st.type == FileType::Directory ? 0 : in->size;
    st.allocatedBytes = st.type == FileType::File ? (in->size + 511) / 512 * 512 : 0;
    st.mtime = st.atime = st.ctime = static_cast<std::int64_t>(in->mtime);
    return st;
}

Expected<std::size_t> ErofsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = inode(file.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= in->size) return 0;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size(), in->size - offset));
    if (auto r = readData(*in, offset, dst.subspan(0, n), 0); !r) return fail(r.error());
    return n;
}

Expected<std::string> ErofsReader::readlink(const Inode& link) {
    auto in = inode(link.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (in->size > 4096) return fail(ErrorCategory::InvalidFormat, "erofs symlink target longer than 4096 bytes");
    std::string target(static_cast<std::size_t>(in->size), '\0');
    if (auto r = readData(*in, 0, std::span<std::byte>(reinterpret_cast<std::byte*>(target.data()), target.size()), 0); !r) return fail(r.error());
    return target;
}

class ErofsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = ErofsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeErofsReaderSource() { return std::make_unique<ErofsReaderSource>(); }

} // namespace stein::fs::detail
