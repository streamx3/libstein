// SPDX-License-Identifier: MIT
// XFS reader: superblock geometry, v2/v3 inodes (bigtime, nrext64), data
// forks in local, extents and B+tree form, directories in shortform, block,
// leaf and node form (data blocks below the 32 GiB leaf offset), inline and
// remote symlinks.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/xfs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint16_t kInodeMagic = 0x494E;   // "IN"
constexpr std::uint8_t kFormatLocal = 1, kFormatExtents = 2, kFormatBtree = 3;
constexpr std::uint32_t kIncompatFtype = 0x1, kIncompatBigtime = 0x8, kIncompatNrext64 = 0x20;
constexpr std::uint64_t kDirLeafOffset = 32ull * 1024 * 1024 * 1024;   // XFS_DIR2_LEAF_OFFSET
constexpr std::int64_t kBigtimeEpochOffset = -2147483648ll;            // bigtime zero = 1901-12-13T20:45:52Z

std::int64_t legacyTime(const std::byte* p) { return static_cast<std::int32_t>(loadBe32(p)); }
std::int64_t bigTime(const std::byte* p) { return static_cast<std::int64_t>(loadBe64(p) / 1000000000ull) + kBigtimeEpochOffset; }

std::string magic4(const std::byte* p) { return std::string(reinterpret_cast<const char*>(p), 4); }

FileType ftypeOf(std::uint8_t t) {
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

FileType modeType(std::uint16_t mode) {
    switch (mode & 0170000) {
    case 0040000: return FileType::Directory;
    case 0120000: return FileType::Symlink;
    case 0020000: return FileType::CharDevice;
    case 0060000: return FileType::BlockDevice;
    case 0010000: return FileType::Fifo;
    case 0140000: return FileType::Socket;
    default: return FileType::File;
    }
}
} // namespace

Expected<std::unique_ptr<XfsReader>> XfsReader::open(std::shared_ptr<BlockDevice> device) {
    auto raw = device->read(0, 512);
    if (!raw) return fail(raw.error());
    const std::byte* sb = raw->data();
    if (magic4(sb) != "XFSB") return fail(ErrorCategory::InvalidFormat, "not an XFS superblock");
    auto r = std::unique_ptr<XfsReader>(new XfsReader());
    r->m_device = std::move(device);
    r->m_blockSize = loadBe32(sb + 4);
    r->m_rootIno = loadBe64(sb + 56);
    r->m_agBlocks = loadBe32(sb + 84);
    r->m_agCount = loadBe32(sb + 88);
    const std::uint16_t versionnum = loadBe16(sb + 100);
    r->m_inodeSize = loadBe16(sb + 104);
    r->m_blockLog = std::to_integer<std::uint8_t>(sb[120]);
    r->m_inopBlog = std::to_integer<std::uint8_t>(sb[123]);
    r->m_agBlkLog = std::to_integer<std::uint8_t>(sb[124]);
    const std::uint8_t dirblklog = std::to_integer<std::uint8_t>(sb[192]);
    const std::uint32_t features2 = loadBe32(sb + 200);
    const std::uint32_t incompat = loadBe32(sb + 216);
    r->m_v5 = (versionnum & 0xF) == 5;
    r->m_ftype = r->m_v5 ? (incompat & kIncompatFtype) != 0 : (features2 & 0x200) != 0;   // XFS_SB_VERSION2_FTYPE
    r->m_bigtime = r->m_v5 && (incompat & kIncompatBigtime);
    r->m_nrext64 = r->m_v5 && (incompat & kIncompatNrext64);
    if (r->m_blockSize < 512 || r->m_blockSize > 65536 || (r->m_blockSize & (r->m_blockSize - 1)) || r->m_inodeSize < 256 || r->m_agBlocks == 0)
        return fail(ErrorCategory::InvalidFormat, "implausible XFS geometry");
    r->m_dirBlockSize = r->m_blockSize << dirblklog;
    return r;
}

ByteCount XfsReader::fsbToByte(std::uint64_t fsb) const {
    const std::uint64_t agno = fsb >> m_agBlkLog, agbno = fsb & ((std::uint64_t{1} << m_agBlkLog) - 1);
    return (agno * m_agBlocks + agbno) * m_blockSize;
}

ByteCount XfsReader::inoToByte(std::uint64_t ino) const {
    const unsigned agShift = m_agBlkLog + m_inopBlog;
    const std::uint64_t agno = ino >> agShift, agino = ino & ((std::uint64_t{1} << agShift) - 1);
    const std::uint64_t agbno = agino >> m_inopBlog, idx = agino & ((std::uint64_t{1} << m_inopBlog) - 1);
    return (agno * m_agBlocks + agbno) * m_blockSize + idx * m_inodeSize;
}

Expected<XfsReader::InodeRec> XfsReader::readInode(std::uint64_t ino) {
    if (auto it = m_cache.find(ino); it != m_cache.end()) return it->second;
    if ((ino >> (m_agBlkLog + m_inopBlog)) >= m_agCount) return fail(ErrorCategory::InvalidArgument, "inode " + std::to_string(ino) + " outside the allocation groups");
    auto raw = m_device->read(inoToByte(ino), m_inodeSize);
    if (!raw) return fail(raw.error());
    const std::byte* d = raw->data();
    if (loadBe16(d) != kInodeMagic) return fail(ErrorCategory::InvalidFormat, "inode " + std::to_string(ino) + " has no IN magic");
    InodeRec in;
    in.ino = ino;
    in.mode = loadBe16(d + 2);
    in.version = std::to_integer<std::uint8_t>(d[4]);
    in.format = std::to_integer<std::uint8_t>(d[5]);
    in.uid = loadBe32(d + 8);
    in.gid = loadBe32(d + 12);
    in.nlink = in.version >= 2 ? loadBe32(d + 16) : loadBe16(d + 6);
    if (m_bigtime) {
        in.atime = bigTime(d + 32);
        in.mtime = bigTime(d + 40);
        in.ctime = bigTime(d + 48);
    } else {
        in.atime = legacyTime(d + 32);
        in.mtime = legacyTime(d + 40);
        in.ctime = legacyTime(d + 48);
    }
    in.size = loadBe64(d + 56);
    in.nblocks = loadBe64(d + 64);
    in.nextents = m_nrext64 ? loadBe64(d + 24) : loadBe32(d + 76);
    in.forkoff = std::to_integer<std::uint8_t>(d[82]);
    if (in.version >= 3) in.crtime = m_bigtime ? bigTime(d + 144) : legacyTime(d + 144);
    in.forkOffset = in.version >= 3 ? 176 : 96;
    if (in.forkOffset > m_inodeSize) return fail(ErrorCategory::InvalidFormat, "inode smaller than its core");
    in.forkSize = in.forkoff ? std::min<std::size_t>(std::size_t{in.forkoff} * 8, m_inodeSize - in.forkOffset) : m_inodeSize - in.forkOffset;
    in.raw = std::move(*raw);
    m_cache[ino] = in;
    return in;
}

void XfsReader::decodeExtent(const std::byte* rec, Extent& e) {
    const std::uint64_t l0 = loadBe64(rec), l1 = loadBe64(rec + 8);
    e.unwritten = (l0 >> 63) != 0;
    e.startoff = (l0 & 0x7FFFFFFFFFFFFFFFull) >> 9;
    e.startblock = ((l0 & 0x1FFull) << 43) | (l1 >> 21);
    e.blockcount = l1 & 0x1FFFFFull;
}

Expected<void> XfsReader::walkBmbt(std::uint64_t fsb, int level, std::vector<Extent>& out, int depth) {
    if (depth > 16) return fail(ErrorCategory::InvalidFormat, "bmap B+tree too deep");
    auto blk = m_device->read(fsbToByte(fsb), m_blockSize);
    if (!blk) return fail(blk.error());
    const std::byte* b = blk->data();
    const std::string magic = magic4(b);
    std::size_t hdr = 0;
    if (magic == "BMA3") hdr = 72;
    else if (magic == "BMAP") hdr = 24;
    else return fail(ErrorCategory::InvalidFormat, "bmap block without BMAP/BMA3 magic");
    const std::uint16_t bbLevel = loadBe16(b + 4), numrecs = loadBe16(b + 6);
    if (bbLevel != level) return fail(ErrorCategory::InvalidFormat, "bmap block level mismatch");
    if (level == 0) {
        for (std::uint16_t i = 0; i < numrecs && hdr + (i + 1) * 16 <= m_blockSize; ++i) {
            Extent e;
            decodeExtent(b + hdr + i * 16, e);
            out.push_back(e);
        }
        return {};
    }
    const std::size_t maxrecs = (m_blockSize - hdr) / 16;
    if (numrecs > maxrecs) return fail(ErrorCategory::InvalidFormat, "bmap node overfull");
    const std::byte* ptrs = b + hdr + maxrecs * 8;
    for (std::uint16_t i = 0; i < numrecs; ++i)
        if (auto w = walkBmbt(loadBe64(ptrs + i * 8), level - 1, out, depth + 1); !w) return w;
    return {};
}

Expected<std::vector<XfsReader::Extent>> XfsReader::extentsOf(const InodeRec& in) {
    std::vector<Extent> out;
    const auto fork = in.fork();
    if (in.format == kFormatExtents) {
        const std::uint64_t n = std::min<std::uint64_t>(in.nextents, fork.size() / 16);
        for (std::uint64_t i = 0; i < n; ++i) {
            Extent e;
            decodeExtent(fork.data() + i * 16, e);
            out.push_back(e);
        }
    } else if (in.format == kFormatBtree) {
        if (fork.size() < 4) return fail(ErrorCategory::InvalidFormat, "bmap root too small");
        const std::uint16_t level = loadBe16(fork.data()), numrecs = loadBe16(fork.data() + 2);
        const std::size_t maxrecs = (fork.size() - 4) / 16;
        if (level == 0 || numrecs > maxrecs) return fail(ErrorCategory::InvalidFormat, "implausible bmap root");
        const std::byte* ptrs = fork.data() + 4 + maxrecs * 8;
        for (std::uint16_t i = 0; i < numrecs; ++i)
            if (auto w = walkBmbt(loadBe64(ptrs + i * 8), level - 1, out, 0); !w) return fail(w.error());
    } else if (in.format != kFormatLocal) {
        return fail(ErrorCategory::Unsupported, "inode data fork format " + std::to_string(in.format) + " is not readable");
    }
    std::sort(out.begin(), out.end(), [](const Extent& a, const Extent& b) { return a.startoff < b.startoff; });
    return out;
}

Expected<void> XfsReader::readMapped(const std::vector<Extent>& extents, std::uint64_t offset, std::span<std::byte> dst) const {
    std::memset(dst.data(), 0, dst.size());
    std::uint64_t done = 0;
    while (done < dst.size()) {
        const std::uint64_t pos = offset + done, block = pos >> m_blockLog, inBlock = pos & (m_blockSize - 1);
        const Extent* hit = nullptr;
        std::uint64_t nextStart = ~0ull;
        for (const auto& e : extents) {
            if (block >= e.startoff && block < e.startoff + e.blockcount) {
                hit = &e;
                break;
            }
            if (e.startoff > block) nextStart = std::min(nextStart, e.startoff);
        }
        if (!hit) {
            // Hole: zeros up to the next extent (or the end of the request).
            const std::uint64_t holeEnd = nextStart == ~0ull ? offset + dst.size() : (nextStart << m_blockLog);
            done += std::min<std::uint64_t>(holeEnd - pos, dst.size() - done);
            continue;
        }
        const std::uint64_t inExtent = ((block - hit->startoff) << m_blockLog) + inBlock;
        const std::uint64_t n = std::min<std::uint64_t>((hit->blockcount << m_blockLog) - inExtent, dst.size() - done);
        if (!hit->unwritten)
            if (auto r = m_device->readAt(fsbToByte(hit->startblock) + inExtent, dst.subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(n))); !r) return r;
        done += n;
    }
    return {};
}

Expected<std::vector<DirEntry>> XfsReader::parseDirBlock(std::span<const std::byte> block) {
    std::vector<DirEntry> out;
    const std::byte* b = block.data();
    const std::string magic = magic4(b);
    std::size_t hdr = 0, end = block.size();
    if (magic == "XDB3" || magic == "XDD3") hdr = 64;
    else if (magic == "XD2B" || magic == "XD2D") hdr = 16;
    else return fail(ErrorCategory::InvalidFormat, "directory block without a known magic (" + magic + ")");
    if (magic == "XDB3" || magic == "XD2B") {
        // Single-block directory: leaf entries and a tail share the block.
        const std::uint32_t count = loadBe32(b + block.size() - 8);
        if (std::size_t{count} * 8 + 8 > block.size()) return fail(ErrorCategory::InvalidFormat, "block directory tail overruns");
        end = block.size() - 8 - std::size_t{count} * 8;
    }
    std::size_t pos = hdr;
    while (pos + 8 <= end) {
        if (loadBe16(b + pos) == 0xFFFF) {   // unused space
            const std::uint16_t len = loadBe16(b + pos + 2);
            if (len < 8) break;
            pos += len;
            continue;
        }
        const std::uint64_t ino = loadBe64(b + pos);
        const std::uint8_t namelen = std::to_integer<std::uint8_t>(b[pos + 8]);
        const std::size_t need = 8 + 1 + namelen + (m_ftype ? 1 : 0) + 2;
        const std::size_t size = (need + 7) & ~std::size_t{7};
        if (pos + size > end || namelen == 0) break;
        std::string name(reinterpret_cast<const char*>(b + pos + 9), namelen);
        const FileType t = m_ftype ? ftypeOf(std::to_integer<std::uint8_t>(b[pos + 9 + namelen])) : FileType::Unknown;
        if (name != "." && name != "..") out.push_back(DirEntry{std::move(name), Inode{ino}, t});
        pos += size;
    }
    return out;
}

Expected<std::vector<DirEntry>> XfsReader::listDir(const InodeRec& dir) {
    if (auto it = m_dirCache.find(dir.ino); it != m_dirCache.end()) return it->second;
    if (modeType(dir.mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    if (dir.format == kFormatLocal) {
        const auto f = dir.fork();
        if (f.size() < 2) return fail(ErrorCategory::InvalidFormat, "shortform directory too small");
        const std::uint8_t count = std::to_integer<std::uint8_t>(f[0]), i8 = std::to_integer<std::uint8_t>(f[1]);
        const std::size_t inoSize = i8 ? 8 : 4;
        std::size_t pos = 2 + inoSize;   // header: count, i8count, parent
        for (std::uint8_t i = 0; i < count; ++i) {
            if (pos + 3 > f.size()) break;
            const std::uint8_t namelen = std::to_integer<std::uint8_t>(f[pos]);
            const std::size_t need = 1 + 2 + namelen + (m_ftype ? 1 : 0) + inoSize;
            if (pos + need > f.size()) break;
            std::string name(reinterpret_cast<const char*>(f.data() + pos + 3), namelen);
            std::size_t p = pos + 3 + namelen;
            FileType t = FileType::Unknown;
            if (m_ftype) t = ftypeOf(std::to_integer<std::uint8_t>(f[p++]));
            const std::uint64_t ino = inoSize == 8 ? loadBe64(f.data() + p) : loadBe32(f.data() + p);
            out.push_back(DirEntry{std::move(name), Inode{ino}, t});
            pos += need;
        }
    } else {
        auto extents = extentsOf(dir);
        if (!extents) return fail(extents.error());
        const std::uint64_t leafBlock = kDirLeafOffset >> m_blockLog;
        const std::uint64_t dirBlocks = m_dirBlockSize >> m_blockLog;
        std::vector<std::byte> block(m_dirBlockSize);
        for (const auto& e : *extents) {
            if (e.startoff >= leafBlock) continue;   // leaf / node / freeindex blocks
            for (std::uint64_t fsBlock = e.startoff; fsBlock < e.startoff + e.blockcount && fsBlock < leafBlock; fsBlock += dirBlocks) {
                if (fsBlock % dirBlocks) continue;   // directory blocks are aligned to their own size
                if (auto r = readMapped(*extents, fsBlock << m_blockLog, block); !r) return fail(r.error());
                auto entries = parseDirBlock(block);
                if (!entries) return fail(entries.error());
                out.insert(out.end(), entries->begin(), entries->end());
            }
        }
    }
    m_dirCache[dir.ino] = out;
    return out;
}

Expected<Inode> XfsReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto in = readInode(dir.id);
    if (!in) return fail(in.error());
    auto entries = listDir(*in);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> XfsReader::stat(const Inode& inode) {
    auto in = readInode(inode.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = modeType(in->mode);
    st.mode = in->mode & 07777;
    st.nlink = in->nlink;
    st.uid = in->uid;
    st.gid = in->gid;
    st.size = in->size;
    st.allocatedBytes = in->nblocks * m_blockSize;
    st.atime = in->atime;
    st.mtime = in->mtime;
    st.ctime = in->ctime;
    st.crtime = in->crtime;
    return st;
}

Expected<std::vector<DirEntry>> XfsReader::readdir(const Inode& dir) {
    auto in = readInode(dir.id);
    if (!in) return fail(in.error());
    return listDir(*in);
}

Expected<std::size_t> XfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = readInode(file.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= in->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), in->size - offset);
    if (in->format == kFormatLocal) {
        const auto f = in->fork();
        const std::uint64_t avail = std::min<std::uint64_t>(in->size, f.size());
        if (offset >= avail) return 0;
        const std::uint64_t take = std::min(n, avail - offset);
        std::memcpy(dst.data(), f.data() + offset, static_cast<std::size_t>(take));
        return static_cast<std::size_t>(take);
    }
    auto extents = extentsOf(*in);
    if (!extents) return fail(extents.error());
    if (auto r = readMapped(*extents, offset, dst.subspan(0, static_cast<std::size_t>(n))); !r) return fail(r.error());
    return static_cast<std::size_t>(n);
}

Expected<std::string> XfsReader::readlink(const Inode& link) {
    auto in = readInode(link.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (in->size > 4096) return fail(ErrorCategory::InvalidFormat, "symlink target longer than 4096 bytes");
    if (in->format == kFormatLocal) {
        const auto f = in->fork();
        return std::string(reinterpret_cast<const char*>(f.data()), std::min<std::size_t>(f.size(), static_cast<std::size_t>(in->size)));
    }
    // Remote symlink: data blocks, each with an XSLM header on v5.
    auto extents = extentsOf(*in);
    if (!extents) return fail(extents.error());
    std::string target;
    for (const auto& e : *extents) {
        for (std::uint64_t i = 0; i < e.blockcount && target.size() < in->size; ++i) {
            auto blk = m_device->read(fsbToByte(e.startblock + i), m_blockSize);
            if (!blk) return fail(blk.error());
            std::size_t hdr = 0, bytes = m_blockSize;
            if (m_v5) {
                if (magic4(blk->data()) != "XSLM") return fail(ErrorCategory::InvalidFormat, "remote symlink block without XSLM magic");
                hdr = 56;
                bytes = loadBe32(blk->data() + 8);
            }
            const std::size_t take = std::min<std::size_t>({bytes, m_blockSize - hdr, static_cast<std::size_t>(in->size) - target.size()});
            target.append(reinterpret_cast<const char*>(blk->data() + hdr), take);
        }
    }
    return target;
}

class XfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = XfsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeXfsReaderSource() { return std::make_unique<XfsReaderSource>(); }

} // namespace stein::fs::detail
