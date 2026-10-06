// SPDX-License-Identifier: MIT
// SquashFS reader: superblock, metadata blocks (2-byte header, 8 KiB max),
// inode table, directory table, fragment and id lookup tables, data blocks.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/inflate.hpp"
#include "stein/core/lz4.hpp"
#include "stein/core/lzma.hpp"
#include "stein/core/lzo.hpp"
#include "stein/core/zstd.hpp"
#include "stein/fs/squashfs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::size_t kMetaSize = 8192;
constexpr std::uint32_t kFragNone = 0xFFFFFFFFu, kUncompressedBlock = 1u << 24;
constexpr std::uint16_t kCompGzip = 1, kCompLzma = 2, kCompLzo = 3, kCompXz = 4, kCompLz4 = 5, kCompZstd = 6;
constexpr std::uint16_t kFlagUncompressedData = 0x0002, kFlagUncompressedFragments = 0x0008;   // inode/id tables carry the flag per block
enum : std::uint16_t { kDir = 1, kFile = 2, kSymlink = 3, kBlk = 4, kChr = 5, kFifo = 6, kSock = 7, kLDir = 8, kLFile = 9, kLSymlink = 10, kLBlk = 11, kLChr = 12, kLFifo = 13, kLSock = 14 };

FileType typeOf(std::uint16_t t) {
    switch (t) {
    case kDir: case kLDir: return FileType::Directory;
    case kFile: case kLFile: return FileType::File;
    case kSymlink: case kLSymlink: return FileType::Symlink;
    case kBlk: case kLBlk: return FileType::BlockDevice;
    case kChr: case kLChr: return FileType::CharDevice;
    case kFifo: case kLFifo: return FileType::Fifo;
    case kSock: case kLSock: return FileType::Socket;
    default: return FileType::Unknown;
    }
}
} // namespace

Expected<std::unique_ptr<SquashfsReader>> SquashfsReader::open(std::shared_ptr<BlockDevice> device) {
    auto sb = device->read(0, 96);
    if (!sb) return fail(sb.error());
    const std::byte* s = sb->data();
    if (loadLe32(s) != 0x73717368u) return fail(ErrorCategory::InvalidFormat, "no squashfs magic");
    std::unique_ptr<SquashfsReader> r(new SquashfsReader());
    r->m_device = std::move(device);
    r->m_blockSize = loadLe32(s + 12);
    r->m_fragCount = loadLe32(s + 16);
    r->m_compressor = loadLe16(s + 20);
    const std::uint16_t blockLog = loadLe16(s + 22);
    r->m_flags = loadLe16(s + 24);
    r->m_idCount = loadLe16(s + 26);
    const std::uint16_t major = loadLe16(s + 28), minor = loadLe16(s + 30);
    if (major != 4 || minor != 0) return fail(ErrorCategory::Unsupported, "squashfs " + std::to_string(major) + "." + std::to_string(minor) + " (only 4.0 is supported)");
    if (blockLog < 12 || blockLog > 20 || r->m_blockSize != (1u << blockLog)) return fail(ErrorCategory::InvalidFormat, "bad squashfs block size");
    if (r->m_compressor < kCompGzip || r->m_compressor > kCompZstd) return fail(ErrorCategory::Unsupported, "unknown squashfs compressor " + std::to_string(r->m_compressor));
    r->m_rootRef = loadLe64(s + 32);
    r->m_idTable = loadLe64(s + 48);
    r->m_inodeTable = loadLe64(s + 64);
    r->m_dirTable = loadLe64(s + 72);
    r->m_fragTable = loadLe64(s + 80);
    auto ids = r->lookupTable(r->m_idTable, r->m_idCount, 4);
    if (!ids) return fail(ids.error());
    r->m_idIndex = std::move(*ids);
    if (r->m_fragCount && r->m_fragTable != ~0ull) {
        auto frags = r->lookupTable(r->m_fragTable, r->m_fragCount, 16);
        if (!frags) return fail(frags.error());
        r->m_fragIndex = std::move(*frags);
    }
    return r;
}

Expected<std::vector<std::uint64_t>> SquashfsReader::lookupTable(std::uint64_t start, std::size_t entries, std::size_t entrySize) {
    const std::size_t blocks = (entries * entrySize + kMetaSize - 1) / kMetaSize;
    if (blocks > 65536) return fail(ErrorCategory::InvalidFormat, "squashfs lookup table too large");
    auto raw = m_device->read(start, blocks * 8);
    if (!raw) return fail(raw.error());
    std::vector<std::uint64_t> out(blocks);
    for (std::size_t i = 0; i < blocks; ++i) out[i] = loadLe64(raw->data() + i * 8);
    return out;
}

Expected<std::size_t> SquashfsReader::decompress(std::span<const std::byte> in, std::span<std::byte> out) const {
    switch (m_compressor) {
    case kCompGzip: return compress::inflateZlib(in, out);
    case kCompLzma: return compress::lzmaDecompress(in, out);
    case kCompLzo: return compress::lzo1xDecompress(in, out);
    case kCompXz: return compress::xzDecompress(in, out);
    case kCompLz4: return lz4::decompressUpTo(in, out);
    case kCompZstd: return compress::zstdDecompressFrame(in, out);
    default: return fail(ErrorCategory::Unsupported, "unknown squashfs compressor");
    }
}

Expected<const std::vector<std::byte>*> SquashfsReader::metadataBlock(std::uint64_t offset, std::uint64_t* next) {
    auto it = m_metaCache.find(offset);
    if (it == m_metaCache.end()) {
        auto hdr = m_device->read(offset, 2);
        if (!hdr) return fail(hdr.error());
        const std::uint16_t h = loadLe16(hdr->data());
        const std::size_t len = h & 0x7FFF;
        const bool stored = (h & 0x8000) != 0;
        if (len == 0 || len > kMetaSize) return fail(ErrorCategory::InvalidFormat, "bad squashfs metadata block length");
        auto raw = m_device->read(offset + 2, len);
        if (!raw) return fail(raw.error());
        std::vector<std::byte> data;
        if (stored) {
            data = std::move(*raw);
        } else {
            data.resize(kMetaSize);
            auto n = decompress(*raw, data);
            if (!n) return fail(ErrorCategory::InvalidFormat, "squashfs metadata block: " + std::string(n.error().message()));
            data.resize(*n);
        }
        if (m_metaCache.size() > 4096) m_metaCache.clear();
        it = m_metaCache.emplace(offset, std::move(data)).first;
        m_metaCache[~offset] = std::vector<std::byte>(reinterpret_cast<const std::byte*>(&len), reinterpret_cast<const std::byte*>(&len) + sizeof len);   // next-block distance
        it = m_metaCache.find(offset);
    }
    if (next) {
        std::size_t len = 0;
        std::memcpy(&len, m_metaCache[~offset].data(), sizeof len);
        *next = offset + 2 + len;
    }
    return &it->second;
}

Expected<std::vector<std::byte>> SquashfsReader::metadata(std::uint64_t tableStart, std::uint64_t block, std::uint32_t offset, std::size_t n) {
    std::vector<std::byte> out;
    out.reserve(n);
    std::uint64_t at = tableStart + block;
    std::size_t skip = offset;
    while (out.size() < n) {
        std::uint64_t next = 0;
        auto b = metadataBlock(at, &next);
        if (!b) return fail(b.error());
        if (skip >= (*b)->size()) return fail(ErrorCategory::InvalidFormat, "squashfs metadata offset beyond its block");
        const std::size_t take = std::min(n - out.size(), (*b)->size() - skip);
        out.insert(out.end(), (*b)->begin() + static_cast<std::ptrdiff_t>(skip), (*b)->begin() + static_cast<std::ptrdiff_t>(skip + take));
        skip = 0;
        at = next;
        if (take == 0) return fail(ErrorCategory::InvalidFormat, "empty squashfs metadata block");
    }
    return out;
}

Expected<SquashfsReader::InodeRec> SquashfsReader::inode(std::uint64_t ref) {
    if (auto it = m_inodes.find(ref); it != m_inodes.end()) return it->second;
    const std::uint64_t block = ref >> 16;
    const std::uint32_t off = ref & 0xFFFF;
    // Read generously: the header plus the largest fixed part; variable parts follow.
    auto head = metadata(m_inodeTable, block, off, 56);
    if (!head) return fail(head.error());
    const std::byte* p = head->data();
    InodeRec in;
    in.type = loadLe16(p);
    in.mode = loadLe16(p + 2);
    in.uidIdx = loadLe16(p + 4);
    in.gidIdx = loadLe16(p + 6);
    in.mtime = loadLe32(p + 8);
    in.number = loadLe32(p + 12);
    auto rest = [&](std::size_t fixed, std::size_t extra) -> Expected<std::vector<std::byte>> { return metadata(m_inodeTable, block, off, fixed + extra); };
    switch (in.type) {
    case kDir:
        in.dirBlock = loadLe32(p + 16);
        in.nlink = loadLe32(p + 20);
        in.size = loadLe16(p + 24);
        in.dirOffset = loadLe16(p + 26);
        break;
    case kLDir:
        in.nlink = loadLe32(p + 16);
        in.size = loadLe32(p + 20);
        in.dirBlock = loadLe32(p + 24);
        in.dirOffset = loadLe16(p + 34);
        break;
    case kFile: {
        in.blocksStart = loadLe32(p + 16);
        in.fragment = loadLe32(p + 20);
        in.fragOffset = loadLe32(p + 24);
        in.size = loadLe32(p + 28);
        const std::size_t blocks = in.fragment == kFragNone ? static_cast<std::size_t>((in.size + m_blockSize - 1) / m_blockSize) : static_cast<std::size_t>(in.size / m_blockSize);
        auto all = rest(32, blocks * 4);
        if (!all) return fail(all.error());
        for (std::size_t i = 0; i < blocks; ++i) in.blockSizes.push_back(loadLe32(all->data() + 32 + i * 4));
        break;
    }
    case kLFile: {
        in.blocksStart = loadLe64(p + 16);
        in.size = loadLe64(p + 24);
        in.nlink = loadLe32(p + 40);
        in.fragment = loadLe32(p + 44);
        in.fragOffset = loadLe32(p + 48);
        const std::size_t blocks = in.fragment == kFragNone ? static_cast<std::size_t>((in.size + m_blockSize - 1) / m_blockSize) : static_cast<std::size_t>(in.size / m_blockSize);
        if (blocks > (1u << 24)) return fail(ErrorCategory::InvalidFormat, "squashfs file with too many blocks");
        auto all = rest(56, blocks * 4);
        if (!all) return fail(all.error());
        for (std::size_t i = 0; i < blocks; ++i) in.blockSizes.push_back(loadLe32(all->data() + 56 + i * 4));
        break;
    }
    case kSymlink: case kLSymlink: {
        in.nlink = loadLe32(p + 16);
        const std::uint32_t len = loadLe32(p + 20);
        if (len > 65535) return fail(ErrorCategory::InvalidFormat, "squashfs symlink target too long");
        auto all = rest(24, len);
        if (!all) return fail(all.error());
        in.target.assign(reinterpret_cast<const char*>(all->data()) + 24, len);
        in.size = len;
        break;
    }
    case kBlk: case kChr: case kLBlk: case kLChr: case kFifo: case kSock: case kLFifo: case kLSock:
        in.nlink = loadLe32(p + 16);
        break;
    default: return fail(ErrorCategory::InvalidFormat, "unknown squashfs inode type " + std::to_string(in.type));
    }
    m_inodes[ref] = in;
    return in;
}

Expected<SquashfsReader::Fragment> SquashfsReader::fragment(std::uint32_t index) {
    if (index >= m_fragCount) return fail(ErrorCategory::InvalidFormat, "squashfs fragment index out of range");
    const std::size_t blockIdx = index * 16 / kMetaSize, inBlock = index * 16 % kMetaSize;
    if (blockIdx >= m_fragIndex.size()) return fail(ErrorCategory::InvalidFormat, "squashfs fragment table index out of range");
    auto b = metadataBlock(m_fragIndex[blockIdx]);
    if (!b) return fail(b.error());
    if (inBlock + 16 > (*b)->size()) return fail(ErrorCategory::InvalidFormat, "squashfs fragment entry beyond its block");
    return Fragment{loadLe64((*b)->data() + inBlock), loadLe32((*b)->data() + inBlock + 8)};
}

Expected<std::uint32_t> SquashfsReader::id(std::uint16_t index) {
    if (index >= m_idCount) return fail(ErrorCategory::InvalidFormat, "squashfs id index out of range");
    const std::size_t blockIdx = index * 4 / kMetaSize, inBlock = index * 4 % kMetaSize;
    if (blockIdx >= m_idIndex.size()) return fail(ErrorCategory::InvalidFormat, "squashfs id table index out of range");
    auto b = metadataBlock(m_idIndex[blockIdx]);
    if (!b) return fail(b.error());
    if (inBlock + 4 > (*b)->size()) return fail(ErrorCategory::InvalidFormat, "squashfs id entry beyond its block");
    return loadLe32((*b)->data() + inBlock);
}

Expected<std::vector<DirEntry>> SquashfsReader::readdir(const Inode& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    auto in = inode(dir.id);
    if (!in) return fail(in.error());
    if (typeOf(in->type) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    if (in->size < 3) {
        m_dirCache[dir.id] = out;
        return out;
    }
    auto listing = metadata(m_dirTable, in->dirBlock, in->dirOffset, static_cast<std::size_t>(in->size - 3));
    if (!listing) return fail(listing.error());
    const std::byte* p = listing->data();
    std::size_t pos = 0;
    const std::size_t end = listing->size();
    while (pos + 12 <= end) {
        const std::uint32_t count = loadLe32(p + pos) + 1, start = loadLe32(p + pos + 4);
        const std::int64_t base = loadLe32(p + pos + 8);
        pos += 12;
        if (count > 256) return fail(ErrorCategory::InvalidFormat, "squashfs directory header with too many entries");
        for (std::uint32_t i = 0; i < count; ++i) {
            if (pos + 8 > end) return fail(ErrorCategory::InvalidFormat, "truncated squashfs directory entry");
            const std::uint16_t offset = loadLe16(p + pos);
            const std::int16_t delta = static_cast<std::int16_t>(loadLe16(p + pos + 2));
            const std::uint16_t type = loadLe16(p + pos + 4), nameLen = loadLe16(p + pos + 6) + 1;
            pos += 8;
            if (pos + nameLen > end) return fail(ErrorCategory::InvalidFormat, "truncated squashfs directory entry name");
            DirEntry e;
            e.name.assign(reinterpret_cast<const char*>(p + pos), nameLen);
            e.inode = Inode{(std::uint64_t{start} << 16) | offset};
            e.type = typeOf(type);
            (void)base;
            (void)delta;
            out.push_back(std::move(e));
            pos += nameLen;
        }
    }
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> SquashfsReader::lookup(const Inode& dir, std::string_view name) {
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> SquashfsReader::stat(const Inode& ino) {
    auto in = inode(ino.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = typeOf(in->type);
    st.mode = in->mode & 07777;
    st.nlink = in->nlink;
    st.size = st.type == FileType::Directory ? 0 : in->size;
    st.allocatedBytes = st.type == FileType::File ? (in->size + 511) / 512 * 512 : 0;
    st.mtime = st.atime = st.ctime = in->mtime;
    if (auto u = id(in->uidIdx)) st.uid = *u;
    if (auto g = id(in->gidIdx)) st.gid = *g;
    return st;
}

Expected<std::size_t> SquashfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = inode(file.id);
    if (!in) return fail(in.error());
    if (typeOf(in->type) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (typeOf(in->type) != FileType::File) return fail(ErrorCategory::InvalidArgument, "not a regular file");
    if (offset >= in->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), in->size - offset);
    std::memset(dst.data(), 0, static_cast<std::size_t>(n));
    std::uint64_t done = 0;
    // A data block (or fragment block), decompressed and cached by its absolute offset.
    auto block = [&](std::uint64_t at, std::uint32_t sizeField, std::size_t expect, bool fragmentBlock) -> Expected<std::span<const std::byte>> {
        const std::uint64_t key = at ^ (fragmentBlock ? (1ull << 63) : 0);
        if (key == m_dataKey) return std::span<const std::byte>(m_dataCache);
        const std::uint32_t len = sizeField & ~kUncompressedBlock;
        const bool stored = (sizeField & kUncompressedBlock) || (m_flags & (fragmentBlock ? kFlagUncompressedFragments : kFlagUncompressedData));
        if (len == 0 || len > m_blockSize + 64) return fail(ErrorCategory::InvalidFormat, "bad squashfs data block size");
        auto raw = m_device->read(at, len);
        if (!raw) return fail(raw.error());
        std::vector<std::byte> data;
        if (stored) {
            data = std::move(*raw);
        } else {
            data.resize(expect);
            auto k = decompress(*raw, data);
            if (!k) return fail(k.error());
            data.resize(*k);
        }
        m_dataCache = std::move(data);
        m_dataKey = key;
        return std::span<const std::byte>(m_dataCache);
    };
    while (done < n) {
        const std::uint64_t pos = offset + done;
        const std::uint64_t blockIdx = pos / m_blockSize, inBlock = pos % m_blockSize;
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(n - done, m_blockSize - inBlock));
        if (blockIdx < in->blockSizes.size()) {
            std::uint64_t at = in->blocksStart;
            for (std::uint64_t i = 0; i < blockIdx; ++i) at += in->blockSizes[static_cast<std::size_t>(i)] & ~kUncompressedBlock;
            const std::uint32_t sizeField = in->blockSizes[static_cast<std::size_t>(blockIdx)];
            if ((sizeField & ~kUncompressedBlock) != 0) {   // size 0: a sparse block of zeros
                const std::size_t expect = static_cast<std::size_t>(std::min<std::uint64_t>(m_blockSize, in->size - blockIdx * m_blockSize));
                auto data = block(at, sizeField, expect, false);
                if (!data) return fail(data.error());
                if (inBlock < data->size()) std::memcpy(dst.data() + done, data->data() + inBlock, std::min<std::size_t>(want, data->size() - static_cast<std::size_t>(inBlock)));
            }
        } else if (in->fragment != kFragNone) {
            auto frag = fragment(in->fragment);
            if (!frag) return fail(frag.error());
            auto data = block(frag->start, frag->size, m_blockSize, true);
            if (!data) return fail(data.error());
            const std::uint64_t start = in->fragOffset + inBlock;
            if (start < data->size()) std::memcpy(dst.data() + done, data->data() + start, std::min<std::size_t>(want, data->size() - static_cast<std::size_t>(start)));
        } else {
            return fail(ErrorCategory::InvalidFormat, "squashfs file data beyond its block list");
        }
        done += want;
    }
    return static_cast<std::size_t>(n);
}

Expected<std::string> SquashfsReader::readlink(const Inode& link) {
    auto in = inode(link.id);
    if (!in) return fail(in.error());
    if (typeOf(in->type) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    return in->target;
}

class SquashfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = SquashfsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeSquashfsReaderSource() { return std::make_unique<SquashfsReaderSource>(); }

} // namespace stein::fs::detail
