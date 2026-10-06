// SPDX-License-Identifier: MIT
// ext2/ext3/ext4 reader: inodes, extent trees and indirect blocks, inline
// data, linear and htree directories (scanned linearly), fast and slow
// symlinks. Read-only; no journal replay (a dirty filesystem is still
// readable, the probe layer warns).
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/ext_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {

constexpr std::uint32_t kFlagExtents = 0x80000;
constexpr std::uint32_t kFlagInlineData = 0x10000000;
constexpr std::uint32_t kIncompatFiletype = 1u << 1;
constexpr std::uint32_t kIncompat64bit = 1u << 7;
constexpr std::uint32_t kIncompatInlineData = 1u << 15;
constexpr std::uint16_t kExtentMagic = 0xF30A;

FileType typeFromMode(std::uint16_t mode) {
    switch (mode & 0xF000) {
    case 0x8000: return FileType::File;
    case 0x4000: return FileType::Directory;
    case 0xA000: return FileType::Symlink;
    case 0x2000: return FileType::CharDevice;
    case 0x6000: return FileType::BlockDevice;
    case 0x1000: return FileType::Fifo;
    case 0xC000: return FileType::Socket;
    default: return FileType::Unknown;
    }
}

FileType typeFromDirent(std::uint8_t t) {
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

struct ExtReader::RawInode {
    std::uint16_t mode = 0, linksCount = 0, extraIsize = 0;
    std::uint32_t uid = 0, gid = 0, flags = 0, atime = 0, ctime = 0, mtime = 0, crtime = 0;
    std::uint64_t size = 0, blocks512 = 0;
    std::uint8_t iblock[60] = {};
    std::vector<std::byte> raw;   // whole on-disk inode (for the in-inode xattr area)
};

Expected<std::unique_ptr<ExtReader>> ExtReader::open(std::shared_ptr<BlockDevice> device) {
    auto r = std::unique_ptr<ExtReader>(new ExtReader());
    r->m_device = std::move(device);
    auto sb = r->m_device->read(1024, 1024);
    if (!sb) return fail(sb.error());
    const std::byte* s = sb->data();
    if (loadLe16(s + 0x38) != 0xEF53) return fail(ErrorCategory::InvalidFormat, "not an ext filesystem");
    r->m_blockSize = ByteCount{1024} << loadLe32(s + 0x18);
    r->m_inodesPerGroup = loadLe32(s + 0x28);
    r->m_blocksPerGroup = loadLe32(s + 0x20);
    r->m_firstDataBlock = loadLe32(s + 0x14);
    const std::uint32_t revLevel = loadLe32(s + 0x4C);
    r->m_inodeSize = revLevel >= 1 ? loadLe16(s + 0x58) : 128;
    r->m_incompat = loadLe32(s + 0x60);
    r->m_is64 = (r->m_incompat & kIncompat64bit) != 0;
    r->m_descSize = r->m_is64 && loadLe16(s + 0xFE) ? loadLe16(s + 0xFE) : 32;
    r->m_inodesCount = loadLe32(s + 0x00);
    r->m_blocksCount = loadLe32(s + 0x04) | (r->m_is64 ? std::uint64_t{loadLe32(s + 0x150)} << 32 : 0);
    if (r->m_inodesPerGroup == 0 || r->m_blocksPerGroup == 0 || r->m_inodeSize < 128 || r->m_inodeSize > r->m_blockSize)
        return fail(ErrorCategory::InvalidFormat, "implausible ext superblock");
    const ByteCount gdtBlock = r->m_blockSize == 1024 ? 2 : 1;
    r->m_gdtOffset = gdtBlock * r->m_blockSize;
    r->m_groups = static_cast<std::uint32_t>((r->m_blocksCount - r->m_firstDataBlock + r->m_blocksPerGroup - 1) / r->m_blocksPerGroup);
    return r;
}

Expected<std::vector<std::byte>> ExtReader::readBlock(std::uint64_t block) const {
    if (block >= m_blocksCount) return fail(ErrorCategory::InvalidFormat, "block " + std::to_string(block) + " beyond the filesystem");
    return m_device->read(block * m_blockSize, m_blockSize);
}

Expected<ExtReader::RawInode> ExtReader::readInode(std::uint64_t ino) const {
    if (ino == 0 || ino > m_inodesCount) return fail(ErrorCategory::NotFound, "inode " + std::to_string(ino) + " out of range");
    const std::uint64_t group = (ino - 1) / m_inodesPerGroup;
    const std::uint64_t index = (ino - 1) % m_inodesPerGroup;
    if (group >= m_groups) return fail(ErrorCategory::InvalidFormat, "inode group out of range");
    auto gd = m_device->read(m_gdtOffset + group * m_descSize, m_descSize);
    if (!gd) return fail(gd.error());
    std::uint64_t table = loadLe32(gd->data() + 8);
    if (m_is64 && m_descSize >= 64) table |= std::uint64_t{loadLe32(gd->data() + 0x28)} << 32;
    auto raw = m_device->read(table * m_blockSize + index * m_inodeSize, m_inodeSize);
    if (!raw) return fail(raw.error());
    const std::byte* p = raw->data();
    RawInode in;
    in.mode = loadLe16(p + 0x00);
    in.uid = loadLe16(p + 0x02) | (std::uint32_t{loadLe16(p + 0x78)} << 16);
    in.size = loadLe32(p + 0x04) | (std::uint64_t{loadLe32(p + 0x6C)} << 32);
    in.atime = loadLe32(p + 0x08);
    in.ctime = loadLe32(p + 0x0C);
    in.mtime = loadLe32(p + 0x10);
    in.gid = loadLe16(p + 0x18) | (std::uint32_t{loadLe16(p + 0x7A)} << 16);
    in.linksCount = loadLe16(p + 0x1A);
    in.blocks512 = loadLe32(p + 0x1C);
    in.flags = loadLe32(p + 0x20);
    std::memcpy(in.iblock, p + 0x28, 60);
    if (m_inodeSize > 128) {
        in.extraIsize = loadLe16(p + 0x80);
        if (in.extraIsize >= 0x20) in.crtime = loadLe32(p + 0x90);
    }
    in.raw = std::move(*raw);
    return in;
}

// Inline data: 60 bytes in i_block, the rest in the in-inode xattr "system.data".
Expected<std::vector<std::byte>> ExtReader::inlineData(const RawInode& in) const {
    std::vector<std::byte> out(reinterpret_cast<const std::byte*>(in.iblock), reinterpret_cast<const std::byte*>(in.iblock) + 60);
    if (m_inodeSize > 128 && in.extraIsize) {
        const std::size_t base = 128 + in.extraIsize;
        if (base + 4 <= in.raw.size() && loadLe32(in.raw.data() + base) == 0xEA020000u) {
            std::size_t pos = base + 4;
            while (pos + 16 <= in.raw.size()) {
                const std::uint8_t nameLen = std::to_integer<std::uint8_t>(in.raw[pos]);
                const std::uint8_t nameIndex = std::to_integer<std::uint8_t>(in.raw[pos + 1]);
                const std::uint16_t valueOffs = loadLe16(in.raw.data() + pos + 2);
                const std::uint32_t valueSize = loadLe32(in.raw.data() + pos + 8);
                if (nameLen == 0 && nameIndex == 0) break;   // end marker
                const std::string name(reinterpret_cast<const char*>(in.raw.data() + pos + 16), nameLen);
                if (nameIndex == 7 && name == "data") {
                    const std::size_t v = base + 4 + valueOffs;
                    if (v + valueSize <= in.raw.size()) out.insert(out.end(), in.raw.begin() + static_cast<std::ptrdiff_t>(v), in.raw.begin() + static_cast<std::ptrdiff_t>(v + valueSize));
                    break;
                }
                pos += (16 + nameLen + 3) & ~std::size_t{3};
            }
        }
    }
    if (out.size() > in.size) out.resize(static_cast<std::size_t>(in.size));
    return out;
}

// Logical block -> physical block (0 = hole) through the extent tree.
Expected<std::uint64_t> ExtReader::mapExtent(std::span<const std::byte> node, std::uint64_t lblock, int depthLeft) const {
    if (node.size() < 12 || loadLe16(node.data()) != kExtentMagic) return fail(ErrorCategory::InvalidFormat, "bad extent header");
    const std::uint16_t entries = loadLe16(node.data() + 2);
    const std::uint16_t depth = loadLe16(node.data() + 6);
    if (12 + static_cast<std::size_t>(entries) * 12 > node.size()) return fail(ErrorCategory::InvalidFormat, "extent node overflows its block");
    if (depth == 0) {
        for (std::uint16_t i = 0; i < entries; ++i) {
            const std::byte* e = node.data() + 12 + i * 12;
            const std::uint32_t eeBlock = loadLe32(e);
            std::uint16_t eeLen = loadLe16(e + 4);
            const bool uninit = eeLen > 32768;
            if (uninit) eeLen = static_cast<std::uint16_t>(eeLen - 32768);
            if (lblock >= eeBlock && lblock < static_cast<std::uint64_t>(eeBlock) + eeLen) {
                if (uninit) return 0;   // unwritten extent reads as zeros
                const std::uint64_t start = (std::uint64_t{loadLe16(e + 6)} << 32) | loadLe32(e + 8);
                return start + (lblock - eeBlock);
            }
        }
        return 0;
    }
    if (depthLeft <= 0) return fail(ErrorCategory::InvalidFormat, "extent tree too deep");
    // Index node: the last entry whose ei_block <= lblock.
    std::uint64_t leaf = 0;
    bool found = false;
    for (std::uint16_t i = 0; i < entries; ++i) {
        const std::byte* e = node.data() + 12 + i * 12;
        if (loadLe32(e) <= lblock) {
            leaf = loadLe32(e + 4) | (std::uint64_t{loadLe16(e + 8)} << 32);
            found = true;
        } else {
            break;
        }
    }
    if (!found) return 0;
    auto child = readBlock(leaf);
    if (!child) return fail(child.error());
    return mapExtent(*child, lblock, depthLeft - 1);
}

Expected<std::uint64_t> ExtReader::mapIndirect(const RawInode& in, std::uint64_t lblock) const {
    const std::uint64_t perBlock = m_blockSize / 4;
    auto word = [&](const std::uint8_t* p, std::size_t i) { return static_cast<std::uint64_t>(loadLe32(reinterpret_cast<const std::byte*>(p) + 4 * i)); };
    if (lblock < 12) return word(in.iblock, static_cast<std::size_t>(lblock));
    lblock -= 12;
    auto follow = [&](std::uint64_t block, std::uint64_t index) -> Expected<std::uint64_t> {
        if (block == 0) return 0;
        auto b = readBlock(block);
        if (!b) return fail(b.error());
        return static_cast<std::uint64_t>(loadLe32(b->data() + 4 * index));
    };
    if (lblock < perBlock) return follow(word(in.iblock, 12), lblock);
    lblock -= perBlock;
    if (lblock < perBlock * perBlock) {
        auto l1 = follow(word(in.iblock, 13), lblock / perBlock);
        if (!l1) return l1;
        return follow(*l1, lblock % perBlock);
    }
    lblock -= perBlock * perBlock;
    if (lblock < perBlock * perBlock * perBlock) {
        auto l1 = follow(word(in.iblock, 14), lblock / (perBlock * perBlock));
        if (!l1) return l1;
        auto l2 = follow(*l1, (lblock / perBlock) % perBlock);
        if (!l2) return l2;
        return follow(*l2, lblock % perBlock);
    }
    return fail(ErrorCategory::OutOfRange, "block beyond triple indirection");
}

Expected<std::uint64_t> ExtReader::mapBlock(const RawInode& in, std::uint64_t lblock) const {
    if (in.flags & kFlagExtents) return mapExtent(std::span<const std::byte>(reinterpret_cast<const std::byte*>(in.iblock), 60), lblock, 8);
    return mapIndirect(in, lblock);
}

Expected<std::vector<std::byte>> ExtReader::readData(const RawInode& in) const {
    if (in.flags & kFlagInlineData) return inlineData(in);
    std::vector<std::byte> out(static_cast<std::size_t>(in.size));
    std::size_t done = 0;
    for (std::uint64_t lb = 0; done < out.size(); ++lb) {
        auto pb = mapBlock(in, lb);
        if (!pb) return fail(pb.error());
        const std::size_t n = std::min<std::size_t>(m_blockSize, out.size() - done);
        if (*pb != 0) {
            auto b = readBlock(*pb);
            if (!b) return fail(b.error());
            std::memcpy(out.data() + done, b->data(), n);
        }
        done += n;
    }
    return out;
}

Expected<Inode> ExtReader::root() const { return Inode{2}; }

Expected<Stat> ExtReader::stat(const Inode& inode) {
    auto in = readInode(inode.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = typeFromMode(in->mode);
    st.size = in->size;
    st.mode = in->mode & 07777;
    st.nlink = in->linksCount;
    st.uid = in->uid;
    st.gid = in->gid;
    st.atime = in->atime;
    st.mtime = in->mtime;
    st.ctime = in->ctime;
    st.crtime = in->crtime;
    st.allocatedBytes = in->blocks512 * 512;
    return st;
}

Expected<std::vector<DirEntry>> ExtReader::readdir(const Inode& dir) {
    auto in = readInode(dir.id);
    if (!in) return fail(in.error());
    if (typeFromMode(in->mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    const bool hasTypes = (m_incompat & kIncompatFiletype) != 0;
    auto scan = [&](std::span<const std::byte> data) {
        std::size_t pos = 0;
        while (pos + 8 <= data.size()) {
            const std::uint32_t ino = loadLe32(data.data() + pos);
            const std::uint16_t recLen = loadLe16(data.data() + pos + 4);
            const std::uint8_t nameLen = std::to_integer<std::uint8_t>(data[pos + 6]);
            const std::uint8_t ftype = std::to_integer<std::uint8_t>(data[pos + 7]);
            if (recLen < 8 || pos + recLen > data.size()) break;
            if (ino != 0 && nameLen && pos + 8 + nameLen <= data.size()) {
                std::string name(reinterpret_cast<const char*>(data.data() + pos + 8), nameLen);
                if (name != "." && name != "..") out.push_back(DirEntry{std::move(name), Inode{ino}, hasTypes ? typeFromDirent(ftype) : FileType::Unknown});
            }
            pos += recLen;
        }
    };
    if (in->flags & kFlagInlineData) {
        // Inline directory: i_block starts with the parent inode (4 bytes), entries follow; the xattr part is plain entries.
        auto data = inlineData(*in);
        if (!data) return fail(data.error());
        if (data->size() > 4) scan(std::span<const std::byte>(*data).subspan(4, std::min<std::size_t>(56, data->size() - 4)));
        if (data->size() > 60) scan(std::span<const std::byte>(*data).subspan(60));
        return out;
    }
    const std::uint64_t blocks = (in->size + m_blockSize - 1) / m_blockSize;
    for (std::uint64_t lb = 0; lb < blocks; ++lb) {
        auto pb = mapBlock(*in, lb);
        if (!pb) return fail(pb.error());
        if (*pb == 0) continue;
        auto b = readBlock(*pb);
        if (!b) return fail(b.error());
        scan(*b);   // htree index blocks look like entries with inode 0 and are skipped
    }
    return out;
}

Expected<Inode> ExtReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    if (name == "..") {
        // ".." is not in our listing; read it from the first entries directly.
        auto in = readInode(dir.id);
        if (!in) return fail(in.error());
        if (in->flags & kFlagInlineData) {
            auto data = inlineData(*in);
            if (!data || data->size() < 4) return fail(ErrorCategory::InvalidFormat, "inline directory too short");
            return Inode{loadLe32(data->data())};
        }
        auto pb = mapBlock(*in, 0);
        if (!pb || *pb == 0) return fail(ErrorCategory::InvalidFormat, "directory has no first block");
        auto b = readBlock(*pb);
        if (!b) return fail(b.error());
        const std::uint16_t rec0 = loadLe16(b->data() + 4);
        if (rec0 + 8u > b->size()) return fail(ErrorCategory::InvalidFormat, "bad '.' entry");
        return Inode{loadLe32(b->data() + rec0)};
    }
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry \"" + std::string(name) + "\"");
}

Expected<std::size_t> ExtReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = readInode(file.id);
    if (!in) return fail(in.error());
    if (typeFromMode(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= in->size) return 0;
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size(), in->size - offset));
    if (in->flags & kFlagInlineData) {
        auto data = inlineData(*in);
        if (!data) return fail(data.error());
        const std::size_t n = std::min(want, data->size() > offset ? data->size() - static_cast<std::size_t>(offset) : 0);
        std::memcpy(dst.data(), data->data() + offset, n);
        return n;
    }
    std::size_t done = 0;
    while (done < want) {
        const std::uint64_t pos = offset + done;
        const std::uint64_t lb = pos / m_blockSize;
        const std::size_t inBlock = static_cast<std::size_t>(pos % m_blockSize);
        const std::size_t n = std::min<std::size_t>(m_blockSize - inBlock, want - done);
        auto pb = mapBlock(*in, lb);
        if (!pb) return fail(pb.error());
        if (*pb == 0) {
            std::memset(dst.data() + done, 0, n);
        } else {
            auto r = m_device->readAt(*pb * m_blockSize + inBlock, dst.subspan(done, n));
            if (!r) return fail(r.error());
        }
        done += n;
    }
    return done;
}

Expected<std::string> ExtReader::readlink(const Inode& link) {
    auto in = readInode(link.id);
    if (!in) return fail(in.error());
    if (typeFromMode(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symlink");
    // Fast symlink: target lives in i_block (no data blocks allocated beyond xattrs).
    const bool fast = !(in->flags & kFlagExtents) && in->size < 60 && (in->blocks512 == 0 || in->blocks512 == m_blockSize / 512 * 0 || in->blocks512 <= m_blockSize / 512);
    if (fast && !(in->flags & kFlagInlineData)) return std::string(reinterpret_cast<const char*>(in->iblock), static_cast<std::size_t>(in->size));
    auto data = readData(*in);
    if (!data) return fail(data.error());
    return std::string(reinterpret_cast<const char*>(data->data()), data->size());
}

// Detector hook.
class ExtReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = ExtReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeExtReaderSource() { return std::make_unique<ExtReaderSource>(); }

} // namespace stein::fs::detail
