// SPDX-License-Identifier: MIT
// btrfs reader: superblock and chunk tree for logical -> physical mapping,
// root tree for the subvolume roots, fs tree items (INODE_ITEM, DIR_INDEX,
// EXTENT_DATA inline/regular/prealloc), range scans over the B-tree.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/fs/btrfs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr ByteCount kSuperOffset = 65536;
constexpr std::size_t kHeaderSize = 101, kItemSize = 25, kKeyPtrSize = 33;
constexpr std::uint64_t kFsTreeObjectid = 5, kFirstChunkTreeObjectid = 256;
constexpr std::uint8_t kInodeItem = 1, kDirIndex = 96, kExtentData = 108, kRootItem = 132, kChunkItem = 228;
constexpr std::uint8_t kExtentInline = 0, kExtentPrealloc = 2;
constexpr std::uint64_t kBlockGroupRaid0 = 1ull << 3, kBlockGroupRaid1 = 1ull << 4, kBlockGroupDup = 1ull << 5, kBlockGroupRaid10 = 1ull << 6, kBlockGroupRaid5 = 1ull << 7,
                        kBlockGroupRaid6 = 1ull << 8, kBlockGroupRaid1c3 = 1ull << 9, kBlockGroupRaid1c4 = 1ull << 10;

FileType dirType(std::uint8_t t) {
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

FileType modeType(std::uint32_t mode) {
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

BtrfsReader::Key BtrfsReader::readKey(const std::byte* p) {
    Key k;
    k.objectid = loadLe64(p);
    k.type = std::to_integer<std::uint8_t>(p[8]);
    k.offset = loadLe64(p + 9);
    return k;
}

Expected<std::unique_ptr<BtrfsReader>> BtrfsReader::open(std::shared_ptr<BlockDevice> device) {
    auto sb = device->read(kSuperOffset, 4096);
    if (!sb) return fail(sb.error());
    const std::byte* s = sb->data();
    if (std::memcmp(s + 64, "_BHRfS_M", 8) != 0) return fail(ErrorCategory::InvalidFormat, "not a btrfs superblock");
    auto r = std::unique_ptr<BtrfsReader>(new BtrfsReader());
    r->m_device = std::move(device);
    std::memcpy(r->m_fsid.data(), s + 32, 16);
    r->m_rootTreeBytenr = loadLe64(s + 80);
    r->m_sectorSize = loadLe32(s + 144);
    r->m_nodeSize = loadLe32(s + 148);
    if (r->m_nodeSize < 4096 || r->m_nodeSize > 65536 || (r->m_nodeSize & (r->m_nodeSize - 1))) return fail(ErrorCategory::InvalidFormat, "implausible btrfs node size");
    if (loadLe64(s + 136) != 1) return fail(ErrorCategory::Unsupported, "multi-device btrfs filesystems need every device (not assembled yet)");
    if (auto c = r->loadChunks(*sb); !c) return fail(c.error());
    // The default subvolume: FS_TREE (objectid 5) unless the root tree's "default" entry says otherwise.
    Tree fs;
    fs.objectid = kFsTreeObjectid;
    Key min{kFsTreeObjectid, kRootItem, 0}, max{kFsTreeObjectid, kRootItem, ~0ull};
    Tree rootTree;
    rootTree.rootBytenr = r->m_rootTreeBytenr;
    rootTree.level = std::to_integer<std::uint8_t>(s[198]);
    bool found = false;
    auto res = r->scanTree(rootTree, min, max, [&](const Key&, std::span<const std::byte> d) {
        if (d.size() < 239) return true;
        fs.rootBytenr = loadLe64(d.data() + 176);
        fs.rootDirId = loadLe64(d.data() + 168);
        fs.level = std::to_integer<std::uint8_t>(d[238]);
        found = true;
        return false;
    });
    if (!res) return fail(res.error());
    if (!found) return fail(ErrorCategory::InvalidFormat, "root tree has no FS_TREE root item");
    r->m_trees.push_back(fs);
    r->m_treeIndex[kFsTreeObjectid] = 0;
    r->m_rootDirId = fs.rootDirId;
    return r;
}

Expected<void> BtrfsReader::loadChunks(std::span<const std::byte> sb) {
    const std::uint32_t arraySize = loadLe32(sb.data() + 160);
    if (arraySize > 2048) return fail(ErrorCategory::InvalidFormat, "sys_chunk_array larger than its slot");
    const std::byte* a = sb.data() + 811;
    std::size_t pos = 0;
    while (pos + 17 + 48 <= arraySize) {
        const Key k = readKey(a + pos);
        pos += 17;
        if (k.type != kChunkItem) break;
        Chunk c;
        c.logical = k.offset;
        c.length = loadLe64(a + pos);
        c.stripeLen = loadLe64(a + pos + 16);
        c.type = loadLe64(a + pos + 24);
        const std::uint16_t numStripes = loadLe16(a + pos + 44);
        c.subStripes = loadLe16(a + pos + 46);
        if (pos + 48 + std::size_t{numStripes} * 32 > arraySize) break;
        for (std::uint16_t i = 0; i < numStripes; ++i) c.stripes.push_back(Stripe{loadLe64(a + pos + 48 + i * 32), loadLe64(a + pos + 48 + i * 32 + 8)});
        pos += 48 + std::size_t{numStripes} * 32;
        m_chunks.push_back(std::move(c));
    }
    if (m_chunks.empty()) return fail(ErrorCategory::InvalidFormat, "no system chunks in the superblock");
    // The chunk tree lists every chunk; walk it with the system chunks mapped so far.
    const std::uint64_t chunkRoot = loadLe64(sb.data() + 88);
    return readChunkTree(chunkRoot, 0);
}

Expected<void> BtrfsReader::readChunkTree(std::uint64_t logical, int depth) {
    if (depth > 8) return fail(ErrorCategory::InvalidFormat, "chunk tree too deep");
    auto node = readNode(logical);
    if (!node) return fail(node.error());
    const std::byte* n = node->data();
    const std::uint32_t nritems = loadLe32(n + 96);
    const std::uint8_t level = std::to_integer<std::uint8_t>(n[100]);
    if (level > 0) {
        for (std::uint32_t i = 0; i < nritems && kHeaderSize + (i + 1) * kKeyPtrSize <= m_nodeSize; ++i)
            if (auto r = readChunkTree(loadLe64(n + kHeaderSize + i * kKeyPtrSize + 17), depth + 1); !r) return r;
        return {};
    }
    for (std::uint32_t i = 0; i < nritems && kHeaderSize + (i + 1) * kItemSize <= m_nodeSize; ++i) {
        const std::byte* item = n + kHeaderSize + i * kItemSize;
        const Key k = readKey(item);
        const std::uint32_t off = loadLe32(item + 17), size = loadLe32(item + 21);
        if (k.type != kChunkItem || k.objectid != kFirstChunkTreeObjectid) continue;
        if (kHeaderSize + off + size > m_nodeSize || size < 48) continue;
        const std::byte* d = n + kHeaderSize + off;
        Chunk c;
        c.logical = k.offset;
        c.length = loadLe64(d);
        c.stripeLen = loadLe64(d + 16);
        c.type = loadLe64(d + 24);
        const std::uint16_t numStripes = loadLe16(d + 44);
        c.subStripes = loadLe16(d + 46);
        if (48 + std::size_t{numStripes} * 32 > size) continue;
        for (std::uint16_t j = 0; j < numStripes; ++j) c.stripes.push_back(Stripe{loadLe64(d + 48 + j * 32), loadLe64(d + 48 + j * 32 + 8)});
        bool known = false;
        for (const auto& existing : m_chunks) known = known || existing.logical == c.logical;
        if (!known) m_chunks.push_back(std::move(c));
    }
    return {};
}

Expected<ByteCount> BtrfsReader::logicalToPhysical(std::uint64_t logical, std::uint64_t length) const {
    for (const auto& c : m_chunks) {
        if (logical < c.logical || logical >= c.logical + c.length) continue;
        if (c.stripes.empty()) break;
        const std::uint64_t in = logical - c.logical;
        if (c.type & (kBlockGroupRaid5 | kBlockGroupRaid6)) return fail(ErrorCategory::Unsupported, "RAID5/6 btrfs chunks are not supported");
        if (c.type & (kBlockGroupRaid0 | kBlockGroupRaid10)) {
            if (c.stripeLen == 0) break;
            const std::uint64_t stripeNr = in / c.stripeLen, inStripe = in % c.stripeLen;
            if (inStripe + length > c.stripeLen) return fail(ErrorCategory::Unsupported, "read crosses a RAID stripe boundary");
            const std::uint64_t groups = (c.type & kBlockGroupRaid10) ? c.stripes.size() / std::max<std::uint16_t>(1, c.subStripes) : c.stripes.size();
            if (groups == 0) break;
            const std::uint64_t idx = (stripeNr % groups) * ((c.type & kBlockGroupRaid10) ? c.subStripes : 1);
            if (idx >= c.stripes.size()) break;
            return c.stripes[idx].offset + (stripeNr / groups) * c.stripeLen + inStripe;
        }
        // SINGLE, DUP, RAID1*: every stripe holds the whole chunk; the first copy will do.
        (void)kBlockGroupRaid1;
        (void)kBlockGroupDup;
        (void)kBlockGroupRaid1c3;
        (void)kBlockGroupRaid1c4;
        return c.stripes[0].offset + in;
    }
    return fail(ErrorCategory::InvalidFormat, "logical address " + std::to_string(logical) + " is in no chunk");
}

Expected<std::vector<std::byte>> BtrfsReader::readNode(std::uint64_t logical) const {
    auto phys = logicalToPhysical(logical, m_nodeSize);
    if (!phys) return fail(phys.error());
    auto node = m_device->read(*phys, m_nodeSize);
    if (!node) return fail(node.error());
    if (loadLe64(node->data() + 48) != logical) return fail(ErrorCategory::InvalidFormat, "btrfs node at " + std::to_string(logical) + " carries another bytenr");
    if (std::memcmp(node->data() + 32, m_fsid.data(), 16) != 0) return fail(ErrorCategory::InvalidFormat, "btrfs node fsid mismatch");
    return node;
}

Expected<void> BtrfsReader::scan(std::uint64_t nodeLogical, const Key& minKey, const Key& maxKey, const ItemVisitor& visit, int depth) const {
    if (depth > 16) return fail(ErrorCategory::InvalidFormat, "btrfs tree too deep");
    auto node = readNode(nodeLogical);
    if (!node) return fail(node.error());
    const std::byte* n = node->data();
    const std::uint32_t nritems = loadLe32(n + 96);
    const std::uint8_t level = std::to_integer<std::uint8_t>(n[100]);
    if (level > 0) {
        if (kHeaderSize + std::size_t{nritems} * kKeyPtrSize > m_nodeSize) return fail(ErrorCategory::InvalidFormat, "btrfs node overfull");
        for (std::uint32_t i = 0; i < nritems; ++i) {
            const Key first = readKey(n + kHeaderSize + i * kKeyPtrSize);
            // Child i covers [first, nextFirst); skip it when the whole range misses the window.
            if (i + 1 < nritems) {
                const Key next = readKey(n + kHeaderSize + (i + 1) * kKeyPtrSize);
                if (next <= minKey) continue;
            }
            if (first > maxKey) break;
            if (auto r = scan(loadLe64(n + kHeaderSize + i * kKeyPtrSize + 17), minKey, maxKey, visit, depth + 1); !r) return r;
        }
        return {};
    }
    if (kHeaderSize + std::size_t{nritems} * kItemSize > m_nodeSize) return fail(ErrorCategory::InvalidFormat, "btrfs leaf overfull");
    for (std::uint32_t i = 0; i < nritems; ++i) {
        const std::byte* item = n + kHeaderSize + i * kItemSize;
        const Key k = readKey(item);
        if (k < minKey) continue;
        if (k > maxKey) break;
        const std::uint32_t off = loadLe32(item + 17), size = loadLe32(item + 21);
        if (kHeaderSize + std::uint64_t{off} + size > m_nodeSize) return fail(ErrorCategory::InvalidFormat, "btrfs item data outside its leaf");
        if (!visit(k, std::span<const std::byte>(n + kHeaderSize + off, size))) return {};
    }
    return {};
}

Expected<void> BtrfsReader::scanTree(const Tree& tree, const Key& minKey, const Key& maxKey, const ItemVisitor& visit) const {
    return scan(tree.rootBytenr, minKey, maxKey, visit, 0);
}

Expected<BtrfsReader::Tree> BtrfsReader::openSubvolume(std::uint64_t objectid) {
    Tree rootTree;
    rootTree.rootBytenr = m_rootTreeBytenr;
    Tree t;
    t.objectid = objectid;
    bool found = false;
    Key min{objectid, kRootItem, 0}, max{objectid, kRootItem, ~0ull};
    auto r = scanTree(rootTree, min, max, [&](const Key&, std::span<const std::byte> d) {
        if (d.size() < 239) return true;
        t.rootBytenr = loadLe64(d.data() + 176);
        t.rootDirId = loadLe64(d.data() + 168);
        t.level = std::to_integer<std::uint8_t>(d[238]);
        found = true;
        return false;
    });
    if (!r) return fail(r.error());
    if (!found) return fail(ErrorCategory::NotFound, "no root item for subvolume " + std::to_string(objectid));
    return t;
}

Expected<std::size_t> BtrfsReader::treeIndexFor(std::uint64_t subvolObjectid) {
    if (auto it = m_treeIndex.find(subvolObjectid); it != m_treeIndex.end()) return it->second;
    auto t = openSubvolume(subvolObjectid);
    if (!t) return fail(t.error());
    if (m_trees.size() >= 255) return fail(ErrorCategory::OutOfRange, "too many subvolumes opened");
    m_trees.push_back(*t);
    m_treeIndex[subvolObjectid] = m_trees.size() - 1;
    return m_trees.size() - 1;
}

Expected<BtrfsReader::InodeItem> BtrfsReader::inodeItem(std::uint64_t id) {
    if (auto it = m_inodes.find(id); it != m_inodes.end()) return it->second;
    const std::uint64_t ti = treeOf(id), obj = objectOf(id);
    if (ti >= m_trees.size()) return fail(ErrorCategory::InvalidArgument, "unknown subvolume in inode id");
    InodeItem in;
    bool found = false;
    Key k{obj, kInodeItem, 0};
    auto r = scanTree(m_trees[ti], k, k, [&](const Key&, std::span<const std::byte> d) {
        if (d.size() < 160) return true;
        const std::byte* p = d.data();
        in.size = loadLe64(p + 16);
        in.nbytes = loadLe64(p + 24);
        in.nlink = loadLe32(p + 40);
        in.uid = loadLe32(p + 44);
        in.gid = loadLe32(p + 48);
        in.mode = loadLe32(p + 52);
        in.flags = loadLe64(p + 64);
        in.atime = static_cast<std::int64_t>(loadLe64(p + 112));
        in.ctime = static_cast<std::int64_t>(loadLe64(p + 124));
        in.mtime = static_cast<std::int64_t>(loadLe64(p + 136));
        in.otime = static_cast<std::int64_t>(loadLe64(p + 148));
        found = true;
        return false;
    });
    if (!r) return fail(r.error());
    if (!found) return fail(ErrorCategory::NotFound, "no inode item for objectid " + std::to_string(obj));
    m_inodes[id] = in;
    return in;
}

Expected<std::vector<BtrfsReader::ExtentItem>> BtrfsReader::extentsOf(std::uint64_t id) {
    const std::uint64_t ti = treeOf(id), obj = objectOf(id);
    std::vector<ExtentItem> out;
    Key min{obj, kExtentData, 0}, max{obj, kExtentData, ~0ull};
    auto r = scanTree(m_trees[ti], min, max, [&](const Key& k, std::span<const std::byte> d) {
        if (d.size() < 21) return true;
        ExtentItem e;
        e.fileOffset = k.offset;
        e.compression = std::to_integer<std::uint8_t>(d[16]);
        e.type = std::to_integer<std::uint8_t>(d[20]);
        if (e.type == kExtentInline) {
            e.inlineData.assign(d.begin() + 21, d.end());
            e.numBytes = loadLe64(d.data() + 8);   // ram_bytes
        } else if (d.size() >= 53) {
            e.diskBytenr = loadLe64(d.data() + 21);
            e.diskOffset = loadLe64(d.data() + 37);
            e.numBytes = loadLe64(d.data() + 45);
        } else {
            return true;
        }
        out.push_back(std::move(e));
        return true;
    });
    if (!r) return fail(r.error());
    return out;
}

Expected<std::vector<DirEntry>> BtrfsReader::readdir(const Inode& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    auto in = inodeItem(dir.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    const std::uint64_t ti = treeOf(dir.id), obj = objectOf(dir.id);
    std::vector<DirEntry> out;
    std::vector<std::pair<std::size_t, std::uint64_t>> subvolRefs;   // entry index -> subvolume objectid
    Key min{obj, kDirIndex, 0}, max{obj, kDirIndex, ~0ull};
    auto r = scanTree(m_trees[ti], min, max, [&](const Key&, std::span<const std::byte> d) {
        if (d.size() < 30) return true;
        const Key loc = readKey(d.data());
        const std::uint16_t nameLen = loadLe16(d.data() + 27);
        const std::uint8_t type = std::to_integer<std::uint8_t>(d[29]);
        if (30u + nameLen > d.size()) return true;
        std::string name(reinterpret_cast<const char*>(d.data() + 30), nameLen);
        if (loc.type == kRootItem) {
            subvolRefs.emplace_back(out.size(), loc.objectid);
            out.push_back(DirEntry{std::move(name), Inode{0}, FileType::Directory});
        } else {
            out.push_back(DirEntry{std::move(name), Inode{makeId(ti, loc.objectid)}, dirType(type)});
        }
        return true;
    });
    if (!r) return fail(r.error());
    for (const auto& [index, subvol] : subvolRefs) {
        auto tidx = treeIndexFor(subvol);
        if (!tidx) return fail(tidx.error());
        out[index].inode = Inode{makeId(*tidx, m_trees[*tidx].rootDirId)};
    }
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> BtrfsReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> BtrfsReader::stat(const Inode& inode) {
    auto in = inodeItem(inode.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = modeType(in->mode);
    st.mode = in->mode & 07777;
    st.nlink = in->nlink;
    st.uid = in->uid;
    st.gid = in->gid;
    st.size = in->size;
    st.allocatedBytes = in->nbytes;
    st.atime = in->atime;
    st.mtime = in->mtime;
    st.ctime = in->ctime;
    st.crtime = in->otime;
    return st;
}

Expected<std::size_t> BtrfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = inodeItem(file.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= in->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), in->size - offset);
    auto extents = extentsOf(file.id);
    if (!extents) return fail(extents.error());
    std::memset(dst.data(), 0, static_cast<std::size_t>(n));
    for (const auto& e : *extents) {
        const std::uint64_t extentEnd = e.fileOffset + e.numBytes;
        if (extentEnd <= offset || e.fileOffset >= offset + n) continue;
        if (e.compression != 0) return fail(ErrorCategory::Unsupported, "compressed btrfs extents (zlib/lzo/zstd) are not supported yet");
        const std::uint64_t from = std::max(offset, e.fileOffset), to = std::min(offset + n, extentEnd);
        auto window = dst.subspan(static_cast<std::size_t>(from - offset), static_cast<std::size_t>(to - from));
        if (e.type == kExtentInline) {
            const std::uint64_t in0 = from - e.fileOffset;
            if (in0 < e.inlineData.size()) std::memcpy(window.data(), e.inlineData.data() + in0, static_cast<std::size_t>(std::min<std::uint64_t>(window.size(), e.inlineData.size() - in0)));
        } else if (e.type == kExtentPrealloc || e.diskBytenr == 0) {
            // unwritten or hole: zeros
        } else {
            const std::uint64_t logical = e.diskBytenr + e.diskOffset + (from - e.fileOffset);
            // Reads may cross chunk (or stripe) boundaries: map piecewise.
            std::uint64_t done = 0;
            while (done < window.size()) {
                const std::uint64_t pos = logical + done;
                std::uint64_t chunkLeft = window.size() - done;
                for (const auto& c : m_chunks)
                    if (pos >= c.logical && pos < c.logical + c.length) {
                        chunkLeft = std::min(chunkLeft, c.logical + c.length - pos);
                        if (c.stripeLen && (c.type & (kBlockGroupRaid0 | kBlockGroupRaid10))) chunkLeft = std::min(chunkLeft, c.stripeLen - (pos - c.logical) % c.stripeLen);
                    }
                auto phys = logicalToPhysical(pos, chunkLeft);
                if (!phys) return fail(phys.error());
                if (auto rd = m_device->readAt(*phys, window.subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(chunkLeft))); !rd) return fail(rd.error());
                done += chunkLeft;
            }
        }
    }
    return static_cast<std::size_t>(n);
}

Expected<std::string> BtrfsReader::readlink(const Inode& link) {
    auto in = inodeItem(link.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (in->size > 4096) return fail(ErrorCategory::InvalidFormat, "symlink target longer than 4096 bytes");
    std::string target(static_cast<std::size_t>(in->size), '\0');
    auto n = read(link, 0, std::span<std::byte>(reinterpret_cast<std::byte*>(target.data()), target.size()));
    if (!n) return fail(n.error());
    target.resize(*n);
    return target;
}

class BtrfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = BtrfsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeBtrfsReaderSource() { return std::make_unique<BtrfsReaderSource>(); }

} // namespace stein::fs::detail
