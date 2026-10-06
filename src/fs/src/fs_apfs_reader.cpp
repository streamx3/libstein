// SPDX-License-Identifier: MIT
// APFS reader. Object headers carry a Fletcher-64 checksum that is verified on
// every read; the container's checkpoint descriptor area is scanned for the
// newest valid superblock; object maps and file system trees are the APFS
// B-tree variant with a table of contents at the front and values growing
// from the back of the node.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/fs/apfs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint32_t kObjNxSuperblock = 1, kObjBtree = 2, kObjBtreeNode = 3, kObjOmap = 11, kObjFs = 13, kObjTypeMask = 0x0000FFFF;
constexpr std::uint16_t kBtnodeRoot = 1, kBtnodeLeaf = 2, kBtnodeFixedKv = 4;
constexpr std::uint32_t kBtreeInfoSize = 40;
constexpr std::uint8_t kTypeInode = 3, kTypeXattr = 4, kTypeFileExtent = 8, kTypeDirRec = 9;
constexpr std::uint64_t kIncompatCaseInsensitive = 1, kIncompatNormalizationInsensitive = 8, kFsUnencrypted = 1;
constexpr std::uint32_t kUfCompressed = 0x20;
constexpr std::uint8_t kXfDstream = 8;
constexpr std::uint16_t kXattrEmbedded = 2;

// Fletcher-64 as APFS uses it (over the block after its 8-byte checksum field).
std::uint64_t fletcher64(std::span<const std::byte> data) {
    std::uint64_t sum1 = 0, sum2 = 0;
    for (std::size_t i = 0; i + 4 <= data.size(); i += 4) {
        sum1 = (sum1 + loadLe32(data.data() + i)) % 0xFFFFFFFFull;
        sum2 = (sum2 + sum1) % 0xFFFFFFFFull;
    }
    const std::uint64_t c1 = 0xFFFFFFFFull - ((sum1 + sum2) % 0xFFFFFFFFull);
    const std::uint64_t c2 = 0xFFFFFFFFull - ((sum1 + c1) % 0xFFFFFFFFull);
    return (c2 << 32) | c1;
}

bool checksumOk(std::span<const std::byte> block) {
    if (block.size() < 32) return false;
    return loadLe64(block.data()) == fletcher64(block.subspan(8));
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

FileType drecType(std::uint16_t flags) {
    switch (flags & 0xF) {
    case 1: return FileType::Fifo;
    case 2: return FileType::CharDevice;
    case 4: return FileType::Directory;
    case 6: return FileType::BlockDevice;
    case 8: return FileType::File;
    case 10: return FileType::Symlink;
    case 12: return FileType::Socket;
    default: return FileType::Unknown;
    }
}

// File system tree keys sort by object id first and record type second; the on-disk word keeps
// the type in the top four bits, so compare on a rotated form.
std::uint64_t fsKeyOrder(std::uint64_t objIdAndType) { return ((objIdAndType & 0x0FFFFFFFFFFFFFFFull) << 4) | (objIdAndType >> 60); }

// A B-tree node's table of contents entry, resolved to key/value spans.
struct NodeView {
    std::span<const std::byte> block;
    std::uint16_t flags = 0, level = 0;
    std::uint32_t nkeys = 0;
    std::uint16_t tocOff = 0, tocLen = 0;
    std::size_t keyArea = 0, valEnd = 0;

    static Expected<NodeView> parse(std::span<const std::byte> block, bool isRoot) {
        NodeView n;
        n.block = block;
        n.flags = loadLe16(block.data() + 32);
        n.level = loadLe16(block.data() + 34);
        n.nkeys = loadLe32(block.data() + 36);
        n.tocOff = loadLe16(block.data() + 40);
        n.tocLen = loadLe16(block.data() + 42);
        n.keyArea = 56 + n.tocOff + n.tocLen;
        n.valEnd = block.size() - (((n.flags & kBtnodeRoot) || isRoot) ? kBtreeInfoSize : 0);
        if (n.keyArea > block.size() || n.nkeys > 65536) return fail(ErrorCategory::InvalidFormat, "bad APFS B-tree node");
        return n;
    }
    bool leaf() const { return (flags & kBtnodeLeaf) != 0; }
    Expected<std::pair<std::span<const std::byte>, std::span<const std::byte>>> entry(std::uint32_t i, std::uint32_t fixedKey, std::uint32_t fixedVal) const {
        const std::byte* toc = block.data() + 56 + tocOff;
        std::size_t koff, klen, voff, vlen;
        if (flags & kBtnodeFixedKv) {
            if (static_cast<std::size_t>(i) * 4 + 4 > tocLen) return fail(ErrorCategory::InvalidFormat, "APFS B-tree TOC overflow");
            koff = loadLe16(toc + i * 4);
            voff = loadLe16(toc + i * 4 + 2);
            klen = fixedKey;
            vlen = leaf() ? fixedVal : 8;
        } else {
            if (static_cast<std::size_t>(i) * 8 + 8 > tocLen) return fail(ErrorCategory::InvalidFormat, "APFS B-tree TOC overflow");
            koff = loadLe16(toc + i * 8);
            klen = loadLe16(toc + i * 8 + 2);
            voff = loadLe16(toc + i * 8 + 4);
            vlen = loadLe16(toc + i * 8 + 6);
        }
        if (keyArea + koff + klen > block.size() || voff > valEnd || vlen > voff) return fail(ErrorCategory::InvalidFormat, "APFS B-tree entry out of its node");
        return std::pair{block.subspan(keyArea + koff, klen), voff == 0xFFFF ? std::span<const std::byte>{} : block.subspan(valEnd - voff, vlen)};
    }
};

} // namespace

Expected<std::vector<std::byte>> ApfsReader::readBlock(std::uint64_t paddr) const {
    if (m_blockCount && paddr >= m_blockCount) return fail(ErrorCategory::InvalidFormat, "APFS block " + std::to_string(paddr) + " is outside the container");
    return m_device->read(paddr * m_blockSize, m_blockSize);
}

Expected<std::vector<std::byte>> ApfsReader::readObject(std::uint64_t paddr, std::uint32_t expectType) const {
    auto b = readBlock(paddr);
    if (!b) return b;
    if (!checksumOk(*b)) return fail(ErrorCategory::Integrity, "APFS object at block " + std::to_string(paddr) + " has a bad checksum");
    const std::uint32_t type = loadLe32(b->data() + 24) & kObjTypeMask;
    if (expectType && type != expectType) return fail(ErrorCategory::InvalidFormat, "APFS object at block " + std::to_string(paddr) + " has type " + std::to_string(type) + ", expected " + std::to_string(expectType));
    return b;
}

Expected<std::unique_ptr<ApfsReader>> ApfsReader::open(std::shared_ptr<BlockDevice> device, unsigned volume) {
    std::unique_ptr<ApfsReader> r(new ApfsReader());
    r->m_device = std::move(device);
    auto first = r->m_device->read(0, 4096);
    if (!first) return fail(first.error());
    if (std::memcmp(first->data() + 32, "NXSB", 4) != 0) return fail(ErrorCategory::InvalidFormat, "no APFS container superblock");
    r->m_blockSize = loadLe32(first->data() + 36);
    if (r->m_blockSize < 4096 || r->m_blockSize > 65536 || (r->m_blockSize & (r->m_blockSize - 1))) return fail(ErrorCategory::InvalidFormat, "bad APFS block size");
    r->m_blockCount = loadLe64(first->data() + 40);
    auto block0 = r->readObject(0, kObjNxSuperblock);
    if (!block0) return fail(block0.error());
    // Newest valid superblock in the checkpoint descriptor area (block 0 is the copy from the
    // last clean unmount; after a crash the descriptor area is newer).
    std::vector<std::byte> sb = *block0;
    std::uint64_t bestXid = loadLe64(sb.data() + 16);
    const std::uint32_t descBlocks = loadLe32(sb.data() + 104) & 0x7FFFFFFFu;
    const std::uint64_t descBase = loadLe64(sb.data() + 112);
    if (!(loadLe32(sb.data() + 104) & 0x80000000u) && descBlocks <= 4096)
        for (std::uint32_t i = 0; i < descBlocks; ++i) {
            auto cand = r->readBlock(descBase + i);
            if (!cand || !checksumOk(*cand) || (loadLe32(cand->data() + 24) & kObjTypeMask) != kObjNxSuperblock) continue;
            if (std::memcmp(cand->data() + 32, "NXSB", 4) != 0) continue;
            const std::uint64_t xid = loadLe64(cand->data() + 16);
            if (xid > bestXid) {
                bestXid = xid;
                sb = std::move(*cand);
            }
        }
    const std::uint64_t omapOid = loadLe64(sb.data() + 160);
    auto omap = r->readObject(omapOid, kObjOmap);
    if (!omap) return fail(omap.error());
    r->m_containerOmapRoot = loadLe64(omap->data() + 48);
    const std::uint32_t maxFs = loadLe32(sb.data() + 180);
    if (volume >= std::min<std::uint32_t>(maxFs, 100)) return fail(ErrorCategory::NotFound, "APFS volume slot " + std::to_string(volume) + " does not exist");
    const std::uint64_t fsOid = loadLe64(sb.data() + 184 + volume * 8);
    if (fsOid == 0) return fail(ErrorCategory::NotFound, "APFS volume slot " + std::to_string(volume) + " is empty");
    auto fsPaddr = r->omapLookup(r->m_containerOmapRoot, fsOid);
    if (!fsPaddr) return fail(fsPaddr.error());
    auto vol = r->readObject(*fsPaddr, kObjFs);
    if (!vol) return fail(vol.error());
    if (std::memcmp(vol->data() + 32, "APSB", 4) != 0) return fail(ErrorCategory::InvalidFormat, "APFS volume superblock without APSB magic");
    const std::uint64_t incompat = loadLe64(vol->data() + 56), fsFlags = loadLe64(vol->data() + 264);
    if (!(fsFlags & kFsUnencrypted)) return fail(ErrorCategory::Unsupported, "encrypted APFS volumes are not supported");
    r->m_caseSensitive = !(incompat & kIncompatCaseInsensitive);
    r->m_hashedKeys = (incompat & (kIncompatCaseInsensitive | kIncompatNormalizationInsensitive)) != 0;
    const char* name = reinterpret_cast<const char*>(vol->data() + 704);
    r->m_volumeName.assign(name, strnlen(name, 256));
    const std::uint64_t volOmapOid = loadLe64(vol->data() + 128), rootTreeOid = loadLe64(vol->data() + 136);
    auto volOmap = r->readObject(volOmapOid, kObjOmap);
    if (!volOmap) return fail(volOmap.error());
    r->m_volumeOmapRoot = loadLe64(volOmap->data() + 48);
    auto rootPaddr = r->omapLookup(r->m_volumeOmapRoot, rootTreeOid);
    if (!rootPaddr) return fail(rootPaddr.error());
    r->m_fsRoot = *rootPaddr;
    return r;
}

Expected<std::uint64_t> ApfsReader::omapLookup(std::uint64_t root, std::uint64_t oid) const {
    std::uint64_t paddr = root;
    for (int depth = 0; depth < 16; ++depth) {
        auto blk = readObject(paddr, depth == 0 ? kObjBtree : kObjBtreeNode);
        if (!blk) return fail(blk.error());
        auto node = NodeView::parse(*blk, depth == 0);
        if (!node) return fail(node.error());
        // Entries are sorted by (oid, xid); take the last one with oid == target (newest xid),
        // or in an index node the last entry whose key <= (oid, max).
        std::int64_t best = -1;
        for (std::uint32_t i = 0; i < node->nkeys; ++i) {
            auto e = node->entry(i, 16, 16);
            if (!e) return fail(e.error());
            if (e->first.size() < 16) return fail(ErrorCategory::InvalidFormat, "short APFS omap key");
            const std::uint64_t koid = loadLe64(e->first.data());
            if (koid < oid || koid == oid) best = static_cast<std::int64_t>(i);
            else break;
        }
        if (best < 0) return fail(ErrorCategory::NotFound, "APFS object " + std::to_string(oid) + " is not in the object map");
        auto e = node->entry(static_cast<std::uint32_t>(best), 16, 16);
        if (!e) return fail(e.error());
        if (node->leaf()) {
            if (loadLe64(e->first.data()) != oid) return fail(ErrorCategory::NotFound, "APFS object " + std::to_string(oid) + " is not in the object map");
            if (e->second.size() < 16) return fail(ErrorCategory::InvalidFormat, "short APFS omap value");
            return loadLe64(e->second.data() + 8);
        }
        if (e->second.size() < 8) return fail(ErrorCategory::InvalidFormat, "short APFS omap index value");
        paddr = loadLe64(e->second.data());
    }
    return fail(ErrorCategory::InvalidFormat, "APFS object map deeper than 16 levels");
}

Expected<void> ApfsReader::scanFsTree(std::uint64_t paddr, std::uint64_t objId, std::uint8_t type, const Visitor& visit, int depth) const {
    if (depth > 16) return fail(ErrorCategory::InvalidFormat, "APFS file system tree deeper than 16 levels");
    auto blk = readObject(paddr, depth == 0 ? kObjBtree : kObjBtreeNode);
    if (!blk) return fail(blk.error());
    auto node = NodeView::parse(*blk, depth == 0);
    if (!node) return fail(node.error());
    const std::uint64_t want = (objId << 4) | type;
    if (node->leaf()) {
        for (std::uint32_t i = 0; i < node->nkeys; ++i) {
            auto e = node->entry(i, 0, 0);
            if (!e) return fail(e.error());
            if (e->first.size() < 8) continue;
            const std::uint64_t k = fsKeyOrder(loadLe64(e->first.data()));
            if (k < want) continue;
            if (k > want) break;
            if (!visit(e->first, e->second)) break;
        }
        return {};
    }
    // Index node: child i covers [key_i, key_{i+1}); descend into every child that may hold `want`.
    for (std::uint32_t i = 0; i < node->nkeys; ++i) {
        auto e = node->entry(i, 0, 0);
        if (!e) return fail(e.error());
        if (e->first.size() < 8 || e->second.size() < 8) return fail(ErrorCategory::InvalidFormat, "short APFS fs-tree index entry");
        const std::uint64_t lo = fsKeyOrder(loadLe64(e->first.data()));
        std::uint64_t hi = ~0ull;
        if (i + 1 < node->nkeys) {
            auto n = node->entry(i + 1, 0, 0);
            if (!n) return fail(n.error());
            if (n->first.size() >= 8) hi = fsKeyOrder(loadLe64(n->first.data()));
        }
        // Child i holds keys in [lo, hi); several children may share the wanted prefix.
        if (lo > want || hi < want) continue;
        const std::uint64_t childOid = loadLe64(e->second.data());
        auto child = omapLookup(m_volumeOmapRoot, childOid);
        if (!child) return fail(child.error());
        if (auto r = scanFsTree(*child, objId, type, visit, depth + 1); !r) return r;
    }
    return {};
}

Expected<void> ApfsReader::scanRecords(std::uint64_t objId, std::uint8_t type, const Visitor& visit) const {
    return scanFsTree(m_fsRoot, objId, type, visit, 0);
}

Expected<ApfsReader::InodeRec> ApfsReader::inode(std::uint64_t id) {
    if (auto it = m_inodes.find(id); it != m_inodes.end()) return it->second;
    InodeRec in;
    bool found = false;
    auto r = scanRecords(id, kTypeInode, [&](std::span<const std::byte>, std::span<const std::byte> v) {
        if (v.size() < 92) return true;
        const std::byte* p = v.data();
        in.parent = loadLe64(p);
        in.privateId = loadLe64(p + 8);
        in.crtime = static_cast<std::int64_t>(loadLe64(p + 16) / 1000000000ull);
        in.mtime = static_cast<std::int64_t>(loadLe64(p + 24) / 1000000000ull);
        in.ctime = static_cast<std::int64_t>(loadLe64(p + 32) / 1000000000ull);
        in.atime = static_cast<std::int64_t>(loadLe64(p + 40) / 1000000000ull);
        in.internalFlags = loadLe64(p + 48);
        in.nlink = loadLe32(p + 56);
        in.bsdFlags = loadLe32(p + 68);
        in.uid = loadLe32(p + 72);
        in.gid = loadLe32(p + 76);
        in.mode = loadLe16(p + 80);
        // Extended fields: count, used bytes, then (type, flags, size) triples and 8-byte aligned data.
        if (v.size() >= 96) {
            const std::uint16_t count = loadLe16(p + 92);
            std::size_t data = 96 + static_cast<std::size_t>(count) * 4;
            for (std::size_t i = 0; i < count && 96 + i * 4 + 4 <= v.size(); ++i) {
                const std::uint8_t xtype = std::to_integer<std::uint8_t>(p[96 + i * 4]);
                const std::uint16_t xsize = loadLe16(p + 96 + i * 4 + 2);
                if (data + xsize > v.size()) break;
                if (xtype == kXfDstream && xsize >= 16) {
                    in.size = loadLe64(p + data);
                    in.allocated = loadLe64(p + data + 8);
                    in.hasDstream = true;
                }
                data += (xsize + 7) & ~std::size_t{7};
            }
        }
        found = true;
        return false;
    });
    if (!r) return fail(r.error());
    if (!found) return fail(ErrorCategory::NotFound, "no APFS inode " + std::to_string(id));
    m_inodes[id] = in;
    return in;
}

Expected<std::vector<ApfsReader::Extent>> ApfsReader::extents(std::uint64_t privateId) {
    if (auto it = m_extentCache.find(privateId); it != m_extentCache.end()) return it->second;
    std::vector<Extent> out;
    auto r = scanRecords(privateId, kTypeFileExtent, [&](std::span<const std::byte> k, std::span<const std::byte> v) {
        if (k.size() < 16 || v.size() < 24) return true;
        Extent e;
        e.logical = loadLe64(k.data() + 8);
        e.length = loadLe64(v.data()) & 0x00FFFFFFFFFFFFFFull;
        e.physical = loadLe64(v.data() + 8);
        out.push_back(e);
        return true;
    });
    if (!r) return fail(r.error());
    std::sort(out.begin(), out.end(), [](const Extent& a, const Extent& b) { return a.logical < b.logical; });
    m_extentCache[privateId] = out;
    return out;
}

Expected<std::vector<DirEntry>> ApfsReader::readdir(const Inode& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    auto in = inode(dir.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Directory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    auto r = scanRecords(dir.id, kTypeDirRec, [&](std::span<const std::byte> k, std::span<const std::byte> v) {
        std::size_t nameOff = m_hashedKeys ? 12 : 10;
        if (k.size() < nameOff || v.size() < 18) return true;
        const std::size_t nameLen = m_hashedKeys ? (loadLe32(k.data() + 8) & 0x3FF) : loadLe16(k.data() + 8);
        if (nameLen == 0 || nameOff + nameLen > k.size()) return true;
        DirEntry e;
        e.name.assign(reinterpret_cast<const char*>(k.data()) + nameOff, nameLen - 1);   // NUL-terminated on disk
        e.inode = Inode{loadLe64(v.data())};
        e.type = drecType(loadLe16(v.data() + 16));
        out.push_back(std::move(e));
        return true;
    });
    if (!r) return fail(r.error());
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> ApfsReader::lookup(const Inode& dir, std::string_view name) {
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    if (!m_caseSensitive)
        for (const auto& e : *entries)
            if (e.name.size() == name.size() && std::equal(e.name.begin(), e.name.end(), name.begin(), [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); }))
                return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> ApfsReader::stat(const Inode& ino) {
    auto in = inode(ino.id);
    if (!in) return fail(in.error());
    Stat st;
    st.type = modeType(in->mode);
    st.mode = in->mode & 07777;
    st.nlink = in->nlink;
    st.uid = in->uid;
    st.gid = in->gid;
    st.size = st.type == FileType::Directory ? 0 : in->size;
    st.allocatedBytes = in->allocated;
    st.atime = in->atime;
    st.mtime = in->mtime;
    st.ctime = in->ctime;
    st.crtime = in->crtime;
    if (st.type == FileType::Symlink && !in->hasDstream) {
        if (auto t = readlink(ino)) st.size = t->size();
    }
    return st;
}

Expected<std::size_t> ApfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = inode(file.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (in->bsdFlags & kUfCompressed) return fail(ErrorCategory::Unsupported, "transparently compressed APFS files (decmpfs) are not supported yet");
    if (offset >= in->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), in->size - offset);
    std::memset(dst.data(), 0, static_cast<std::size_t>(n));
    auto ext = extents(in->privateId);
    if (!ext) return fail(ext.error());
    for (const auto& e : *ext) {
        const std::uint64_t end = e.logical + e.length;
        if (end <= offset || e.logical >= offset + n) continue;
        if (e.physical == 0) continue;   // sparse
        const std::uint64_t from = std::max(offset, e.logical), to = std::min(offset + n, end);
        auto window = dst.subspan(static_cast<std::size_t>(from - offset), static_cast<std::size_t>(to - from));
        if (auto r = m_device->readAt(e.physical * m_blockSize + (from - e.logical), window); !r) return fail(r.error());
    }
    return static_cast<std::size_t>(n);
}

Expected<std::string> ApfsReader::readlink(const Inode& link) {
    auto in = inode(link.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    std::string target;
    bool found = false;
    auto r = scanRecords(link.id, kTypeXattr, [&](std::span<const std::byte> k, std::span<const std::byte> v) {
        if (k.size() < 10) return true;
        const std::uint16_t nameLen = loadLe16(k.data() + 8);
        if (10 + static_cast<std::size_t>(nameLen) > k.size()) return true;
        const std::string_view name(reinterpret_cast<const char*>(k.data()) + 10, nameLen > 0 ? nameLen - 1 : 0);
        if (name != "com.apple.fs.symlink") return true;
        if (v.size() < 4) return true;
        const std::uint16_t flags = loadLe16(v.data()), len = loadLe16(v.data() + 2);
        if (!(flags & kXattrEmbedded) || 4 + static_cast<std::size_t>(len) > v.size()) return true;
        target.assign(reinterpret_cast<const char*>(v.data()) + 4, len);
        while (!target.empty() && target.back() == '\0') target.pop_back();
        found = true;
        return false;
    });
    if (!r) return fail(r.error());
    if (!found) return fail(ErrorCategory::InvalidFormat, "APFS symlink without a com.apple.fs.symlink attribute");
    return target;
}

class ApfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = ApfsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeApfsReaderSource() { return std::make_unique<ApfsReaderSource>(); }

} // namespace stein::fs::detail
