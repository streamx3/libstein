// SPDX-License-Identifier: MIT
// APFS reader. Object headers carry a Fletcher-64 checksum that is verified on
// every read; the container's checkpoint descriptor area is scanned for the
// newest valid superblock; object maps and file system trees are the APFS
// B-tree variant with a table of contents at the front and values growing
// from the back of the node. A snapshot is read through its own volume
// superblock with every object-map lookup bounded by the snapshot's
// transaction id, which is how the object map keeps old versions alive.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/inflate.hpp"
#include "stein/core/lzfse.hpp"
#include "stein/fs/apfs_reader.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint32_t kObjNxSuperblock = 1, kObjBtree = 2, kObjBtreeNode = 3, kObjOmap = 11, kObjFs = 13, kObjTypeMask = 0x0000FFFF;
constexpr std::uint16_t kBtnodeRoot = 1, kBtnodeLeaf = 2, kBtnodeFixedKv = 4;
constexpr std::uint32_t kBtreeInfoSize = 40;
constexpr std::uint8_t kTypeSnapMetadata = 1, kTypeInode = 3, kTypeXattr = 4, kTypeFileExtent = 8, kTypeDirRec = 9;
constexpr std::uint64_t kIncompatCaseInsensitive = 1, kIncompatNormalizationInsensitive = 8, kFsUnencrypted = 1;
constexpr std::uint32_t kUfCompressed = 0x20;
constexpr std::uint8_t kXfDstream = 8;
constexpr std::uint16_t kXattrDataStream = 1, kXattrEmbedded = 2;
constexpr std::uint32_t kOmapValDeleted = 1;
// Volume superblock offsets (apfs_superblock_t).
constexpr std::size_t kVolIncompat = 56, kVolOmapOid = 128, kVolRootTreeOid = 136, kVolSnapMetaTreeOid = 152, kVolNumSnapshots = 216, kVolFlags = 264, kVolName = 704, kVolRole = 964;
// decmpfs compression types.
constexpr std::uint32_t kCmpXattrRaw = 1, kCmpZlibXattr = 3, kCmpZlibRsrc = 4, kCmpLzvnXattr = 7, kCmpLzvnRsrc = 8, kCmpLzfseXattr = 11, kCmpLzfseRsrc = 12;
constexpr std::size_t kDecmpfsBlock = 65536;

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

const char* roleName(std::uint16_t role) {
    switch (role) {
    case 0: return "";
    case 1: return "system";
    case 2: return "user";
    case 4: return "recovery";
    case 8: return "vm";
    case 0x10: return "preboot";
    case 0x20: return "installer";
    case 0x40: return "data";
    case 0x80: return "baseband";
    case 0xC0: return "update";
    case 0x100: return "xart";
    case 0x140: return "hardware";
    case 0x180: return "backup";
    case 0x240: return "enterprise";
    case 0x280: return "prelogin";
    default: return "other";
    }
}

std::string volumeNameOf(const std::vector<std::byte>& sb) {
    const char* name = reinterpret_cast<const char*>(sb.data() + kVolName);
    return std::string(name, strnlen(name, 256));
}

bool parseNumber(std::string_view s, std::uint64_t& out) {
    if (s.empty()) return false;
    auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
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

Expected<void> ApfsReader::loadContainer() {
    auto first = m_device->read(0, 4096);
    if (!first) return fail(first.error());
    if (std::memcmp(first->data() + 32, "NXSB", 4) != 0) return fail(ErrorCategory::InvalidFormat, "no APFS container superblock");
    m_blockSize = loadLe32(first->data() + 36);
    if (m_blockSize < 4096 || m_blockSize > 65536 || (m_blockSize & (m_blockSize - 1))) return fail(ErrorCategory::InvalidFormat, "bad APFS block size");
    m_blockCount = loadLe64(first->data() + 40);
    auto block0 = readObject(0, kObjNxSuperblock);
    if (!block0) return fail(block0.error());
    // Newest valid superblock in the checkpoint descriptor area (block 0 is the copy from the
    // last clean unmount; after a crash the descriptor area is newer).
    std::vector<std::byte> sb = *block0;
    std::uint64_t bestXid = loadLe64(sb.data() + 16);
    const std::uint32_t descBlocks = loadLe32(sb.data() + 104) & 0x7FFFFFFFu;
    const std::uint64_t descBase = loadLe64(sb.data() + 112);
    if (!(loadLe32(sb.data() + 104) & 0x80000000u) && descBlocks <= 4096)
        for (std::uint32_t i = 0; i < descBlocks; ++i) {
            auto cand = readBlock(descBase + i);
            if (!cand || !checksumOk(*cand) || (loadLe32(cand->data() + 24) & kObjTypeMask) != kObjNxSuperblock) continue;
            if (std::memcmp(cand->data() + 32, "NXSB", 4) != 0) continue;
            const std::uint64_t xid = loadLe64(cand->data() + 16);
            if (xid > bestXid) {
                bestXid = xid;
                sb = std::move(*cand);
            }
        }
    const std::uint64_t omapOid = loadLe64(sb.data() + 160);
    auto omap = readObject(omapOid, kObjOmap);
    if (!omap) return fail(omap.error());
    m_containerOmapRoot = loadLe64(omap->data() + 48);
    m_nxSb = std::move(sb);
    return {};
}

Expected<std::uint64_t> ApfsReader::volumeSuperblock(unsigned slot) const {
    const std::uint32_t maxFs = loadLe32(m_nxSb.data() + 180);
    if (slot >= std::min<std::uint32_t>(maxFs, 100)) return fail(ErrorCategory::NotFound, "APFS volume slot " + std::to_string(slot) + " does not exist");
    const std::uint64_t fsOid = loadLe64(m_nxSb.data() + 184 + slot * 8);
    if (fsOid == 0) return 0;
    return omapLookup(m_containerOmapRoot, fsOid);
}

Expected<std::vector<ApfsReader::Snapshot>> ApfsReader::snapshots(const std::vector<std::byte>& volumeSb) const {
    std::vector<Snapshot> out;
    const std::uint64_t treeOid = loadLe64(volumeSb.data() + kVolSnapMetaTreeOid);
    if (treeOid == 0 || loadLe64(volumeSb.data() + kVolNumSnapshots) == 0) return out;
    // The snapshot metadata tree is a physical B-tree: metadata records keyed by xid, name
    // records keyed by name.
    std::unordered_map<std::uint64_t, Snapshot> byXid;
    auto r = walkTree(treeOid, true, [&](std::span<const std::byte> k, std::span<const std::byte> v) {
        if (k.size() < 8) return true;
        const std::uint64_t hdr = loadLe64(k.data());
        const std::uint8_t type = static_cast<std::uint8_t>(hdr >> 60);
        if (type == kTypeSnapMetadata && v.size() >= 50) {
            Snapshot s;
            s.xid = hdr & 0x0FFFFFFFFFFFFFFFull;
            s.sblock = loadLe64(v.data() + 8);
            const std::uint16_t nameLen = loadLe16(v.data() + 48);
            if (50 + static_cast<std::size_t>(nameLen) <= v.size() && nameLen > 0) s.name.assign(reinterpret_cast<const char*>(v.data()) + 50, nameLen - 1);
            byXid[s.xid] = s;
        }
        return true;
    }, 0);
    if (!r) return fail(r.error());
    for (auto& [xid, s] : byXid) out.push_back(s);
    std::sort(out.begin(), out.end(), [](const Snapshot& a, const Snapshot& b) { return a.xid < b.xid; });
    return out;
}

Expected<std::unique_ptr<ApfsReader>> ApfsReader::open(std::shared_ptr<BlockDevice> device, unsigned volume) {
    ReaderOptions o;
    o.volume = std::to_string(volume);
    return open(std::move(device), o);
}

Expected<std::unique_ptr<ApfsReader>> ApfsReader::open(std::shared_ptr<BlockDevice> device, const ReaderOptions& options) {
    std::unique_ptr<ApfsReader> r(new ApfsReader());
    r->m_device = std::move(device);
    if (auto c = r->loadContainer(); !c) return fail(c.error());
    // The volume: by slot number, by name, or the first one present.
    const std::uint32_t maxFs = std::min<std::uint32_t>(loadLe32(r->m_nxSb.data() + 180), 100);
    std::vector<std::byte> liveSb;
    std::uint64_t wantSlot = 0;
    const bool numeric = parseNumber(options.volume, wantSlot);
    std::string names;
    for (std::uint32_t slot = 0; slot < maxFs && liveSb.empty(); ++slot) {
        if (numeric && slot != wantSlot) continue;
        auto paddr = r->volumeSuperblock(slot);
        if (!paddr) return fail(paddr.error());
        if (*paddr == 0) {
            if (numeric) return fail(ErrorCategory::NotFound, "APFS volume slot " + std::to_string(slot) + " is empty");
            continue;
        }
        auto vol = r->readObject(*paddr, kObjFs);
        if (!vol) return fail(vol.error());
        if (std::memcmp(vol->data() + 32, "APSB", 4) != 0) return fail(ErrorCategory::InvalidFormat, "APFS volume superblock without APSB magic");
        const std::string name = volumeNameOf(*vol);
        if (numeric || options.volume.empty() || name == options.volume) liveSb = std::move(*vol);
        else names += (names.empty() ? "" : ", ") + name;
    }
    if (liveSb.empty()) {
        if (options.volume.empty()) return fail(ErrorCategory::NotFound, "APFS container has no volume");
        return fail(ErrorCategory::NotFound, "no APFS volume named \"" + options.volume + "\" (volumes: " + names + ")");
    }
    std::vector<std::byte> sb = liveSb;
    if (!options.snapshot.empty()) {
        auto snaps = r->snapshots(liveSb);
        if (!snaps) return fail(snaps.error());
        std::uint64_t wantXid = 0;
        const bool byXid = parseNumber(options.snapshot, wantXid);
        const Snapshot* chosen = nullptr;
        std::string list;
        for (const auto& s : *snaps) {
            if ((byXid && s.xid == wantXid) || s.name == options.snapshot) chosen = &s;
            list += (list.empty() ? "" : ", ") + s.name + " (xid " + std::to_string(s.xid) + ")";
        }
        if (!chosen) return fail(ErrorCategory::NotFound, "no snapshot \"" + options.snapshot + "\" on APFS volume \"" + volumeNameOf(liveSb) + "\"" + (list.empty() ? "" : " (snapshots: " + list + ")"));
        auto snapSb = r->readObject(chosen->sblock, kObjFs);
        if (!snapSb) return fail(snapSb.error());
        if (std::memcmp(snapSb->data() + 32, "APSB", 4) != 0) return fail(ErrorCategory::InvalidFormat, "APFS snapshot superblock without APSB magic");
        sb = std::move(*snapSb);
        r->m_xid = chosen->xid;
        r->m_snapshotName = chosen->name;
    }
    const std::uint64_t incompat = loadLe64(sb.data() + kVolIncompat), fsFlags = loadLe64(sb.data() + kVolFlags);
    if (!(fsFlags & kFsUnencrypted)) return fail(ErrorCategory::Unsupported, "encrypted APFS volumes are not supported");
    r->m_caseSensitive = !(incompat & kIncompatCaseInsensitive);
    r->m_hashedKeys = (incompat & (kIncompatCaseInsensitive | kIncompatNormalizationInsensitive)) != 0;
    r->m_volumeName = volumeNameOf(sb);
    // The object map is the live volume's (it keeps the versions a snapshot needs); the root
    // tree oid comes from the chosen superblock and resolves at the snapshot's xid.
    const std::uint64_t volOmapOid = loadLe64(liveSb.data() + kVolOmapOid), rootTreeOid = loadLe64(sb.data() + kVolRootTreeOid);
    auto volOmap = r->readObject(volOmapOid, kObjOmap);
    if (!volOmap) return fail(volOmap.error());
    r->m_volumeOmapRoot = loadLe64(volOmap->data() + 48);
    auto rootPaddr = r->omapLookup(r->m_volumeOmapRoot, rootTreeOid, r->m_xid);
    if (!rootPaddr) return fail(rootPaddr.error());
    r->m_fsRoot = *rootPaddr;
    return r;
}

Expected<std::vector<SubvolumeInfo>> ApfsReader::enumerate(std::shared_ptr<BlockDevice> device) {
    ApfsReader r;
    r.m_device = std::move(device);
    if (auto c = r.loadContainer(); !c) return fail(c.error());
    std::vector<SubvolumeInfo> out;
    const std::uint32_t maxFs = std::min<std::uint32_t>(loadLe32(r.m_nxSb.data() + 180), 100);
    for (std::uint32_t slot = 0; slot < maxFs; ++slot) {
        auto paddr = r.volumeSuperblock(slot);
        if (!paddr || *paddr == 0) continue;
        auto vol = r.readObject(*paddr, kObjFs);
        if (!vol || std::memcmp(vol->data() + 32, "APSB", 4) != 0) continue;
        SubvolumeInfo v;
        v.kind = "volume";
        v.name = volumeNameOf(*vol);
        v.id = slot;
        const std::uint16_t role = loadLe16(vol->data() + kVolRole);
        const std::uint64_t nsnap = loadLe64(vol->data() + kVolNumSnapshots);
        v.note = roleName(role);
        if (!(loadLe64(vol->data() + kVolFlags) & kFsUnencrypted)) v.note += std::string(v.note.empty() ? "" : ", ") + "encrypted";
        if (nsnap) v.note += std::string(v.note.empty() ? "" : ", ") + std::to_string(nsnap) + (nsnap == 1 ? " snapshot" : " snapshots");
        out.push_back(v);
        auto snaps = r.snapshots(*vol);
        if (!snaps) continue;
        for (const auto& s : *snaps) out.push_back(SubvolumeInfo{"snapshot", s.name, v.name, s.xid, "xid " + std::to_string(s.xid)});
    }
    return out;
}

Expected<std::uint64_t> ApfsReader::omapLookup(std::uint64_t root, std::uint64_t oid, std::uint64_t maxXid) const {
    std::uint64_t paddr = root;
    for (int depth = 0; depth < 16; ++depth) {
        auto blk = readObject(paddr, depth == 0 ? kObjBtree : kObjBtreeNode);
        if (!blk) return fail(blk.error());
        auto node = NodeView::parse(*blk, depth == 0);
        if (!node) return fail(node.error());
        // Entries are sorted by (oid, xid); take the last one with key <= (oid, maxXid).
        std::int64_t best = -1;
        for (std::uint32_t i = 0; i < node->nkeys; ++i) {
            auto e = node->entry(i, 16, 16);
            if (!e) return fail(e.error());
            if (e->first.size() < 16) return fail(ErrorCategory::InvalidFormat, "short APFS omap key");
            const std::uint64_t koid = loadLe64(e->first.data()), kxid = loadLe64(e->first.data() + 8);
            if (koid < oid || (koid == oid && kxid <= maxXid)) best = static_cast<std::int64_t>(i);
            else break;
        }
        if (best < 0) return fail(ErrorCategory::NotFound, "APFS object " + std::to_string(oid) + " is not in the object map");
        auto e = node->entry(static_cast<std::uint32_t>(best), 16, 16);
        if (!e) return fail(e.error());
        if (node->leaf()) {
            if (loadLe64(e->first.data()) != oid) return fail(ErrorCategory::NotFound, "APFS object " + std::to_string(oid) + " is not in the object map");
            if (e->second.size() < 16) return fail(ErrorCategory::InvalidFormat, "short APFS omap value");
            if (loadLe32(e->second.data()) & kOmapValDeleted) return fail(ErrorCategory::NotFound, "APFS object " + std::to_string(oid) + " was deleted");
            return loadLe64(e->second.data() + 8);
        }
        if (e->second.size() < 8) return fail(ErrorCategory::InvalidFormat, "short APFS omap index value");
        paddr = loadLe64(e->second.data());
    }
    return fail(ErrorCategory::InvalidFormat, "APFS object map deeper than 16 levels");
}

Expected<void> ApfsReader::walkTree(std::uint64_t paddr, bool physicalChildren, const Visitor& visit, int depth) const {
    if (depth > 16) return fail(ErrorCategory::InvalidFormat, "APFS B-tree deeper than 16 levels");
    auto blk = readObject(paddr, depth == 0 ? kObjBtree : kObjBtreeNode);
    if (!blk) return fail(blk.error());
    auto node = NodeView::parse(*blk, depth == 0);
    if (!node) return fail(node.error());
    for (std::uint32_t i = 0; i < node->nkeys; ++i) {
        auto e = node->entry(i, 0, 0);
        if (!e) return fail(e.error());
        if (node->leaf()) {
            if (!visit(e->first, e->second)) return {};
            continue;
        }
        if (e->second.size() < 8) return fail(ErrorCategory::InvalidFormat, "short APFS B-tree index value");
        std::uint64_t child = loadLe64(e->second.data());
        if (!physicalChildren) {
            auto p = omapLookup(m_volumeOmapRoot, child, m_xid);
            if (!p) return fail(p.error());
            child = *p;
        }
        if (auto r = walkTree(child, physicalChildren, visit, depth + 1); !r) return r;
    }
    return {};
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
        auto child = omapLookup(m_volumeOmapRoot, childOid, m_xid);
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

Expected<std::size_t> ApfsReader::readExtents(std::uint64_t privateId, std::uint64_t size, std::uint64_t offset, std::span<std::byte> dst) {
    if (offset >= size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), size - offset);
    std::memset(dst.data(), 0, static_cast<std::size_t>(n));
    auto ext = extents(privateId);
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

Expected<std::optional<std::vector<std::byte>>> ApfsReader::xattr(std::uint64_t id, std::string_view wanted) {
    std::optional<std::vector<std::byte>> result;
    std::uint64_t streamId = 0, streamSize = 0;
    bool stream = false;
    auto r = scanRecords(id, kTypeXattr, [&](std::span<const std::byte> k, std::span<const std::byte> v) {
        if (k.size() < 10) return true;
        const std::uint16_t nameLen = loadLe16(k.data() + 8);
        if (10 + static_cast<std::size_t>(nameLen) > k.size()) return true;
        const std::string_view name(reinterpret_cast<const char*>(k.data()) + 10, nameLen > 0 ? nameLen - 1 : 0);
        if (name != wanted) return true;
        if (v.size() < 4) return true;
        const std::uint16_t flags = loadLe16(v.data()), len = loadLe16(v.data() + 2);
        if (flags & kXattrEmbedded) {
            if (4 + static_cast<std::size_t>(len) > v.size()) return true;
            result.emplace(v.begin() + 4, v.begin() + 4 + len);
        } else if ((flags & kXattrDataStream) && v.size() >= 4 + 16) {
            streamId = loadLe64(v.data() + 4);
            streamSize = loadLe64(v.data() + 12);
            stream = true;
        }
        return false;
    });
    if (!r) return fail(r.error());
    if (stream) {
        if (streamSize > (std::uint64_t{1} << 31)) return fail(ErrorCategory::OutOfRange, "APFS extended attribute larger than 2 GiB");
        result.emplace(static_cast<std::size_t>(streamSize));
        auto n = readExtents(streamId, streamSize, 0, *result);
        if (!n) return fail(n.error());
        result->resize(*n);
    }
    return result;
}

Expected<ApfsReader::Decmpfs> ApfsReader::decmpfs(std::uint64_t id) {
    auto x = xattr(id, "com.apple.decmpfs");
    if (!x) return fail(x.error());
    if (!*x || (*x)->size() < 16 || std::memcmp((*x)->data(), "fpmc", 4) != 0) return fail(ErrorCategory::InvalidFormat, "compressed APFS file without a valid com.apple.decmpfs attribute");
    Decmpfs d;
    d.type = loadLe32((*x)->data() + 4);
    d.size = loadLe64((*x)->data() + 8);
    d.payload.assign((*x)->begin() + 16, (*x)->end());
    return d;
}

Expected<std::shared_ptr<const std::vector<std::byte>>> ApfsReader::decompressed(std::uint64_t id, const InodeRec&) {
    if (m_decompId == id && m_decompData) return m_decompData;
    auto d = decmpfs(id);
    if (!d) return fail(d.error());
    if (d->size > (std::uint64_t{1} << 31)) return fail(ErrorCategory::OutOfRange, "compressed APFS file larger than 2 GiB");
    auto out = std::make_shared<std::vector<std::byte>>(static_cast<std::size_t>(d->size));
    std::span<std::byte> dst(*out);
    auto raw = [&](std::span<const std::byte> src, std::span<std::byte> to) -> Expected<void> {
        if (src.size() != to.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs raw block has the wrong size");
        std::memcpy(to.data(), src.data(), src.size());
        return {};
    };
    // One in-xattr payload, or one resource-fork block, into `to` (exactly to.size() bytes).
    static const bool debug = std::getenv("STEIN_APFS_DEBUG") != nullptr;
    if (debug) std::fprintf(stderr, "decmpfs inode %llu type %u size %llu payload %zu\n", static_cast<unsigned long long>(id), d->type, static_cast<unsigned long long>(d->size), d->payload.size());
    auto decodeBlock = [&](std::uint32_t type, std::span<const std::byte> src, std::span<std::byte> to) -> Expected<void> {
        if (to.empty()) return {};
        if (src.empty()) return fail(ErrorCategory::InvalidFormat, "decmpfs block is empty");
        const std::uint8_t marker = std::to_integer<std::uint8_t>(src[0]);
        if (debug) std::fprintf(stderr, "  block in %zu bytes (first 0x%02x 0x%02x) -> out %zu\n", src.size(), marker, src.size() > 1 ? std::to_integer<unsigned>(src[1]) : 0u, to.size());
        Expected<std::size_t> n;
        switch (type) {
        case kCmpZlibXattr:
        case kCmpZlibRsrc:
            if (marker == 0xFF) return raw(src.subspan(1), to);
            n = compress::inflateZlib(src, to);
            break;
        case kCmpLzvnXattr:
        case kCmpLzvnRsrc:
            if (marker == 0x06) return raw(src.subspan(1), to);
            n = compress::lzvnDecompress(src, to);
            break;
        case kCmpLzfseXattr:
        case kCmpLzfseRsrc: n = compress::lzfseDecompress(src, to); break;
        default: return fail(ErrorCategory::Unsupported, "decmpfs compression type " + std::to_string(type) + " is not supported");
        }
        if (!n) return fail(n.error());
        if (*n != to.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs block decoded to " + std::to_string(*n) + " bytes, expected " + std::to_string(to.size()));
        return {};
    };
    switch (d->type) {
    case kCmpXattrRaw:
        if (auto r = raw(d->payload, dst); !r) return fail(r.error());
        break;
    case kCmpZlibXattr:
    case kCmpLzvnXattr:
    case kCmpLzfseXattr:
        if (auto r = decodeBlock(d->type, d->payload, dst); !r) return fail(r.error());
        break;
    case kCmpZlibRsrc:
    case kCmpLzvnRsrc:
    case kCmpLzfseRsrc: {
        auto fork = xattr(id, "com.apple.ResourceFork");
        if (!fork) return fail(fork.error());
        if (!*fork) return fail(ErrorCategory::InvalidFormat, "compressed APFS file without its resource fork");
        const std::span<const std::byte> rf(**fork);
        const std::size_t blocks = static_cast<std::size_t>((d->size + kDecmpfsBlock - 1) / kDecmpfsBlock);
        if (d->type == kCmpZlibRsrc) {
            // Classic resource fork: big-endian header, then at dataOff a length, then a little-endian
            // block table (count, {offset, size}) relative to the table itself.
            if (rf.size() < 16) return fail(ErrorCategory::InvalidFormat, "decmpfs resource fork too short");
            const std::size_t dataOff = loadBe32(rf.data());
            if (dataOff + 8 > rf.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs resource fork data offset out of range");
            const std::size_t table = dataOff + 4;
            const std::uint32_t count = loadLe32(rf.data() + table);
            if (count != blocks) return fail(ErrorCategory::InvalidFormat, "decmpfs resource fork has " + std::to_string(count) + " blocks, expected " + std::to_string(blocks));
            for (std::size_t i = 0; i < blocks; ++i) {
                const std::size_t ent = table + 4 + i * 8;
                if (ent + 8 > rf.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs block table truncated");
                const std::size_t off = table + loadLe32(rf.data() + ent), len = loadLe32(rf.data() + ent + 4);
                if (off + len > rf.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs block outside the resource fork");
                const std::size_t outLen = std::min(kDecmpfsBlock, dst.size() - i * kDecmpfsBlock);
                if (auto r = decodeBlock(d->type, rf.subspan(off, len), dst.subspan(i * kDecmpfsBlock, outLen)); !r) return fail(r.error());
            }
        } else {
            // lzvn/lzfse forks: a little-endian table of blocks + 1 offsets from the fork start.
            if (rf.size() < (blocks + 1) * 4) return fail(ErrorCategory::InvalidFormat, "decmpfs resource fork offset table truncated");
            for (std::size_t i = 0; i < blocks; ++i) {
                const std::size_t off = loadLe32(rf.data() + 4 * i), end = loadLe32(rf.data() + 4 * (i + 1));
                if (end < off || end > rf.size()) return fail(ErrorCategory::InvalidFormat, "decmpfs block outside the resource fork");
                const std::size_t outLen = std::min(kDecmpfsBlock, dst.size() - i * kDecmpfsBlock);
                if (auto r = decodeBlock(d->type, rf.subspan(off, end - off), dst.subspan(i * kDecmpfsBlock, outLen)); !r) return fail(r.error());
            }
        }
        break;
    }
    default: return fail(ErrorCategory::Unsupported, "decmpfs compression type " + std::to_string(d->type) + " is not supported");
    }
    m_decompId = id;
    m_decompData = out;
    return m_decompData;
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
    if (st.type == FileType::File && (in->bsdFlags & kUfCompressed)) {
        if (auto d = decmpfs(ino.id)) st.size = d->size;
    }
    return st;
}

Expected<std::size_t> ApfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto in = inode(file.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) == FileType::Directory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (in->bsdFlags & kUfCompressed) {
        auto data = decompressed(file.id, *in);
        if (!data) return fail(data.error());
        if (offset >= (*data)->size()) return 0;
        const std::size_t n = std::min<std::size_t>(dst.size(), (*data)->size() - static_cast<std::size_t>(offset));
        std::memcpy(dst.data(), (*data)->data() + offset, n);
        return n;
    }
    return readExtents(in->privateId, in->size, offset, dst);
}

Expected<std::string> ApfsReader::readlink(const Inode& link) {
    auto in = inode(link.id);
    if (!in) return fail(in.error());
    if (modeType(in->mode) != FileType::Symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    auto x = xattr(link.id, "com.apple.fs.symlink");
    if (!x) return fail(x.error());
    if (!*x) return fail(ErrorCategory::InvalidFormat, "APFS symlink without a com.apple.fs.symlink attribute");
    std::string target(reinterpret_cast<const char*>((*x)->data()), (*x)->size());
    while (!target.empty() && target.back() == '\0') target.pop_back();
    return target;
}

class ApfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override { return openWith(std::move(device), ReaderOptions{}); }
    Expected<std::unique_ptr<Reader>> openWith(std::shared_ptr<BlockDevice> device, const ReaderOptions& options) const override {
        auto r = ApfsReader::open(std::move(device), options);
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeApfsReaderSource() { return std::make_unique<ApfsReaderSource>(); }

} // namespace stein::fs::detail
