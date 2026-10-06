// SPDX-License-Identifier: MIT
// HFS+ / HFSX reader: volume header forks, B-tree nodes (header, index,
// leaf), catalog folder/file/thread records, extents overflow for files with
// more than eight extents, hard links through the private metadata folder,
// S_IFLNK symlinks, case-insensitive lookup for HFS+ and binary for HFSX.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/hfsplus_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint32_t kExtentsFileId = 3, kCatalogFileId = 4;
constexpr std::int64_t kMacEpochOffset = 2082844800;   // 1904-01-01 -> 1970-01-01
constexpr std::int16_t kFolderRecord = 1, kFileRecord = 2, kFolderThread = 3, kFileThread = 4;
constexpr std::uint8_t kBinaryCompare = 0xBC;
constexpr std::uint32_t kBTVariableIndexKeys = 0x4;
constexpr std::uint8_t kUfCompressed = 0x20;

std::int64_t macTime(std::uint32_t t) { return t ? static_cast<std::int64_t>(t) - kMacEpochOffset : 0; }

std::u16string readUniStr(const std::byte* p, std::size_t maxUnits) {
    const std::uint16_t len = std::min<std::uint16_t>(loadBe16(p), static_cast<std::uint16_t>(maxUnits));
    std::u16string s(len, u'\0');
    for (std::uint16_t i = 0; i < len; ++i) s[i] = static_cast<char16_t>(loadBe16(p + 2 + i * 2));
    return s;
}

std::string u16ToUtf8(const std::u16string& s) {
    std::vector<std::byte> buf(s.size() * 2);
    for (std::size_t i = 0; i < s.size(); ++i) storeLe16(buf.data() + i * 2, static_cast<std::uint16_t>(s[i]));
    return utf16leToUtf8(buf, false);
}

std::u16string utf8ToU16(std::string_view s) {
    const std::size_t units = utf16Length(s);
    std::vector<std::byte> buf(units * 2);
    if (!utf8ToUtf16le(s, buf)) return {};
    std::u16string out(units, u'\0');
    for (std::size_t i = 0; i < units; ++i) out[i] = static_cast<char16_t>(loadLe16(buf.data() + i * 2));
    return out;
}

// Catalog key: keyLength u16, parentID u32, name (length u16 + UTF-16BE).
struct CatalogTarget {
    std::uint32_t parent;
};
int compareCatalogParent(const std::byte* key, const void* t) {
    const auto* target = static_cast<const CatalogTarget*>(t);
    const std::uint32_t parent = loadBe32(key + 2);
    if (parent != target->parent) return parent < target->parent ? -1 : 1;
    return loadBe16(key + 6) == 0 ? 0 : 1;   // the thread record (empty name) is the first key of a parent
}

// Extents key: keyLength u16 (10), forkType u8, pad u8, fileID u32, startBlock u32.
struct ExtentsTarget {
    std::uint8_t forkType;
    std::uint32_t fileId, startBlock;
};
int compareExtents(const std::byte* key, const void* t) {
    const auto* target = static_cast<const ExtentsTarget*>(t);
    const std::uint8_t fork = std::to_integer<std::uint8_t>(key[2]);
    if (fork != target->forkType) return fork < target->forkType ? -1 : 1;
    const std::uint32_t id = loadBe32(key + 4);
    if (id != target->fileId) return id < target->fileId ? -1 : 1;
    const std::uint32_t start = loadBe32(key + 8);
    if (start != target->startBlock) return start < target->startBlock ? -1 : 1;
    return 0;
}

bool isPrivateName(const std::u16string& n) {
    static const std::u16string data(u"\0\0\0\0HFS+ Private Data", 21), dir = u".HFS+ Private Directory Data\r";
    return n == data || n == dir;
}
} // namespace

HfsPlusReader::Fork HfsPlusReader::parseFork(const std::byte* p) {
    Fork f;
    f.logicalSize = loadBe64(p);
    f.totalBlocks = loadBe32(p + 12);
    for (int i = 0; i < 8; ++i) {
        const std::uint32_t start = loadBe32(p + 16 + i * 8), count = loadBe32(p + 16 + i * 8 + 4);
        if (count == 0) break;
        f.extents.emplace_back(start, count);
    }
    return f;
}

Expected<std::unique_ptr<HfsPlusReader>> HfsPlusReader::open(std::shared_ptr<BlockDevice> device, ByteCount base) {
    auto raw = device->read(base + 1024, 512);
    if (!raw) return fail(raw.error());
    const std::byte* h = raw->data();
    const std::string sig(reinterpret_cast<const char*>(h), 2);
    if (sig != "H+" && sig != "HX") return fail(ErrorCategory::InvalidFormat, "not an HFS+ volume header");
    auto r = std::unique_ptr<HfsPlusReader>(new HfsPlusReader());
    r->m_device = std::move(device);
    r->m_base = base;
    r->m_blockSize = loadBe32(h + 0x28);
    r->m_totalBlocks = loadBe32(h + 0x2C);
    if (r->m_blockSize < 512 || (r->m_blockSize & (r->m_blockSize - 1)) != 0) return fail(ErrorCategory::InvalidFormat, "bad HFS+ block size");
    r->m_journaled = (loadBe32(h + 4) & (1u << 13)) != 0;
    // Extents overflow first (the catalog may need it), then the catalog.
    auto ext = r->openTree(parseFork(h + 0xC0), kExtentsFileId);
    if (!ext) return fail(ext.error());
    r->m_extents = std::move(*ext);
    auto cat = r->openTree(parseFork(h + 0x110), kCatalogFileId);
    if (!cat) return fail(cat.error());
    r->m_catalog = std::move(*cat);
    r->m_caseSensitive = sig == "HX" && r->m_catalog.keyCompareType == kBinaryCompare;
    // Locate the private metadata folders so listings can hide them and hard links can resolve.
    auto rootEntries = r->listFolder(2);
    if (!rootEntries) return fail(rootEntries.error());
    return r;
}

Expected<HfsPlusReader::BTree> HfsPlusReader::openTree(const Fork& fork, std::uint32_t cnid) {
    BTree t;
    t.fork = fork;
    t.cnid = cnid;
    if (fork.extents.empty()) return fail(ErrorCategory::InvalidFormat, "B-tree file " + std::to_string(cnid) + " has no extents");
    if (auto c = completeExtents(t.fork, cnid, 0); !c) return fail(c.error());
    std::vector<std::byte> hdr(512);
    if (auto rd = readForkInto(t.fork, 0, hdr); !rd) return fail(rd.error());
    const std::byte* rec = hdr.data() + 14;   // BTHeaderRec follows the node descriptor
    t.rootNode = loadBe32(rec + 2);
    t.firstLeaf = loadBe32(rec + 10);
    t.nodeSize = loadBe16(rec + 18);
    t.maxKeyLength = loadBe16(rec + 20);
    t.totalNodes = loadBe32(rec + 22);
    t.keyCompareType = std::to_integer<std::uint8_t>(rec[37]);
    t.attributes = loadBe32(rec + 38);
    if (t.nodeSize < 512 || t.nodeSize > 32768 || (t.nodeSize & (t.nodeSize - 1)) != 0) return fail(ErrorCategory::InvalidFormat, "bad B-tree node size");
    if (ByteCount{t.totalNodes} * t.nodeSize > t.fork.logicalSize) return fail(ErrorCategory::InvalidFormat, "B-tree claims more nodes than its file holds");
    return t;
}

Expected<void> HfsPlusReader::completeExtents(Fork& fork, std::uint32_t cnid, std::uint8_t forkType) {
    std::uint32_t have = 0;
    for (const auto& e : fork.extents) have += e.second;
    int rounds = 0;
    while (have < fork.totalBlocks && cnid != kExtentsFileId && ++rounds < 4096) {
        ExtentsTarget target{forkType, cnid, have};
        auto leaf = findLeaf(m_extents, &compareExtents, &target);
        if (!leaf) return fail(leaf.error());
        const std::uint16_t numRecords = loadBe16(leaf->bytes.data() + 10);
        if (leaf->record >= numRecords) return fail(ErrorCategory::InvalidFormat, "missing extents overflow record");
        const std::uint16_t off = loadBe16(leaf->bytes.data() + m_extents.nodeSize - 2 * (leaf->record + 1));
        if (off + 12u + 64u > m_extents.nodeSize) return fail(ErrorCategory::InvalidFormat, "extents record outside its node");
        if (compareExtents(leaf->bytes.data() + off, &target) != 0) return fail(ErrorCategory::InvalidFormat, "extents overflow record for block " + std::to_string(have) + " not found");
        const std::byte* data = leaf->bytes.data() + off + 12;
        bool any = false;
        for (int i = 0; i < 8; ++i) {
            const std::uint32_t start = loadBe32(data + i * 8), count = loadBe32(data + i * 8 + 4);
            if (count == 0) break;
            fork.extents.emplace_back(start, count);
            have += count;
            any = true;
        }
        if (!any) break;
    }
    return {};
}

Expected<void> HfsPlusReader::readForkInto(const Fork& fork, std::uint64_t offset, std::span<std::byte> dst) const {
    std::uint64_t done = 0;
    while (done < dst.size()) {
        const std::uint64_t pos = offset + done;
        std::uint64_t block = pos / m_blockSize, skipped = 0;
        const std::pair<std::uint32_t, std::uint32_t>* ext = nullptr;
        for (const auto& e : fork.extents) {
            if (block < skipped + e.second) {
                ext = &e;
                break;
            }
            skipped += e.second;
        }
        if (!ext) return fail(ErrorCategory::InvalidFormat, "read beyond the fork's extents");
        const std::uint64_t inExtent = (block - skipped) * m_blockSize + pos % m_blockSize;
        const std::uint64_t extentBytes = std::uint64_t{ext->second} * m_blockSize;
        const std::uint64_t n = std::min<std::uint64_t>(extentBytes - inExtent, dst.size() - done);
        if (ext->first >= m_totalBlocks) return fail(ErrorCategory::InvalidFormat, "extent outside the volume");
        if (auto r = m_device->readAt(blockOffset(ext->first) + inExtent, dst.subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(n))); !r) return fail(r.error());
        done += n;
    }
    return {};
}

Expected<std::vector<std::byte>> HfsPlusReader::readNode(const BTree& tree, std::uint32_t node) const {
    if (node >= tree.totalNodes) return fail(ErrorCategory::InvalidFormat, "B-tree node " + std::to_string(node) + " out of range");
    std::vector<std::byte> out(tree.nodeSize);
    if (auto r = readForkInto(tree.fork, ByteCount{node} * tree.nodeSize, out); !r) return fail(r.error());
    return out;
}

Expected<HfsPlusReader::LeafPos> HfsPlusReader::findLeaf(const BTree& tree, KeyCompare cmp, const void* target) const {
    std::uint32_t node = tree.rootNode;
    if (node == 0) {
        LeafPos empty;
        empty.node = 0;
        empty.bytes.assign(tree.nodeSize, std::byte{0});
        return empty;   // empty tree: zero records
    }
    for (int depth = 0; depth < 32; ++depth) {
        auto bytes = readNode(tree, node);
        if (!bytes) return fail(bytes.error());
        const std::byte* n = bytes->data();
        const auto kind = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(n[8]));
        const std::uint16_t numRecords = loadBe16(n + 10);
        const auto recordAt = [&](std::uint16_t i) -> const std::byte* {
            const std::uint16_t off = loadBe16(n + tree.nodeSize - 2 * (i + 1));
            return off + 2u <= tree.nodeSize ? n + off : nullptr;
        };
        if (kind == -1) {
            std::uint16_t i = 0;
            for (; i < numRecords; ++i) {
                const std::byte* rec = recordAt(i);
                if (!rec) break;
                if (cmp(rec, target) >= 0) break;
            }
            LeafPos pos;
            pos.node = node;
            pos.record = i;
            pos.bytes = std::move(*bytes);
            return pos;
        }
        if (kind != 0) return fail(ErrorCategory::InvalidFormat, "unexpected B-tree node kind on the search path");
        if (numRecords == 0) return fail(ErrorCategory::InvalidFormat, "empty index node");
        // Last record whose key <= target, else the first.
        std::uint32_t child = 0;
        bool found = false;
        for (std::uint16_t i = 0; i < numRecords; ++i) {
            const std::byte* rec = recordAt(i);
            if (!rec) break;
            const std::uint16_t keyLen = (tree.attributes & kBTVariableIndexKeys) ? loadBe16(rec) : tree.maxKeyLength;
            const std::byte* data = rec + 2 + keyLen + (keyLen & 1);
            if (data + 4 > n + tree.nodeSize) break;
            if (cmp(rec, target) <= 0) {
                child = loadBe32(data);
                found = true;
            } else {
                if (!found) child = loadBe32(data);
                break;
            }
        }
        if (child == 0) return fail(ErrorCategory::InvalidFormat, "index node without a usable child");
        node = child;
    }
    return fail(ErrorCategory::InvalidFormat, "B-tree deeper than 32 levels");
}

Expected<std::vector<HfsPlusReader::Record>> HfsPlusReader::listFolder(std::uint32_t cnid) {
    if (auto it = m_dirCache.find(cnid); it != m_dirCache.end()) return it->second;
    CatalogTarget target{cnid};
    auto leaf = findLeaf(m_catalog, &compareCatalogParent, &target);
    if (!leaf) return fail(leaf.error());
    std::vector<Record> out;
    std::uint32_t node = leaf->node;
    std::uint16_t index = leaf->record;
    std::vector<std::byte> bytes = std::move(leaf->bytes);
    for (int hops = 0; hops < 1 << 20; ++hops) {
        const std::byte* n = bytes.data();
        const std::uint16_t numRecords = loadBe16(n + 10);
        bool done = false;
        for (; index < numRecords; ++index) {
            const std::uint16_t off = loadBe16(n + m_catalog.nodeSize - 2 * (index + 1));
            if (off + 8u > m_catalog.nodeSize) continue;
            const std::byte* key = n + off;
            const std::uint16_t keyLen = loadBe16(key);
            const std::uint32_t parent = loadBe32(key + 2);
            if (parent > cnid) {
                done = true;
                break;
            }
            if (parent < cnid) continue;
            const std::uint16_t nameLen = loadBe16(key + 6);
            if (off + 2u + keyLen > m_catalog.nodeSize || nameLen > 255 || 6u + 2u * nameLen > keyLen) continue;
            const std::byte* data = key + 2 + keyLen + (keyLen & 1);
            if (data + 2 > n + m_catalog.nodeSize) continue;
            const auto type = static_cast<std::int16_t>(loadBe16(data));
            if (type == kFolderThread || type == kFileThread || nameLen == 0) continue;
            if (type != kFolderRecord && type != kFileRecord) continue;
            const std::size_t need = type == kFolderRecord ? 88 : 248;
            if (data + need > n + m_catalog.nodeSize) continue;
            Record rec;
            rec.parent = parent;
            rec.name16 = readUniStr(key + 6, nameLen);
            rec.name = u16ToUtf8(rec.name16);
            rec.folder = type == kFolderRecord;
            rec.cnid = loadBe32(data + 8);
            if (rec.folder) rec.valence = loadBe32(data + 4);
            rec.createDate = loadBe32(data + 12);
            rec.modDate = loadBe32(data + 16);
            rec.attrModDate = loadBe32(data + 20);
            rec.accessDate = loadBe32(data + 24);
            rec.uid = loadBe32(data + 32);
            rec.gid = loadBe32(data + 36);
            rec.adminFlags = std::to_integer<std::uint8_t>(data[40]);
            rec.ownerFlags = std::to_integer<std::uint8_t>(data[41]);
            rec.mode = loadBe16(data + 42);
            rec.special = loadBe32(data + 44);
            rec.fdType = loadBe32(data + 48);
            rec.fdCreator = loadBe32(data + 52);
            if (!rec.folder) {
                rec.data = parseFork(data + 88);
                rec.rsrc = parseFork(data + 168);
            }
            if (cnid == 2 && isPrivateName(rec.name16)) {
                (rec.name16[0] == u'\0' ? m_privateDataCnid : m_privateDirCnid) = rec.cnid;
                continue;   // hidden, like the kernel does
            }
            if (cnid == 2 && m_journaled && (rec.name == ".journal" || rec.name == ".journal_info_block")) continue;
            m_cache[rec.cnid] = rec;
            out.push_back(std::move(rec));
        }
        if (done) break;
        const std::uint32_t next = loadBe32(n);   // fLink
        if (next == 0) break;
        auto nb = readNode(m_catalog, next);
        if (!nb) return fail(nb.error());
        bytes = std::move(*nb);
        node = next;
        index = 0;
    }
    (void)node;
    m_dirCache[cnid] = out;
    return out;
}

Expected<HfsPlusReader::Record> HfsPlusReader::recordOf(std::uint32_t cnid) {
    if (auto it = m_cache.find(cnid); it != m_cache.end()) return it->second;
    // Thread record (cnid, "") -> parent, then the parent's listing.
    CatalogTarget target{cnid};
    auto leaf = findLeaf(m_catalog, &compareCatalogParent, &target);
    if (!leaf) return fail(leaf.error());
    const std::byte* n = leaf->bytes.data();
    const std::uint16_t numRecords = loadBe16(n + 10);
    if (leaf->record >= numRecords) return fail(ErrorCategory::NotFound, "no catalog record for CNID " + std::to_string(cnid));
    const std::uint16_t off = loadBe16(n + m_catalog.nodeSize - 2 * (leaf->record + 1));
    const std::byte* key = n + off;
    if (compareCatalogParent(key, &target) != 0) return fail(ErrorCategory::NotFound, "no thread record for CNID " + std::to_string(cnid));
    const std::uint16_t keyLen = loadBe16(key);
    const std::byte* data = key + 2 + keyLen + (keyLen & 1);
    if (data + 10 > n + m_catalog.nodeSize) return fail(ErrorCategory::InvalidFormat, "thread record outside its node");
    const auto type = static_cast<std::int16_t>(loadBe16(data));
    if (type != kFolderThread && type != kFileThread) return fail(ErrorCategory::InvalidFormat, "expected a thread record");
    const std::uint32_t parent = loadBe32(data + 4);
    auto siblings = listFolder(parent);
    if (!siblings) return fail(siblings.error());
    for (const auto& s : *siblings)
        if (s.cnid == cnid) return s;
    if (cnid == 2 || parent == 1) {
        // The root folder record lives under parent 1; synthesise it from the thread.
        Record root;
        root.cnid = cnid;
        root.parent = parent;
        root.folder = true;
        root.name16 = readUniStr(data + 8, 255);
        root.name = u16ToUtf8(root.name16);
        root.mode = 0755;
        m_cache[cnid] = root;
        return root;
    }
    return fail(ErrorCategory::NotFound, "catalog record for CNID " + std::to_string(cnid) + " not in its parent");
}

Expected<HfsPlusReader::Record> HfsPlusReader::resolveLink(const Record& link) {
    if (!link.hardLink()) return link;
    if (!m_privateDataCnid) return fail(ErrorCategory::InvalidFormat, "hard link without a private metadata folder");
    auto inodes = listFolder(m_privateDataCnid);
    if (!inodes) return fail(inodes.error());
    const std::string want = "iNode" + std::to_string(link.special);
    for (const auto& r : *inodes)
        if (r.name == want) return r;
    return fail(ErrorCategory::NotFound, "hard link target " + want + " missing");
}

std::u16string HfsPlusReader::fold(std::u16string s) const {
    if (m_caseSensitive) return s;
    for (auto& c : s) {
        if (c >= u'A' && c <= u'Z') c = static_cast<char16_t>(c + 32);
        else if (c >= 0xC0 && c <= 0xDE && c != 0xD7) c = static_cast<char16_t>(c + 32);
        else if (c >= 0x100 && c <= 0x137 && (c & 1) == 0) c = static_cast<char16_t>(c + 1);
        else if (c >= 0x139 && c <= 0x148 && (c & 1) == 1) c = static_cast<char16_t>(c + 1);
        else if (c >= 0x14A && c <= 0x177 && (c & 1) == 0) c = static_cast<char16_t>(c + 1);
        else if (c == 0x178) c = 0xFF;
        else if (c >= 0x179 && c <= 0x17E && (c & 1) == 1) c = static_cast<char16_t>(c + 1);
        else if (c >= 0x391 && c <= 0x3AB && c != 0x3A2) c = static_cast<char16_t>(c + 32);
        else if (c >= 0x410 && c <= 0x42F) c = static_cast<char16_t>(c + 32);
        else if (c >= 0x400 && c <= 0x40F) c = static_cast<char16_t>(c + 80);
    }
    return s;
}

Expected<Inode> HfsPlusReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto entries = listFolder(static_cast<std::uint32_t>(dir.id));
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return Inode{e.cnid};
    if (!m_caseSensitive) {
        const std::u16string want = fold(utf8ToU16(name));
        for (const auto& e : *entries)
            if (fold(e.name16) == want) return Inode{e.cnid};
    }
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> HfsPlusReader::stat(const Inode& inode) {
    auto rec = recordOf(static_cast<std::uint32_t>(inode.id));
    if (!rec) return fail(rec.error());
    Stat st;
    st.nlink = 1;
    if (rec->hardLink()) {
        auto target = resolveLink(*rec);
        if (!target) return fail(target.error());
        st.nlink = target->special ? target->special : 1;   // link count lives in the iNode file
        rec = target;
    }
    const std::uint16_t fmt = rec->mode & 0170000;
    if (rec->folder) st.type = FileType::Directory;
    else if (fmt == 0120000) st.type = FileType::Symlink;
    else if (fmt == 0020000) st.type = FileType::CharDevice;
    else if (fmt == 0060000) st.type = FileType::BlockDevice;
    else if (fmt == 0010000) st.type = FileType::Fifo;
    else if (fmt == 0140000) st.type = FileType::Socket;
    else st.type = FileType::File;
    st.mode = rec->mode ? (rec->mode & 07777) : (rec->folder ? 0755 : 0644);
    st.uid = rec->uid;
    st.gid = rec->gid;
    if (rec->folder) {
        st.size = std::uint64_t{rec->valence} * 32;
    } else {
        st.size = rec->data.logicalSize;
        st.allocatedBytes = std::uint64_t{rec->data.totalBlocks} * m_blockSize;
    }
    st.crtime = macTime(rec->createDate);
    st.mtime = macTime(rec->modDate);
    st.ctime = macTime(rec->attrModDate);
    st.atime = macTime(rec->accessDate);
    return st;
}

Expected<std::vector<DirEntry>> HfsPlusReader::readdir(const Inode& dir) {
    auto entries = listFolder(static_cast<std::uint32_t>(dir.id));
    if (!entries) return fail(entries.error());
    std::vector<DirEntry> out;
    out.reserve(entries->size());
    for (auto& e : *entries) {
        FileType t = e.folder ? FileType::Directory : FileType::Unknown;   // files may be symlinks or hard links
        out.push_back(DirEntry{std::move(e.name), Inode{e.cnid}, t});
    }
    return out;
}

Expected<std::size_t> HfsPlusReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto rec = recordOf(static_cast<std::uint32_t>(file.id));
    if (!rec) return fail(rec.error());
    if (rec->folder) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (rec->hardLink()) {
        auto target = resolveLink(*rec);
        if (!target) return fail(target.error());
        rec = target;
    }
    if (rec->ownerFlags & kUfCompressed) return fail(ErrorCategory::Unsupported, "HFS+ compressed file (decmpfs) is not supported yet");
    if (offset >= rec->data.logicalSize) return 0;
    Fork fork = rec->data;
    if (auto c = completeExtents(fork, rec->cnid, 0); !c) return fail(c.error());
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), rec->data.logicalSize - offset);
    if (auto r = readForkInto(fork, offset, dst.subspan(0, static_cast<std::size_t>(n))); !r) return fail(r.error());
    return static_cast<std::size_t>(n);
}

Expected<std::string> HfsPlusReader::readlink(const Inode& link) {
    auto rec = recordOf(static_cast<std::uint32_t>(link.id));
    if (!rec) return fail(rec.error());
    if (rec->folder || (rec->mode & 0170000) != 0120000) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (rec->data.logicalSize > 4096) return fail(ErrorCategory::InvalidFormat, "symlink target longer than 4096 bytes");
    std::string target(static_cast<std::size_t>(rec->data.logicalSize), '\0');
    if (auto r = readForkInto(rec->data, 0, std::span<std::byte>(reinterpret_cast<std::byte*>(target.data()), target.size())); !r) return fail(r.error());
    return target;
}

class HfsPlusReaderSource final : public ReaderSource {
public:
    explicit HfsPlusReaderSource(ByteCount base) : m_base(base) {}
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = HfsPlusReader::open(std::move(device), m_base);
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }

private:
    ByteCount m_base;
};

std::unique_ptr<ReaderSource> makeHfsPlusReaderSource(ByteCount base) { return std::make_unique<HfsPlusReaderSource>(base); }

} // namespace stein::fs::detail
