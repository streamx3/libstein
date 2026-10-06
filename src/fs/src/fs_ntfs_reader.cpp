// SPDX-License-Identifier: MIT
// NTFS reader: MFT records (with attribute lists), resident and non-resident
// $DATA through run lists (sparse runs, initialized size), directories from
// $INDEX_ROOT plus the in-use INDX blocks of $INDEX_ALLOCATION, names from
// $FILE_NAME (Win32/POSIX namespaces), symlinks from $REPARSE_POINT or
// ntfs-3g's Interix links. Compressed and encrypted data are refused.
#include "detectors.hpp"
#include "ntfs_common.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/ntfs_reader.hpp"

#include <algorithm>
#include <cstring>

namespace stein::fs::detail {

namespace {
constexpr std::uint32_t kAttrStandardInfo = 0x10, kAttrAttributeList = 0x20, kAttrFileName = 0x30, kAttrData = 0x80, kAttrIndexRoot = 0x90, kAttrIndexAlloc = 0xA0,
                        kAttrBitmap = 0xB0, kAttrReparse = 0xC0;
constexpr std::uint16_t kRecordInUse = 0x1, kRecordDirectory = 0x2;
constexpr std::uint32_t kFileAttrReparse = 0x400;
constexpr std::uint64_t kSparseLcn = ~std::uint64_t{0};

// Windows FILETIME (100 ns since 1601) -> Unix seconds.
std::int64_t fileTimeToUnix(std::uint64_t ft) { return ft ? static_cast<std::int64_t>(ft / 10000000ull) - 11644473600ll : 0; }

std::string lowerAscii(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
} // namespace

struct NtfsReader::Attribute {
    std::uint32_t type = 0;
    std::string name;
    bool nonResident = false;
    std::uint16_t flags = 0;                 // 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse
    std::vector<std::byte> resident;         // value when resident
    std::vector<Run> runs;                   // when non-resident
    std::uint64_t startVcn = 0, dataSize = 0, initializedSize = 0, allocatedSize = 0;
};

struct NtfsReader::Record {
    std::uint64_t index = 0;
    std::uint16_t flags = 0, hardLinks = 0;
    std::vector<Attribute> attrs;
};

Expected<std::unique_ptr<NtfsReader>> NtfsReader::open(std::shared_ptr<BlockDevice> device) {
    auto r = std::unique_ptr<NtfsReader>(new NtfsReader());
    r->m_device = std::move(device);
    auto boot = r->m_device->read(0, 512);
    if (!boot) return fail(boot.error());
    layout::gen::NtfsBootSector b(*boot);
    if (b.oemId() != "NTFS") return fail(ErrorCategory::InvalidFormat, "not NTFS");
    r->m_sectorSize = b.bytesPerSector();
    const std::uint8_t spcRaw = b.sectorsPerCluster();
    const ByteCount spc = spcRaw > 0x80 ? (ByteCount{1} << (256 - spcRaw)) : spcRaw;
    r->m_cluster = r->m_sectorSize * spc;
    const std::int8_t cpmr = b.clustersPerMftRecord();
    r->m_recordSize = cpmr < 0 ? (ByteCount{1} << static_cast<unsigned>(-cpmr)) : ByteCount{static_cast<std::uint8_t>(cpmr)} * r->m_cluster;
    const std::int8_t cpir = b.clustersPerIndexRecord();
    r->m_indexRecordSize = cpir < 0 ? (ByteCount{1} << static_cast<unsigned>(-cpir)) : ByteCount{static_cast<std::uint8_t>(cpir)} * r->m_cluster;
    r->m_mftOffset = b.mftLcn() * r->m_cluster;
    r->m_clusters = b.numberOfSectors() * r->m_sectorSize / r->m_cluster;
    if (r->m_recordSize < 256 || r->m_recordSize > 64 * KiB || r->m_indexRecordSize < 512) return fail(ErrorCategory::InvalidFormat, "bad NTFS record sizes");
    // $MFT (record 0): its $DATA run list maps every other record.
    auto mft = r->loadRecord(0);
    if (!mft) return fail(mft.error());
    const Attribute* data = r->find(*mft, kAttrData);
    if (!data || !data->nonResident) return fail(ErrorCategory::InvalidFormat, "$MFT has no non-resident $DATA");
    for (const auto& run : data->runs) r->m_mftRuns.emplace_back(run.lcn, run.count);
    r->m_mftRecords = data->dataSize / r->m_recordSize;
    return r;
}

Expected<std::vector<std::byte>> NtfsReader::readRecordRaw(std::uint64_t index) const {
    ByteCount offset = 0;
    if (m_mftRuns.empty()) {
        offset = m_mftOffset + index * m_recordSize;   // bootstrap: record 0
    } else {
        if (index >= m_mftRecords) return fail(ErrorCategory::NotFound, "MFT record " + std::to_string(index) + " out of range");
        const ByteCount byteOff = index * m_recordSize;
        ByteCount vcnBytes = 0;
        bool found = false;
        for (const auto& [lcn, count] : m_mftRuns) {
            const ByteCount len = count * m_cluster;
            if (byteOff < vcnBytes + len) {
                if (lcn == kSparseLcn) return fail(ErrorCategory::InvalidFormat, "MFT record in a sparse run");
                offset = lcn * m_cluster + (byteOff - vcnBytes);
                found = true;
                break;
            }
            vcnBytes += len;
        }
        if (!found) return fail(ErrorCategory::NotFound, "MFT record beyond $MFT's runs");
    }
    auto rec = m_device->read(offset, m_recordSize);
    if (!rec) return fail(rec.error());
    if (std::string(reinterpret_cast<const char*>(rec->data()), 4) != "FILE") return fail(ErrorCategory::InvalidFormat, "MFT record " + std::to_string(index) + " is not a FILE record");
    if (!applyFixups(*rec, m_sectorSize)) return fail(ErrorCategory::Integrity, "MFT record " + std::to_string(index) + " has a torn update sequence");
    return rec;
}

Expected<NtfsReader::Record> NtfsReader::loadRecord(std::uint64_t index) const {
    auto raw = readRecordRaw(index);
    if (!raw) return fail(raw.error());
    Record rec;
    rec.index = index;
    layout::gen::NtfsMftRecordHeader h(*raw);
    rec.flags = loadLe16(raw->data() + 0x16);
    rec.hardLinks = loadLe16(raw->data() + 0x12);
    if (!(rec.flags & kRecordInUse)) return fail(ErrorCategory::NotFound, "MFT record " + std::to_string(index) + " is not in use");
    auto parseAttrs = [&](const std::vector<std::byte>& r, std::vector<Attribute>& out) -> Expected<void> {
        layout::gen::NtfsMftRecordHeader hh(r);
        std::size_t pos = hh.attrsOffset();
        while (pos + 16 <= r.size()) {
            const std::uint32_t type = loadLe32(r.data() + pos);
            if (type == 0xFFFFFFFFu) break;
            const std::uint32_t length = loadLe32(r.data() + pos + 4);
            if (length < 16 || pos + length > r.size()) break;
            Attribute a;
            a.type = type;
            a.nonResident = std::to_integer<std::uint8_t>(r[pos + 8]) != 0;
            const std::uint8_t nameLen = std::to_integer<std::uint8_t>(r[pos + 9]);
            const std::uint16_t nameOff = loadLe16(r.data() + pos + 10);
            a.flags = loadLe16(r.data() + pos + 12);
            if (nameLen && pos + nameOff + nameLen * 2u <= r.size()) a.name = utf16leToUtf8(std::span<const std::byte>(r).subspan(pos + nameOff, nameLen * 2u), false);
            if (!a.nonResident) {
                const std::uint32_t vlen = loadLe32(r.data() + pos + 16);
                const std::uint16_t voff = loadLe16(r.data() + pos + 20);
                if (pos + voff + vlen <= r.size()) a.resident.assign(r.begin() + static_cast<std::ptrdiff_t>(pos + voff), r.begin() + static_cast<std::ptrdiff_t>(pos + voff + vlen));
                a.dataSize = a.initializedSize = a.resident.size();
            } else if (pos + 64 <= r.size()) {
                a.startVcn = loadLe64(r.data() + pos + 16);
                const std::uint16_t runsOff = loadLe16(r.data() + pos + 32);
                a.allocatedSize = loadLe64(r.data() + pos + 40);
                a.dataSize = loadLe64(r.data() + pos + 48);
                a.initializedSize = loadLe64(r.data() + pos + 56);
                if (runsOff < length) a.runs = decodeRuns(std::span<const std::byte>(r).subspan(pos + runsOff, length - runsOff));
            }
            out.push_back(std::move(a));
            pos += length;
        }
        return {};
    };
    if (auto p = parseAttrs(*raw, rec.attrs); !p) return fail(p.error());
    // Attribute list: attributes continue in extension records.
    for (std::size_t i = 0; i < rec.attrs.size(); ++i) {
        if (rec.attrs[i].type != kAttrAttributeList) continue;
        auto list = attrAll(rec.attrs[i]);
        if (!list) return fail(list.error());
        std::vector<std::uint64_t> extensions;
        for (std::size_t pos = 0; pos + 26 <= list->size();) {
            const std::uint16_t len = loadLe16(list->data() + pos + 4);
            if (len < 26) break;
            const std::uint64_t ref = loadLe64(list->data() + pos + 16) & 0xFFFFFFFFFFFFull;
            if (ref != index && std::find(extensions.begin(), extensions.end(), ref) == extensions.end()) extensions.push_back(ref);
            pos += len;
        }
        for (auto ext : extensions) {
            auto eraw = readRecordRaw(ext);
            if (!eraw) continue;
            std::vector<Attribute> more;
            if (parseAttrs(*eraw, more))
                for (auto& a : more) {
                    // Non-resident pieces of one attribute (split $DATA): append runs in VCN order.
                    bool merged = false;
                    for (auto& have : rec.attrs)
                        if (have.type == a.type && have.name == a.name && have.nonResident && a.nonResident && a.startVcn > have.startVcn) {
                            have.runs.insert(have.runs.end(), a.runs.begin(), a.runs.end());
                            merged = true;
                            break;
                        }
                    if (!merged) rec.attrs.push_back(std::move(a));
                }
        }
        break;
    }
    return rec;
}

const NtfsReader::Attribute* NtfsReader::find(const Record& r, std::uint32_t type, std::string_view name) const {
    for (const auto& a : r.attrs)
        if (a.type == type && a.name == name) return &a;
    return nullptr;
}

Expected<std::vector<std::byte>> NtfsReader::attrData(const Attribute& a, std::uint64_t offset, std::uint64_t length) const {
    std::vector<std::byte> out(static_cast<std::size_t>(length), std::byte{0});
    if (!a.nonResident) {
        if (offset < a.resident.size()) std::memcpy(out.data(), a.resident.data() + offset, static_cast<std::size_t>(std::min<std::uint64_t>(length, a.resident.size() - offset)));
        return out;
    }
    if (a.flags & 0x0001) return fail(ErrorCategory::Unsupported, "compressed NTFS data is not supported yet");
    if (a.flags & 0x4000) return fail(ErrorCategory::Unsupported, "encrypted (EFS) NTFS data cannot be read");
    // Bytes beyond the initialized size read as zeros.
    const std::uint64_t readable = offset < a.initializedSize ? std::min(length, a.initializedSize - offset) : 0;
    std::uint64_t done = 0, vcnBytes = 0;
    for (const auto& run : a.runs) {
        const std::uint64_t runLen = run.count * m_cluster;
        const std::uint64_t runStart = vcnBytes, runEnd = vcnBytes + runLen;
        vcnBytes = runEnd;
        if (runEnd <= offset || done >= readable) continue;
        const std::uint64_t from = std::max(offset, runStart);
        const std::uint64_t to = std::min(offset + readable, runEnd);
        if (from >= to) continue;
        if (run.lcn != kSparseLcn) {
            auto r = m_device->readAt(run.lcn * m_cluster + (from - runStart), std::span<std::byte>(out).subspan(static_cast<std::size_t>(from - offset), static_cast<std::size_t>(to - from)));
            if (!r) return fail(r.error());
        }
        done = to - offset;
    }
    return out;
}

Expected<std::vector<std::byte>> NtfsReader::attrAll(const Attribute& a) const { return attrData(a, 0, a.dataSize); }

Expected<Stat> NtfsReader::stat(const Inode& inode) {
    auto rec = loadRecord(inode.id);
    if (!rec) return fail(rec.error());
    Stat st;
    st.nlink = rec->hardLinks;
    std::uint32_t fileAttrs = 0;
    if (const Attribute* si = find(*rec, kAttrStandardInfo); si && si->resident.size() >= 48) {
        const auto* p = si->resident.data();
        st.crtime = fileTimeToUnix(loadLe64(p));
        st.mtime = fileTimeToUnix(loadLe64(p + 8));
        st.ctime = fileTimeToUnix(loadLe64(p + 16));
        st.atime = fileTimeToUnix(loadLe64(p + 24));
        fileAttrs = loadLe32(p + 32);
    }
    if (rec->flags & kRecordDirectory) st.type = FileType::Directory;
    else if (fileAttrs & kFileAttrReparse) st.type = FileType::Symlink;
    else st.type = FileType::File;
    if (const Attribute* data = find(*rec, kAttrData)) {
        st.size = data->dataSize;
        st.allocatedBytes = data->nonResident ? data->allocatedSize : 0;
        // ntfs-3g Interix symlinks are plain files whose data starts with "IntxLNK\1".
        if (st.type == FileType::File && data->dataSize >= 10 && data->dataSize < 4096) {
            auto head = attrData(*data, 0, 8);
            if (head && std::string(reinterpret_cast<const char*>(head->data()), 8) == "IntxLNK\x01") st.type = FileType::Symlink;
        }
    }
    if (st.type == FileType::Symlink) {
        if (auto t = readlink(inode)) st.size = t->size();
    }
    st.mode = st.type == FileType::Directory ? 0755 : (fileAttrs & 0x1 ? 0444 : 0644);
    return st;
}

Expected<std::vector<DirEntry>> NtfsReader::readdir(const Inode& dir) {
    auto rec = loadRecord(dir.id);
    if (!rec) return fail(rec.error());
    if (!(rec->flags & kRecordDirectory)) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<DirEntry> out;
    auto scanEntries = [&](std::span<const std::byte> entries) {
        std::size_t pos = 0;
        while (pos + 16 <= entries.size()) {
            const std::uint64_t ref = loadLe64(entries.data() + pos) & 0xFFFFFFFFFFFFull;
            const std::uint16_t len = loadLe16(entries.data() + pos + 8);
            const std::uint16_t keyLen = loadLe16(entries.data() + pos + 10);
            const std::uint32_t flags = loadLe32(entries.data() + pos + 12);
            if (len < 16 || pos + len > entries.size()) break;
            if (flags & 2) break;   // last entry (no key)
            if (keyLen >= 66 && pos + 16 + keyLen <= entries.size()) {
                const std::byte* fn = entries.data() + pos + 16;
                const std::uint8_t nameLen = std::to_integer<std::uint8_t>(fn[64]);
                const std::uint8_t ns = std::to_integer<std::uint8_t>(fn[65]);
                const std::uint32_t fattrs = loadLe32(fn + 56);
                if (66u + nameLen * 2u <= keyLen) {
                    std::string name = utf16leToUtf8(std::span<const std::byte>(fn + 66, nameLen * 2u), false);
                    // Namespace 2 is the DOS-only 8.3 alias of a long name; records below 16 are NTFS metafiles.
                    if (ns != 2 && ref >= 16 && ref != dir.id && name != ".") {
                        // Hard links are separate entries sharing one record. Plain files stay Unknown here
                        // because an ntfs-3g Interix symlink looks like a file until its data is read.
                        FileType t = (fattrs & 0x10000000) ? FileType::Directory : (fattrs & kFileAttrReparse) ? FileType::Symlink : FileType::Unknown;
                        out.push_back(DirEntry{std::move(name), Inode{ref}, t});
                    }
                }
            }
            pos += len;
        }
    };
    const Attribute* root = find(*rec, kAttrIndexRoot, "$I30");
    if (!root || root->resident.size() < 32) return fail(ErrorCategory::InvalidFormat, "directory without $INDEX_ROOT");
    {
        // INDEX_ROOT header (16) + INDEX_HEADER: entries offset (4), total size (4), allocated (4), flags (1)
        const std::uint32_t entriesOff = loadLe32(root->resident.data() + 16);
        const std::uint32_t total = loadLe32(root->resident.data() + 20);
        if (16 + entriesOff <= root->resident.size()) scanEntries(std::span<const std::byte>(root->resident).subspan(16 + entriesOff, std::min<std::size_t>(total - std::min<std::uint32_t>(total, entriesOff), root->resident.size() - 16 - entriesOff)));
    }
    if (const Attribute* alloc = find(*rec, kAttrIndexAlloc, "$I30")) {
        std::vector<std::byte> bitmap;
        if (const Attribute* bm = find(*rec, kAttrBitmap, "$I30"))
            if (auto b = attrAll(*bm)) bitmap = std::move(*b);
        const std::uint64_t blocks = alloc->dataSize / m_indexRecordSize;
        for (std::uint64_t i = 0; i < blocks; ++i) {
            if (!bitmap.empty() && (i / 8 >= bitmap.size() || !((std::to_integer<std::uint8_t>(bitmap[i / 8]) >> (i % 8)) & 1))) continue;
            auto blk = attrData(*alloc, i * m_indexRecordSize, m_indexRecordSize);
            if (!blk) return fail(blk.error());
            if (std::string(reinterpret_cast<const char*>(blk->data()), 4) != "INDX") continue;
            if (!applyFixups(*blk, m_sectorSize)) return fail(ErrorCategory::Integrity, "torn INDX block in directory " + std::to_string(dir.id));
            // INDX header: magic(4) usaOff(2) usaCount(2) lsn(8) vcn(8) then INDEX_HEADER at 24.
            const std::uint32_t entriesOff = loadLe32(blk->data() + 24);
            const std::uint32_t total = loadLe32(blk->data() + 28);
            if (24 + entriesOff <= blk->size()) scanEntries(std::span<const std::byte>(*blk).subspan(24 + entriesOff, std::min<std::size_t>(total > entriesOff ? total - entriesOff : 0, blk->size() - 24 - entriesOff)));
        }
    }
    return out;
}

Expected<Inode> NtfsReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    if (name == "..") {
        auto rec = loadRecord(dir.id);
        if (!rec) return fail(rec.error());
        if (const Attribute* fn = find(*rec, kAttrFileName); fn && fn->resident.size() >= 8) return Inode{loadLe64(fn->resident.data()) & 0xFFFFFFFFFFFFull};
        return fail(ErrorCategory::NotFound, "no parent");
    }
    auto entries = readdir(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    const std::string want = lowerAscii(std::string(name));
    for (const auto& e : *entries)
        if (lowerAscii(e.name) == want) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry \"" + std::string(name) + "\"");
}

Expected<std::size_t> NtfsReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto rec = loadRecord(file.id);
    if (!rec) return fail(rec.error());
    if (rec->flags & kRecordDirectory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    const Attribute* data = find(*rec, kAttrData);
    if (!data) return 0;
    if (offset >= data->dataSize) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), data->dataSize - offset);
    auto bytes = attrData(*data, offset, n);
    if (!bytes) return fail(bytes.error());
    std::memcpy(dst.data(), bytes->data(), static_cast<std::size_t>(n));
    return static_cast<std::size_t>(n);
}

Expected<std::string> NtfsReader::readlink(const Inode& link) {
    auto rec = loadRecord(link.id);
    if (!rec) return fail(rec.error());
    if (const Attribute* rp = find(*rec, kAttrReparse)) {
        auto v = attrAll(*rp);
        if (!v) return fail(v.error());
        if (v->size() >= 20) {
            const std::uint32_t tag = loadLe32(v->data());
            const std::uint16_t subOff = loadLe16(v->data() + 8), subLen = loadLe16(v->data() + 10), prOff = loadLe16(v->data() + 12), prLen = loadLe16(v->data() + 14);
            const std::size_t base = tag == 0xA000000Cu ? 20 : 16;   // symlink has a 4-byte flags field; junctions do not
            auto pick = [&](std::uint16_t off, std::uint16_t len) -> std::string {
                if (base + off + len > v->size()) return {};
                std::string s = utf16leToUtf8(std::span<const std::byte>(*v).subspan(base + off, len), false);
                if (s.rfind("\\??\\", 0) == 0) s = s.substr(4);
                for (auto& c : s)
                    if (c == '\\') c = '/';
                return s;
            };
            std::string target = pick(prOff, prLen);
            if (target.empty()) target = pick(subOff, subLen);
            return target;
        }
    }
    if (const Attribute* data = find(*rec, kAttrData)) {
        auto v = attrAll(*data);
        if (!v) return fail(v.error());
        if (v->size() >= 8 && std::string(reinterpret_cast<const char*>(v->data()), 8) == "IntxLNK\x01") return utf16leToUtf8(std::span<const std::byte>(*v).subspan(8), false);
    }
    return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
}

class NtfsReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = NtfsReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeNtfsReaderSource() { return std::make_unique<NtfsReaderSource>(); }

} // namespace stein::fs::detail
