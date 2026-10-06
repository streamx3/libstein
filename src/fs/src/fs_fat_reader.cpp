// SPDX-License-Identifier: MIT
// FAT12/16/32 reader: BPB geometry, cluster chains through the first FAT,
// fixed root directory (12/16) or root chain (32), long file names (UTF-16)
// with checksum validation and 8.3 fallback, DOS timestamps.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/fat_reader.hpp"
#include "stein/layout/gen/fat.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace stein::fs::detail {

namespace gen = layout::gen;

namespace {
constexpr std::uint8_t kAttrReadOnly = 0x01, kAttrHidden = 0x02, kAttrSystem = 0x04, kAttrVolumeId = 0x08, kAttrDirectory = 0x10, kAttrLfn = 0x0F;

std::int64_t dosTime(std::uint16_t date, std::uint16_t time) {
    if (date == 0) return 0;
    std::tm tm{};
    tm.tm_year = ((date >> 9) & 0x7F) + 80;
    tm.tm_mon = ((date >> 5) & 0x0F) - 1;
    tm.tm_mday = date & 0x1F;
    tm.tm_hour = (time >> 11) & 0x1F;
    tm.tm_min = (time >> 5) & 0x3F;
    tm.tm_sec = (time & 0x1F) * 2;
    // FAT times are local time with no zone; treat them as UTC for determinism.
#if defined(_WIN32)
    return static_cast<std::int64_t>(_mkgmtime(&tm));
#else
    return static_cast<std::int64_t>(timegm(&tm));
#endif
}

std::uint8_t lfnChecksum(const std::uint8_t shortName[11]) {
    std::uint8_t sum = 0;
    for (int i = 0; i < 11; ++i) sum = static_cast<std::uint8_t>(((sum & 1) << 7) + (sum >> 1) + shortName[i]);
    return sum;
}

std::string shortName(const std::uint8_t raw[11], std::uint8_t caseFlags) {
    std::string base(reinterpret_cast<const char*>(raw), 8), ext(reinterpret_cast<const char*>(raw + 8), 3);
    while (!base.empty() && base.back() == ' ') base.pop_back();
    while (!ext.empty() && ext.back() == ' ') ext.pop_back();
    if (!base.empty() && static_cast<std::uint8_t>(base[0]) == 0x05) base[0] = static_cast<char>(0xE5);
    if (caseFlags & 0x08) for (auto& c : base) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (caseFlags & 0x10) for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return ext.empty() ? base : base + "." + ext;
}

std::string lowerAscii(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
} // namespace

Expected<std::unique_ptr<FatReader>> FatReader::open(std::shared_ptr<BlockDevice> device) {
    auto r = std::unique_ptr<FatReader>(new FatReader());
    r->m_device = std::move(device);
    auto raw = r->m_device->read(0, 512);
    if (!raw) return fail(raw.error());
    gen::FatBpb bpb(*raw);
    gen::Fat32Ebpb e32(std::span<const std::byte>(*raw).subspan(36, gen::Fat32Ebpb::kSize));
    r->m_bps = bpb.bytesPerSector();
    r->m_spc = bpb.sectorsPerCluster();
    if (!(r->m_bps == 512 || r->m_bps == 1024 || r->m_bps == 2048 || r->m_bps == 4096) || r->m_spc == 0) return fail(ErrorCategory::InvalidFormat, "bad FAT BPB");
    const std::uint32_t reserved = bpb.reservedSectors(), fats = bpb.numFats();
    const std::uint32_t totalSectors = bpb.totalSectors16() ? bpb.totalSectors16() : bpb.totalSectors32();
    const std::uint32_t fatSectors = bpb.sectorsPerFat16() ? bpb.sectorsPerFat16() : e32.sectorsPerFat32();
    const std::uint32_t rootDirSectors = (bpb.rootEntries() * 32u + r->m_bps - 1) / r->m_bps;
    const std::uint64_t dataStart = ByteCount{reserved} + ByteCount{fats} * fatSectors + rootDirSectors;
    if (totalSectors == 0 || fatSectors == 0 || dataStart >= totalSectors) return fail(ErrorCategory::InvalidFormat, "bad FAT geometry");
    r->m_clusters = static_cast<std::uint32_t>((totalSectors - dataStart) / r->m_spc);
    const bool isFat32 = bpb.sectorsPerFat16() == 0 && bpb.rootEntries() == 0;
    r->m_bits = isFat32 ? 32 : r->m_clusters < 4085 ? 12 : 16;
    r->m_endMark = r->m_bits == 12 ? 0xFF8 : r->m_bits == 16 ? 0xFFF8 : 0x0FFFFFF8;
    r->m_clusterBytes = ByteCount{r->m_bps} * r->m_spc;
    r->m_fatOffset = ByteCount{reserved} * r->m_bps;
    r->m_fatBytes = ByteCount{fatSectors} * r->m_bps;
    r->m_rootOffset = (ByteCount{reserved} + ByteCount{fats} * fatSectors) * r->m_bps;
    r->m_rootBytes = ByteCount{rootDirSectors} * r->m_bps;
    r->m_dataOffset = dataStart * r->m_bps;
    r->m_rootCluster = isFat32 ? e32.rootCluster() : 0;
    return r;
}

Expected<std::uint32_t> FatReader::nextCluster(std::uint32_t c) const {
    if (m_fat.empty()) {
        auto f = m_device->read(m_fatOffset, std::min<ByteCount>(m_fatBytes, 256 * MiB));
        if (!f) return fail(f.error());
        m_fat = std::move(*f);
    }
    if (m_bits == 12) {
        const std::size_t pos = c + c / 2;
        if (pos + 1 >= m_fat.size()) return fail(ErrorCategory::InvalidFormat, "FAT12 entry out of range");
        const std::uint16_t v = loadLe16(m_fat.data() + pos);
        return (c & 1) ? (v >> 4) : (v & 0x0FFF);
    }
    if (m_bits == 16) {
        if ((c + 1u) * 2 > m_fat.size()) return fail(ErrorCategory::InvalidFormat, "FAT16 entry out of range");
        return loadLe16(m_fat.data() + c * 2);
    }
    if ((c + 1u) * 4 > m_fat.size()) return fail(ErrorCategory::InvalidFormat, "FAT32 entry out of range");
    return loadLe32(m_fat.data() + c * 4) & 0x0FFFFFFFu;
}

Expected<std::vector<std::uint32_t>> FatReader::chain(std::uint32_t first) const {
    std::vector<std::uint32_t> out;
    std::uint32_t c = first;
    while (c >= 2 && c < m_endMark && c - 2 < m_clusters) {
        out.push_back(c);
        if (out.size() > m_clusters) return fail(ErrorCategory::InvalidFormat, "cluster chain loops");
        auto n = nextCluster(c);
        if (!n) return fail(n.error());
        c = *n;
    }
    return out;
}

Expected<std::vector<std::byte>> FatReader::dirBytes(const Inode& dir) const {
    if (dir.id == 1 && m_bits != 32) return m_device->read(m_rootOffset, m_rootBytes);
    std::uint32_t first = m_rootCluster;
    if (dir.id != 1) {
        auto e = entryOf(dir);
        if (!e) return fail(e.error());
        if (!(e->attrs & kAttrDirectory)) return fail(ErrorCategory::InvalidArgument, "not a directory");
        first = e->firstCluster;
    }
    auto cl = chain(first);
    if (!cl) return fail(cl.error());
    std::vector<std::byte> out;
    out.reserve(cl->size() * m_clusterBytes);
    for (auto c : *cl) {
        auto b = m_device->read(clusterOffset(c), m_clusterBytes);
        if (!b) return fail(b.error());
        out.insert(out.end(), b->begin(), b->end());
    }
    return out;
}

Expected<std::vector<FatReader::Entry>> FatReader::listDirAt(const Inode& dir) const {
    auto bytes = dirBytes(dir);
    if (!bytes) return fail(bytes.error());
    // Byte offsets of the directory data on the device, per 32-byte slot (for inode ids).
    std::vector<ByteCount> slotOffsets;
    if (dir.id == 1 && m_bits != 32) {
        for (ByteCount i = 0; i < bytes->size(); i += 32) slotOffsets.push_back(m_rootOffset + i);
    } else {
        std::uint32_t first = m_rootCluster;
        if (dir.id != 1) first = entryOf(dir)->firstCluster;
        auto cl = chain(first);
        for (auto c : *cl)
            for (ByteCount i = 0; i < m_clusterBytes; i += 32) slotOffsets.push_back(clusterOffset(c) + i);
    }
    std::vector<Entry> out;
    std::u16string lfn;
    std::uint8_t lfnSum = 0;
    bool lfnValid = false;
    for (std::size_t i = 0; i + 32 <= bytes->size(); i += 32) {
        const auto* e = reinterpret_cast<const std::uint8_t*>(bytes->data() + i);
        if (e[0] == 0x00) break;   // end of directory
        if (e[0] == 0xE5) {        // deleted
            lfn.clear();
            lfnValid = false;
            continue;
        }
        const std::uint8_t attrs = e[11];
        if ((attrs & 0x3F) == kAttrLfn) {
            const std::uint8_t seq = e[0];
            if (seq & 0x40) {
                lfn.clear();
                lfnValid = true;
                lfnSum = e[13];
            }
            if (e[13] != lfnSum) lfnValid = false;
            std::u16string part;
            const int offs[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
            for (int k = 0; k < 13; ++k) part.push_back(static_cast<char16_t>(loadLe16(bytes->data() + i + offs[k])));
            lfn.insert(lfn.begin(), part.begin(), part.end());
            continue;
        }
        if (attrs & kAttrVolumeId) {
            lfn.clear();
            lfnValid = false;
            continue;
        }
        Entry ent;
        ent.attrs = attrs;
        ent.firstCluster = loadLe16(bytes->data() + i + 26) | (m_bits == 32 ? std::uint32_t{loadLe16(bytes->data() + i + 20)} << 16 : 0);
        ent.size = loadLe32(bytes->data() + i + 28);
        ent.ctime = loadLe16(bytes->data() + i + 14);
        ent.cdate = loadLe16(bytes->data() + i + 16);
        ent.adate = loadLe16(bytes->data() + i + 18);
        ent.mtime = loadLe16(bytes->data() + i + 22);
        ent.mdate = loadLe16(bytes->data() + i + 24);
        ent.entryOffset = i / 32 < slotOffsets.size() ? slotOffsets[i / 32] : 0;
        const std::string shortN = shortName(e, e[12]);
        if (lfnValid && !lfn.empty() && lfnChecksum(e) == lfnSum) {
            // Trim the 0x0000 terminator and 0xFFFF padding.
            while (!lfn.empty() && (lfn.back() == 0 || lfn.back() == 0xFFFF)) lfn.pop_back();
            std::vector<std::byte> le(lfn.size() * 2);
            for (std::size_t k = 0; k < lfn.size(); ++k) storeLe16(le.data() + 2 * k, static_cast<std::uint16_t>(lfn[k]));
            ent.name = utf16leToUtf8(le, false);
        } else {
            ent.name = shortN;
        }
        lfn.clear();
        lfnValid = false;
        if (ent.name == "." || ent.name == "..") continue;
        out.push_back(std::move(ent));
    }
    return out;
}

Expected<FatReader::Entry> FatReader::entryOf(const Inode& inode) const {
    if (inode.id == 1) return fail(ErrorCategory::InvalidArgument, "the root directory has no entry");
    auto raw = m_device->read(inode.id, 32);
    if (!raw) return fail(raw.error());
    const auto* e = reinterpret_cast<const std::uint8_t*>(raw->data());
    Entry ent;
    ent.attrs = e[11];
    ent.firstCluster = loadLe16(raw->data() + 26) | (m_bits == 32 ? std::uint32_t{loadLe16(raw->data() + 20)} << 16 : 0);
    ent.size = loadLe32(raw->data() + 28);
    ent.ctime = loadLe16(raw->data() + 14);
    ent.cdate = loadLe16(raw->data() + 16);
    ent.adate = loadLe16(raw->data() + 18);
    ent.mtime = loadLe16(raw->data() + 22);
    ent.mdate = loadLe16(raw->data() + 24);
    ent.entryOffset = inode.id;
    ent.name = shortName(e, e[12]);
    return ent;
}

Expected<std::vector<DirEntry>> FatReader::readdir(const Inode& dir) {
    auto entries = listDirAt(dir);
    if (!entries) return fail(entries.error());
    std::vector<DirEntry> out;
    for (auto& e : *entries) out.push_back(DirEntry{std::move(e.name), Inode{e.entryOffset}, (e.attrs & kAttrDirectory) ? FileType::Directory : FileType::File});
    return out;
}

Expected<Inode> FatReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    if (name == "..") {
        if (dir.id == 1) return dir;
        // The ".." entry's cluster; the root is cluster 0 (FAT12/16) or the root cluster.
        auto bytes = dirBytes(dir);
        if (!bytes || bytes->size() < 64) return fail(ErrorCategory::InvalidFormat, "directory too short for '..'");
        const std::uint32_t parentCluster = loadLe16(bytes->data() + 32 + 26) | (m_bits == 32 ? std::uint32_t{loadLe16(bytes->data() + 32 + 20)} << 16 : 0);
        if (parentCluster == 0 || parentCluster == m_rootCluster) return Inode{1};
        // Find the entry in the grandparent that points at parentCluster: walk from the root.
        std::vector<Inode> stack{Inode{1}};
        while (!stack.empty()) {
            Inode d = stack.back();
            stack.pop_back();
            auto list = listDirAt(d);
            if (!list) continue;
            for (const auto& e : *list)
                if (e.attrs & kAttrDirectory) {
                    if (e.firstCluster == parentCluster) return Inode{e.entryOffset};
                    stack.push_back(Inode{e.entryOffset});
                }
        }
        return fail(ErrorCategory::NotFound, "parent directory not found");
    }
    auto entries = listDirAt(dir);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return Inode{e.entryOffset};
    const std::string want = lowerAscii(std::string(name));
    for (const auto& e : *entries)
        if (lowerAscii(e.name) == want) return Inode{e.entryOffset};
    return fail(ErrorCategory::NotFound, "no entry \"" + std::string(name) + "\"");
}

Expected<Stat> FatReader::stat(const Inode& inode) {
    Stat st;
    if (inode.id == 1) {
        st.type = FileType::Directory;
        st.mode = 0755;
        st.nlink = 1;
        return st;
    }
    auto e = entryOf(inode);
    if (!e) return fail(e.error());
    st.type = (e->attrs & kAttrDirectory) ? FileType::Directory : FileType::File;
    st.size = st.type == FileType::Directory ? 0 : e->size;
    st.mode = (e->attrs & kAttrReadOnly) ? 0444 : (st.type == FileType::Directory ? 0755 : 0644);
    st.nlink = 1;
    st.mtime = dosTime(e->mdate, e->mtime);
    st.ctime = st.crtime = dosTime(e->cdate, e->ctime);
    st.atime = dosTime(e->adate, 0);
    if (e->firstCluster >= 2)
        if (auto cl = chain(e->firstCluster)) st.allocatedBytes = cl->size() * m_clusterBytes;
    return st;
}

Expected<std::vector<std::byte>> FatReader::fileBytes(const Entry& e, std::uint64_t offset, std::uint64_t length) const {
    std::vector<std::byte> out(static_cast<std::size_t>(length), std::byte{0});
    if (length == 0) return out;
    auto cl = chain(e.firstCluster);
    if (!cl) return fail(cl.error());
    std::uint64_t done = 0;
    while (done < length) {
        const std::uint64_t pos = offset + done;
        const std::uint64_t idx = pos / m_clusterBytes;
        if (idx >= cl->size()) return fail(ErrorCategory::InvalidFormat, "cluster chain shorter than the file size");
        const std::uint64_t inCluster = pos % m_clusterBytes;
        const std::uint64_t n = std::min(m_clusterBytes - inCluster, length - done);
        auto r = m_device->readAt(clusterOffset((*cl)[static_cast<std::size_t>(idx)]) + inCluster, std::span<std::byte>(out).subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(n)));
        if (!r) return fail(r.error());
        done += n;
    }
    return out;
}

Expected<std::size_t> FatReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto e = entryOf(file);
    if (!e) return fail(e.error());
    if (e->attrs & kAttrDirectory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= e->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), e->size - offset);
    auto bytes = fileBytes(*e, offset, n);
    if (!bytes) return fail(bytes.error());
    std::memcpy(dst.data(), bytes->data(), static_cast<std::size_t>(n));
    return static_cast<std::size_t>(n);
}

class FatReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = FatReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeFatReaderSource() { return std::make_unique<FatReaderSource>(); }

} // namespace stein::fs::detail
