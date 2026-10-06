// SPDX-License-Identifier: MIT
// exFAT reader: boot-sector geometry, 32-bit FAT chains or contiguous
// (NoFatChain) streams, directory entry sets (File 0x85 + Stream 0xC0 +
// Name 0xC1), the up-case table for case-insensitive lookup, timestamps
// with their UTC offsets, ValidDataLength-aware reads.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/exfat_reader.hpp"
#include "stein/layout/gen/exfat.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace stein::fs::detail {

namespace gen = layout::gen;

namespace {
constexpr std::uint16_t kAttrReadOnly = 0x01, kAttrDirectory = 0x10;
constexpr std::uint8_t kTypeBitmap = 0x81, kTypeUpcase = 0x82, kTypeFile = 0x85, kTypeStream = 0xC0, kTypeName = 0xC1;
constexpr std::uint32_t kEndOfChain = 0xFFFFFFFFu, kBadCluster = 0xFFFFFFF7u;
constexpr std::uint64_t kMaxFatBytes = 256 * MiB;

std::int64_t exfatTime(std::uint32_t ts, std::uint8_t tenMs, std::uint8_t utcOffset) {
    if (ts == 0) return 0;
    std::tm tm{};
    tm.tm_year = static_cast<int>((ts >> 25) & 0x7F) + 80;
    tm.tm_mon = static_cast<int>((ts >> 21) & 0x0F) - 1;
    tm.tm_mday = static_cast<int>((ts >> 16) & 0x1F);
    tm.tm_hour = static_cast<int>((ts >> 11) & 0x1F);
    tm.tm_min = static_cast<int>((ts >> 5) & 0x3F);
    tm.tm_sec = static_cast<int>(ts & 0x1F) * 2 + tenMs / 100;
#if defined(_WIN32)
    std::int64_t t = static_cast<std::int64_t>(_mkgmtime(&tm));
#else
    std::int64_t t = static_cast<std::int64_t>(timegm(&tm));
#endif
    if (utcOffset & 0x80) {
        // 7-bit signed count of 15-minute units; the stored time is local, so subtract to get UTC.
        int units = utcOffset & 0x7F;
        if (units & 0x40) units -= 0x80;
        t -= static_cast<std::int64_t>(units) * 15 * 60;
    }
    return t;
}

std::u16string utf8ToU16(std::string_view s) {
    const std::size_t units = utf16Length(s);
    std::vector<std::byte> buf(units * 2);
    if (!utf8ToUtf16le(s, buf)) return {};
    std::u16string out(units, u'\0');
    for (std::size_t i = 0; i < units; ++i) out[i] = static_cast<char16_t>(loadLe16(buf.data() + i * 2));
    return out;
}

std::string u16ToUtf8(const std::u16string& s) {
    std::vector<std::byte> buf(s.size() * 2);
    for (std::size_t i = 0; i < s.size(); ++i) storeLe16(buf.data() + i * 2, static_cast<std::uint16_t>(s[i]));
    return utf16leToUtf8(buf, false);
}
} // namespace

Expected<std::unique_ptr<ExfatReader>> ExfatReader::open(std::shared_ptr<BlockDevice> device) {
    auto raw = device->read(0, 512);
    if (!raw) return fail(raw.error());
    gen::ExfatBootSector b(*raw);
    if (b.fsName() != "EXFAT") return fail(ErrorCategory::InvalidFormat, "not an exFAT boot sector");
    const std::uint8_t bpsShift = b.bytesPerSectorShift(), spcShift = b.sectorsPerClusterShift();
    if (bpsShift < 9 || bpsShift > 12 || spcShift > 25) return fail(ErrorCategory::InvalidFormat, "implausible exFAT sector/cluster shifts");
    auto r = std::unique_ptr<ExfatReader>(new ExfatReader());
    r->m_device = std::move(device);
    r->m_bps = ByteCount{1} << bpsShift;
    r->m_clusterBytes = r->m_bps << spcShift;
    r->m_fatOffset = ByteCount{b.fatOffset()} * r->m_bps;
    r->m_fatBytes = ByteCount{b.fatLength()} * r->m_bps;
    r->m_heapOffset = ByteCount{b.clusterHeapOffset()} * r->m_bps;
    r->m_clusterCount = b.clusterCount();
    r->m_rootCluster = b.firstClusterOfRoot();
    if (r->m_rootCluster < 2 || r->m_rootCluster - 2 >= r->m_clusterCount) return fail(ErrorCategory::InvalidFormat, "exFAT root cluster out of range");
    // The root directory carries the up-case table entry.
    auto rootEntries = r->listDir(Inode{1});
    if (!rootEntries) return fail(rootEntries.error());
    return r;
}

Expected<void> ExfatReader::loadFat() const {
    if (!m_fat.empty()) return {};
    const ByteCount needed = std::min<ByteCount>(m_fatBytes, std::min<ByteCount>((ByteCount{m_clusterCount} + 2) * 4, kMaxFatBytes));
    auto fat = m_device->read(m_fatOffset, needed);
    if (!fat) return fail(fat.error());
    m_fat = std::move(*fat);
    return {};
}

Expected<std::uint32_t> ExfatReader::fatEntry(std::uint32_t cluster) const {
    if (auto l = loadFat(); !l) return fail(l.error());
    const std::size_t pos = static_cast<std::size_t>(cluster) * 4;
    if (pos + 4 > m_fat.size()) return fail(ErrorCategory::InvalidFormat, "FAT entry beyond the FAT");
    return loadLe32(m_fat.data() + pos);
}

Expected<std::vector<std::uint32_t>> ExfatReader::clustersOf(const Stream& s) const {
    std::vector<std::uint32_t> out;
    if (s.dataLength == 0 || s.firstCluster < 2) return out;
    const std::uint64_t count = (s.dataLength + m_clusterBytes - 1) / m_clusterBytes;
    if (count > m_clusterCount) return fail(ErrorCategory::InvalidFormat, "stream longer than the cluster heap");
    out.reserve(static_cast<std::size_t>(count));
    std::uint32_t c = s.firstCluster;
    for (std::uint64_t i = 0; i < count; ++i) {
        if (c < 2 || c - 2 >= m_clusterCount) return fail(ErrorCategory::InvalidFormat, "cluster " + std::to_string(c) + " out of range in chain");
        out.push_back(c);
        if (i + 1 == count) break;
        if (s.noFatChain) {
            ++c;
            continue;
        }
        auto n = fatEntry(c);
        if (!n) return fail(n.error());
        if (*n == kEndOfChain) return fail(ErrorCategory::InvalidFormat, "cluster chain ends before the stream's data length");
        if (*n == kBadCluster) return fail(ErrorCategory::InvalidFormat, "bad cluster in chain");
        if (*n == 0) {
            // The bitmap and up-case table may be written without FAT entries by some formatters: treat as contiguous.
            ++c;
            continue;
        }
        c = *n;
    }
    return out;
}

Expected<std::vector<std::byte>> ExfatReader::readStream(const Stream& s, std::uint64_t offset, std::uint64_t length) const {
    std::vector<std::byte> out(static_cast<std::size_t>(length), std::byte{0});
    if (length == 0) return out;
    auto cl = clustersOf(s);
    if (!cl) return fail(cl.error());
    const std::uint64_t valid = std::min(s.validDataLength, s.dataLength);
    std::uint64_t done = 0;
    while (done < length) {
        const std::uint64_t pos = offset + done;
        if (pos >= valid) break;   // beyond ValidDataLength reads as zeros
        const std::uint64_t idx = pos / m_clusterBytes, inCluster = pos % m_clusterBytes;
        if (idx >= cl->size()) return fail(ErrorCategory::InvalidFormat, "cluster chain shorter than the data length");
        const std::uint64_t n = std::min({m_clusterBytes - inCluster, length - done, valid - pos});
        auto r = m_device->readAt(clusterOffset((*cl)[static_cast<std::size_t>(idx)]) + inCluster,
                                  std::span<std::byte>(out).subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(n)));
        if (!r) return fail(r.error());
        done += n;
    }
    return out;
}

Expected<ExfatReader::Stream> ExfatReader::dirStream(const Inode& dir) {
    if (dir.id == 1) {
        // The root directory has no stream entry: its length is the FAT chain's.
        Stream s;
        s.firstCluster = m_rootCluster;
        std::uint32_t c = m_rootCluster;
        std::uint64_t n = 0;
        while (c >= 2 && c - 2 < m_clusterCount && n < m_clusterCount) {
            ++n;
            auto next = fatEntry(c);
            if (!next) return fail(next.error());
            if (*next == kEndOfChain || *next == 0) break;
            c = *next;
        }
        s.dataLength = s.validDataLength = n * m_clusterBytes;
        return s;
    }
    auto e = entryOf(dir);
    if (!e) return fail(e.error());
    if (!(e->attrs & kAttrDirectory)) return fail(ErrorCategory::InvalidArgument, "not a directory");
    return e->stream;
}

Expected<std::vector<ExfatReader::Entry>> ExfatReader::listDir(const Inode& dir) {
    auto s = dirStream(dir);
    if (!s) return fail(s.error());
    auto cl = clustersOf(*s);
    if (!cl) return fail(cl.error());
    auto bytes = readStream(*s, 0, s->dataLength);
    if (!bytes) return fail(bytes.error());
    const auto deviceOffset = [&](std::size_t pos) { return clusterOffset((*cl)[pos / m_clusterBytes]) + pos % m_clusterBytes; };
    std::vector<Entry> out;
    const std::byte* d = bytes->data();
    for (std::size_t off = 0; off + 32 <= bytes->size(); off += 32) {
        const auto type = std::to_integer<std::uint8_t>(d[off]);
        if (type == 0x00) break;                 // end of directory
        if (!(type & 0x80)) continue;            // deleted / unused
        if (dir.id == 1 && type == kTypeUpcase && m_upcase.empty()) {
            if (auto u = loadUpcase(loadLe32(d + off + 20), loadLe64(d + off + 24)); !u) return fail(u.error());
            continue;
        }
        if (type == kTypeBitmap || type == kTypeUpcase || type != kTypeFile) continue;
        Entry e;
        e.entryOffset = deviceOffset(off);
        const std::uint8_t secondaries = std::to_integer<std::uint8_t>(d[off + 1]);
        e.attrs = loadLe16(d + off + 4);
        e.created = loadLe32(d + off + 8);
        e.modified = loadLe32(d + off + 12);
        e.accessed = loadLe32(d + off + 16);
        e.created10ms = std::to_integer<std::uint8_t>(d[off + 20]);
        e.modified10ms = std::to_integer<std::uint8_t>(d[off + 21]);
        e.createdOffset = std::to_integer<std::uint8_t>(d[off + 22]);
        e.modifiedOffset = std::to_integer<std::uint8_t>(d[off + 23]);
        e.accessedOffset = std::to_integer<std::uint8_t>(d[off + 24]);
        std::uint8_t nameLength = 0;
        bool haveStream = false;
        std::size_t i = 1;
        for (; i <= secondaries && off + (i + 1) * 32 <= bytes->size(); ++i) {
            const std::byte* s2 = d + off + i * 32;
            const auto t2 = std::to_integer<std::uint8_t>(s2[0]);
            if (t2 == kTypeStream && !haveStream) {
                haveStream = true;
                e.stream.noFatChain = (std::to_integer<std::uint8_t>(s2[1]) & 0x02) != 0;
                nameLength = std::to_integer<std::uint8_t>(s2[3]);
                e.stream.validDataLength = loadLe64(s2 + 8);
                e.stream.firstCluster = loadLe32(s2 + 20);
                e.stream.dataLength = loadLe64(s2 + 24);
            } else if (t2 == kTypeName) {
                for (std::size_t k = 0; k < 15 && e.name16.size() < nameLength; ++k) e.name16.push_back(static_cast<char16_t>(loadLe16(s2 + 2 + k * 2)));
            }
            // Other secondaries (vendor extensions 0xE0/0xE1, TexFAT padding) are skipped.
        }
        off += (i - 1) * 32;
        if (!haveStream || e.name16.empty()) continue;   // damaged entry set
        e.name = u16ToUtf8(e.name16);
        m_cache[e.entryOffset] = e;
        out.push_back(std::move(e));
    }
    return out;
}

Expected<ExfatReader::Entry> ExfatReader::entryOf(const Inode& inode) {
    if (inode.id == 1) return fail(ErrorCategory::InvalidArgument, "root has no directory entry");
    if (auto it = m_cache.find(inode.id); it != m_cache.end()) return it->second;
    // Not seen through a listing: read the entry set in place, following the FAT across cluster boundaries.
    if (inode.id < m_heapOffset || inode.id % 32 != 0) return fail(ErrorCategory::InvalidArgument, "not an exFAT inode");
    std::vector<std::byte> set;
    ByteCount off = inode.id;
    std::uint8_t secondaries = 0;
    for (std::size_t i = 0; i <= secondaries; ++i) {
        auto e = m_device->read(off, 32);
        if (!e) return fail(e.error());
        if (i == 0) {
            if (std::to_integer<std::uint8_t>((*e)[0]) != kTypeFile) return fail(ErrorCategory::NotFound, "no file entry at this inode");
            secondaries = std::to_integer<std::uint8_t>((*e)[1]);
        }
        set.insert(set.end(), e->begin(), e->end());
        off += 32;
        if ((off - m_heapOffset) % m_clusterBytes == 0) {
            const auto c = static_cast<std::uint32_t>((off - 1 - m_heapOffset) / m_clusterBytes + 2);
            auto n = fatEntry(c);
            if (!n) return fail(n.error());
            if (*n >= 2 && *n - 2 < m_clusterCount) off = clusterOffset(*n);
        }
    }
    // Parse through listDir's logic by faking a one-set directory buffer.
    Entry e;
    e.entryOffset = inode.id;
    const std::byte* d = set.data();
    e.attrs = loadLe16(d + 4);
    e.created = loadLe32(d + 8);
    e.modified = loadLe32(d + 12);
    e.accessed = loadLe32(d + 16);
    e.created10ms = std::to_integer<std::uint8_t>(d[20]);
    e.modified10ms = std::to_integer<std::uint8_t>(d[21]);
    e.createdOffset = std::to_integer<std::uint8_t>(d[22]);
    e.modifiedOffset = std::to_integer<std::uint8_t>(d[23]);
    e.accessedOffset = std::to_integer<std::uint8_t>(d[24]);
    std::uint8_t nameLength = 0;
    bool haveStream = false;
    for (std::size_t i = 1; i <= secondaries; ++i) {
        const std::byte* s2 = d + i * 32;
        const auto t2 = std::to_integer<std::uint8_t>(s2[0]);
        if (t2 == kTypeStream && !haveStream) {
            haveStream = true;
            e.stream.noFatChain = (std::to_integer<std::uint8_t>(s2[1]) & 0x02) != 0;
            nameLength = std::to_integer<std::uint8_t>(s2[3]);
            e.stream.validDataLength = loadLe64(s2 + 8);
            e.stream.firstCluster = loadLe32(s2 + 20);
            e.stream.dataLength = loadLe64(s2 + 24);
        } else if (t2 == kTypeName) {
            for (std::size_t k = 0; k < 15 && e.name16.size() < nameLength; ++k) e.name16.push_back(static_cast<char16_t>(loadLe16(s2 + 2 + k * 2)));
        }
    }
    if (!haveStream) return fail(ErrorCategory::InvalidFormat, "file entry without a stream extension");
    e.name = u16ToUtf8(e.name16);
    m_cache[inode.id] = e;
    return e;
}

Expected<void> ExfatReader::loadUpcase(std::uint32_t firstCluster, std::uint64_t length) {
    if (firstCluster < 2 || firstCluster - 2 >= m_clusterCount || length < 2 || length > 128 * KiB + 2) return fail(ErrorCategory::InvalidFormat, "exFAT up-case table entry is implausible");
    Stream s;
    s.firstCluster = firstCluster;
    s.dataLength = s.validDataLength = length;
    auto bytes = readStream(s, 0, length);
    if (!bytes) return fail(bytes.error());
    // The table may be compressed: 0xFFFF followed by a count means that many identity-mapped code units.
    std::vector<char16_t> table(65536);
    for (std::size_t i = 0; i < table.size(); ++i) table[i] = static_cast<char16_t>(i);
    std::size_t index = 0;
    for (std::size_t off = 0; off + 2 <= bytes->size() && index < table.size(); off += 2) {
        const std::uint16_t w = loadLe16(bytes->data() + off);
        if (w == 0xFFFF && off + 4 <= bytes->size()) {
            index += loadLe16(bytes->data() + off + 2);
            off += 2;
            continue;
        }
        table[index++] = static_cast<char16_t>(w);
    }
    m_upcase = std::move(table);
    return {};
}

std::u16string ExfatReader::upcase(std::u16string s) const {
    for (auto& c : s) {
        if (!m_upcase.empty()) c = m_upcase[static_cast<std::size_t>(c)];
        else if (c >= u'a' && c <= u'z') c = static_cast<char16_t>(c - 32);
    }
    return s;
}

Expected<Inode> ExfatReader::lookup(const Inode& dir, std::string_view name) {
    if (name == "." ) return dir;
    auto entries = listDir(dir);
    if (!entries) return fail(entries.error());
    const std::u16string want = upcase(utf8ToU16(name));
    // Exact match first (cheap), then case-folded through the volume's own up-case table.
    for (const auto& e : *entries)
        if (e.name == name) return Inode{e.entryOffset};
    for (const auto& e : *entries)
        if (upcase(e.name16) == want) return Inode{e.entryOffset};
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> ExfatReader::stat(const Inode& inode) {
    Stat st;
    if (inode.id == 1) {
        auto s = dirStream(inode);
        if (!s) return fail(s.error());
        st.type = FileType::Directory;
        st.mode = 0755;
        st.nlink = 1;
        st.size = s->dataLength;
        st.allocatedBytes = s->dataLength;
        return st;
    }
    auto e = entryOf(inode);
    if (!e) return fail(e.error());
    st.type = (e->attrs & kAttrDirectory) ? FileType::Directory : FileType::File;
    st.mode = (e->attrs & kAttrReadOnly) ? 0555 : (st.type == FileType::Directory ? 0755 : 0644);
    st.nlink = 1;
    st.size = e->stream.dataLength;
    st.allocatedBytes = (e->stream.dataLength + m_clusterBytes - 1) / m_clusterBytes * m_clusterBytes;
    st.crtime = exfatTime(e->created, e->created10ms, e->createdOffset);
    st.mtime = exfatTime(e->modified, e->modified10ms, e->modifiedOffset);
    st.ctime = st.mtime;
    st.atime = exfatTime(e->accessed, 0, e->accessedOffset);
    return st;
}

Expected<std::vector<DirEntry>> ExfatReader::readdir(const Inode& dir) {
    auto entries = listDir(dir);
    if (!entries) return fail(entries.error());
    std::vector<DirEntry> out;
    out.reserve(entries->size());
    for (auto& e : *entries) out.push_back(DirEntry{std::move(e.name), Inode{e.entryOffset}, (e.attrs & kAttrDirectory) ? FileType::Directory : FileType::File});
    return out;
}

Expected<std::size_t> ExfatReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto e = entryOf(file);
    if (!e) return fail(e.error());
    if (e->attrs & kAttrDirectory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= e->stream.dataLength) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), e->stream.dataLength - offset);
    auto bytes = readStream(e->stream, offset, n);
    if (!bytes) return fail(bytes.error());
    std::memcpy(dst.data(), bytes->data(), static_cast<std::size_t>(n));
    return static_cast<std::size_t>(n);
}

class ExfatReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = ExfatReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeExfatReaderSource() { return std::make_unique<ExfatReaderSource>(); }

} // namespace stein::fs::detail
