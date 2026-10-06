// SPDX-License-Identifier: MIT
// ISO 9660 reader: primary/supplementary volume descriptors, directory
// records (both-endian fields, multi-extent files), Rock Ridge SUSP entries
// (SP/CE/NM/PX/SL/TF/CL/RE) and Joliet UCS-2 names.
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/iso_reader.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace stein::fs::detail {

namespace {
constexpr std::uint8_t kFlagDirectory = 0x02, kFlagMultiExtent = 0x80;

std::int64_t isoDate7(const std::byte* d) {
    const int year = std::to_integer<int>(d[0]);
    if (year == 0 && std::to_integer<int>(d[1]) == 0) return 0;
    std::tm tm{};
    tm.tm_year = year;
    tm.tm_mon = std::to_integer<int>(d[1]) - 1;
    tm.tm_mday = std::to_integer<int>(d[2]);
    tm.tm_hour = std::to_integer<int>(d[3]);
    tm.tm_min = std::to_integer<int>(d[4]);
    tm.tm_sec = std::to_integer<int>(d[5]);
#if defined(_WIN32)
    std::int64_t t = static_cast<std::int64_t>(_mkgmtime(&tm));
#else
    std::int64_t t = static_cast<std::int64_t>(timegm(&tm));
#endif
    const auto tz = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(d[6]));
    return t - static_cast<std::int64_t>(tz) * 15 * 60;
}

std::int64_t isoDate17(const std::byte* d) {
    auto num = [&](int off, int len) {
        int v = 0;
        for (int i = 0; i < len; ++i) v = v * 10 + (std::to_integer<int>(d[off + i]) - '0');
        return v;
    };
    if (num(0, 4) == 0) return 0;
    std::tm tm{};
    tm.tm_year = num(0, 4) - 1900;
    tm.tm_mon = num(4, 2) - 1;
    tm.tm_mday = num(6, 2);
    tm.tm_hour = num(8, 2);
    tm.tm_min = num(10, 2);
    tm.tm_sec = num(12, 2);
#if defined(_WIN32)
    std::int64_t t = static_cast<std::int64_t>(_mkgmtime(&tm));
#else
    std::int64_t t = static_cast<std::int64_t>(timegm(&tm));
#endif
    const auto tz = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(d[16]));
    return t - static_cast<std::int64_t>(tz) * 15 * 60;
}

std::string ucs2beToUtf8(std::span<const std::byte> in) {
    std::vector<std::byte> le(in.size());
    for (std::size_t i = 0; i + 1 < in.size(); i += 2) {
        le[i] = in[i + 1];
        le[i + 1] = in[i];
    }
    return utf16leToUtf8(le, false);
}

void stripVersion(std::string& name) {
    const auto semi = name.rfind(';');
    if (semi != std::string::npos && semi + 1 < name.size() && std::all_of(name.begin() + static_cast<std::ptrdiff_t>(semi) + 1, name.end(), [](char c) { return c >= '0' && c <= '9'; }))
        name.erase(semi);
}

std::string foldAscii(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}
} // namespace

Expected<std::unique_ptr<IsoReader>> IsoReader::open(std::shared_ptr<BlockDevice> device) {
    auto r = std::unique_ptr<IsoReader>(new IsoReader());
    r->m_device = std::move(device);
    ByteCount pvdOff = 0, jolietOff = 0;
    for (int i = 0; i < 16; ++i) {
        const ByteCount off = 16 * kBlock + ByteCount{static_cast<std::uint64_t>(i)} * kBlock;
        auto d = r->m_device->read(off, kBlock);
        if (!d) break;
        if (std::memcmp(d->data() + 1, "CD001", 5) != 0) break;
        const auto type = std::to_integer<std::uint8_t>((*d)[0]);
        if (type == 255) break;
        if (type == 1 && !pvdOff) pvdOff = off;
        if (type == 2 && !jolietOff) {
            const std::byte* esc = d->data() + 88;
            if (esc[0] == std::byte{0x25} && esc[1] == std::byte{0x2F} && (esc[2] == std::byte{0x40} || esc[2] == std::byte{0x43} || esc[2] == std::byte{0x45})) jolietOff = off;
        }
    }
    if (!pvdOff) return fail(ErrorCategory::InvalidFormat, "no ISO 9660 primary volume descriptor");
    // Rock Ridge: the root directory's "." record carries an SP entry.
    auto pvd = r->m_device->read(pvdOff, kBlock);
    if (!pvd) return fail(pvd.error());
    const std::uint32_t rootExtent = loadLe32(pvd->data() + 156 + 2);
    auto dot = r->m_device->read(ByteCount{rootExtent} * kBlock, 256);
    if (!dot) return fail(dot.error());
    {
        const std::size_t len = std::to_integer<std::uint8_t>((*dot)[0]);
        const std::size_t nameLen = len > 33 ? std::to_integer<std::uint8_t>((*dot)[32]) : 0;
        std::size_t su = 33 + nameLen + ((nameLen & 1) ? 0 : 1);
        if (len >= su + 7 && (*dot)[su] == std::byte{'S'} && (*dot)[su + 1] == std::byte{'P'} && (*dot)[su + 4] == std::byte{0xBE} && (*dot)[su + 5] == std::byte{0xEF}) {
            r->m_names = Names::RockRidge;
            r->m_suspSkip = std::to_integer<std::uint8_t>((*dot)[su + 6]);
        }
    }
    if (r->m_names != Names::RockRidge && jolietOff) r->m_names = Names::Joliet;
    const ByteCount descriptor = r->m_names == Names::Joliet ? jolietOff : pvdOff;
    auto desc = r->m_device->read(descriptor, kBlock);
    if (!desc) return fail(desc.error());
    Entry root;
    auto n = r->parseRecord(*desc, 156, descriptor, root);
    if (!n) return fail(n.error());
    if (*n == 0 || !root.dir) return fail(ErrorCategory::InvalidFormat, "ISO root directory record is invalid");
    root.name = "/";
    root.dot = false;
    r->m_rootId = descriptor + 156;
    root.id = r->m_rootId;
    r->m_root = root;
    r->m_cache[root.id] = root;
    return r;
}

Expected<void> IsoReader::parseSusp(std::span<const std::byte> area, Entry& e, std::string& rrName, bool& haveName, int depth) const {
    if (depth > 8) return fail(ErrorCategory::InvalidFormat, "Rock Ridge continuation chain too deep");
    std::size_t pos = 0;
    while (pos + 4 <= area.size()) {
        const char s0 = static_cast<char>(area[pos]), s1 = static_cast<char>(area[pos + 1]);
        const std::size_t len = std::to_integer<std::uint8_t>(area[pos + 2]);
        if (len < 4 || pos + len > area.size()) break;
        const std::byte* d = area.data() + pos;
        if (s0 == 'C' && s1 == 'E' && len >= 28) {
            const std::uint32_t block = loadLe32(d + 4), offset = loadLe32(d + 12), length = loadLe32(d + 20);
            if (offset < kBlock && length <= kBlock) {
                auto cont = m_device->read(ByteCount{block} * kBlock + offset, length);
                if (!cont) return fail(cont.error());
                if (auto r = parseSusp(*cont, e, rrName, haveName, depth + 1); !r) return r;
            }
        } else if (s0 == 'N' && s1 == 'M' && len >= 5) {
            const auto flags = std::to_integer<std::uint8_t>(d[4]);
            if (flags & 0x02) e.dot = true;      // current directory
            else if (flags & 0x04) e.dot = true; // parent directory
            else {
                rrName.append(reinterpret_cast<const char*>(d + 5), len - 5);
                haveName = true;
            }
        } else if (s0 == 'P' && s1 == 'X' && len >= 36) {
            e.hasPosix = true;
            e.mode = loadLe32(d + 4);
            e.nlink = loadLe32(d + 12);
            e.uid = loadLe32(d + 20);
            e.gid = loadLe32(d + 28);
            e.symlink = (e.mode & 0170000) == 0120000;
        } else if (s0 == 'S' && s1 == 'L' && len >= 5) {
            std::size_t p = 5;
            while (p + 2 <= len) {
                const auto cflags = std::to_integer<std::uint8_t>(d[p]);
                const std::size_t clen = std::to_integer<std::uint8_t>(d[p + 1]);
                if (p + 2 + clen > len) break;
                if (cflags & 0x08) e.target = "/";
                else {
                    // A component longer than 255 bytes is split; "continue" means no separator yet.
                    if (!e.target.empty() && e.target.back() != '/' && !e.targetContinues) e.target += '/';
                    if (cflags & 0x02) e.target += ".";
                    else if (cflags & 0x04) e.target += "..";
                    else e.target.append(reinterpret_cast<const char*>(d + p + 2), clen);
                }
                e.targetContinues = (cflags & 0x01) != 0;
                p += 2 + clen;
            }
        } else if (s0 == 'T' && s1 == 'F' && len >= 5) {
            const auto flags = std::to_integer<std::uint8_t>(d[4]);
            const bool longForm = (flags & 0x80) != 0;
            const std::size_t stampLen = longForm ? 17 : 7;
            std::size_t p = 5;
            auto take = [&](std::int64_t& out) {
                if (p + stampLen <= len) out = longForm ? isoDate17(d + p) : isoDate7(d + p);
                p += stampLen;
            };
            if (flags & 0x01) take(e.crtime);
            if (flags & 0x02) take(e.mtime);
            if (flags & 0x04) take(e.atime);
            if (flags & 0x08) take(e.ctime);
        } else if (s0 == 'C' && s1 == 'L' && len >= 12) {
            // Relocated directory: this placeholder is the real directory living elsewhere.
            e.dir = true;
            e.extents.assign(1, {loadLe32(d + 4), 0});
        } else if (s0 == 'R' && s1 == 'E') {
            e.relocated = true;
        } else if (s0 == 'S' && s1 == 'T') {
            break;
        }
        pos += len;
    }
    return {};
}

Expected<std::uint64_t> IsoReader::dirSizeAt(std::uint32_t extent) const {
    auto dot = m_device->read(ByteCount{extent} * kBlock, 34);
    if (!dot) return fail(dot.error());
    if (std::to_integer<std::uint8_t>((*dot)[0]) < 33) return fail(ErrorCategory::InvalidFormat, "relocated directory has no '.' record");
    return loadLe32(dot->data() + 10);
}

Expected<std::size_t> IsoReader::parseRecord(std::span<const std::byte> buf, std::size_t pos, ByteCount base, Entry& out) const {
    if (pos >= buf.size()) return 0;
    const std::size_t len = std::to_integer<std::uint8_t>(buf[pos]);
    if (len == 0) return 0;
    if (len < 34 || pos + len > buf.size()) return fail(ErrorCategory::InvalidFormat, "directory record outside its sector");
    const std::byte* d = buf.data() + pos;
    Entry e;
    e.id = base + pos;
    e.flags = std::to_integer<std::uint8_t>(d[25]);
    e.dir = (e.flags & kFlagDirectory) != 0;
    e.unitSize = std::to_integer<std::uint8_t>(d[26]);
    const std::uint32_t extent = loadLe32(d + 2) + std::to_integer<std::uint8_t>(d[1]);
    const std::uint64_t size = loadLe32(d + 10);
    e.extents.emplace_back(extent, size);
    e.size = size;
    e.mtime = e.ctime = e.atime = e.crtime = isoDate7(d + 18);
    const std::size_t nameLen = std::to_integer<std::uint8_t>(d[32]);
    if (33 + nameLen > len) return fail(ErrorCategory::InvalidFormat, "directory record name overruns the record");
    const std::byte* name = d + 33;
    if (nameLen == 1 && (name[0] == std::byte{0} || name[0] == std::byte{1})) {
        e.dot = true;
        e.name = name[0] == std::byte{0} ? "." : "..";
    } else if (m_names == Names::Joliet) {
        e.name = ucs2beToUtf8(std::span<const std::byte>(name, nameLen));
        stripVersion(e.name);
    } else {
        e.name.assign(reinterpret_cast<const char*>(name), nameLen);
        stripVersion(e.name);
    }
    if (m_names == Names::RockRidge) {
        std::size_t su = 33 + nameLen + ((nameLen & 1) ? 0 : 1) + m_suspSkip;
        if (su < len) {
            std::string rrName;
            bool haveName = false;
            if (auto r = parseSusp(std::span<const std::byte>(d + su, len - su), e, rrName, haveName, 0); !r) return fail(r.error());
            if (haveName && !e.dot) e.name = rrName;
            if (e.extents.size() == 1 && e.extents[0].second == 0 && e.dir && !e.dot) {
                // CL placeholder: size comes from the relocated directory itself.
                auto sz = dirSizeAt(e.extents[0].first);
                if (!sz) return fail(sz.error());
                e.extents[0].second = e.size = *sz;
            }
        }
    }
    out = std::move(e);
    return len;
}

Expected<std::vector<IsoReader::Entry>> IsoReader::listDir(const Entry& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    if (!dir.dir) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<Entry> out;
    for (const auto& [extent, bytes] : dir.extents) {
        auto buf = m_device->read(ByteCount{extent} * kBlock, bytes);
        if (!buf) return fail(buf.error());
        std::size_t pos = 0;
        while (pos < buf->size()) {
            Entry e;
            auto n = parseRecord(*buf, pos, ByteCount{extent} * kBlock, e);
            if (!n) return fail(n.error());
            if (*n == 0) {
                pos = (pos / kBlock + 1) * kBlock;   // records never cross a sector: skip the padding
                continue;
            }
            pos += *n;
            if (e.dot) continue;
            if (!out.empty() && (out.back().flags & kFlagMultiExtent) && out.back().name == e.name) {
                out.back().extents.push_back(e.extents[0]);
                out.back().size += e.size;
                out.back().flags = e.flags;
                continue;
            }
            out.push_back(std::move(e));
        }
    }
    for (const auto& e : out) m_cache[e.id] = e;
    m_dirCache[dir.id] = out;
    return out;
}

Expected<IsoReader::Entry> IsoReader::entryOf(const Inode& inode) {
    if (auto it = m_cache.find(inode.id); it != m_cache.end()) return it->second;
    if (inode.id < 16 * kBlock) return fail(ErrorCategory::InvalidArgument, "not an ISO 9660 inode");
    // Read from the record to the end of its sector so multi-extent continuations can be merged.
    const ByteCount sectorEnd = (inode.id / kBlock + 1) * kBlock;
    auto buf = m_device->read(inode.id, sectorEnd - inode.id);
    if (!buf) return fail(buf.error());
    Entry e;
    auto n = parseRecord(*buf, 0, inode.id, e);
    if (!n) return fail(n.error());
    if (*n == 0) return fail(ErrorCategory::NotFound, "no directory record at this inode");
    std::size_t pos = *n;
    while ((e.flags & kFlagMultiExtent) && pos < buf->size()) {
        Entry more;
        auto m = parseRecord(*buf, pos, inode.id, more);
        if (!m || *m == 0 || more.name != e.name) break;
        e.extents.push_back(more.extents[0]);
        e.size += more.size;
        e.flags = more.flags;
        pos += *m;
    }
    m_cache[inode.id] = e;
    return e;
}

Expected<Inode> IsoReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto d = entryOf(dir);
    if (!d) return fail(d.error());
    auto entries = listDir(*d);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (!e.relocated && e.name == name) return Inode{e.id};
    if (m_names != Names::RockRidge) {
        const std::string want = foldAscii(name);
        for (const auto& e : *entries)
            if (!e.relocated && foldAscii(e.name) == want) return Inode{e.id};
    }
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> IsoReader::stat(const Inode& inode) {
    auto e = entryOf(inode);
    if (!e) return fail(e.error());
    Stat st;
    if (e->dir) st.type = FileType::Directory;
    else if (e->symlink) st.type = FileType::Symlink;
    else if (e->hasPosix) {
        switch (e->mode & 0170000) {
        case 0020000: st.type = FileType::CharDevice; break;
        case 0060000: st.type = FileType::BlockDevice; break;
        case 0010000: st.type = FileType::Fifo; break;
        case 0140000: st.type = FileType::Socket; break;
        default: st.type = FileType::File; break;
        }
    } else st.type = FileType::File;
    st.mode = e->hasPosix ? (e->mode & 07777) : (e->dir ? 0555 : 0444);
    st.nlink = e->nlink ? e->nlink : 1;
    st.uid = e->uid;
    st.gid = e->gid;
    st.size = e->symlink ? e->target.size() : e->size;
    for (const auto& [extent, bytes] : e->extents) st.allocatedBytes += (bytes + kBlock - 1) / kBlock * kBlock;
    st.mtime = e->mtime;
    st.ctime = e->ctime;
    st.atime = e->atime;
    st.crtime = e->crtime;
    return st;
}

Expected<std::vector<DirEntry>> IsoReader::readdir(const Inode& dir) {
    auto d = entryOf(dir);
    if (!d) return fail(d.error());
    auto entries = listDir(*d);
    if (!entries) return fail(entries.error());
    std::vector<DirEntry> out;
    for (const auto& e : *entries) {
        if (e.relocated) continue;   // lives at its CL placeholder, like the kernel shows it
        out.push_back(DirEntry{e.name, Inode{e.id}, e.dir ? FileType::Directory : e.symlink ? FileType::Symlink : FileType::File});
    }
    return out;
}

Expected<std::size_t> IsoReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto e = entryOf(file);
    if (!e) return fail(e.error());
    if (e->dir) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (e->unitSize) return fail(ErrorCategory::Unsupported, "interleaved ISO 9660 files are not supported");
    if (offset >= e->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), e->size - offset);
    std::uint64_t done = 0, sectionStart = 0;
    for (const auto& [extent, bytes] : e->extents) {
        if (done >= n) break;
        const std::uint64_t pos = offset + done;
        if (pos >= sectionStart + bytes) {
            sectionStart += bytes;
            continue;
        }
        const std::uint64_t in = pos - sectionStart;
        const std::uint64_t take = std::min(bytes - in, n - done);
        if (auto r = m_device->readAt(ByteCount{extent} * kBlock + in, dst.subspan(static_cast<std::size_t>(done), static_cast<std::size_t>(take))); !r) return fail(r.error());
        done += take;
        sectionStart += bytes;
    }
    return static_cast<std::size_t>(done);
}

Expected<std::string> IsoReader::readlink(const Inode& link) {
    auto e = entryOf(link);
    if (!e) return fail(e.error());
    if (!e->symlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    return e->target;
}

class IsoReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = IsoReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeIsoReaderSource() { return std::make_unique<IsoReaderSource>(); }

} // namespace stein::fs::detail
