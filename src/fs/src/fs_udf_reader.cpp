// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/udf_reader.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace stein::fs::detail {

namespace {
constexpr std::uint16_t kTagAvdp = 2, kTagPartition = 5, kTagLogicalVolume = 6, kTagTerminating = 8, kTagFileSet = 256, kTagFileIdentifier = 257,
                        kTagAllocationExtent = 258, kTagFileEntry = 261, kTagExtendedFileEntry = 266;
constexpr std::uint8_t kTypeDirectory = 4, kTypeRegular = 5, kTypeBlockDevice = 6, kTypeCharDevice = 7, kTypeFifo = 9, kTypeSocket = 10, kTypeSymlink = 12, kTypeMetadataFile = 250;
constexpr std::uint32_t kExtentLengthMask = 0x3FFFFFFFu;

bool tagChecksumOk(const std::byte* p) {
    std::uint8_t sum = 0;
    for (int i = 0; i < 16; ++i)
        if (i != 4) sum = static_cast<std::uint8_t>(sum + std::to_integer<std::uint8_t>(p[i]));
    return sum == std::to_integer<std::uint8_t>(p[4]);
}

std::uint16_t tagId(const std::byte* p) { return tagChecksumOk(p) ? loadLe16(p) : 0xFFFF; }

// OSTA compressed unicode: compression id 8 (Latin-1) or 16 (UCS-2 BE); 254/255 are the UDF 2.x
// variants with the same encodings.
std::string dstring(std::span<const std::byte> s) {
    if (s.empty()) return {};
    const auto id = std::to_integer<std::uint8_t>(s[0]);
    std::string out;
    if (id == 8 || id == 254) {
        for (std::size_t i = 1; i < s.size(); ++i) {
            const auto c = std::to_integer<std::uint8_t>(s[i]);
            if (c == 0) break;
            if (c < 0x80) out += static_cast<char>(c);
            else {
                out += static_cast<char>(0xC0 | (c >> 6));
                out += static_cast<char>(0x80 | (c & 0x3F));
            }
        }
    } else if (id == 16 || id == 255) {
        std::vector<std::byte> le;
        for (std::size_t i = 1; i + 1 < s.size(); i += 2) {
            le.push_back(s[i + 1]);
            le.push_back(s[i]);
        }
        out = utf16leToUtf8(le, true);
    }
    return out;
}

std::int64_t udfTime(const std::byte* p) {
    const std::uint16_t typeTz = loadLe16(p);
    const std::int16_t year = static_cast<std::int16_t>(loadLe16(p + 2));
    if (year == 0) return 0;
    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = std::to_integer<int>(p[4]) - 1;
    tm.tm_mday = std::to_integer<int>(p[5]);
    tm.tm_hour = std::to_integer<int>(p[6]);
    tm.tm_min = std::to_integer<int>(p[7]);
    tm.tm_sec = std::to_integer<int>(p[8]);
#if defined(_WIN32)
    std::int64_t t = static_cast<std::int64_t>(_mkgmtime(&tm));
#else
    std::int64_t t = static_cast<std::int64_t>(timegm(&tm));
#endif
    int tz = typeTz & 0x0FFF;
    if (tz & 0x800) tz -= 0x1000;   // 12-bit signed minutes east of UTC; -2047 = unspecified
    if (tz != -2047) t -= static_cast<std::int64_t>(tz) * 60;
    return t;
}

FileType fileTypeOf(std::uint8_t t) {
    switch (t) {
    case kTypeDirectory: return FileType::Directory;
    case kTypeRegular: case 0: return FileType::File;
    case kTypeSymlink: return FileType::Symlink;
    case kTypeBlockDevice: return FileType::BlockDevice;
    case kTypeCharDevice: return FileType::CharDevice;
    case kTypeFifo: return FileType::Fifo;
    case kTypeSocket: return FileType::Socket;
    default: return FileType::Unknown;
    }
}

std::uint32_t posixMode(std::uint32_t udfPerms) {
    // UDF: per class, bit0 execute, bit1 write, bit2 read (plus chattr/delete bits); classes other, group, owner.
    const auto cls = [&](int shift) { return udfPerms >> shift & 7; };
    return (cls(10) << 6) | (cls(5) << 3) | cls(0);
}
} // namespace

Expected<std::unique_ptr<UdfReader>> UdfReader::open(std::shared_ptr<BlockDevice> device) {
    auto r = std::unique_ptr<UdfReader>(new UdfReader());
    r->m_device = std::move(device);
    // Volume recognition sequence: an NSR02/NSR03 descriptor from byte 32768 on.
    bool nsr = false;
    for (int i = 0; i < 16 && !nsr; ++i) {
        auto s = r->m_device->read(32768 + ByteCount{static_cast<std::uint64_t>(i)} * 2048, 2048);
        if (!s) break;
        const char* id = reinterpret_cast<const char*>(s->data() + 1);
        if (std::memcmp(id, "NSR02", 5) == 0 || std::memcmp(id, "NSR03", 5) == 0) nsr = true;
        else if (std::memcmp(id, "BEA01", 5) != 0 && std::memcmp(id, "BOOT2", 5) != 0 && std::memcmp(id, "CD001", 5) != 0 && std::memcmp(id, "CDW02", 5) != 0 && std::memcmp(id, "TEA01", 5) != 0) break;
    }
    if (!nsr) return fail(ErrorCategory::InvalidFormat, "no UDF NSR descriptor in the volume recognition sequence");
    // Anchor at sector 256 (also tried: the last sector and 256 before it) for 2048/512/1024/4096-byte blocks.
    std::uint32_t mainLoc = 0, mainLen = 0, reserveLoc = 0, reserveLen = 0;
    bool anchored = false;
    for (std::uint32_t bs : {2048u, 512u, 4096u, 1024u}) {
        const ByteCount last = r->m_device->size() / bs;
        for (ByteCount sector : {ByteCount{256}, last > 1 ? last - 1 : 0, last > 257 ? last - 257 : 0}) {
            if (sector == 0) continue;
            auto a = r->m_device->read(sector * bs, 512);
            if (!a || tagId(a->data()) != kTagAvdp || loadLe32(a->data() + 12) != sector) continue;
            mainLen = loadLe32(a->data() + 16);
            mainLoc = loadLe32(a->data() + 20);
            reserveLen = loadLe32(a->data() + 24);
            reserveLoc = loadLe32(a->data() + 28);
            r->m_blockSize = bs;
            anchored = true;
            break;
        }
        if (anchored) break;
    }
    if (!anchored) return fail(ErrorCategory::InvalidFormat, "no UDF anchor volume descriptor pointer");
    auto vds = r->loadVds(mainLoc, mainLen);
    if (!vds && reserveLoc) vds = r->loadVds(reserveLoc, reserveLen);
    if (!vds) return fail(vds.error());
    if (r->m_maps.empty()) return fail(ErrorCategory::InvalidFormat, "UDF logical volume has no partition map");
    // File set descriptor -> root directory ICB.
    auto fsdOff = r->blockToByte(r->m_rootPartition, r->m_rootBlock);
    if (!fsdOff) return fail(fsdOff.error());
    auto fsd = r->m_device->read(*fsdOff, 512);
    if (!fsd) return fail(fsd.error());
    if (tagId(fsd->data()) != kTagFileSet) return fail(ErrorCategory::InvalidFormat, "UDF file set descriptor not found");
    const std::uint32_t rootBlock = loadLe32(fsd->data() + 404);
    const std::uint16_t rootPart = loadLe16(fsd->data() + 408);
    if (rootPart >= r->m_maps.size()) return fail(ErrorCategory::InvalidFormat, "UDF root directory in an unknown partition");
    auto rootOff = r->blockToByte(rootPart, rootBlock);
    if (!rootOff) return fail(rootOff.error());
    r->m_rootId = *rootOff;
    auto root = r->readEntry(rootPart, rootBlock);
    if (!root) return fail(root.error());
    return r;
}

Expected<void> UdfReader::loadVds(std::uint32_t location, std::uint32_t length) {
    m_maps.clear();
    struct Physical {
        std::uint16_t number;
        std::uint32_t start, length;
    };
    std::vector<Physical> physicals;
    std::vector<std::byte> lvd;
    for (std::uint32_t i = 0; i < std::max<std::uint32_t>(1, length / m_blockSize) && i < 64; ++i) {
        auto d = m_device->read(ByteCount{location + i} * m_blockSize, m_blockSize);
        if (!d) return fail(d.error());
        const std::uint16_t tag = tagId(d->data());
        if (tag == kTagTerminating || tag == 0xFFFF) break;
        if (tag == kTagPartition) physicals.push_back(Physical{loadLe16(d->data() + 22), loadLe32(d->data() + 188), loadLe32(d->data() + 192)});   // flags @20, number @22
        else if (tag == kTagLogicalVolume) lvd = *d;
    }
    if (lvd.empty() || physicals.empty()) return fail(ErrorCategory::InvalidFormat, "UDF volume descriptor sequence lacks a logical volume or partition descriptor");
    const std::uint32_t lvBlockSize = loadLe32(lvd.data() + 212);
    if (lvBlockSize != m_blockSize) {
        if (lvBlockSize < 512 || lvBlockSize > 65536 || (lvBlockSize & (lvBlockSize - 1))) return fail(ErrorCategory::InvalidFormat, "UDF logical block size is implausible");
        m_blockSize = lvBlockSize;
    }
    m_label = dstring(std::span<const std::byte>(lvd).subspan(84, 128));
    m_rootBlock = loadLe32(lvd.data() + 252);          // logical volume contents use: FSD long_ad (length, block, partition)
    m_rootPartition = loadLe16(lvd.data() + 256);
    const std::uint32_t mapTableLength = loadLe32(lvd.data() + 264), mapCount = loadLe32(lvd.data() + 268);
    std::size_t pos = 440;
    for (std::uint32_t m = 0; m < mapCount && pos + 2 <= lvd.size() && pos < 440 + mapTableLength; ++m) {
        const auto type = std::to_integer<std::uint8_t>(lvd[pos]), len = std::to_integer<std::uint8_t>(lvd[pos + 1]);
        if (len < 2 || pos + len > lvd.size()) break;
        PartitionMap pm;
        std::uint16_t number = 0;
        if (type == 1 && len >= 6) {
            number = loadLe16(lvd.data() + pos + 4);
        } else if (type == 2 && len >= 64) {
            const std::string ident(reinterpret_cast<const char*>(lvd.data() + pos + 5), 23);
            number = loadLe16(lvd.data() + pos + 38);
            if (ident.rfind("*UDF Sparable Partition", 0) == 0) {
                pm.kind = PartitionMap::Kind::Sparable;
                pm.packetLength = loadLe16(lvd.data() + pos + 40);
                const auto tables = std::to_integer<std::uint8_t>(lvd[pos + 42]);
                const std::uint32_t tableSize = loadLe32(lvd.data() + pos + 44);
                for (int t = 0; t < tables && t < 4 && pm.sparing.empty(); ++t) {
                    const std::uint32_t loc = loadLe32(lvd.data() + pos + 48 + t * 4);
                    auto st = m_device->read(ByteCount{loc} * m_blockSize, std::min<ByteCount>(tableSize, 1 * MiB));
                    if (!st || tagId(st->data()) != 0) continue;
                    const std::uint16_t entries = loadLe16(st->data() + 48);
                    for (std::size_t e = 0; e < entries && 56 + (e + 1) * 8 <= st->size(); ++e) {
                        const std::uint32_t orig = loadLe32(st->data() + 56 + e * 8), mapped = loadLe32(st->data() + 60 + e * 8);
                        if (orig < 0xFFFFFFF0u) pm.sparing.emplace_back(orig, mapped);
                    }
                }
            } else if (ident.rfind("*UDF Metadata Partition", 0) == 0) {
                pm.kind = PartitionMap::Kind::Metadata;
                pm.start = loadLe32(lvd.data() + pos + 40);   // metadata file location, resolved below
            } else if (ident.rfind("*UDF Virtual Partition", 0) == 0) {
                return fail(ErrorCategory::Unsupported, "UDF virtual (write-once, VAT) partitions are not supported yet");
            } else {
                return fail(ErrorCategory::Unsupported, "unknown UDF type 2 partition map");
            }
        } else {
            return fail(ErrorCategory::Unsupported, "unknown UDF partition map type");
        }
        pm.partitionNumber = number;
        if (pm.kind != PartitionMap::Kind::Metadata) {
            bool found = false;
            for (const auto& p : physicals)
                if (p.number == number) {
                    pm.start = p.start;
                    pm.length = p.length;
                    found = true;
                }
            if (!found) return fail(ErrorCategory::InvalidFormat, "UDF partition map references an unknown partition number");
        }
        m_maps.push_back(std::move(pm));
        pos += len;
    }
    // Metadata partitions: their blocks live in the metadata file, which sits in the physical partition of the same number.
    for (std::size_t i = 0; i < m_maps.size(); ++i) {
        if (m_maps[i].kind != PartitionMap::Kind::Metadata) continue;
        std::size_t phys = m_maps.size();
        for (std::size_t j = 0; j < m_maps.size(); ++j)
            if (j != i && m_maps[j].kind == PartitionMap::Kind::Physical && m_maps[j].partitionNumber == m_maps[i].partitionNumber) phys = j;
        if (phys == m_maps.size()) return fail(ErrorCategory::InvalidFormat, "UDF metadata partition without its physical partition");
        m_maps[i].underlying = static_cast<std::uint16_t>(phys);
        auto meta = readEntry(static_cast<std::uint16_t>(phys), m_maps[i].start);
        if (!meta) return fail(meta.error());
        if (meta->fileType != kTypeMetadataFile) return fail(ErrorCategory::InvalidFormat, "UDF metadata file has the wrong type");
        m_maps[i].metadataExtents = meta->extents;
        m_maps[i].length = m_maps[phys].length;
    }
    return {};
}

Expected<ByteCount> UdfReader::blockToByte(std::uint16_t partition, std::uint32_t block) const {
    if (partition >= m_maps.size()) return fail(ErrorCategory::InvalidFormat, "UDF reference to partition map " + std::to_string(partition) + " of " + std::to_string(m_maps.size()));
    const PartitionMap& pm = m_maps[partition];
    switch (pm.kind) {
    case PartitionMap::Kind::Physical:
        if (block >= pm.length) return fail(ErrorCategory::InvalidFormat, "UDF block beyond its partition");
        return ByteCount{pm.start + block} * m_blockSize;
    case PartitionMap::Kind::Sparable: {
        std::uint32_t phys = block;
        if (pm.packetLength) {
            const std::uint32_t packet = block - block % pm.packetLength;
            for (const auto& [orig, mapped] : pm.sparing)
                if (orig == packet) phys = mapped + block % pm.packetLength;
        }
        return ByteCount{pm.start + phys} * m_blockSize;
    }
    case PartitionMap::Kind::Metadata: {
        const std::uint64_t off = std::uint64_t{block} * m_blockSize;
        for (const auto& e : pm.metadataExtents)
            if (off >= e.fileOffset && off < e.fileOffset + e.length) {
                if (!e.recorded) return fail(ErrorCategory::InvalidFormat, "UDF metadata block in an unrecorded extent");
                return blockToByte(e.partition, e.block + static_cast<std::uint32_t>((off - e.fileOffset) / m_blockSize));
            }
        return fail(ErrorCategory::InvalidFormat, "UDF metadata block outside the metadata file");
    }
    }
    return fail(ErrorCategory::Internal, "bad partition map kind");
}

Expected<void> UdfReader::parseAllocationDescriptors(Entry& e, std::span<const std::byte> ads, std::uint8_t kind, std::uint16_t partition, int depth) {
    if (depth > 16) return fail(ErrorCategory::InvalidFormat, "UDF allocation extent chain too deep");
    const std::size_t stride = kind == 0 ? 8 : kind == 1 ? 16 : 20;
    std::uint64_t fileOffset = e.extents.empty() ? 0 : e.extents.back().fileOffset + e.extents.back().length;
    for (std::size_t pos = 0; pos + stride <= ads.size(); pos += stride) {
        const std::uint32_t raw = loadLe32(ads.data() + pos);
        const std::uint32_t length = raw & kExtentLengthMask, flags = raw >> 30;
        if (length == 0) break;
        std::uint32_t block = 0;
        std::uint16_t part = partition;
        if (kind == 0) block = loadLe32(ads.data() + pos + 4);
        else if (kind == 1) {
            block = loadLe32(ads.data() + pos + 4);
            part = loadLe16(ads.data() + pos + 8);
        } else {
            block = loadLe32(ads.data() + pos + 12);
            part = loadLe16(ads.data() + pos + 16);
        }
        if (flags == 3) {
            // Continuation: an allocation extent descriptor holds more descriptors.
            auto off = blockToByte(part, block);
            if (!off) return fail(off.error());
            auto aed = m_device->read(*off, std::min<ByteCount>(length, m_blockSize));
            if (!aed || tagId(aed->data()) != kTagAllocationExtent) return fail(ErrorCategory::InvalidFormat, "UDF allocation extent descriptor missing");
            const std::uint32_t adLen = loadLe32(aed->data() + 20);
            if (24u + adLen > aed->size()) return fail(ErrorCategory::InvalidFormat, "UDF allocation extent descriptor overruns");
            return parseAllocationDescriptors(e, std::span<const std::byte>(aed->data() + 24, adLen), kind, part, depth + 1);
        }
        Extent x;
        x.fileOffset = fileOffset;
        x.length = length;
        x.block = block;
        x.partition = part;
        x.recorded = flags == 0;
        fileOffset += length;
        e.extents.push_back(x);
    }
    return {};
}

Expected<UdfReader::Entry> UdfReader::readEntry(std::uint16_t partition, std::uint32_t block) {
    auto off = blockToByte(partition, block);
    if (!off) return fail(off.error());
    if (auto it = m_cache.find(*off); it != m_cache.end()) return it->second;
    auto raw = m_device->read(*off, m_blockSize);
    if (!raw) return fail(raw.error());
    const std::byte* d = raw->data();
    const std::uint16_t tag = tagId(d);
    if (tag != kTagFileEntry && tag != kTagExtendedFileEntry) return fail(ErrorCategory::InvalidFormat, "UDF file entry expected at block " + std::to_string(block) + " (tag " + std::to_string(tag) + ")");
    const bool extended = tag == kTagExtendedFileEntry;
    Entry e;
    e.id = *off;
    e.fileType = std::to_integer<std::uint8_t>(d[27]);
    const std::uint16_t icbFlags = loadLe16(d + 34);
    e.uid = loadLe32(d + 36);
    e.gid = loadLe32(d + 40);
    e.permissions = loadLe32(d + 44);
    e.links = loadLe16(d + 48);
    e.size = loadLe64(d + 56);
    std::size_t eaLenOff, adLenOff, eaOff;
    if (extended) {
        e.blocksRecorded = loadLe64(d + 72);
        e.atime = udfTime(d + 80);
        e.mtime = udfTime(d + 92);
        e.crtime = udfTime(d + 104);
        e.ctime = udfTime(d + 116);
        eaLenOff = 208;
        adLenOff = 212;
        eaOff = 216;
    } else {
        e.blocksRecorded = loadLe64(d + 64);
        e.atime = udfTime(d + 72);
        e.mtime = udfTime(d + 84);
        e.ctime = udfTime(d + 96);
        e.crtime = e.mtime;
        eaLenOff = 168;
        adLenOff = 172;
        eaOff = 176;
    }
    const std::uint32_t eaLen = loadLe32(d + eaLenOff), adLen = loadLe32(d + adLenOff);
    if (eaOff + eaLen + adLen > raw->size()) return fail(ErrorCategory::InvalidFormat, "UDF file entry descriptors overrun the block");
    const std::span<const std::byte> ads(d + eaOff + eaLen, adLen);
    const std::uint8_t adKind = icbFlags & 7;
    if (adKind == 3) {
        e.inlined = true;
        e.inlineData.assign(ads.begin(), ads.end());
    } else if (adKind <= 2) {
        if (auto p = parseAllocationDescriptors(e, ads, adKind, partition, 0); !p) return fail(p.error());
    } else {
        return fail(ErrorCategory::InvalidFormat, "unknown UDF allocation descriptor type");
    }
    m_cache[*off] = e;
    return e;
}

Expected<UdfReader::Entry> UdfReader::entryOf(const Inode& inode) {
    if (auto it = m_cache.find(inode.id); it != m_cache.end()) return it->second;
    // Not seen through a listing: find the partition whose byte range holds the entry, then read it.
    for (std::uint16_t p = 0; p < m_maps.size(); ++p) {
        const auto& pm = m_maps[p];
        if (pm.kind != PartitionMap::Kind::Physical) continue;
        const ByteCount start = ByteCount{pm.start} * m_blockSize, end = start + ByteCount{pm.length} * m_blockSize;
        if (inode.id >= start && inode.id < end && (inode.id - start) % m_blockSize == 0) return readEntry(p, static_cast<std::uint32_t>((inode.id - start) / m_blockSize));
    }
    return fail(ErrorCategory::InvalidArgument, "not a UDF inode");
}

Expected<void> UdfReader::readData(const Entry& e, std::uint64_t offset, std::span<std::byte> dst) const {
    std::memset(dst.data(), 0, dst.size());
    if (e.inlined) {
        if (offset < e.inlineData.size()) std::memcpy(dst.data(), e.inlineData.data() + offset, std::min<std::size_t>(dst.size(), e.inlineData.size() - static_cast<std::size_t>(offset)));
        return {};
    }
    for (const auto& x : e.extents) {
        const std::uint64_t xEnd = x.fileOffset + x.length;
        if (xEnd <= offset || x.fileOffset >= offset + dst.size()) continue;
        if (!x.recorded) continue;
        const std::uint64_t from = std::max(offset, x.fileOffset), to = std::min<std::uint64_t>(offset + dst.size(), xEnd);
        // Map piecewise by block (sparable/metadata partitions may be non-contiguous).
        std::uint64_t pos = from;
        while (pos < to) {
            const std::uint64_t inExtent = pos - x.fileOffset;
            const std::uint32_t blockIndex = static_cast<std::uint32_t>(inExtent / m_blockSize);
            const std::uint64_t inBlock = inExtent % m_blockSize;
            const std::uint64_t n = std::min<std::uint64_t>(m_blockSize - inBlock, to - pos);
            auto off = blockToByte(x.partition, x.block + blockIndex);
            if (!off) return fail(off.error());
            if (auto r = m_device->readAt(*off + inBlock, dst.subspan(static_cast<std::size_t>(pos - offset), static_cast<std::size_t>(n))); !r) return r;
            pos += n;
        }
    }
    return {};
}

Expected<std::vector<DirEntry>> UdfReader::listDir(const Entry& dir) {
    if (auto it = m_dirCache.find(dir.id); it != m_dirCache.end()) return it->second;
    if (dir.fileType != kTypeDirectory) return fail(ErrorCategory::InvalidArgument, "not a directory");
    std::vector<std::byte> data(static_cast<std::size_t>(std::min<std::uint64_t>(dir.size, 64 * MiB)));
    if (auto r = readData(dir, 0, data); !r) return fail(r.error());
    std::vector<DirEntry> out;
    std::size_t pos = 0;
    while (pos + 38 <= data.size()) {
        const std::byte* f = data.data() + pos;
        if (tagId(f) != kTagFileIdentifier) break;
        const auto chars = std::to_integer<std::uint8_t>(f[18]), lfi = std::to_integer<std::uint8_t>(f[19]);
        const std::uint32_t icbBlock = loadLe32(f + 24);
        const std::uint16_t icbPart = loadLe16(f + 28);
        const std::uint16_t liu = loadLe16(f + 36);
        const std::size_t total = (38 + liu + lfi + 3) & ~std::size_t{3};
        if (pos + total > data.size()) break;
        pos += total;
        if ((chars & 0x08) || (chars & 0x04) || lfi == 0) continue;   // parent, deleted
        auto off = blockToByte(icbPart, icbBlock);
        if (!off) return fail(off.error());
        std::string name = dstring(std::span<const std::byte>(f + 38 + liu, lfi));
        out.push_back(DirEntry{std::move(name), Inode{*off}, (chars & 0x02) ? FileType::Directory : FileType::Unknown});
        // Prime the cache so stat() does not have to locate the partition from the offset alone.
        (void)readEntry(icbPart, icbBlock);
    }
    m_dirCache[dir.id] = out;
    return out;
}

Expected<Inode> UdfReader::lookup(const Inode& dir, std::string_view name) {
    if (name == ".") return dir;
    auto d = entryOf(dir);
    if (!d) return fail(d.error());
    auto entries = listDir(*d);
    if (!entries) return fail(entries.error());
    for (const auto& e : *entries)
        if (e.name == name) return e.inode;
    return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
}

Expected<Stat> UdfReader::stat(const Inode& inode) {
    auto e = entryOf(inode);
    if (!e) return fail(e.error());
    Stat st;
    st.type = fileTypeOf(e->fileType);
    st.mode = posixMode(e->permissions);
    if (st.mode == 0) st.mode = st.type == FileType::Directory ? 0555 : 0444;
    st.nlink = e->links;
    st.uid = e->uid == 0xFFFFFFFFu ? 0 : e->uid;
    st.gid = e->gid == 0xFFFFFFFFu ? 0 : e->gid;
    st.size = e->size;
    st.allocatedBytes = e->blocksRecorded * m_blockSize;
    st.atime = e->atime;
    st.mtime = e->mtime;
    st.ctime = e->ctime;
    st.crtime = e->crtime;
    return st;
}

Expected<std::vector<DirEntry>> UdfReader::readdir(const Inode& dir) {
    auto d = entryOf(dir);
    if (!d) return fail(d.error());
    return listDir(*d);
}

Expected<std::size_t> UdfReader::read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) {
    auto e = entryOf(file);
    if (!e) return fail(e.error());
    if (e->fileType == kTypeDirectory) return fail(ErrorCategory::InvalidArgument, "is a directory");
    if (offset >= e->size) return 0;
    const std::uint64_t n = std::min<std::uint64_t>(dst.size(), e->size - offset);
    if (auto r = readData(*e, offset, dst.subspan(0, static_cast<std::size_t>(n))); !r) return fail(r.error());
    return static_cast<std::size_t>(n);
}

Expected<std::string> UdfReader::readlink(const Inode& link) {
    auto e = entryOf(link);
    if (!e) return fail(e.error());
    if (e->fileType != kTypeSymlink) return fail(ErrorCategory::InvalidArgument, "not a symbolic link");
    if (e->size > 4096) return fail(ErrorCategory::InvalidFormat, "symlink pathname longer than 4096 bytes");
    std::vector<std::byte> data(static_cast<std::size_t>(e->size));
    if (auto r = readData(*e, 0, data); !r) return fail(r.error());
    // Pathname components: type, identifier length, version, identifier (d-string).
    std::string target;
    std::size_t pos = 0;
    while (pos + 4 <= data.size()) {
        const auto type = std::to_integer<std::uint8_t>(data[pos]), len = std::to_integer<std::uint8_t>(data[pos + 1]);
        if (pos + 4 + len > data.size()) break;
        std::string piece;
        switch (type) {
        case 1: target = "/"; pos += 4 + len; continue;
        case 2: piece = ".."; break;
        case 3: piece = "."; break;
        case 5: piece = dstring(std::span<const std::byte>(data).subspan(pos + 4, len)); break;
        default: piece = dstring(std::span<const std::byte>(data).subspan(pos + 4, len)); break;
        }
        if (!target.empty() && target.back() != '/') target += '/';
        target += piece;
        pos += 4 + len;
    }
    return target;
}

class UdfReaderSource final : public ReaderSource {
public:
    Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const override {
        auto r = UdfReader::open(std::move(device));
        if (!r) return fail(r.error());
        return std::unique_ptr<Reader>(std::move(*r));
    }
};

std::unique_ptr<ReaderSource> makeUdfReaderSource() { return std::make_unique<UdfReaderSource>(); }

} // namespace stein::fs::detail
