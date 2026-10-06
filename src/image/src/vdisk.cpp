// SPDX-License-Identifier: MIT
#include "stein/image/vdisk.hpp"

#include "stein/block/concat_device.hpp"
#include "stein/block/file_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/core/bzip2.hpp"
#include "stein/core/crc32.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/inflate.hpp"
#include "stein/core/lzma.hpp"
#include "stein/core/zstd.hpp"
#include "stein/core/strings.hpp"
#include "stein/image/stein_format.hpp"
#include "stein/image/operations.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <functional>

namespace stein::image {

std::string_view toString(VdiskFormat f) {
    switch (f) {
    case VdiskFormat::Raw: return "raw";
    case VdiskFormat::Stein: return "stein";
    case VdiskFormat::Qcow2: return "qcow2";
    case VdiskFormat::Vhd: return "vhd";
    case VdiskFormat::Vhdx: return "vhdx";
    case VdiskFormat::Vmdk: return "vmdk";
    case VdiskFormat::Vdi: return "vdi";
    case VdiskFormat::Ewf: return "ewf";
    case VdiskFormat::Dmg: return "dmg";
    }
    return "?";
}

namespace {

// Read-only device assembled from a mapping function: for any guest offset the
// format answers "zeros", "bytes at this file offset" or "this compressed unit",
// plus how many bytes that answer covers. One decompressed unit is cached.
class MappedDevice final : public BlockDevice {
public:
    enum class Kind : std::uint8_t { Zero, File, Compressed };
    struct Map {
        Kind kind = Kind::Zero;
        ByteCount fileOffset = 0;      // File: where the bytes live
        ByteCount length = 0;          // how many guest bytes this answer covers (from the asked offset)
        std::uint64_t unit = 0;        // Compressed: identifier of the unit (cache key)
        ByteCount unitStart = 0;       // Compressed: guest offset where the unit begins
        std::size_t fileIndex = 0;     // File: which of the container's files (segments)
    };
    using Mapper = std::function<Expected<Map>(ByteCount guestOffset)>;
    using Decompressor = std::function<Expected<void>(std::uint64_t unit, std::span<std::byte> out)>;   // fills one whole unit

    MappedDevice(std::shared_ptr<BlockDevice> file, std::string name, ByteCount size, std::uint32_t unitSize, Mapper map, Decompressor decompress)
        : m_file(std::move(file)), m_name(std::move(name)), m_unitSize(unitSize), m_map(std::move(map)), m_decompress(std::move(decompress)) {
        m_files.push_back(m_file);
        m_geometry.sizeBytes = size;
        m_geometry.logicalSectorSize = 512;
        m_geometry.physicalSectorSize = 512;
    }
    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return true; }
    std::shared_ptr<BlockDevice> parent() const override { return m_file; }
    Expected<void> flush() override { return {}; }
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override { return fail(ErrorCategory::Permission, m_name + " is a read-only container"); }
    void setFiles(std::vector<std::shared_ptr<BlockDevice>> files) { m_files = std::move(files); }

    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        std::size_t done = 0;
        while (done < dst.size()) {
            const ByteCount pos = offset + done;
            auto m = m_map(pos);
            if (!m) return fail(m.error());
            if (m->length == 0) return fail(ErrorCategory::Internal, "container mapping made no progress");
            const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>(m->length, dst.size() - done));
            auto window = dst.subspan(done, n);
            switch (m->kind) {
            case MappedDevice::Kind::Zero: std::memset(window.data(), 0, n); break;
            case MappedDevice::Kind::File:
                if (m->fileIndex >= m_files.size()) return fail(ErrorCategory::Internal, "container mapping names a missing file");
                if (auto r = m_files[m->fileIndex]->readAt(m->fileOffset, window); !r) return r;
                break;
            case MappedDevice::Kind::Compressed: {
                if (m_cachedUnit != m->unit || m_cache.size() != m_unitSize) {
                    m_cache.assign(m_unitSize, std::byte{0});
                    if (auto d = m_decompress(m->unit, m_cache); !d) return d;
                    m_cachedUnit = m->unit;
                }
                const ByteCount in = pos - m->unitStart;
                if (in + n > m_cache.size()) return fail(ErrorCategory::Internal, "compressed unit window out of range");
                std::memcpy(window.data(), m_cache.data() + in, n);
                break;
            }
            }
            done += n;
        }
        return {};
    }

private:
    std::shared_ptr<BlockDevice> m_file;
    std::vector<std::shared_ptr<BlockDevice>> m_files;
    std::string m_name;
    std::uint32_t m_unitSize;
    Mapper m_map;
    Decompressor m_decompress;
    Geometry m_geometry;
    std::vector<std::byte> m_cache;
    std::uint64_t m_cachedUnit = ~0ull;
};

class ZeroDevice final : public BlockDevice {
public:
    explicit ZeroDevice(ByteCount size) { m_geometry.sizeBytes = size; }
    std::string name() const override { return "zero extent"; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        std::memset(dst.data(), 0, dst.size());
        return {};
    }
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override { return fail(ErrorCategory::Permission, "zero extent is read-only"); }
    Expected<void> flush() override { return {}; }

private:
    Geometry m_geometry;
};

Expected<std::vector<std::byte>> readExact(BlockDevice& f, ByteCount off, ByteCount len) {
    if (off + len > f.size()) return fail(ErrorCategory::InvalidFormat, "container header beyond the end of the file");
    return f.read(off, len);
}

// GUID as stored by Microsoft formats: first three groups little-endian.
std::array<std::byte, 16> msGuid(std::string_view text) {
    std::array<std::byte, 16> g{};
    std::string hex;
    for (char c : text)
        if (c != '-') hex += c;
    std::array<std::uint8_t, 16> b{};
    for (int i = 0; i < 16; ++i) b[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    const int order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    for (int i = 0; i < 16; ++i) g[i] = std::byte(b[order[i]]);
    return g;
}

bool guidAt(const std::byte* p, const std::array<std::byte, 16>& g) { return std::memcmp(p, g.data(), 16) == 0; }

// ----------------------------------------------------------------------------- qcow2

Expected<std::shared_ptr<BlockDevice>> openQcow2(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    auto h = readExact(*file, 0, 112);
    if (!h) return fail(h.error());
    const std::byte* d = h->data();
    const std::uint32_t version = loadBe32(d + 4);
    if (version != 2 && version != 3) return fail(ErrorCategory::Unsupported, "qcow2 version " + std::to_string(version));
    const std::uint64_t backingOffset = loadBe64(d + 8);
    const std::uint32_t clusterBits = loadBe32(d + 20);
    const std::uint64_t size = loadBe64(d + 24);
    const std::uint32_t crypt = loadBe32(d + 32), l1Size = loadBe32(d + 36);
    const std::uint64_t l1Offset = loadBe64(d + 40);
    if (clusterBits < 9 || clusterBits > 21) return fail(ErrorCategory::InvalidFormat, "qcow2 cluster_bits out of range");
    if (backingOffset != 0) return fail(ErrorCategory::Unsupported, "qcow2 images with a backing file are not supported yet");
    if (crypt != 0) return fail(ErrorCategory::Unsupported, "encrypted qcow2 images are not supported");
    std::uint8_t compressionType = 0;
    if (version == 3) {
        const std::uint64_t incompatible = loadBe64(d + 72);
        const std::uint32_t headerLength = loadBe32(d + 100);
        if (incompatible & 0x4) return fail(ErrorCategory::Unsupported, "qcow2 external data files are not supported");
        if (incompatible & 0x10) return fail(ErrorCategory::Unsupported, "qcow2 extended L2 entries (subclusters) are not supported yet");
        if (incompatible & 0x1) info.notes.push_back("dirty bit set: the image was not cleanly closed (refcounts may be stale; data reads are unaffected)");
        if (incompatible & 0x2) info.notes.push_back("corrupt bit set");
        if ((incompatible & 0x8) && headerLength > 104) compressionType = std::to_integer<std::uint8_t>(d[104]);
        info.variant = "v3";
    } else {
        info.variant = "v2";
    }
    if (compressionType == 1) info.notes.push_back("zstd-compressed clusters");
    else if (compressionType != 0) return fail(ErrorCategory::Unsupported, "unknown qcow2 compression type");
    const std::uint32_t clusterSize = 1u << clusterBits;
    const std::uint64_t l2Entries = clusterSize / 8;
    const unsigned l2Bits = clusterBits - 3;
    auto l1 = readExact(*file, l1Offset, ByteCount{l1Size} * 8);
    if (!l1) return fail(l1.error());
    auto l1Table = std::make_shared<std::vector<std::uint64_t>>(l1Size);
    for (std::uint32_t i = 0; i < l1Size; ++i) (*l1Table)[i] = loadBe64(l1->data() + i * 8) & 0x00FFFFFFFFFFFE00ull;
    info.format = VdiskFormat::Qcow2;
    info.virtualSize = size;
    info.clusterSize = clusterSize;
    struct L2Cache {
        std::uint64_t offset = ~0ull;
        std::vector<std::uint64_t> entries;
    };
    auto l2Cache = std::make_shared<L2Cache>();
    auto loadL2 = [file, l2Cache, l2Entries](std::uint64_t off) -> Expected<const std::vector<std::uint64_t>*> {
        if (l2Cache->offset != off) {
            auto raw = readExact(*file, off, l2Entries * 8);
            if (!raw) return fail(raw.error());
            l2Cache->entries.resize(l2Entries);
            for (std::uint64_t i = 0; i < l2Entries; ++i) l2Cache->entries[i] = loadBe64(raw->data() + i * 8);
            l2Cache->offset = off;
        }
        return &l2Cache->entries;
    };
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t cluster = guest >> clusterBits, inCluster = guest & (clusterSize - 1);
        m.length = clusterSize - inCluster;
        m.unitStart = cluster << clusterBits;
        const std::uint64_t l1Index = cluster >> l2Bits, l2Index = cluster & (l2Entries - 1);
        if (l1Index >= l1Table->size() || (*l1Table)[l1Index] == 0) return m;   // unallocated L2: zeros
        auto l2 = loadL2((*l1Table)[l1Index]);
        if (!l2) return fail(l2.error());
        const std::uint64_t e = (**l2)[l2Index];
        if (e & (1ull << 62)) {
            m.kind = MappedDevice::Kind::Compressed;
            m.unit = (std::uint64_t{l1Index} << 32) | l2Index;   // decoder re-derives the entry from the tables
            return m;
        }
        const std::uint64_t host = e & 0x00FFFFFFFFFFFE00ull;
        if (host == 0 || (e & 1)) return m;   // unallocated or explicit zero cluster
        m.kind = MappedDevice::Kind::File;
        m.fileOffset = host + inCluster;
        return m;
    };
    auto decompress = [=](std::uint64_t unit, std::span<std::byte> out) -> Expected<void> {
        const std::uint64_t l1Index = unit >> 32, l2Index = unit & 0xFFFFFFFFu;
        auto l2 = loadL2((*l1Table)[l1Index]);
        if (!l2) return fail(l2.error());
        const std::uint64_t e = (**l2)[l2Index];
        const unsigned x = 62 - (clusterBits - 8);
        const std::uint64_t host = e & ((1ull << x) - 1);
        const std::uint64_t sectors = ((e >> x) & ((1ull << (clusterBits - 8)) - 1)) + 1;
        const std::uint64_t compressedLen = sectors * 512 - (host & 511);
        auto comp = readExact(*file, host, compressedLen);
        if (!comp) return fail(comp.error());
        auto n = compressionType == 1 ? compress::zstdDecompressFrame(*comp, out) : compress::inflateRaw(*comp, out);
        if (!n) return fail(n.error());
        // Short output is legal (the rest of the cluster is zero); longer input is clamped by the sector count.
        return {};
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + " (qcow2)", size, clusterSize, mapper, decompress);
    (void)l2Bits;
    return std::shared_ptr<BlockDevice>(dev);
}

// ----------------------------------------------------------------------------- VHD

Expected<std::shared_ptr<BlockDevice>> openVhd(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    const ByteCount fsize = file->size();
    if (fsize < 512) return fail(ErrorCategory::InvalidFormat, "file too small for a VHD footer");
    auto footer = readExact(*file, fsize - 512, 512);
    if (!footer) return fail(footer.error());
    if (std::memcmp(footer->data(), "conectix", 8) != 0) {
        // Some writers emit a 511-byte footer; try one byte earlier.
        footer = readExact(*file, fsize - 511, 511);
        if (!footer || std::memcmp(footer->data(), "conectix", 8) != 0) return fail(ErrorCategory::InvalidFormat, "no VHD footer");
    }
    const std::byte* f = footer->data();
    const std::uint64_t dataOffset = loadBe64(f + 16), currentSize = loadBe64(f + 48);
    const std::uint32_t diskType = loadBe32(f + 60);
    info.format = VdiskFormat::Vhd;
    info.virtualSize = currentSize;
    if (diskType == 2) {
        info.variant = "fixed";
        if (currentSize + 512 > fsize) return fail(ErrorCategory::InvalidFormat, "fixed VHD shorter than its declared size");
        auto slice = SliceDevice::create(file, Region{0, currentSize}, path.filename().string() + " (vhd fixed)");
        if (!slice) return fail(slice.error());
        return std::shared_ptr<BlockDevice>(*slice);
    }
    if (diskType == 4) return fail(ErrorCategory::Unsupported, "differencing VHDs (with a parent) are not supported yet");
    if (diskType != 3) return fail(ErrorCategory::Unsupported, "VHD disk type " + std::to_string(diskType));
    auto dyn = readExact(*file, dataOffset, 1024);
    if (!dyn) return fail(dyn.error());
    if (std::memcmp(dyn->data(), "cxsparse", 8) != 0) return fail(ErrorCategory::InvalidFormat, "no VHD dynamic header");
    const std::uint64_t tableOffset = loadBe64(dyn->data() + 16);
    const std::uint32_t maxEntries = loadBe32(dyn->data() + 28), blockSize = loadBe32(dyn->data() + 32);
    if (blockSize < 512 || (blockSize & 511)) return fail(ErrorCategory::InvalidFormat, "bad VHD block size");
    auto batRaw = readExact(*file, tableOffset, ByteCount{maxEntries} * 4);
    if (!batRaw) return fail(batRaw.error());
    auto bat = std::make_shared<std::vector<std::uint32_t>>(maxEntries);
    for (std::uint32_t i = 0; i < maxEntries; ++i) (*bat)[i] = loadBe32(batRaw->data() + i * 4);
    const std::uint32_t bitmapBytes = ((blockSize / 512 + 7) / 8 + 511) / 512 * 512;
    info.variant = "dynamic";
    info.clusterSize = blockSize;
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t block = guest / blockSize, inBlock = guest % blockSize;
        m.length = blockSize - inBlock;
        if (block >= bat->size() || (*bat)[block] == 0xFFFFFFFFu) return m;
        m.kind = MappedDevice::Kind::File;
        m.fileOffset = ByteCount{(*bat)[block]} * 512 + bitmapBytes + inBlock;
        return m;
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + " (vhd dynamic)", currentSize, blockSize, mapper, nullptr);
    return std::shared_ptr<BlockDevice>(dev);
}

// ----------------------------------------------------------------------------- VHDX

Expected<std::shared_ptr<BlockDevice>> openVhdx(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    // Pick the header copy with the valid checksum and the higher sequence number.
    std::uint64_t bestSeq = 0;
    std::vector<std::byte> best;
    for (ByteCount off : {ByteCount{64 * KiB}, ByteCount{128 * KiB}}) {
        auto h = readExact(*file, off, 4096);
        if (!h || std::memcmp(h->data(), "head", 4) != 0) continue;
        std::vector<std::byte> copy = *h;
        const std::uint32_t stored = loadLe32(copy.data() + 4);
        std::memset(copy.data() + 4, 0, 4);
        if (Crc32c::compute(copy) != stored) continue;
        const std::uint64_t seq = loadLe64(h->data() + 8);
        if (best.empty() || seq > bestSeq) {
            bestSeq = seq;
            best = *h;
        }
    }
    if (best.empty()) return fail(ErrorCategory::InvalidFormat, "no valid VHDX header");
    bool logGuidZero = true;
    for (int i = 0; i < 16; ++i) logGuidZero = logGuidZero && best[40 + i] == std::byte{0};
    if (!logGuidZero) {
        // A LogGuid is set while a writer has the image open; the log only matters when it
        // holds entries tagged with that GUID. qemu leaves the GUID behind with an empty log.
        const std::uint32_t logLength = loadLe32(best.data() + 60);
        const std::uint64_t logOffset = loadLe64(best.data() + 64);
        if (logLength && logOffset + logLength <= file->size()) {
            auto log = readExact(*file, logOffset, std::min<ByteCount>(logLength, 16 * MiB));
            if (!log) return fail(log.error());
            for (std::size_t off = 0; off + 64 <= log->size(); off += 4096)
                if (std::memcmp(log->data() + off, "loge", 4) == 0 && std::memcmp(log->data() + off + 44, best.data() + 40, 16) == 0)
                    return fail(ErrorCategory::Unsupported, "VHDX has an unreplayed log (was not cleanly closed); replay it with its native tool first");
        }
        info.notes.push_back("log GUID set but the log is empty (writer did not clear it)");
    }
    // Region table: BAT and metadata regions.
    auto region = readExact(*file, 192 * KiB, 64 * KiB);
    if (!region || std::memcmp(region->data(), "regi", 4) != 0) return fail(ErrorCategory::InvalidFormat, "no VHDX region table");
    const std::uint32_t entryCount = loadLe32(region->data() + 8);
    if (entryCount > 2047) return fail(ErrorCategory::InvalidFormat, "VHDX region table overfull");
    const auto batGuid = msGuid("2DC27766-F623-4200-9D64-115E9BFD4A08"), metaGuid = msGuid("8B7CA206-4790-4B9A-B8FE-575F050F886E");
    std::uint64_t batOffset = 0, metaOffset = 0;
    std::uint32_t batLength = 0, metaLength = 0;
    for (std::uint32_t i = 0; i < entryCount; ++i) {
        const std::byte* e = region->data() + 16 + i * 32;
        if (guidAt(e, batGuid)) {
            batOffset = loadLe64(e + 16);
            batLength = loadLe32(e + 24);
        } else if (guidAt(e, metaGuid)) {
            metaOffset = loadLe64(e + 16);
            metaLength = loadLe32(e + 24);
        } else if (loadLe32(e + 28) & 1) {
            return fail(ErrorCategory::Unsupported, "VHDX has an unknown required region");
        }
    }
    if (!batOffset || !metaOffset) return fail(ErrorCategory::InvalidFormat, "VHDX lacks the BAT or metadata region");
    auto meta = readExact(*file, metaOffset, std::min<ByteCount>(metaLength, 1 * MiB));
    if (!meta || std::memcmp(meta->data(), "metadata", 8) != 0) return fail(ErrorCategory::InvalidFormat, "no VHDX metadata table");
    const std::uint16_t metaCount = loadLe16(meta->data() + 10);
    const auto fileParams = msGuid("CAA16737-FA36-4D43-B3B6-33F0AA44E76B"), vsize = msGuid("2FA54224-CD1B-4876-B211-5DBED83BF4B8"),
               lsector = msGuid("8141BF1D-A96F-4709-BA47-F233A8FAAB5F"), parentLocator = msGuid("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C");
    std::uint32_t blockSize = 0, logicalSector = 512;
    std::uint64_t virtualSize = 0;
    bool hasParent = false;
    for (std::size_t i = 0; i < metaCount && 32 + (i + 1) * 32 <= meta->size(); ++i) {
        const std::byte* e = meta->data() + 32 + i * 32;
        const std::uint32_t off = loadLe32(e + 16), len = loadLe32(e + 20);
        if (ByteCount{off} + len > meta->size()) continue;
        const std::byte* item = meta->data() + off;
        if (guidAt(e, fileParams) && len >= 8) {
            blockSize = loadLe32(item);
            hasParent = (loadLe32(item + 4) & 2) != 0;
        } else if (guidAt(e, vsize) && len >= 8) virtualSize = loadLe64(item);
        else if (guidAt(e, lsector) && len >= 4) logicalSector = loadLe32(item);
        else if (guidAt(e, parentLocator)) hasParent = true;
    }
    if (hasParent) return fail(ErrorCategory::Unsupported, "differencing VHDX (with a parent) is not supported yet");
    if (blockSize < 1 * MiB || (blockSize & (blockSize - 1)) || virtualSize == 0) return fail(ErrorCategory::InvalidFormat, "VHDX metadata lacks sane block or disk size");
    const std::uint64_t chunkRatio = (std::uint64_t{1} << 23) * logicalSector / blockSize;
    const std::uint64_t dataBlocks = (virtualSize + blockSize - 1) / blockSize;
    const std::uint64_t batEntries = dataBlocks + (dataBlocks + chunkRatio - 1) / chunkRatio;
    if (ByteCount{batEntries} * 8 > batLength) return fail(ErrorCategory::InvalidFormat, "VHDX BAT region smaller than the disk needs");
    auto batRaw = readExact(*file, batOffset, batEntries * 8);
    if (!batRaw) return fail(batRaw.error());
    auto bat = std::make_shared<std::vector<std::uint64_t>>(batEntries);
    for (std::uint64_t i = 0; i < batEntries; ++i) (*bat)[i] = loadLe64(batRaw->data() + i * 8);
    info.format = VdiskFormat::Vhdx;
    info.virtualSize = virtualSize;
    info.clusterSize = blockSize;
    info.variant = "dynamic";
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t block = guest / blockSize, inBlock = guest % blockSize;
        m.length = blockSize - inBlock;
        const std::uint64_t idx = block + block / chunkRatio;
        if (idx >= bat->size()) return m;
        const std::uint64_t e = (*bat)[idx];
        const std::uint32_t state = static_cast<std::uint32_t>(e & 7);
        if (state == 6) {
            m.kind = MappedDevice::Kind::File;
            m.fileOffset = ((e >> 20) << 20) + inBlock;
        } else if (state == 7) {
            return fail(ErrorCategory::Unsupported, "partially present VHDX block (differencing data)");
        }
        return m;   // not present / undefined / zero / unmapped
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + " (vhdx)", virtualSize, blockSize, mapper, nullptr);
    return std::shared_ptr<BlockDevice>(dev);
}

// ----------------------------------------------------------------------------- VMDK

Expected<std::shared_ptr<BlockDevice>> openVmdkSparse(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info, std::uint64_t* capacitySectors) {
    auto h = readExact(*file, 0, 512);
    if (!h) return fail(h.error());
    if (std::memcmp(h->data(), "KDMV", 4) != 0) return fail(ErrorCategory::InvalidFormat, "no VMDK sparse extent header");
    std::vector<std::byte> hdr = *h;
    std::uint64_t gdOffset = loadLe64(hdr.data() + 56);
    if (gdOffset == ~0ull) {
        // Stream-optimized: the real header (footer) sits 1024 bytes before the end, after the data.
        auto foot = readExact(*file, file->size() - 1024, 512);
        if (!foot || std::memcmp(foot->data(), "KDMV", 4) != 0) return fail(ErrorCategory::InvalidFormat, "stream-optimized VMDK without a footer");
        hdr = *foot;
        gdOffset = loadLe64(hdr.data() + 56);
    }
    const std::byte* d = hdr.data();
    const std::uint32_t flags = loadLe32(d + 8);
    const std::uint64_t capacity = loadLe64(d + 12), grainSize = loadLe64(d + 20);
    const std::uint32_t gtesPerGt = loadLe32(d + 44);
    const std::uint16_t compressAlgorithm = loadLe16(d + 77);
    if (grainSize == 0 || grainSize > (1u << 16) || gtesPerGt == 0) return fail(ErrorCategory::InvalidFormat, "bad VMDK grain geometry");
    const bool compressed = (flags & (1u << 16)) != 0;
    if (compressed && compressAlgorithm != 1) return fail(ErrorCategory::Unsupported, "VMDK compression algorithm " + std::to_string(compressAlgorithm));
    const std::uint64_t grainBytes = grainSize * 512;
    const std::uint64_t gtCount = (capacity + grainSize * gtesPerGt - 1) / (grainSize * gtesPerGt);
    auto gdRaw = readExact(*file, gdOffset * 512, gtCount * 4);
    if (!gdRaw) return fail(gdRaw.error());
    auto gts = std::make_shared<std::vector<std::vector<std::uint32_t>>>(gtCount);
    for (std::uint64_t i = 0; i < gtCount; ++i) {
        const std::uint32_t gtSector = loadLe32(gdRaw->data() + i * 4);
        if (gtSector == 0) continue;
        auto gt = readExact(*file, ByteCount{gtSector} * 512, ByteCount{gtesPerGt} * 4);
        if (!gt) return fail(gt.error());
        (*gts)[i].resize(gtesPerGt);
        for (std::uint32_t j = 0; j < gtesPerGt; ++j) (*gts)[i][j] = loadLe32(gt->data() + j * 4);
    }
    if (capacitySectors) *capacitySectors = capacity;
    info.compressed = info.compressed || compressed;
    info.clusterSize = static_cast<std::uint32_t>(grainBytes);
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t grain = guest / grainBytes, inGrain = guest % grainBytes;
        m.length = grainBytes - inGrain;
        m.unitStart = grain * grainBytes;
        const std::uint64_t gt = grain / gtesPerGt, gte = grain % gtesPerGt;
        if (gt >= gts->size() || (*gts)[gt].empty()) return m;
        const std::uint32_t sector = (*gts)[gt][gte];
        if (sector <= 1) return m;   // 0 = unallocated, 1 = zero grain
        if (compressed) {
            m.kind = MappedDevice::Kind::Compressed;
            m.unit = grain;
            return m;
        }
        m.kind = MappedDevice::Kind::File;
        m.fileOffset = ByteCount{sector} * 512 + inGrain;
        return m;
    };
    auto decompress = [=](std::uint64_t grain, std::span<std::byte> out) -> Expected<void> {
        const std::uint32_t sector = (*gts)[grain / gtesPerGt][grain % gtesPerGt];
        auto marker = readExact(*file, ByteCount{sector} * 512, 12);
        if (!marker) return fail(marker.error());
        const std::uint32_t compressedSize = loadLe32(marker->data() + 8);
        if (compressedSize == 0 || compressedSize > 16 * MiB) return fail(ErrorCategory::InvalidFormat, "bad VMDK grain marker");
        auto comp = readExact(*file, ByteCount{sector} * 512 + 12, compressedSize);
        if (!comp) return fail(comp.error());
        auto n = compress::inflateZlib(*comp, out);
        if (!n) return fail(n.error());
        return {};
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + (compressed ? " (vmdk stream-optimized)" : " (vmdk sparse)"), capacity * 512, static_cast<std::uint32_t>(grainBytes), mapper, decompress);
    return std::shared_ptr<BlockDevice>(dev);
}

Expected<std::shared_ptr<BlockDevice>> openVmdk(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    info.format = VdiskFormat::Vmdk;
    auto head = readExact(*file, 0, std::min<ByteCount>(file->size(), 512));
    if (!head) return fail(head.error());
    std::string descriptor;
    if (std::memcmp(head->data(), "KDMV", 4) == 0) {
        // The embedded descriptor tells the create type and whether a parent exists.
        const std::uint64_t descOffset = loadLe64(head->data() + 28), descSize = loadLe64(head->data() + 36);
        if (descOffset && descSize && descSize < 2048)   // both in sectors
            if (auto desc = readExact(*file, descOffset * 512, descSize * 512)) descriptor.assign(reinterpret_cast<const char*>(desc->data()), desc->size());
        descriptor.erase(std::find(descriptor.begin(), descriptor.end(), '\0'), descriptor.end());
        for (const auto& line : split(descriptor, '\n')) {
            const std::string l = std::string(trim(line));
            if (l.rfind("createType", 0) == 0) info.variant = l.substr(l.find('"') + 1, l.rfind('"') - l.find('"') - 1);
            if (l.rfind("parentCID", 0) == 0 && l.find("ffffffff") == std::string::npos) return fail(ErrorCategory::Unsupported, "VMDK with a parent (snapshot chain) is not supported yet");
        }
        std::uint64_t capacity = 0;
        auto dev = openVmdkSparse(file, path, info, &capacity);
        if (!dev) return dev;
        info.virtualSize = capacity * 512;
        return dev;
    }
    // Plain-text descriptor: extents live in other files next to it.
    descriptor.assign(reinterpret_cast<const char*>(head->data()), head->size());
    if (descriptor.find("# Disk DescriptorFile") == std::string::npos) return fail(ErrorCategory::InvalidFormat, "not a VMDK descriptor");
    auto whole = readExact(*file, 0, file->size());
    if (!whole) return fail(whole.error());
    descriptor.assign(reinterpret_cast<const char*>(whole->data()), whole->size());
    std::vector<BlockDevicePtr> parts;
    for (const auto& rawLine : split(descriptor, '\n')) {
        const std::string line = std::string(trim(rawLine));
        if (line.rfind("createType", 0) == 0) info.variant = line.substr(line.find('"') + 1, line.rfind('"') - line.find('"') - 1);
        if (line.rfind("parentCID", 0) == 0 && line.find("ffffffff") == std::string::npos) return fail(ErrorCategory::Unsupported, "VMDK with a parent (snapshot chain) is not supported yet");
        if (line.rfind("RW ", 0) != 0 && line.rfind("RDONLY ", 0) != 0 && line.rfind("NOACCESS ", 0) != 0) continue;
        // ACCESS SIZE TYPE "FILENAME" [OFFSET]
        auto fields = split(line, ' ');
        if (fields.size() < 3) continue;
        const std::uint64_t sectors = std::stoull(std::string(fields[1]));
        const std::string type(fields[2]);
        if (type == "ZERO") {
            parts.push_back(std::make_shared<ZeroDevice>(sectors * 512));
            continue;
        }
        const auto q1 = line.find('"'), q2 = line.rfind('"');
        if (q1 == std::string::npos || q2 <= q1) return fail(ErrorCategory::InvalidFormat, "VMDK extent line without a file name");
        const std::filesystem::path extentPath = path.parent_path() / line.substr(q1 + 1, q2 - q1 - 1);
        info.files.push_back(extentPath);
        auto ef = FileDevice::open(extentPath, FileDevice::Mode::ReadOnly);
        if (!ef) return fail(ef.error());
        if (type == "SPARSE") {
            VdiskInfo sub;
            std::uint64_t cap = 0;
            auto s = openVmdkSparse(*ef, extentPath, sub, &cap);
            if (!s) return s;
            info.compressed = info.compressed || sub.compressed;
            info.clusterSize = sub.clusterSize;
            parts.push_back(*s);
        } else if (type == "FLAT" || type == "VMFS") {
            std::uint64_t offsetSectors = 0;
            if (fields.size() >= 5) offsetSectors = std::stoull(std::string(fields.back()));
            auto slice = SliceDevice::create(*ef, Region{offsetSectors * 512, sectors * 512}, extentPath.filename().string() + " (flat)");
            if (!slice) return fail(slice.error());
            parts.push_back(*slice);
        } else {
            return fail(ErrorCategory::Unsupported, "VMDK extent type " + type);
        }
    }
    if (parts.empty()) return fail(ErrorCategory::InvalidFormat, "VMDK descriptor lists no extents");
    auto cat = ConcatDevice::create(std::move(parts), path.filename().string() + " (vmdk)");
    if (!cat) return fail(cat.error());
    info.virtualSize = (*cat)->size();
    return std::shared_ptr<BlockDevice>(*cat);
}

// ----------------------------------------------------------------------------- VDI

Expected<std::shared_ptr<BlockDevice>> openVdi(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    auto h = readExact(*file, 0, 512);
    if (!h) return fail(h.error());
    const std::byte* d = h->data();
    if (loadLe32(d + 64) != 0xBEDA107Fu) return fail(ErrorCategory::InvalidFormat, "no VDI signature");
    const std::uint32_t imageType = loadLe32(d + 76), offsetBlocks = loadLe32(d + 340), offsetData = loadLe32(d + 344);
    const std::uint64_t diskSize = loadLe64(d + 368);
    const std::uint32_t blockSize = loadLe32(d + 376), blockExtra = loadLe32(d + 380), blocksInImage = loadLe32(d + 384);
    if (imageType != 1 && imageType != 2) return fail(ErrorCategory::Unsupported, "VDI image type " + std::to_string(imageType) + " (undo/differencing)");
    if (blockSize < 512 || (blockSize & (blockSize - 1))) return fail(ErrorCategory::InvalidFormat, "bad VDI block size");
    auto mapRaw = readExact(*file, offsetBlocks, ByteCount{blocksInImage} * 4);
    if (!mapRaw) return fail(mapRaw.error());
    auto map = std::make_shared<std::vector<std::uint32_t>>(blocksInImage);
    for (std::uint32_t i = 0; i < blocksInImage; ++i) (*map)[i] = loadLe32(mapRaw->data() + i * 4);
    info.format = VdiskFormat::Vdi;
    info.virtualSize = diskSize;
    info.clusterSize = blockSize;
    info.variant = imageType == 1 ? "dynamic" : "fixed";
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t block = guest / blockSize, inBlock = guest % blockSize;
        m.length = blockSize - inBlock;
        if (block >= map->size()) return m;
        const std::uint32_t e = (*map)[block];
        if (e == 0xFFFFFFFFu || e == 0xFFFFFFFEu) return m;   // free / zero
        m.kind = MappedDevice::Kind::File;
        m.fileOffset = ByteCount{offsetData} + ByteCount{e} * (ByteCount{blockSize} + blockExtra) + blockExtra + inBlock;
        return m;
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + " (vdi)", diskSize, blockSize, mapper, nullptr);
    return std::shared_ptr<BlockDevice>(dev);
}


// ----------------------------------------------------------------------------- EWF / E01

// Segment file names: .E01 .. .E99, then .EAA .. .EZZ, .FAA ... (libewf's scheme).
std::string nextEwfExtension(const std::string& ext) {
    if (ext.size() != 3) return {};
    std::string n = ext;
    if (std::isdigit(static_cast<unsigned char>(n[1])) && std::isdigit(static_cast<unsigned char>(n[2]))) {
        const int v = (n[1] - '0') * 10 + (n[2] - '0');
        if (v < 99) {
            n[1] = static_cast<char>('0' + (v + 1) / 10);
            n[2] = static_cast<char>('0' + (v + 1) % 10);
            return n;
        }
        n[1] = n[2] = 'A';
        return n;
    }
    for (int i = 2; i >= 0; --i) {
        if (n[i] < 'Z') {
            ++n[i];
            return n;
        }
        n[i] = 'A';
    }
    return {};
}

Expected<std::shared_ptr<BlockDevice>> openEwf(const std::filesystem::path& path, VdiskInfo& info) {
    struct Chunk {
        std::size_t file;
        ByteCount offset;
        std::uint32_t size;
        bool compressed;
    };
    std::vector<std::shared_ptr<BlockDevice>> files;
    std::vector<Chunk> chunks;
    std::uint32_t sectorsPerChunk = 0, bytesPerSector = 0;
    std::uint64_t sectorCount = 0, declaredChunks = 0;
    std::string md5, sha1;
    bool done = false;
    std::filesystem::path current = path;
    std::string ext = path.extension().string();
    if (ext.size() == 4 && ext[0] == '.') ext = ext.substr(1);
    if (ext.size() != 3) return fail(ErrorCategory::InvalidFormat, "EWF segment needs a .E01-style extension");
    for (int segment = 1; !done && segment < 100000; ++segment) {
        auto f = FileDevice::open(current, FileDevice::Mode::ReadOnly);
        if (!f) return fail(ErrorCategory::NotFound, "EWF segment " + current.string() + " is missing: " + f.error().message());
        files.push_back(*f);
        info.files.push_back(current);
        const std::size_t fileIndex = files.size() - 1;
        auto head = readExact(**f, 0, 13);
        if (!head || std::memcmp(head->data(), "EVF\x09\x0d\x0a\xff\x00", 8) != 0) return fail(ErrorCategory::InvalidFormat, current.string() + ": not an EWF segment");
        if (loadLe16(head->data() + 9) != static_cast<std::uint16_t>(segment)) return fail(ErrorCategory::InvalidFormat, current.string() + ": unexpected segment number");
        ByteCount off = 13;
        ByteCount sectorsStart = 0, sectorsEnd = 0;
        std::vector<Chunk> pending;   // entries of the last table, sized once the section bounds are known
        for (int guard = 0; guard < 100000; ++guard) {
            auto sh = readExact(**f, off, 76);
            if (!sh) return fail(sh.error());
            if (compress::adler32(std::span<const std::byte>(sh->data(), 72)) != loadLe32(sh->data() + 72)) return fail(ErrorCategory::Integrity, current.string() + ": section header checksum mismatch");
            std::string type(reinterpret_cast<const char*>(sh->data()), 16);
            type.erase(std::find(type.begin(), type.end(), '\0'), type.end());
            const std::uint64_t next = loadLe64(sh->data() + 16), size = loadLe64(sh->data() + 24);
            if (type == "volume" || type == "disk") {
                auto body = readExact(**f, off + 76, std::min<ByteCount>(size - 76, 1052));
                if (!body || body->size() < 24) return fail(ErrorCategory::InvalidFormat, "EWF volume section too small");
                declaredChunks = loadLe32(body->data() + 4);
                sectorsPerChunk = loadLe32(body->data() + 8);
                bytesPerSector = loadLe32(body->data() + 12);
                sectorCount = loadLe64(body->data() + 16);
                if (body->size() >= 1052) {
                    const auto level = std::to_integer<std::uint8_t>((*body)[52]);
                    if (level) info.compressed = true;
                }
            } else if (type == "sectors") {
                sectorsStart = off + 76;
                sectorsEnd = off + size;
            } else if (type == "table") {
                auto body = readExact(**f, off + 76, size - 76);
                if (!body || body->size() < 24) return fail(ErrorCategory::InvalidFormat, "EWF table section too small");
                const std::uint32_t entries = loadLe32(body->data());
                const std::uint64_t base = loadLe64(body->data() + 8);
                if (compress::adler32(std::span<const std::byte>(body->data(), 20)) != loadLe32(body->data() + 20)) return fail(ErrorCategory::Integrity, "EWF table header checksum mismatch");
                if (24 + std::size_t{entries} * 4 > body->size()) return fail(ErrorCategory::InvalidFormat, "EWF table entries overrun the section");
                std::vector<Chunk> these;
                these.reserve(entries);
                for (std::uint32_t i = 0; i < entries; ++i) {
                    const std::uint32_t e = loadLe32(body->data() + 24 + i * 4);
                    these.push_back(Chunk{fileIndex, base + (e & 0x7FFFFFFFu), 0, (e & 0x80000000u) != 0});
                }
                for (std::size_t i = 0; i < these.size(); ++i) {
                    const ByteCount end = i + 1 < these.size() ? these[i + 1].offset : sectorsEnd;
                    if (end < these[i].offset || these[i].offset < sectorsStart) return fail(ErrorCategory::InvalidFormat, "EWF chunk offsets are not monotonic within their sectors section");
                    these[i].size = static_cast<std::uint32_t>(end - these[i].offset);
                }
                chunks.insert(chunks.end(), these.begin(), these.end());
            } else if (type == "hash") {
                auto body = readExact(**f, off + 76, 16);
                if (body) md5 = Hasher::hex(std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body->data()), reinterpret_cast<const std::uint8_t*>(body->data()) + 16));
            } else if (type == "digest") {
                auto body = readExact(**f, off + 76, 36);
                if (body) {
                    md5 = Hasher::hex(std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body->data()), reinterpret_cast<const std::uint8_t*>(body->data()) + 16));
                    sha1 = Hasher::hex(std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body->data()) + 16, reinterpret_cast<const std::uint8_t*>(body->data()) + 36));
                }
            } else if (type == "done") {
                done = true;
                break;
            } else if (type == "next") {
                break;
            }
            // "table2" mirrors "table"; header/header2/data/error2/session carry nothing we map.
            if (next <= off || next > (*f)->size()) return fail(ErrorCategory::InvalidFormat, current.string() + ": broken section chain");
            off = next;
        }
        if (!done) {
            ext = nextEwfExtension(ext);
            if (ext.empty()) return fail(ErrorCategory::InvalidFormat, "ran out of EWF segment names");
            current = current.parent_path() / (current.stem().string() + "." + ext);
        }
    }
    if (sectorsPerChunk == 0 || bytesPerSector == 0 || sectorCount == 0) return fail(ErrorCategory::InvalidFormat, "EWF image has no volume section");
    if (chunks.size() < declaredChunks) return fail(ErrorCategory::InvalidFormat, "EWF image is missing chunks (" + std::to_string(chunks.size()) + " of " + std::to_string(declaredChunks) + ")");
    const std::uint32_t chunkBytes = sectorsPerChunk * bytesPerSector;
    const ByteCount mediaSize = sectorCount * bytesPerSector;
    info.format = VdiskFormat::Ewf;
    info.virtualSize = mediaSize;
    info.clusterSize = chunkBytes;
    info.variant = "EnCase/EWF v1, " + std::to_string(files.size()) + " segment(s)";
    info.storedMd5 = md5;
    info.storedSha1 = sha1;
    auto table = std::make_shared<std::vector<Chunk>>(std::move(chunks));
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t index = guest / chunkBytes, in = guest % chunkBytes;
        m.length = chunkBytes - in;
        m.unitStart = index * chunkBytes;
        if (index >= table->size()) return m;
        m.kind = MappedDevice::Kind::Compressed;   // uncompressed chunks go through the same path for their checksum
        m.unit = index;
        return m;
    };
    auto filesCopy = files;
    auto decompress = [=](std::uint64_t index, std::span<std::byte> out) -> Expected<void> {
        const Chunk& c = (*table)[index];
        auto raw = readExact(*filesCopy[c.file], c.offset, c.size);
        if (!raw) return fail(raw.error());
        if (c.compressed) {
            auto n = compress::inflateZlib(*raw, out);
            if (!n) return fail(n.error());
            return {};
        }
        if (raw->size() < 4) return fail(ErrorCategory::InvalidFormat, "EWF chunk too small");
        const std::size_t data = raw->size() - 4;
        if (data > out.size()) return fail(ErrorCategory::InvalidFormat, "EWF chunk larger than the chunk size");
        if (compress::adler32(std::span<const std::byte>(raw->data(), data)) != loadLe32(raw->data() + data)) return fail(ErrorCategory::Integrity, "EWF chunk checksum mismatch");
        std::memcpy(out.data(), raw->data(), data);
        return {};
    };
    auto dev = std::make_shared<MappedDevice>(files[0], path.filename().string() + " (ewf)", mediaSize, chunkBytes, mapper, decompress);
    dev->setFiles(files);
    return std::shared_ptr<BlockDevice>(dev);
}


// ----------------------------------------------------------------------------- DMG / UDIF

Expected<std::shared_ptr<BlockDevice>> openDmg(std::shared_ptr<BlockDevice> file, const std::filesystem::path& path, VdiskInfo& info) {
    const ByteCount fsize = file->size();
    if (fsize < 512) return fail(ErrorCategory::InvalidFormat, "file too small for a DMG trailer");
    auto koly = readExact(*file, fsize - 512, 512);
    if (!koly || std::memcmp(koly->data(), "koly", 4) != 0) return fail(ErrorCategory::InvalidFormat, "no DMG koly trailer");
    const std::byte* k = koly->data();
    const std::uint64_t dataForkOffset = loadBe64(k + 24), xmlOffset = loadBe64(k + 216), xmlLength = loadBe64(k + 224);
    const std::uint64_t sectorCount = loadBe64(k + 492);
    const std::uint32_t segmentCount = loadBe32(k + 60);
    if (segmentCount > 1) return fail(ErrorCategory::Unsupported, "segmented DMG sets are not supported yet");
    if (xmlLength == 0 || xmlLength > 64 * MiB || xmlOffset + xmlLength > fsize) return fail(ErrorCategory::InvalidFormat, "DMG property list is missing (raw-attached or encrypted image?)");
    auto xmlRaw = readExact(*file, xmlOffset, xmlLength);
    if (!xmlRaw) return fail(xmlRaw.error());
    const std::string xml(reinterpret_cast<const char*>(xmlRaw->data()), xmlRaw->size());
    struct Chunk {
        std::uint32_t type;
        std::uint64_t sector, sectors, offset, length;
    };
    std::vector<Chunk> chunks;
    // Every <data> element that decodes to a "mish" block is a blkx entry; nothing else in the
    // plist is needed to read the image.
    std::size_t pos = 0;
    while ((pos = xml.find("<data>", pos)) != std::string::npos) {
        const std::size_t end = xml.find("</data>", pos);
        if (end == std::string::npos) break;
        std::string b64 = xml.substr(pos + 6, end - pos - 6);
        b64.erase(std::remove_if(b64.begin(), b64.end(), [](char c) { return c == '\n' || c == '\r' || c == '\t' || c == ' '; }), b64.end());
        pos = end + 7;
        auto bytes = fromBase64(b64);
        if (!bytes || bytes->size() < 204 || std::memcmp(bytes->data(), "mish", 4) != 0) continue;
        const std::byte* m = bytes->data();
        const std::uint64_t firstSector = loadBe64(m + 8), dataOffset = loadBe64(m + 24);
        const std::uint32_t count = loadBe32(m + 200);
        if (204 + std::size_t{count} * 40 > bytes->size()) return fail(ErrorCategory::InvalidFormat, "DMG blkx chunk table truncated");
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::byte* c = m + 204 + i * 40;
            Chunk ch{loadBe32(c), firstSector + loadBe64(c + 8), loadBe64(c + 16), dataForkOffset + dataOffset + loadBe64(c + 24), loadBe64(c + 32)};
            if (ch.type == 0xFFFFFFFFu || ch.type == 0x7FFFFFFEu || ch.sectors == 0) continue;   // terminator / comment
            chunks.push_back(ch);
        }
    }
    if (chunks.empty()) return fail(ErrorCategory::InvalidFormat, "DMG has no blkx chunks");
    std::sort(chunks.begin(), chunks.end(), [](const Chunk& a, const Chunk& b) { return a.sector < b.sector; });
    std::uint64_t maxChunkBytes = 0;
    bool compressed = false;
    for (const auto& c : chunks) {
        maxChunkBytes = std::max(maxChunkBytes, c.sectors * 512);
        compressed = compressed || (c.type & 0x80000000u) != 0;
    }
    if (maxChunkBytes > 256 * MiB) return fail(ErrorCategory::Unsupported, "DMG chunk larger than 256 MiB");
    info.format = VdiskFormat::Dmg;
    info.virtualSize = sectorCount * 512;
    info.clusterSize = static_cast<std::uint32_t>(std::min<std::uint64_t>(maxChunkBytes, 0xFFFFFFFFu));
    info.compressed = compressed;
    info.variant = compressed ? "compressed (UDZO/UDBZ/UDCO)" : "read-only raw (UDRO)";
    auto table = std::make_shared<std::vector<Chunk>>(std::move(chunks));
    auto mapper = [=](ByteCount guest) -> Expected<MappedDevice::Map> {
        MappedDevice::Map m;
        const std::uint64_t sector = guest / 512;
        // Binary search the chunk holding this sector.
        std::size_t lo = 0, hi = table->size();
        while (lo < hi) {
            const std::size_t mid = (lo + hi) / 2;
            if ((*table)[mid].sector + (*table)[mid].sectors <= sector) lo = mid + 1;
            else hi = mid;
        }
        if (lo >= table->size() || (*table)[lo].sector > sector) {
            m.length = lo < table->size() ? (*table)[lo].sector * 512 - guest : 512;   // gap: zeros up to the next chunk
            return m;
        }
        const Chunk& c = (*table)[lo];
        const std::uint64_t in = guest - c.sector * 512;
        m.length = c.sectors * 512 - in;
        m.unitStart = c.sector * 512;
        switch (c.type) {
        case 0x00000000: case 0x00000002: return m;   // zero fill / ignored
        case 0x00000001:
            m.kind = MappedDevice::Kind::File;
            m.fileOffset = c.offset + in;
            return m;
        case 0x80000004: case 0x80000005: case 0x80000006: case 0x80000008:
            m.kind = MappedDevice::Kind::Compressed;
            m.unit = lo;
            return m;
        case 0x80000007: return fail(ErrorCategory::Unsupported, "lzfse-compressed DMG block (ULFO) is not supported yet");
        default: return fail(ErrorCategory::Unsupported, "unknown DMG block type");
        }
    };
    auto decompress = [=](std::uint64_t index, std::span<std::byte> out) -> Expected<void> {
        const Chunk& c = (*table)[index];
        auto comp = readExact(*file, c.offset, c.length);
        if (!comp) return fail(comp.error());
        auto window = out.subspan(0, static_cast<std::size_t>(c.sectors * 512));
        Expected<std::size_t> n;
        switch (c.type) {
        case 0x80000005: n = compress::inflateZlib(*comp, window); break;
        case 0x80000006: n = compress::bunzip2(*comp, window); break;
        case 0x80000008:
            // ULMO blocks are xz streams from liblzma; accept a bare .lzma stream too.
            n = comp->size() >= 6 && std::memcmp(comp->data(), "\xFD" "7zXZ", 5) == 0 ? compress::xzDecompress(*comp, window) : compress::lzmaDecompress(*comp, window);
            break;
        default: n = compress::adcDecompress(*comp, window); break;
        }
        if (!n) return fail(n.error());
        return {};
    };
    auto dev = std::make_shared<MappedDevice>(file, path.filename().string() + " (dmg)", sectorCount * 512, static_cast<std::uint32_t>(maxChunkBytes), mapper, decompress);
    return std::shared_ptr<BlockDevice>(dev);
}

} // namespace

Expected<VdiskFormat> detectVdiskFormat(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) return fail(ErrorCategory::NotFound, "cannot stat " + path.string());
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail(ErrorCategory::Io, "cannot open " + path.string());
    std::array<char, 512> head{};
    in.read(head.data(), static_cast<std::streamsize>(std::min<std::uintmax_t>(512, size)));
    if (SteinReader::looksLikeStein(path)) return VdiskFormat::Stein;
    if (std::memcmp(head.data(), "QFI\xfb", 4) == 0) return VdiskFormat::Qcow2;
    if (std::memcmp(head.data(), "EVF\x09\x0d\x0a\xff\x00", 8) == 0) return VdiskFormat::Ewf;
    if (std::memcmp(head.data(), "vhdxfile", 8) == 0) return VdiskFormat::Vhdx;
    if (std::memcmp(head.data(), "KDMV", 4) == 0 || std::string_view(head.data(), head.size()).find("# Disk DescriptorFile") != std::string_view::npos) return VdiskFormat::Vmdk;
    if (size >= 512 && loadLe32(reinterpret_cast<const std::byte*>(head.data()) + 64) == 0xBEDA107Fu) return VdiskFormat::Vdi;
    if (std::memcmp(head.data(), "conectix", 8) == 0) return VdiskFormat::Vhd;
    if (size >= 512) {
        std::array<char, 8> tail{};
        in.seekg(static_cast<std::streamoff>(size - 512));
        in.read(tail.data(), 8);
        if (std::memcmp(tail.data(), "conectix", 8) == 0) return VdiskFormat::Vhd;
        if (std::memcmp(tail.data(), "koly", 4) == 0) return VdiskFormat::Dmg;
    }
    return VdiskFormat::Raw;
}

Expected<std::shared_ptr<BlockDevice>> openVdisk(const std::filesystem::path& path, VdiskInfo* infoOut) {
    auto format = detectVdiskFormat(path);
    if (!format) return fail(format.error());
    VdiskInfo info;
    info.format = *format;
    info.files.push_back(path);
    Expected<std::shared_ptr<BlockDevice>> dev = fail(ErrorCategory::Internal, "unreachable");
    if (*format == VdiskFormat::Raw) {
        auto f = FileDevice::open(path, FileDevice::Mode::ReadOnly);
        if (!f) return fail(f.error());
        dev = std::shared_ptr<BlockDevice>(*f);
        info.virtualSize = (*dev)->size();
    } else if (*format == VdiskFormat::Stein) {
        dev = openImage(path, {});
        if (dev) info.virtualSize = (*dev)->size();
    } else {
        if (*format == VdiskFormat::Ewf) {
            info.files.clear();
            dev = openEwf(path, info);
            if (!dev) return dev;
            if (infoOut) *infoOut = info;
            return dev;
        }
        auto file = FileDevice::open(path, FileDevice::Mode::ReadOnly);
        if (!file) return fail(file.error());
        switch (*format) {
        case VdiskFormat::Qcow2: dev = openQcow2(*file, path, info); break;
        case VdiskFormat::Vhd: dev = openVhd(*file, path, info); break;
        case VdiskFormat::Vhdx: dev = openVhdx(*file, path, info); break;
        case VdiskFormat::Vmdk: dev = openVmdk(*file, path, info); break;
        case VdiskFormat::Vdi: dev = openVdi(*file, path, info); break;
        case VdiskFormat::Dmg: dev = openDmg(*file, path, info); break;
        default: break;
        }
    }
    if (!dev) return dev;
    if (infoOut) *infoOut = info;
    return dev;
}

} // namespace stein::image
