// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/hfs.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

namespace {

// The UUID blkid/macOS derive from the 8-byte seed in finderInfo[6..7]: MD5 of a
// fixed namespace plus the seed, marked as a version-3 UUID.
std::string hfsUuidFromSeed(std::span<const std::byte> seed8) {
    static constexpr std::uint8_t ns[16] = {0xb3, 0xe2, 0x0f, 0x39, 0xf2, 0x92, 0x11, 0xd6,
                                            0x97, 0xa4, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac};
    bool allZero = true;
    for (auto b : seed8) allZero = allZero && b == std::byte{0};
    if (allZero) return {};
    Md5 md5;
    md5.update(std::as_bytes(std::span(ns)));
    md5.update(seed8);
    auto d = md5.finish();
    d[6] = static_cast<std::uint8_t>((d[6] & 0x0F) | 0x30);
    d[8] = static_cast<std::uint8_t>((d[8] & 0x3F) | 0x80);
    std::array<std::byte, 16> b{};
    for (int i = 0; i < 16; ++i) b[i] = std::byte(d[i]);
    return uuidText(b);
}

// UTF-16BE decode (HFS+ names).
std::string utf16beToUtf8(std::span<const std::byte> in) {
    std::vector<std::byte> le(in.size());
    for (std::size_t i = 0; i + 1 < in.size(); i += 2) {
        le[i] = in[i + 1];
        le[i + 1] = in[i];
    }
    return utf16leToUtf8(le, false);
}

// Find the root folder's name in the catalog B-tree: the leaf record whose key has parentID 1.
std::string hfsPlusLabel(BlockDevice& dev, ByteCount base, std::span<const std::byte> header, ByteCount blockSize) {
    // catalogFile HFSPlusForkData at 0x110: logicalSize u64, clumpSize u32, totalBlocks u32, extents[8]{start,count}
    constexpr std::size_t kCatalog = 0x110;
    if (header.size() < kCatalog + 80) return {};
    const std::uint32_t ext0Start = loadBe32(header.data() + kCatalog + 16);
    const std::uint32_t ext0Count = loadBe32(header.data() + kCatalog + 20);
    if (ext0Start == 0 || ext0Count == 0) return {};
    const ByteCount catOff = base + ByteCount{ext0Start} * blockSize;
    auto hdrNode = dev.read(catOff, 512);
    if (!hdrNode) return {};
    const std::uint16_t nodeSize = loadBe16(hdrNode->data() + 14 + 18);   // BTHeaderRec.nodeSize
    const std::uint32_t firstLeaf = loadBe32(hdrNode->data() + 14 + 10); // BTHeaderRec.firstLeafNode
    if (nodeSize < 512 || nodeSize > 32768 || firstLeaf == 0) return {};
    const ByteCount leafOff = catOff + ByteCount{firstLeaf} * nodeSize;
    if (leafOff + nodeSize > base + ByteCount{ext0Start + ext0Count} * blockSize) return {};   // outside first extent
    auto leaf = dev.read(leafOff, nodeSize);
    if (!leaf) return {};
    const std::uint16_t numRecords = loadBe16(leaf->data() + 10);
    for (std::uint16_t i = 0; i < numRecords && i < 64; ++i) {
        const std::uint16_t recOff = loadBe16(leaf->data() + nodeSize - 2 * (i + 1));
        if (recOff + 8u > nodeSize) continue;
        const std::uint32_t parent = loadBe32(leaf->data() + recOff + 2);
        const std::uint16_t nameLen = loadBe16(leaf->data() + recOff + 6);
        if (parent == 1 && nameLen > 0 && nameLen <= 255 && recOff + 8u + nameLen * 2u <= nodeSize)
            return utf16beToUtf8(std::span<const std::byte>(*leaf).subspan(recOff + 8, nameLen * 2u));
    }
    return {};
}

// HFS+ allocation file: fork data at 0x70 in the volume header, bits MSB first.
class HfsPlusAllocation final : public AllocationSource {
public:
    ByteCount base = 0, blockSize = 0;
    std::uint32_t totalBlocks = 0;
    std::uint64_t logicalSize = 0;
    std::uint32_t extents[8][2] = {};

    Expected<AllocationMap> load(BlockDevice& dev) const override {
        const std::uint64_t needed = (std::uint64_t{totalBlocks} + 7) / 8;
        if (logicalSize < needed) return fail(ErrorCategory::InvalidFormat, "HFS+ allocation file is too short");
        std::vector<std::byte> bits;
        bits.reserve(static_cast<std::size_t>(needed));
        for (const auto& e : extents) {
            if (bits.size() >= needed) break;
            if (e[1] == 0) break;
            const ByteCount want = std::min<ByteCount>(ByteCount{e[1]} * blockSize, needed - bits.size());
            auto part = dev.read(base + ByteCount{e[0]} * blockSize, want);
            if (!part) return fail(part.error());
            bits.insert(bits.end(), part->begin(), part->end());
        }
        // More than eight extents live in the extents overflow file; refuse rather than guess.
        if (bits.size() < needed) return fail(ErrorCategory::Unsupported, "HFS+ allocation file is fragmented beyond the volume header extents");
        AllocationMap map(base, blockSize, totalBlocks, true);
        map.importBitmap(0, totalBlocks, bits, false, true);
        return map;
    }
};

Result parseHfsPlus(Dev dev, ByteCount base, bool wrapped, Result&& wrapperTree) {
    auto raw = readOrNotFound(*dev, base + 1024, 512);
    if (!raw) return fail(raw.error());
    gen::HfsplusVolumeHeader h(*raw);
    const std::string sig = h.signature();
    if (sig != "H+" && sig != "HX") return notMine("no HFS+ signature");
    if (h.blockSize() < 512 || (h.blockSize() & (h.blockSize() - 1)) != 0) return notMine("bad HFS+ block size");

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = sig == "HX" ? FsType::HfsX : FsType::HfsPlus;
    info.version = std::to_string(h.version());
    info.blockSize = h.blockSize();
    info.totalBytes = ByteCount{h.totalBlocks()} * h.blockSize();
    info.usedBytes = ByteCount{h.totalBlocks() - std::min(h.freeBlocks(), h.totalBlocks())} * h.blockSize();
    info.clean = (h.attributes() & (1u << 8)) != 0;
    if (!*info.clean) fs->diag(Validity::Warning, "hfsplus.not_unmounted", "volume was not cleanly unmounted");
    if (h.attributes() & (1u << 13)) info.features.push_back("journaled");
    if (h.attributes() & (1u << 11)) fs->diag(Validity::Warning, "hfsplus.inconsistent", "boot volume inconsistent flag set");
    info.uuid = hfsUuidFromSeed(std::span<const std::byte>(*raw).subspan(0x50 + 24, 8));
    info.label = hfsPlusLabel(*dev, base, *raw, h.blockSize());
    {
        auto alloc = std::make_unique<HfsPlusAllocation>();
        alloc->base = base;
        alloc->blockSize = h.blockSize();
        alloc->totalBlocks = h.totalBlocks();
        alloc->logicalSize = loadBe64(raw->data() + 0x70);
        for (int i = 0; i < 8; ++i) {
            alloc->extents[i][0] = loadBe32(raw->data() + 0x70 + 16 + i * 8);
            alloc->extents[i][1] = loadBe32(raw->data() + 0x70 + 16 + i * 8 + 4);
        }
        fs->setAllocationSource(std::move(alloc));
    }
    if (wrapped) info.extra = "embedded in an HFS wrapper at offset " + std::to_string(base);
    fs->setTreeName(std::string(displayName(info.type)) + " filesystem");
    if (wrapperTree) fs->addNode((*wrapperTree)->describe());
    auto tree = h.describe(base + 1024);
    tree.name = "volume header";
    fs->addNode(std::move(tree));
    fs->addRegion(Region{base + 1024, 512});
    const ByteCount alt = base + *info.totalBytes - 1024;
    if (alt + 512 <= dev->size()) fs->addRegion(Region{alt, 512});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace

Result detectHfsPlus(Dev dev) { return parseHfsPlus(dev, 0, false, notMine("")); }

Result detectHfs(Dev dev) {
    auto raw = readOrNotFound(*dev, 1024, 512);
    if (!raw) return fail(raw.error());
    gen::HfsMdb mdb(*raw);
    if (mdb.signature() != "BD") return notMine("no HFS signature");
    if (mdb.allocBlockSize() == 0 || mdb.numAllocBlocks() == 0) return notMine("bad HFS MDB");
    if (mdb.embedSignature() == "H+") {
        // HFS wrapper around HFS+: descend.
        const ByteCount base = ByteCount{mdb.firstAllocBlock()} * 512 + ByteCount{mdb.embedStartBlock()} * mdb.allocBlockSize();
        auto wrapper = std::make_unique<SimpleFileSystem>(dev);
        wrapper->setTreeName("HFS wrapper");
        auto t = mdb.describe(1024);
        t.name = "HFS master directory block (wrapper)";
        wrapper->addNode(std::move(t));
        Result w = std::unique_ptr<FileSystem>(std::move(wrapper));
        auto inner = parseHfsPlus(dev, base, true, std::move(w));
        if (inner) return inner;
    }
    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    info.type = FsType::Hfs;
    info.blockSize = mdb.allocBlockSize();
    info.totalBytes = ByteCount{mdb.numAllocBlocks()} * mdb.allocBlockSize();
    info.usedBytes = static_cast<ByteCount>(mdb.numAllocBlocks() - std::min(mdb.freeBlocks(), mdb.numAllocBlocks())) * mdb.allocBlockSize();
    const auto nameLen = std::min<std::size_t>(mdb.volumeNameLen(), 27);
    info.label = asciiField(std::span<const std::byte>(*raw).subspan(0x25, nameLen));
    info.clean = (mdb.attributes() & (1u << 8)) != 0;
    info.uuid = hfsUuidFromSeed(std::span<const std::byte>(*raw).subspan(0x5C + 24, 8));
    fs->setTreeName("HFS filesystem");
    auto tree = mdb.describe(1024);
    tree.name = "master directory block";
    fs->addNode(std::move(tree));
    fs->addRegion(Region{1024, 512});
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
