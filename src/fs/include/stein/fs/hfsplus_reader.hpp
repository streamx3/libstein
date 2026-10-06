// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>
#include <utility>

namespace stein::fs::detail {

// HFS+ / HFSX reader (TN1150). Inode ids are catalog node ids (CNIDs); the
// root folder is 2. Hard links resolve to their iNode files in the private
// metadata folder; symlinks are files whose mode says S_IFLNK.
class HfsPlusReader final : public Reader {
public:
    // `base` is the byte offset of the HFS+ volume on the device (non-zero inside an HFS wrapper).
    static Expected<std::unique_ptr<HfsPlusReader>> open(std::shared_ptr<BlockDevice> device, ByteCount base);
    Expected<Inode> root() const override { return Inode{2}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return m_caseSensitive; }

private:
    struct Fork {
        std::uint64_t logicalSize = 0;
        std::uint32_t totalBlocks = 0;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> extents;   // (startBlock, blockCount)
    };
    struct Record {
        std::uint32_t cnid = 0, parent = 0;
        std::string name;
        std::u16string name16;
        bool folder = false;
        std::uint32_t valence = 0;
        std::uint32_t createDate = 0, modDate = 0, attrModDate = 0, accessDate = 0;   // Mac epoch, UTC
        std::uint32_t uid = 0, gid = 0, special = 0;
        std::uint8_t adminFlags = 0, ownerFlags = 0;
        std::uint16_t mode = 0;
        std::uint32_t fdType = 0, fdCreator = 0;
        Fork data, rsrc;
        bool hardLink() const { return !folder && fdType == 0x686C6E6Bu && fdCreator == 0x6866732Bu; }   // 'hlnk' / 'hfs+'
    };
    struct BTree {
        Fork fork;
        std::uint32_t cnid = 0;
        std::uint16_t nodeSize = 0, maxKeyLength = 0;
        std::uint32_t rootNode = 0, firstLeaf = 0, totalNodes = 0, attributes = 0;
        std::uint8_t keyCompareType = 0;
    };
    struct LeafPos {
        std::uint32_t node = 0;
        std::uint16_t record = 0;
        std::vector<std::byte> bytes;
    };
    using KeyCompare = int (*)(const std::byte* key, const void* target);

    HfsPlusReader() = default;
    ByteCount blockOffset(std::uint32_t block) const { return m_base + ByteCount{block} * m_blockSize; }
    static Fork parseFork(const std::byte* p);
    Expected<void> completeExtents(Fork& fork, std::uint32_t cnid, std::uint8_t forkType);
    Expected<void> readForkInto(const Fork& fork, std::uint64_t offset, std::span<std::byte> dst) const;
    Expected<BTree> openTree(const Fork& fork, std::uint32_t cnid);
    Expected<std::vector<std::byte>> readNode(const BTree& tree, std::uint32_t node) const;
    // Descend to the leaf holding the first record whose key is >= target (per cmp).
    Expected<LeafPos> findLeaf(const BTree& tree, KeyCompare cmp, const void* target) const;
    Expected<std::vector<Record>> listFolder(std::uint32_t cnid);
    Expected<Record> recordOf(std::uint32_t cnid);
    Expected<Record> resolveLink(const Record& link);
    std::u16string fold(std::u16string s) const;

    std::shared_ptr<BlockDevice> m_device;
    ByteCount m_base = 0;
    std::uint32_t m_blockSize = 4096, m_totalBlocks = 0;
    bool m_caseSensitive = false, m_journaled = false;
    BTree m_catalog, m_extents;
    std::uint32_t m_privateDataCnid = 0, m_privateDirCnid = 0;   // "\0\0\0\0HFS+ Private Data", ".HFS+ Private Directory Data\r"
    std::unordered_map<std::uint32_t, Record> m_cache;
    std::unordered_map<std::uint32_t, std::vector<Record>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeHfsPlusReaderSource(ByteCount base);

} // namespace stein::fs::detail
