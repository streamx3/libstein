// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <functional>
#include <unordered_map>

namespace stein::fs::detail {

// btrfs reader (single device; SINGLE/DUP/RAID0/1/10 chunk layouts mapped,
// RAID5/6 refused). Inode ids are (subvolume index << 56) | objectid, so
// subvolumes reached from the default tree get their own id space.
class BtrfsReader final : public Reader {
public:
    static Expected<std::unique_ptr<BtrfsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{makeId(0, m_rootDirId)}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return true; }

private:
    struct Key {
        std::uint64_t objectid = 0;
        std::uint8_t type = 0;
        std::uint64_t offset = 0;
        auto operator<=>(const Key&) const = default;
    };
    struct Stripe {
        std::uint64_t devid = 0, offset = 0;
    };
    struct Chunk {
        std::uint64_t logical = 0, length = 0, stripeLen = 0, type = 0;
        std::uint16_t subStripes = 1;
        std::vector<Stripe> stripes;
    };
    struct Tree {
        std::uint64_t objectid = 0, rootBytenr = 0, rootDirId = 256;
        std::uint8_t level = 0;
    };
    struct InodeItem {
        std::uint64_t size = 0, nbytes = 0, flags = 0;
        std::uint32_t nlink = 0, uid = 0, gid = 0, mode = 0;
        std::int64_t atime = 0, ctime = 0, mtime = 0, otime = 0;
    };
    struct ExtentItem {
        std::uint64_t fileOffset = 0, numBytes = 0, diskBytenr = 0, diskOffset = 0;
        std::uint8_t type = 0, compression = 0;
        std::vector<std::byte> inlineData;
    };
    using ItemVisitor = std::function<bool(const Key&, std::span<const std::byte> data)>;   // return false to stop

    BtrfsReader() = default;
    static std::uint64_t makeId(std::uint64_t tree, std::uint64_t objectid) { return (tree << 56) | (objectid & 0x00FFFFFFFFFFFFFFull); }
    static std::uint64_t treeOf(std::uint64_t id) { return id >> 56; }
    static std::uint64_t objectOf(std::uint64_t id) { return id & 0x00FFFFFFFFFFFFFFull; }
    static Key readKey(const std::byte* p);
    Expected<ByteCount> logicalToPhysical(std::uint64_t logical, std::uint64_t length) const;
    Expected<std::vector<std::byte>> readNode(std::uint64_t logical) const;
    Expected<void> loadChunks(std::span<const std::byte> superblock);
    Expected<void> readChunkTree(std::uint64_t logical, int depth);
    // Visit items with minKey <= key <= maxKey in key order.
    Expected<void> scan(std::uint64_t nodeLogical, const Key& minKey, const Key& maxKey, const ItemVisitor& visit, int depth) const;
    Expected<void> scanTree(const Tree& tree, const Key& minKey, const Key& maxKey, const ItemVisitor& visit) const;
    Expected<Tree> openSubvolume(std::uint64_t objectid);
    Expected<std::size_t> treeIndexFor(std::uint64_t subvolObjectid);
    Expected<InodeItem> inodeItem(std::uint64_t id);
    Expected<std::vector<ExtentItem>> extentsOf(std::uint64_t id);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_nodeSize = 16384, m_sectorSize = 4096;
    std::uint64_t m_rootTreeBytenr = 0, m_rootDirId = 256;
    std::array<std::byte, 16> m_fsid{};
    std::vector<Chunk> m_chunks;
    std::vector<Tree> m_trees;                 // index 0 = the default subvolume
    std::unordered_map<std::uint64_t, std::size_t> m_treeIndex;   // subvolume objectid -> index
    std::unordered_map<std::uint64_t, InodeItem> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeBtrfsReaderSource();

} // namespace stein::fs::detail
