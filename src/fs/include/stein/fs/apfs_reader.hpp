// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <functional>
#include <unordered_map>

namespace stein::fs::detail {

class ReaderSource;

// APFS reader: container superblock (latest checkpoint), container and volume
// object maps, B-trees, one volume's file system tree (inodes, directory
// records, file extents, embedded xattrs for symlinks). Unencrypted volumes
// only; transparently compressed files are refused. Inode ids are APFS inode
// numbers.
class ApfsReader final : public Reader {
public:
    // `volume` picks the fs_oid slot in the container (0 = first volume).
    static Expected<std::unique_ptr<ApfsReader>> open(std::shared_ptr<BlockDevice> device, unsigned volume = 0);
    Expected<Inode> root() const override { return Inode{2}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return m_caseSensitive; }
    const std::string& volumeName() const { return m_volumeName; }

private:
    struct InodeRec {
        std::uint64_t parent = 0, privateId = 0, size = 0, allocated = 0;
        std::int64_t crtime = 0, mtime = 0, ctime = 0, atime = 0;
        std::uint64_t internalFlags = 0;
        std::uint32_t nlink = 1, bsdFlags = 0, uid = 0, gid = 0;
        std::uint16_t mode = 0;
        bool hasDstream = false;
    };
    struct Extent {
        std::uint64_t logical = 0, length = 0, physical = 0;
    };
    // Visitor over fs-tree records whose key starts with (objId, type); return false to stop.
    using Visitor = std::function<bool(std::span<const std::byte> key, std::span<const std::byte> val)>;

    ApfsReader() = default;
    Expected<std::vector<std::byte>> readBlock(std::uint64_t paddr) const;
    Expected<std::vector<std::byte>> readObject(std::uint64_t paddr, std::uint32_t expectType) const;
    // Resolve a virtual oid through an object map rooted at `omapTreeRoot` (physical).
    Expected<std::uint64_t> omapLookup(std::uint64_t omapTreeRoot, std::uint64_t oid) const;
    Expected<void> scanFsTree(std::uint64_t nodePaddr, std::uint64_t objId, std::uint8_t type, const Visitor& visit, int depth) const;
    Expected<void> scanRecords(std::uint64_t objId, std::uint8_t type, const Visitor& visit) const;
    Expected<InodeRec> inode(std::uint64_t id);
    Expected<std::vector<Extent>> extents(std::uint64_t privateId);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_blockSize = 4096;
    std::uint64_t m_blockCount = 0, m_containerOmapRoot = 0, m_volumeOmapRoot = 0, m_fsRoot = 0;
    bool m_caseSensitive = false, m_hashedKeys = true;
    std::string m_volumeName;
    std::unordered_map<std::uint64_t, InodeRec> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
    std::unordered_map<std::uint64_t, std::vector<Extent>> m_extentCache;
};

std::unique_ptr<ReaderSource> makeApfsReaderSource();

} // namespace stein::fs::detail
