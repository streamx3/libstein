// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <functional>
#include <optional>
#include <unordered_map>

namespace stein::fs::detail {

class ReaderSource;

// APFS reader: container superblock (latest checkpoint), container and volume
// object maps, B-trees, one volume's file system tree (inodes, directory
// records, file extents, xattrs embedded or in their own data streams),
// any volume of the container by name or slot, any snapshot of a volume (the
// snapshot's superblock with object-map lookups bounded by its transaction
// id), and transparently compressed files (decmpfs: zlib, lzvn and lzfse in
// the xattr or the resource fork). Unencrypted volumes only. Inode ids are
// APFS inode numbers.
class ApfsReader final : public Reader {
public:
    // `volume` picks the fs_oid slot in the container (0 = first volume).
    static Expected<std::unique_ptr<ApfsReader>> open(std::shared_ptr<BlockDevice> device, unsigned volume = 0);
    // Volume by name or slot number and optionally a snapshot by name or transaction id.
    static Expected<std::unique_ptr<ApfsReader>> open(std::shared_ptr<BlockDevice> device, const ReaderOptions& options);
    // Every volume of the container and every snapshot of each volume.
    static Expected<std::vector<SubvolumeInfo>> enumerate(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{2}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return m_caseSensitive; }
    const std::string& volumeName() const { return m_volumeName; }
    const std::string& snapshotName() const { return m_snapshotName; }   // empty for the live tree

private:
    struct Snapshot {
        std::string name;
        std::uint64_t xid = 0, sblock = 0;
    };
    struct Decmpfs {
        std::uint32_t type = 0;
        std::uint64_t size = 0;
        std::vector<std::byte> payload;   // bytes after the 16-byte header (in-xattr types)
    };
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
    // Container superblock (newest checkpoint) and container object map.
    Expected<void> loadContainer();
    // Physical address of the volume superblock in fs slot `slot` (0 when the slot is empty).
    Expected<std::uint64_t> volumeSuperblock(unsigned slot) const;
    Expected<std::vector<Snapshot>> snapshots(const std::vector<std::byte>& volumeSb) const;
    // Resolve a virtual oid through an object map rooted at `omapTreeRoot` (physical), taking
    // the newest version with xid <= maxXid.
    Expected<std::uint64_t> omapLookup(std::uint64_t omapTreeRoot, std::uint64_t oid, std::uint64_t maxXid = ~0ull) const;
    // Visit every leaf entry of a B-tree whose children are physical (true) or virtual oids.
    Expected<void> walkTree(std::uint64_t nodePaddr, bool physicalChildren, const Visitor& visit, int depth) const;
    Expected<void> scanFsTree(std::uint64_t nodePaddr, std::uint64_t objId, std::uint8_t type, const Visitor& visit, int depth) const;
    Expected<void> scanRecords(std::uint64_t objId, std::uint8_t type, const Visitor& visit) const;
    Expected<InodeRec> inode(std::uint64_t id);
    Expected<std::vector<Extent>> extents(std::uint64_t privateId);
    Expected<std::size_t> readExtents(std::uint64_t privateId, std::uint64_t size, std::uint64_t offset, std::span<std::byte> dst);
    // An extended attribute's bytes (embedded or from its data stream); nullopt when absent.
    Expected<std::optional<std::vector<std::byte>>> xattr(std::uint64_t id, std::string_view name);
    Expected<Decmpfs> decmpfs(std::uint64_t id);
    Expected<std::shared_ptr<const std::vector<std::byte>>> decompressed(std::uint64_t id, const InodeRec& in);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_blockSize = 4096;
    std::uint64_t m_blockCount = 0, m_containerOmapRoot = 0, m_volumeOmapRoot = 0, m_fsRoot = 0;
    std::uint64_t m_xid = ~0ull;   // object-map bound: the snapshot's transaction id, or everything
    std::vector<std::byte> m_nxSb;
    bool m_caseSensitive = false, m_hashedKeys = true;
    std::string m_volumeName, m_snapshotName;
    std::uint64_t m_decompId = ~0ull;
    std::shared_ptr<const std::vector<std::byte>> m_decompData;
    std::unordered_map<std::uint64_t, InodeRec> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
    std::unordered_map<std::uint64_t, std::vector<Extent>> m_extentCache;
};

std::unique_ptr<ReaderSource> makeApfsReaderSource();

} // namespace stein::fs::detail
