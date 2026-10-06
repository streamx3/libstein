// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <map>
#include <memory>
#include <unordered_map>

namespace stein::fs::detail {

class ReaderSource;

// F2FS reader: superblock, the newer valid checkpoint pack, the node address
// table with the checkpoint's NAT journal applied, inodes with extra
// attributes, inline data and inline dentries, the direct/indirect/double
// indirect node tree, hash-table directories read as plain dentry blocks,
// compressed clusters (lz4, lzo, zstd; decode paths without a fixture yet,
// since Ubuntu's f2fs-tools cannot compress). Casefolded directories match
// ASCII case-insensitively. Encrypted files and lzo-rle clusters are
// refused. Inode ids are F2FS inode numbers (nids).
class F2fsReader final : public Reader {
public:
    static Expected<std::unique_ptr<F2fsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootIno}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return !m_casefold; }

private:
    using Block = std::shared_ptr<const std::vector<std::byte>>;
    struct InodeRec {
        Block node;                        // the whole inode block: i_addr and the inline area live here
        std::uint16_t mode = 0;
        std::uint8_t advise = 0, inlineFlags = 0;
        std::uint32_t uid = 0, gid = 0, links = 1, flags = 0;
        std::uint64_t size = 0, blocks = 0;
        std::int64_t atime = 0, mtime = 0, ctime = 0, crtime = 0;
        std::uint16_t extraIsize = 0;
        std::uint32_t inlineXattrSlots = 0;
        std::uint32_t addrsPerInode = 923, addrsPerBlock = 1018;   // both rounded down to the cluster size for compressed files
        std::size_t addrBase = 360;        // byte offset of the first data address slot
        std::uint8_t compressAlgorithm = 0, logClusterSize = 0;
        bool compressed = false;
    };

    F2fsReader() = default;
    Expected<Block> readBlock(std::uint32_t addr) const;
    Expected<std::uint32_t> nodeAddr(std::uint32_t nid) const;
    Expected<Block> nodeBlock(std::uint32_t nid) const;
    Expected<const InodeRec*> inode(std::uint64_t ino);
    // Block address of logical block `index` of a file (0 = hole / unallocated; special values pass through).
    Expected<std::uint32_t> dataAddr(const InodeRec& in, std::uint64_t index) const;
    Expected<std::vector<DirEntry>> parseDentries(std::span<const std::byte> bitmap, std::size_t count, std::span<const std::byte> dentries, std::span<const std::byte> names) const;
    Expected<std::size_t> readCluster(const InodeRec& in, std::uint64_t cluster, std::span<std::byte> out);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_blockSize = 4096, m_blocksPerSeg = 512, m_natBlkaddr = 0, m_rootIno = 3, m_feature = 0;
    std::uint64_t m_blockCount = 0;
    bool m_casefold = false;
    std::vector<std::uint8_t> m_natBitmap;
    std::unordered_map<std::uint32_t, std::uint32_t> m_natJournal;
    mutable std::unordered_map<std::uint32_t, Block> m_nodeCache;
    std::unordered_map<std::uint64_t, InodeRec> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeF2fsReaderSource();

} // namespace stein::fs::detail
