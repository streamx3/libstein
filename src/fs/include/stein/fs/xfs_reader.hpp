// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>

namespace stein::fs::detail {

// XFS reader (v4 and v5 on-disk formats). Inode ids are XFS inode numbers.
class XfsReader final : public Reader {
public:
    static Expected<std::unique_ptr<XfsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootIno}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return true; }

private:
    struct Extent {
        std::uint64_t startoff = 0, startblock = 0, blockcount = 0;
        bool unwritten = false;
    };
    struct InodeRec {
        std::uint64_t ino = 0;
        std::uint16_t mode = 0;
        std::uint8_t version = 0, format = 0, forkoff = 0;
        std::uint32_t uid = 0, gid = 0, nlink = 0;
        std::uint64_t size = 0, nblocks = 0, nextents = 0;
        std::int64_t atime = 0, mtime = 0, ctime = 0, crtime = 0;
        std::vector<std::byte> raw;        // the whole on-disk inode
        std::size_t forkOffset = 0, forkSize = 0;
        std::span<const std::byte> fork() const { return std::span<const std::byte>(raw).subspan(forkOffset, forkSize); }
    };
    XfsReader() = default;
    ByteCount fsbToByte(std::uint64_t fsb) const;
    ByteCount inoToByte(std::uint64_t ino) const;
    Expected<InodeRec> readInode(std::uint64_t ino);
    Expected<std::vector<Extent>> extentsOf(const InodeRec& in);
    Expected<void> walkBmbt(std::uint64_t fsb, int level, std::vector<Extent>& out, int depth);
    static void decodeExtent(const std::byte* rec, Extent& e);
    // Read `dst` from the file's logical byte range; holes and unwritten extents read as zeros.
    Expected<void> readMapped(const std::vector<Extent>& extents, std::uint64_t offset, std::span<std::byte> dst) const;
    Expected<std::vector<DirEntry>> listDir(const InodeRec& dir);
    Expected<std::vector<DirEntry>> parseDirBlock(std::span<const std::byte> block);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_blockSize = 4096, m_agBlocks = 0, m_agCount = 0, m_inodeSize = 512, m_dirBlockSize = 4096;
    std::uint8_t m_agBlkLog = 0, m_inopBlog = 0, m_blockLog = 12;
    std::uint64_t m_rootIno = 0;
    bool m_v5 = false, m_ftype = false, m_bigtime = false, m_nrext64 = false;
    std::unordered_map<std::uint64_t, InodeRec> m_cache;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeXfsReaderSource();

} // namespace stein::fs::detail
