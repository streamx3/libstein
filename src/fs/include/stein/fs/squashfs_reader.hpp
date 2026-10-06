// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>

namespace stein::fs::detail {

// SquashFS 4.0 reader: gzip, lzo, xz, lz4, zstd and lzma compressors, metadata
// blocks, basic and extended inodes, fragments, sparse blocks, directory
// indexes skipped (listings are read whole). Inode ids are inode references
// (metadata block offset << 16 | offset in block).
class SquashfsReader final : public Reader {
public:
    static Expected<std::unique_ptr<SquashfsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootRef}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return true; }

private:
    struct InodeRec {
        std::uint16_t type = 0, mode = 0, uidIdx = 0, gidIdx = 0;
        std::uint32_t mtime = 0, number = 0, nlink = 1;
        std::uint64_t size = 0;
        // directories
        std::uint32_t dirBlock = 0, dirOffset = 0;
        // files
        std::uint64_t blocksStart = 0;
        std::uint32_t fragment = 0xFFFFFFFFu, fragOffset = 0;
        std::vector<std::uint32_t> blockSizes;
        // symlinks
        std::string target;
    };
    struct Fragment {
        std::uint64_t start = 0;
        std::uint32_t size = 0;
    };
    SquashfsReader() = default;
    Expected<std::size_t> decompress(std::span<const std::byte> in, std::span<std::byte> out) const;
    // One metadata block at an absolute offset: decompressed content and the offset of the next block.
    Expected<const std::vector<std::byte>*> metadataBlock(std::uint64_t offset, std::uint64_t* next = nullptr);
    // `n` bytes of a metadata stream starting at (block offset, offset in block).
    Expected<std::vector<std::byte>> metadata(std::uint64_t tableStart, std::uint64_t block, std::uint32_t offset, std::size_t n);
    Expected<InodeRec> inode(std::uint64_t ref);
    Expected<Fragment> fragment(std::uint32_t index);
    Expected<std::uint32_t> id(std::uint16_t index);
    Expected<std::vector<std::uint64_t>> lookupTable(std::uint64_t start, std::size_t entries, std::size_t entrySize);

    std::shared_ptr<BlockDevice> m_device;
    std::uint16_t m_compressor = 0, m_flags = 0;
    std::uint32_t m_blockSize = 131072, m_fragCount = 0, m_idCount = 0;
    std::uint64_t m_rootRef = 0, m_inodeTable = 0, m_dirTable = 0, m_fragTable = 0, m_idTable = 0;
    std::vector<std::uint64_t> m_fragIndex, m_idIndex;
    std::unordered_map<std::uint64_t, std::vector<std::byte>> m_metaCache;
    std::unordered_map<std::uint64_t, InodeRec> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
    std::uint64_t m_dataKey = ~0ull;   // last decompressed data block (absolute offset)
    std::vector<std::byte> m_dataCache;
};

std::unique_ptr<ReaderSource> makeSquashfsReaderSource();

} // namespace stein::fs::detail
