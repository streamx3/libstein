// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>

namespace stein::fs::detail {

class ReaderSource;

// EROFS reader: compact and extended inodes, flat plain/inline and chunk-based
// data, compressed data with full and compact lcluster indexes (big physical
// clusters, tail packing, fragments in the packed inode, dedupe partial
// references), lz4, lzma (MicroLZMA), deflate and zstd. Inode ids are nids.
class ErofsReader final : public Reader {
public:
    static Expected<std::unique_ptr<ErofsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootNid}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return true; }

private:
    struct InodeRec {
        std::uint64_t nid = 0, iloc = 0, size = 0, startBlock = 0, mtime = 0;
        std::uint32_t inodeSize = 32, xattrSize = 0, nlink = 1, uid = 0, gid = 0, ino = 0;
        std::uint16_t mode = 0, chunkFormat = 0;
        std::uint8_t layout = 0;
        // z_erofs
        bool zInit = false;
        std::uint16_t zAdvise = 0, zIdataSize = 0;
        std::uint8_t zLclusterBits = 12, zAlg[2] = {0, 0};
        std::uint64_t zFragmentOff = 0, zTailHeadLcn = ~0ull, zIdataPos = 0;
        bool zWholeInPacked = false;
    };
    struct Lcluster {
        std::uint64_t lcn = 0;
        std::uint8_t type = 0;
        bool partialRef = false;
        std::uint32_t clusterOfs = 0, pblk = 0, compressedBlocks = 0;
        std::uint32_t delta[2] = {0, 0};
        std::uint64_t nextPackOff = 0;
    };
    struct Map {
        std::uint64_t la = 0, llen = 0, pa = 0, plen = 0;
        bool mapped = false, encoded = false, fullMapped = false, partialRef = false, meta = false, fragment = false;
        std::uint8_t alg = 0;   // 0 lz4, 1 lzma, 2 deflate, 3 zstd, 4 shifted, 5 interlaced
    };
    ErofsReader() = default;
    Expected<InodeRec> inode(std::uint64_t nid);
    Expected<void> zInit(InodeRec& in);
    Expected<Lcluster> loadLcluster(const InodeRec& in, std::uint64_t lcn, bool lookahead);
    Expected<Lcluster> loadFullLcluster(const InodeRec& in, std::uint64_t lcn);
    Expected<Lcluster> loadCompactLcluster(const InodeRec& in, std::uint64_t lcn, bool lookahead);
    Expected<Map> mapBlocks(InodeRec& in, std::uint64_t la, bool findTail);
    Expected<void> readRaw(const InodeRec& in, std::uint64_t offset, std::span<std::byte> dst);
    Expected<void> readCompressed(InodeRec& in, std::uint64_t offset, std::span<std::byte> dst, int depth);
    Expected<void> readData(InodeRec& in, std::uint64_t offset, std::span<std::byte> dst, int depth);
    Expected<std::vector<std::byte>> readMeta(std::uint64_t offset, std::size_t n) const;

    std::shared_ptr<BlockDevice> m_device;
    std::uint8_t m_blkszBits = 12;
    std::uint32_t m_blockSize = 4096, m_dirBlockSize = 4096, m_featureIncompat = 0, m_featureCompat = 0;
    std::uint64_t m_metaBlkAddr = 0, m_rootNid = 0, m_packedNid = 0, m_epoch = 0;
    std::uint16_t m_availableAlgs = 1;
    std::unordered_map<std::uint64_t, InodeRec> m_inodes;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeErofsReaderSource();

} // namespace stein::fs::detail
