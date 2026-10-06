// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>

namespace stein::fs::detail {

class ReaderSource;

// UDF reader (ECMA-167 / OSTA UDF 1.02-2.60): physical, sparable and metadata
// partition maps, file entries and extended file entries with short, long or
// inline allocation descriptors, file identifier descriptors, symlinks.
// Inode ids are the byte offset of the (extended) file entry on the device.
class UdfReader final : public Reader {
public:
    static Expected<std::unique_ptr<UdfReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootId}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return true; }

private:
    struct Extent {
        std::uint64_t fileOffset = 0, length = 0;
        std::uint32_t block = 0;      // logical block in `partition`
        std::uint16_t partition = 0;  // partition map index
        bool recorded = true;
    };
    struct Entry {
        std::uint64_t id = 0;
        std::uint8_t fileType = 0;
        std::uint32_t uid = 0, gid = 0, permissions = 0;
        std::uint16_t links = 1;
        std::uint64_t size = 0, blocksRecorded = 0;
        std::int64_t atime = 0, mtime = 0, ctime = 0, crtime = 0;
        std::vector<Extent> extents;
        std::vector<std::byte> inlineData;
        bool inlined = false;
    };
    struct PartitionMap {
        enum class Kind : std::uint8_t { Physical, Sparable, Metadata } kind = Kind::Physical;
        std::uint16_t partitionNumber = 0;
        std::uint32_t start = 0, length = 0;          // physical partition, in sectors
        std::uint32_t packetLength = 0;               // sparable
        std::vector<std::pair<std::uint32_t, std::uint32_t>> sparing;   // original -> mapped
        std::vector<Extent> metadataExtents;          // metadata file's data, in the underlying map
        std::uint16_t underlying = 0;                 // metadata: index of the physical map
    };
    UdfReader() = default;
    Expected<ByteCount> blockToByte(std::uint16_t partition, std::uint32_t block) const;
    Expected<void> loadVds(std::uint32_t location, std::uint32_t length);
    Expected<Entry> readEntry(std::uint16_t partition, std::uint32_t block);
    Expected<Entry> entryOf(const Inode& inode);
    Expected<void> parseAllocationDescriptors(Entry& e, std::span<const std::byte> ads, std::uint8_t kind, std::uint16_t partition, int depth);
    Expected<void> readData(const Entry& e, std::uint64_t offset, std::span<std::byte> dst) const;
    Expected<std::vector<DirEntry>> listDir(const Entry& dir);

    std::shared_ptr<BlockDevice> m_device;
    std::uint32_t m_blockSize = 2048;
    std::vector<PartitionMap> m_maps;
    std::uint64_t m_rootId = 0;
    std::uint16_t m_rootPartition = 0;
    std::uint32_t m_rootBlock = 0;
    std::string m_label;
    std::unordered_map<std::uint64_t, Entry> m_cache;
    std::unordered_map<std::uint64_t, std::vector<DirEntry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeUdfReaderSource();

} // namespace stein::fs::detail
