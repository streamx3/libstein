// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

namespace stein::fs::detail {

// FAT12/16/32 reader. Inode ids are the byte offset of the entry's short
// directory entry on the device (unique and stable), with 1 for the root.
class FatReader final : public Reader {
public:
    static Expected<std::unique_ptr<FatReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{1}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode&) override { return fail(ErrorCategory::InvalidArgument, "FAT has no symbolic links"); }
    bool caseSensitive() const override { return false; }

private:
    struct Entry {
        std::string name;
        std::uint8_t attrs = 0;
        std::uint32_t firstCluster = 0, size = 0;
        std::uint16_t mtime = 0, mdate = 0, ctime = 0, cdate = 0, adate = 0;
        ByteCount entryOffset = 0;   // of the short entry
    };
    FatReader() = default;
    Expected<std::uint32_t> nextCluster(std::uint32_t cluster) const;
    Expected<std::vector<std::uint32_t>> chain(std::uint32_t first) const;
    ByteCount clusterOffset(std::uint32_t cluster) const { return m_dataOffset + ByteCount{cluster - 2} * m_clusterBytes; }
    Expected<std::vector<Entry>> listDirAt(const Inode& dir) const;
    Expected<Entry> entryOf(const Inode& inode) const;
    Expected<std::vector<std::byte>> dirBytes(const Inode& dir) const;
    Expected<std::vector<std::byte>> fileBytes(const Entry& e, std::uint64_t offset, std::uint64_t length) const;

    std::shared_ptr<BlockDevice> m_device;
    int m_bits = 16;
    std::uint32_t m_bps = 512, m_spc = 1, m_clusters = 0, m_rootCluster = 0, m_endMark = 0xFFF8;
    ByteCount m_clusterBytes = 0, m_fatOffset = 0, m_fatBytes = 0, m_rootOffset = 0, m_rootBytes = 0, m_dataOffset = 0;
    mutable std::vector<std::byte> m_fat;   // the first FAT, read once
};

std::unique_ptr<ReaderSource> makeFatReaderSource();

} // namespace stein::fs::detail
