// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>

namespace stein::fs::detail {

// exFAT reader. Inode ids are the byte offset of the File directory entry
// (type 0x85) on the device, with 1 for the root directory.
class ExfatReader final : public Reader {
public:
    static Expected<std::unique_ptr<ExfatReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{1}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode&) override { return fail(ErrorCategory::InvalidArgument, "exFAT has no symbolic links"); }
    bool caseSensitive() const override { return false; }

private:
    struct Stream {
        std::uint32_t firstCluster = 0;
        std::uint64_t dataLength = 0, validDataLength = 0;
        bool noFatChain = false;
    };
    struct Entry {
        std::u16string name16;
        std::string name;
        std::uint16_t attrs = 0;
        Stream stream;
        std::uint32_t created = 0, modified = 0, accessed = 0;
        std::uint8_t created10ms = 0, modified10ms = 0, createdOffset = 0, modifiedOffset = 0, accessedOffset = 0;
        ByteCount entryOffset = 0;   // of the 0x85 entry
    };
    ExfatReader() = default;
    ByteCount clusterOffset(std::uint32_t cluster) const { return m_heapOffset + ByteCount{cluster - 2} * m_clusterBytes; }
    Expected<void> loadFat() const;
    Expected<std::uint32_t> fatEntry(std::uint32_t cluster) const;
    // Clusters holding `length` bytes starting at `first` (FAT chain, or contiguous when noFatChain).
    Expected<std::vector<std::uint32_t>> clustersOf(const Stream& s) const;
    Expected<std::vector<std::byte>> readStream(const Stream& s, std::uint64_t offset, std::uint64_t length) const;
    Expected<Stream> dirStream(const Inode& dir);
    Expected<std::vector<Entry>> listDir(const Inode& dir);
    Expected<Entry> entryOf(const Inode& inode);
    Expected<void> loadUpcase(std::uint32_t firstCluster, std::uint64_t length);
    std::u16string upcase(std::u16string s) const;

    std::shared_ptr<BlockDevice> m_device;
    ByteCount m_bps = 512, m_clusterBytes = 0, m_fatOffset = 0, m_fatBytes = 0, m_heapOffset = 0;
    std::uint32_t m_clusterCount = 0, m_rootCluster = 0;
    mutable std::vector<std::byte> m_fat;   // first FAT, read once
    std::vector<char16_t> m_upcase;         // 65536 entries, or empty = ASCII-only folding
    std::unordered_map<std::uint64_t, Entry> m_cache;   // inode id -> entry set, filled by listDir/lookup
};

std::unique_ptr<ReaderSource> makeExfatReaderSource();

} // namespace stein::fs::detail
