// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

namespace stein::fs::detail {

class ReaderSource;   // stein/fs/detail/simple_fs.hpp

// FAT type and active FAT, shared by the detector (fs_fat.cpp), the allocation source and the
// reader so the three never disagree on which entries they read.
//
// Microsoft "FAT32 File System Specification": CountofClusters < 4085 is FAT12, < 65525 is
// FAT16, otherwise FAT32. A boot sector whose sectors_per_fat16 is 0 has the FAT32 layout
// (FAT size in the extended BPB, root directory as a cluster chain) and is read as FAT32
// whatever its count, as Linux and mkfs.vfat on small media do; the detector says so with
// fat.small_fat32. A 16-bit layout with 65525 or more clusters cannot address them all and is
// read as FAT16 with a fat.bpb_geometry error.
constexpr std::uint64_t kFat12MaxClusters = 4084;
constexpr std::uint64_t kFat16MaxClusters = 65524;
constexpr std::uint64_t kFat32MaxClusters = 0x0FFFFFF6u - 2;   // entries 2..0x0FFFFFF5

inline int fatBitsFor(bool fat32Layout, std::uint64_t clusters) {
    if (fat32Layout) return 32;
    return clusters > kFat12MaxClusters ? 16 : 12;
}

// FAT32 ext_flags (BPB offset 0x28): bit 7 set = mirroring disabled and bits 0-3 name the one
// FAT the driver keeps current. With mirroring on every copy is current and FAT 0 is read; an
// index past the last FAT falls back to 0 (the detector reports fat.active_fat_out_of_range).
inline std::uint32_t fatActiveIndex(std::uint16_t extFlags, std::uint32_t fats) {
    if (!(extFlags & 0x80)) return 0;
    const std::uint32_t index = extFlags & 0x0F;
    return index < fats ? index : 0;
}
inline bool fatMirroring(std::uint16_t extFlags) { return !(extFlags & 0x80); }

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
    mutable std::vector<std::byte> m_fat;   // the active FAT, read once
};

std::unique_ptr<ReaderSource> makeFatReaderSource();

} // namespace stein::fs::detail
