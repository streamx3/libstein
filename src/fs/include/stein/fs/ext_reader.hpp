// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

namespace stein::fs::detail {

class ExtReader final : public Reader {
public:
    static Expected<std::unique_ptr<ExtReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override;
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    ByteCount blockSize() const { return m_blockSize; }

private:
    struct RawInode;
    ExtReader() = default;
    Expected<RawInode> readInode(std::uint64_t ino) const;
    Expected<std::vector<std::byte>> readBlock(std::uint64_t block) const;
    Expected<std::vector<std::byte>> inlineData(const RawInode& in) const;
    Expected<std::uint64_t> mapExtent(std::span<const std::byte> node, std::uint64_t lblock, int depthLeft) const;
    Expected<std::uint64_t> mapIndirect(const RawInode& in, std::uint64_t lblock) const;
    Expected<std::uint64_t> mapBlock(const RawInode& in, std::uint64_t lblock) const;
    Expected<std::vector<std::byte>> readData(const RawInode& in) const;

    std::shared_ptr<BlockDevice> m_device;
    ByteCount m_blockSize = 0;
    std::uint32_t m_inodesPerGroup = 0, m_blocksPerGroup = 0, m_firstDataBlock = 0, m_inodeSize = 0, m_descSize = 32, m_incompat = 0, m_groups = 0, m_inodesCount = 0;
    std::uint64_t m_blocksCount = 0;
    ByteCount m_gdtOffset = 0;
    bool m_is64 = false;
};

std::unique_ptr<ReaderSource> makeExtReaderSource();

} // namespace stein::fs::detail
