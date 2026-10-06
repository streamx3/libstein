// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <map>

namespace stein::fs::detail {

class NtfsReader final : public Reader {
public:
    static Expected<std::unique_ptr<NtfsReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{5}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return false; }

private:
    struct Attribute;
    struct Record;
    NtfsReader() = default;
    Expected<std::vector<std::byte>> readRecordRaw(std::uint64_t index) const;
    Expected<Record> loadRecord(std::uint64_t index) const;
    Expected<std::vector<std::byte>> attrData(const Attribute& a, std::uint64_t offset, std::uint64_t length) const;   // bytes of an attribute's value
    Expected<std::vector<std::byte>> attrAll(const Attribute& a) const;
    const Attribute* find(const Record& r, std::uint32_t type, std::string_view name = {}) const;

    std::shared_ptr<BlockDevice> m_device;
    ByteCount m_cluster = 0, m_recordSize = 0, m_indexRecordSize = 0;
    std::uint32_t m_sectorSize = 512;
    std::uint64_t m_mftOffset = 0, m_clusters = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> m_mftRuns;   // (lcn, clusters) of $MFT's $DATA, lcn == max = sparse
    std::uint64_t m_mftRecords = 0;
};

std::unique_ptr<ReaderSource> makeNtfsReaderSource();

} // namespace stein::fs::detail
