// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/fs/reader.hpp"

#include <unordered_map>
#include <utility>

namespace stein::fs::detail {

// ISO 9660 reader with Rock Ridge (POSIX names, modes, symlinks, deep-directory
// relocation) and Joliet (UCS-2 names). Name source, in order of preference:
// Rock Ridge, Joliet, plain ISO (version suffix ";1" stripped). Inode ids are
// the byte offset of the directory record on the device.
class IsoReader final : public Reader {
public:
    enum class Names : std::uint8_t { Plain, Joliet, RockRidge };

    static Expected<std::unique_ptr<IsoReader>> open(std::shared_ptr<BlockDevice> device);
    Expected<Inode> root() const override { return Inode{m_rootId}; }
    Expected<Inode> lookup(const Inode& dir, std::string_view name) override;
    Expected<Stat> stat(const Inode& inode) override;
    Expected<std::vector<DirEntry>> readdir(const Inode& dir) override;
    Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) override;
    Expected<std::string> readlink(const Inode& link) override;
    bool caseSensitive() const override { return m_names == Names::RockRidge; }
    Names names() const { return m_names; }

private:
    struct Entry {
        std::uint64_t id = 0;
        std::string name;
        bool dir = false, dot = false, relocated = false, hasPosix = false, symlink = false;
        std::uint8_t flags = 0, unitSize = 0;
        std::vector<std::pair<std::uint32_t, std::uint64_t>> extents;   // (first block, byte length) per section
        std::uint64_t size = 0;
        std::int64_t mtime = 0, ctime = 0, atime = 0, crtime = 0;
        std::uint32_t mode = 0, nlink = 1, uid = 0, gid = 0;
        std::string target;
        bool targetContinues = false;
    };
    IsoReader() = default;
    static constexpr std::uint32_t kBlock = 2048;
    // Parse the record at `pos` inside `buf` (whose first byte sits at device offset `base`);
    // follows CE continuation areas. Returns the record length (0 = end of sector padding).
    Expected<std::size_t> parseRecord(std::span<const std::byte> buf, std::size_t pos, ByteCount base, Entry& out) const;
    Expected<void> parseSusp(std::span<const std::byte> area, Entry& e, std::string& rrName, bool& haveName, int depth) const;
    Expected<std::vector<Entry>> listDir(const Entry& dir);
    Expected<Entry> entryOf(const Inode& inode);
    Expected<std::uint64_t> dirSizeAt(std::uint32_t extent) const;

    std::shared_ptr<BlockDevice> m_device;
    Names m_names = Names::Plain;
    std::uint8_t m_suspSkip = 0;
    std::uint64_t m_rootId = 0;
    Entry m_root;
    std::unordered_map<std::uint64_t, Entry> m_cache;
    std::unordered_map<std::uint64_t, std::vector<Entry>> m_dirCache;
};

std::unique_ptr<ReaderSource> makeIsoReaderSource();

} // namespace stein::fs::detail
