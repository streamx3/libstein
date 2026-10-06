// SPDX-License-Identifier: MIT
// L3: read files and directories of a filesystem in-process. The interface is
// the subset of doc/design/15-userspace-fs.md §Reader that every format can
// serve; mount backends (FUSE/WinFsp) and `stein ls|cat|cp` sit on top.
#pragma once

#include "stein/core/error.hpp"
#include "stein/core/progress.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace stein::fs {

struct Inode {
    std::uint64_t id = 0;
    bool operator==(const Inode&) const = default;
};

enum class FileType : std::uint8_t { Unknown, File, Directory, Symlink, CharDevice, BlockDevice, Fifo, Socket };
std::string_view toString(FileType t);

// Which tree of a filesystem a reader opens: a volume of an APFS container (name or slot number;
// empty = the first), a snapshot of it (name or transaction id; empty = the live tree).
struct ReaderOptions {
    std::string volume;
    std::string snapshot;
};

// A volume, snapshot or subvolume a filesystem offers to openReader(): kind is "volume",
// "snapshot" or "subvolume"; parent names the volume a snapshot belongs to.
struct SubvolumeInfo {
    std::string kind, name, parent;
    std::uint64_t id = 0;   // slot, transaction id or subvolume id
    std::string note;       // role, snapshot count, ...
};

struct Stat {
    FileType type = FileType::Unknown;
    std::uint64_t size = 0;
    std::uint32_t mode = 0;          // POSIX permission bits (lower 12 bits)
    std::uint32_t nlink = 0;
    std::uint32_t uid = 0, gid = 0;
    std::int64_t atime = 0, mtime = 0, ctime = 0, crtime = 0;   // seconds since the epoch; 0 = unknown
    std::uint64_t allocatedBytes = 0;
};

struct DirEntry {
    std::string name;
    Inode inode;
    FileType type = FileType::Unknown;   // from the directory entry when the format records it
};

class Reader {
public:
    virtual ~Reader() = default;
    virtual Expected<Inode> root() const = 0;
    virtual Expected<Inode> lookup(const Inode& dir, std::string_view name) = 0;
    virtual Expected<Stat> stat(const Inode& inode) = 0;
    virtual Expected<std::vector<DirEntry>> readdir(const Inode& dir) = 0;   // without "." and ".."
    // Reads up to dst.size() bytes at `offset`; returns the count (short at EOF, holes read as zeros).
    virtual Expected<std::size_t> read(const Inode& file, std::uint64_t offset, std::span<std::byte> dst) = 0;
    virtual Expected<std::string> readlink(const Inode& link) = 0;
    virtual bool caseSensitive() const { return true; }
};

// Walk `path` ("/a/b/c" or "a/b/c") from the root, following symlinks inside the filesystem when asked.
Expected<Inode> resolvePath(Reader& reader, std::string_view path, bool followSymlinks = true);
// Read a whole file (bounded by maxBytes).
struct CopyTreeOptions {
    bool followSymlinks = false;     // false: recreate symlinks (where the host allows), true: copy their targets
    bool preserveTimes = true;       // set the destination's modification time from the source
    bool overwrite = true;           // replace existing destination files
    std::uint64_t maxFileBytes = ~std::uint64_t{0};
};

struct CopyTreeStats {
    std::uint64_t files = 0, directories = 0, symlinks = 0, bytes = 0, skipped = 0;
    std::vector<std::string> warnings;   // per entry that could not be copied, with the reason
};

// Copy a file or a whole directory tree out of the reader into `destination` on the host
// filesystem (the directory itself is created at `destination`; a file is written to that path).
// The building block for "drag out of the image": a viewer hands over an inode and a drop target.
// Progress counts bytes; `cancel` aborts between entries. Problems with single entries are
// recorded as warnings, errors that stop the copy are returned.
Expected<CopyTreeStats> copyTree(Reader& reader, const Inode& source, const std::filesystem::path& destination, const CopyTreeOptions& options = {}, Progress* progress = nullptr);

Expected<std::vector<std::byte>> readAll(Reader& reader, const Inode& file, std::uint64_t maxBytes = 1ull << 31);

} // namespace stein::fs
