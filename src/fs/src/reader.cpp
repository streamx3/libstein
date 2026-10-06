// SPDX-License-Identifier: MIT
#include "stein/fs/reader.hpp"

#include "stein/core/progress.hpp"
#include "stein/core/strings.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>

namespace stein::fs {

std::string_view toString(FileType t) {
    switch (t) {
    case FileType::Unknown: return "unknown";
    case FileType::File: return "file";
    case FileType::Directory: return "directory";
    case FileType::Symlink: return "symlink";
    case FileType::CharDevice: return "char device";
    case FileType::BlockDevice: return "block device";
    case FileType::Fifo: return "fifo";
    case FileType::Socket: return "socket";
    }
    return "?";
}

Expected<Inode> resolvePath(Reader& reader, std::string_view path, bool followSymlinks) {
    auto root = reader.root();
    if (!root) return root;
    // Ancestors of the current directory, root first: ".." pops instead of relying on a
    // ".." directory entry, which exFAT, NTFS and HFS+ do not have.
    std::vector<Inode> stack{*root};
    int hops = 0;
    std::vector<std::string> parts;
    for (const auto& p : split(path, '/'))
        if (!p.empty() && p != ".") parts.push_back(p);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const auto& name = parts[i];
        if (name == "..") {
            if (stack.size() > 1) stack.pop_back();
            continue;
        }
        auto next = reader.lookup(stack.back(), name);
        if (!next) return next;
        if (followSymlinks) {
            auto st = reader.stat(*next);
            if (!st) return fail(st.error());
            if (st->type == FileType::Symlink) {
                if (++hops > 40) return fail(ErrorCategory::InvalidArgument, "too many levels of symbolic links");
                auto target = reader.readlink(*next);
                if (!target) return fail(target.error());
                // Splice the target into the remaining path and restart from the right base.
                std::vector<std::string> rest(parts.begin() + static_cast<std::ptrdiff_t>(i) + 1, parts.end());
                std::vector<std::string> tparts;
                for (const auto& p : split(*target, '/'))
                    if (!p.empty() && p != ".") tparts.push_back(p);
                tparts.insert(tparts.end(), rest.begin(), rest.end());
                parts = std::move(tparts);
                i = static_cast<std::size_t>(-1);
                if (!target->empty() && (*target)[0] == '/') stack.assign(1, *root);
                continue;
            }
        }
        stack.push_back(*next);
    }
    return stack.back();
}

namespace {

std::filesystem::path pathFromUtf8(const std::string& s) {
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(s.data()), s.size()));
}

// Windows limits ordinary paths to 260 characters; filesystems allow 255-byte names at any
// depth, so the destination is written as an extended-length path ("\\?\C:\...", backslashes,
// no "." or ".." components), which the file APIs accept up to 32767 characters.
std::filesystem::path hostDestination(const std::filesystem::path& destination) {
#if defined(_WIN32)
    std::error_code ec;
    std::filesystem::path p = std::filesystem::absolute(destination, ec);
    if (ec) return destination;
    p = p.lexically_normal();
    p.make_preferred();
    const auto& s = p.native();
    if (s.size() >= 3 && s[1] == L':' && s[2] == L'\\') return std::filesystem::path(L"\\\\?\\" + s);
    return p;
#else
    return destination;
#endif
}

Expected<void> copyFile(Reader& reader, const Inode& file, const Stat& st, const std::filesystem::path& dest, const CopyTreeOptions& options, Progress* progress, CopyTreeStats& stats) {
    std::error_code ec;
    if (!options.overwrite && std::filesystem::exists(dest, ec)) return fail(ErrorCategory::InvalidArgument, dest.string() + " exists");
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    if (!out) return fail(ErrorCategory::Io, "cannot create " + dest.string());
    std::vector<std::byte> buf(static_cast<std::size_t>(std::min<std::uint64_t>(4u << 20, std::max<std::uint64_t>(st.size, 1))));
    std::uint64_t off = 0;
    while (off < st.size) {
        if (progress && progress->isCancelled()) return fail(ErrorCategory::Internal, "cancelled");
        auto n = reader.read(file, off, std::span<std::byte>(buf).subspan(0, static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), st.size - off))));
        if (!n) return fail(n.error());
        if (*n == 0) break;
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(*n));
        if (!out) return fail(ErrorCategory::Io, "write to " + dest.string() + " failed");
        off += *n;
        stats.bytes += *n;
        if (progress) progress->advance(*n);
    }
    out.close();
    if (options.preserveTimes && st.mtime > 0) {
        const auto t = std::filesystem::file_time_type::clock::now() + (std::chrono::system_clock::time_point(std::chrono::seconds(st.mtime)) - std::chrono::system_clock::now());
        std::filesystem::last_write_time(dest, std::chrono::time_point_cast<std::filesystem::file_time_type::duration>(t), ec);
    }
    return {};
}

Expected<void> copyEntry(Reader& reader, const Inode& inode, const std::filesystem::path& dest, const CopyTreeOptions& options, Progress* progress, CopyTreeStats& stats, int depth) {
    if (depth > 128) return fail(ErrorCategory::InvalidFormat, "directory tree deeper than 128 levels");
    auto st = reader.stat(inode);
    if (!st) return fail(st.error());
    std::error_code ec;
    switch (st->type) {
    case FileType::Directory: {
        std::filesystem::create_directories(dest, ec);
        if (ec) return fail(ErrorCategory::Io, "cannot create directory " + dest.string() + ": " + ec.message());
        ++stats.directories;
        auto entries = reader.readdir(inode);
        if (!entries) return fail(entries.error());
        for (const auto& e : *entries) {
            if (e.name == "." || e.name == ".." || e.name.empty() || e.name.find('/') != std::string::npos || e.name.find('\\') != std::string::npos) continue;
            if (progress && progress->isCancelled()) return fail(ErrorCategory::Internal, "cancelled");
            auto r = copyEntry(reader, e.inode, dest / pathFromUtf8(e.name), options, progress, stats, depth + 1);
            if (!r) {
                if (r.error().category() == ErrorCategory::Io && r.error().message().find("cannot") == 0) return r;   // the host refused: stop
                stats.warnings.push_back(e.name + ": " + std::string(r.error().message()));
                ++stats.skipped;
            }
        }
        return {};
    }
    case FileType::File:
        if (st->size > options.maxFileBytes) {
            stats.warnings.push_back(dest.filename().string() + ": larger than the limit, skipped");
            ++stats.skipped;
            return {};
        }
        if (auto r = copyFile(reader, inode, *st, dest, options, progress, stats); !r) return r;
        ++stats.files;
        return {};
    case FileType::Symlink: {
        auto target = reader.readlink(inode);
        if (!target) return fail(target.error());
        if (options.followSymlinks) {
            auto resolved = resolvePath(reader, *target, true);
            if (!resolved) return fail(resolved.error());
            return copyEntry(reader, *resolved, dest, options, progress, stats, depth + 1);
        }
        std::filesystem::remove(dest, ec);
        std::filesystem::create_symlink(pathFromUtf8(*target), dest, ec);
        if (ec) return fail(ErrorCategory::Unsupported, "symlink " + dest.filename().string() + " -> " + *target + ": " + ec.message());
        ++stats.symlinks;
        return {};
    }
    default:
        stats.warnings.push_back(dest.filename().string() + ": " + std::string(toString(st->type)) + " not copied");
        ++stats.skipped;
        return {};
    }
}

} // namespace

Expected<CopyTreeStats> copyTree(Reader& reader, const Inode& source, const std::filesystem::path& destination, const CopyTreeOptions& options, Progress* progress) {
    CopyTreeStats stats;
    auto r = copyEntry(reader, source, hostDestination(destination), options, progress, stats, 0);
    if (!r) return fail(r.error());
    return stats;
}

Expected<std::vector<std::byte>> readAll(Reader& reader, const Inode& file, std::uint64_t maxBytes) {
    auto st = reader.stat(file);
    if (!st) return fail(st.error());
    if (st->size > maxBytes) return fail(ErrorCategory::OutOfRange, "file larger than the read limit");
    std::vector<std::byte> out(static_cast<std::size_t>(st->size));
    std::size_t done = 0;
    while (done < out.size()) {
        auto n = reader.read(file, done, std::span<std::byte>(out).subspan(done));
        if (!n) return fail(n.error());
        if (*n == 0) break;
        done += *n;
    }
    out.resize(done);
    return out;
}

} // namespace stein::fs
