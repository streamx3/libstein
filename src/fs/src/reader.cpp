// SPDX-License-Identifier: MIT
#include "stein/fs/reader.hpp"

#include "stein/core/strings.hpp"

#include <algorithm>

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
