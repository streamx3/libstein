// SPDX-License-Identifier: MIT
#define FUSE_USE_VERSION 31
#include "stein/mount/mount.hpp"

#include "stein/core/strings.hpp"

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>
#include <unistd.h>

namespace stein::mount {

struct Mount::Impl {
    std::unique_ptr<fs::Reader> reader;
    std::mutex mutex;                      // the reader is not thread-safe; fuse runs single-threaded anyway
    std::map<std::string, fs::Inode> cache; // path -> inode
    struct fuse* fuse = nullptr;
    struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    bool mounted = false;
    std::atomic<bool> running{false};
    std::atomic<bool> stopRequested{false};

    Expected<fs::Inode> inodeFor(const char* path) {
        std::string p = path;
        if (auto it = cache.find(p); it != cache.end()) return it->second;
        auto ino = fs::resolvePath(*reader, p, false);
        if (!ino) return ino;
        if (cache.size() > 65536) cache.clear();
        cache[p] = *ino;
        return *ino;
    }
    static Impl& self() { return *static_cast<Impl*>(fuse_get_context()->private_data); }
    static int toErrno(const Error& e) {
        switch (e.category()) {
        case ErrorCategory::NotFound: return -ENOENT;
        case ErrorCategory::Permission: return -EACCES;
        case ErrorCategory::Unsupported: return -ENOTSUP;
        case ErrorCategory::InvalidArgument: return -EINVAL;
        case ErrorCategory::OutOfRange: return -EINVAL;
        default: return -EIO;
        }
    }
    static void fillStat(const fs::Stat& st, struct stat* out) {
        std::memset(out, 0, sizeof *out);
        mode_t type = S_IFREG;
        switch (st.type) {
        case fs::FileType::Directory: type = S_IFDIR; break;
        case fs::FileType::Symlink: type = S_IFLNK; break;
        case fs::FileType::CharDevice: type = S_IFCHR; break;
        case fs::FileType::BlockDevice: type = S_IFBLK; break;
        case fs::FileType::Fifo: type = S_IFIFO; break;
        case fs::FileType::Socket: type = S_IFSOCK; break;
        default: break;
        }
        // Read-only mount: strip write bits; directories need x to be traversable.
        mode_t perm = (st.mode ? st.mode : 0644) & 0555;
        if (type == S_IFDIR) perm |= 0555;
        if (type == S_IFLNK) perm = 0777;
        out->st_mode = type | perm;
        out->st_nlink = st.nlink ? st.nlink : 1;
        out->st_size = static_cast<off_t>(st.size);
        out->st_uid = getuid();
        out->st_gid = getgid();
        out->st_blksize = 4096;
        out->st_blocks = static_cast<blkcnt_t>((st.allocatedBytes ? st.allocatedBytes : st.size + 511) / 512);
        out->st_atime = static_cast<time_t>(st.atime);
        out->st_mtime = static_cast<time_t>(st.mtime);
        out->st_ctime = static_cast<time_t>(st.ctime);
    }

    static int opGetattr(const char* path, struct stat* out, struct fuse_file_info*) {
        auto& s = self();
        std::lock_guard lock(s.mutex);
        auto ino = s.inodeFor(path);
        if (!ino) return toErrno(ino.error());
        auto st = s.reader->stat(*ino);
        if (!st) return toErrno(st.error());
        fillStat(*st, out);
        return 0;
    }
    static int opReaddir(const char* path, void* buf, fuse_fill_dir_t fill, off_t, struct fuse_file_info*, enum fuse_readdir_flags) {
        auto& s = self();
        std::lock_guard lock(s.mutex);
        auto ino = s.inodeFor(path);
        if (!ino) return toErrno(ino.error());
        auto entries = s.reader->readdir(*ino);
        if (!entries) return toErrno(entries.error());
        fill(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        fill(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        for (const auto& e : *entries) {
            const std::string child = std::string(path) == "/" ? "/" + e.name : std::string(path) + "/" + e.name;
            s.cache[child] = e.inode;
            fill(buf, e.name.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        }
        return 0;
    }
    static int opOpen(const char* path, struct fuse_file_info* fi) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;
        auto& s = self();
        std::lock_guard lock(s.mutex);
        auto ino = s.inodeFor(path);
        if (!ino) return toErrno(ino.error());
        fi->fh = ino->id;
        fi->keep_cache = 1;
        return 0;
    }
    static int opRead(const char* path, char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
        auto& s = self();
        std::lock_guard lock(s.mutex);
        fs::Inode ino{fi ? fi->fh : 0};
        if (!fi) {
            auto r = s.inodeFor(path);
            if (!r) return toErrno(r.error());
            ino = *r;
        }
        auto n = s.reader->read(ino, static_cast<std::uint64_t>(off), std::span<std::byte>(reinterpret_cast<std::byte*>(buf), size));
        if (!n) return toErrno(n.error());
        return static_cast<int>(*n);
    }
    static int opReadlink(const char* path, char* buf, size_t size) {
        auto& s = self();
        std::lock_guard lock(s.mutex);
        auto ino = s.inodeFor(path);
        if (!ino) return toErrno(ino.error());
        auto t = s.reader->readlink(*ino);
        if (!t) return toErrno(t.error());
        std::strncpy(buf, t->c_str(), size - 1);
        buf[size - 1] = '\0';
        return 0;
    }
    static int opStatfs(const char*, struct statvfs* st) {
        std::memset(st, 0, sizeof *st);
        st->f_bsize = st->f_frsize = 4096;
        st->f_namemax = 255;
        return 0;
    }
};

bool Mount::available() {
    return ::access("/dev/fuse", R_OK | W_OK) == 0;
}

Expected<std::unique_ptr<Mount>> Mount::create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options) {
    if (!reader) return fail(ErrorCategory::InvalidArgument, "no reader");
    std::error_code ec;
    if (!std::filesystem::is_directory(mountpoint, ec)) return fail(ErrorCategory::NotFound, "mountpoint " + mountpoint.string() + " is not a directory");
    auto m = std::unique_ptr<Mount>(new Mount());
    m->m_impl = std::make_unique<Impl>();
    m->m_impl->reader = std::move(reader);
    m->m_mountpoint = mountpoint;
    auto& a = m->m_impl->args;
    fuse_opt_add_arg(&a, "stein");
    fuse_opt_add_arg(&a, "-o");
    fuse_opt_add_arg(&a, ("ro,fsname=" + options.fsName + ",subtype=stein" + (options.allowOther ? ",allow_other" : "")).c_str());
    if (options.debug) fuse_opt_add_arg(&a, "-d");
    static const fuse_operations ops = [] {
        fuse_operations o{};
        o.getattr = &Impl::opGetattr;
        o.readdir = &Impl::opReaddir;
        o.open = &Impl::opOpen;
        o.read = &Impl::opRead;
        o.readlink = &Impl::opReadlink;
        o.statfs = &Impl::opStatfs;
        return o;
    }();
    m->m_impl->fuse = fuse_new(&a, &ops, sizeof ops, m->m_impl.get());
    if (!m->m_impl->fuse) return fail(ErrorCategory::Internal, "fuse_new failed");
    if (fuse_mount(m->m_impl->fuse, mountpoint.c_str()) != 0) {
        fuse_destroy(m->m_impl->fuse);
        m->m_impl->fuse = nullptr;
        return fail(ErrorCategory::Permission, "cannot mount at " + mountpoint.string() + " (is fusermount3 available and /dev/fuse accessible?)");
    }
    m->m_impl->mounted = true;
    return m;
}

Expected<void> Mount::run() {
    if (!m_impl || !m_impl->fuse) return fail(ErrorCategory::InvalidArgument, "not mounted");
    m_impl->running.store(true);
    errno = 0;
    // Single-threaded: the readers are not thread-safe. The loop ends cleanly when the
    // kernel unmounts (fusermount3 -u, umount, stop()): libfuse maps ENODEV to a normal exit.
    const int rc = fuse_loop(m_impl->fuse);
    const int err = errno;
    m_impl->running.store(false);
    if (rc != 0 && !m_impl->stopRequested.load())
        return fail(ErrorCategory::Io, "fuse loop ended with " + std::to_string(rc) + (err ? std::string(": ") + std::strerror(err) : std::string()));
    return {};
}

bool Mount::running() const { return m_impl && m_impl->running.load(); }

void Mount::stop() {
    if (!m_impl || !m_impl->fuse) return;
    // fuse_exit() alone does not wake a loop blocked in read(): libfuse even drops a request it
    // reads after the exit flag is set, which would leave the requester waiting forever. Unmounting
    // aborts the kernel connection instead; the loop's read() then fails with ENODEV and returns.
    m_impl->stopRequested.store(true);
    fuse_session_exit(fuse_get_session(m_impl->fuse));
    if (m_impl->mounted) {
        fuse_unmount(m_impl->fuse);
        m_impl->mounted = false;
    }
}

Mount::~Mount() {
    if (m_impl && m_impl->fuse) {
        if (m_impl->mounted) fuse_unmount(m_impl->fuse);
        fuse_destroy(m_impl->fuse);
    }
    if (m_impl) fuse_opt_free_args(&m_impl->args);
}

} // namespace stein::mount
