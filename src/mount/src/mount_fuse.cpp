// SPDX-License-Identifier: MIT
// libfuse3 on Linux; on Windows the same code targets WinFsp's fuse3 layer
// (winfsp-x64.dll, delay-loaded so the binary starts without it).
#define FUSE_USE_VERSION 31
#include "stein/mount/mount.hpp"

#include "stein/core/strings.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fuse3/fuse.h>
#include <fcntl.h>
#else
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>

#ifndef O_ACCMODE
#define O_ACCMODE 3
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef EROFS
#define EROFS 30
#endif

namespace stein::mount {

#if defined(_WIN32)
using StatT = fuse_stat;        // WinFsp spells these without the struct tag being usable in an elaborated specifier
using StatvfsT = fuse_statvfs;
using OffT = fuse_off_t;
#else
using StatT = struct stat;
using StatvfsT = struct statvfs;
using OffT = off_t;
#endif

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
    static void fillStat(const fs::Stat& st, StatT* out) {
        std::memset(out, 0, sizeof *out);
        unsigned type = S_IFREG;
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
        unsigned perm = (st.mode ? st.mode : 0644) & 0555;
        if (type == S_IFDIR) perm |= 0555;
        if (type == S_IFLNK) perm = 0777;
        out->st_mode = type | perm;
        out->st_nlink = static_cast<decltype(out->st_nlink)>(st.nlink ? st.nlink : 1);
        out->st_size = static_cast<OffT>(st.size);
        const fuse_context* ctx = fuse_get_context();
        out->st_uid = ctx ? ctx->uid : 0;
        out->st_gid = ctx ? ctx->gid : 0;
        out->st_blksize = 4096;
        out->st_blocks = static_cast<decltype(out->st_blocks)>((st.allocatedBytes ? st.allocatedBytes : st.size + 511) / 512);
        out->st_atim.tv_sec = static_cast<decltype(out->st_atim.tv_sec)>(st.atime);
        out->st_mtim.tv_sec = static_cast<decltype(out->st_mtim.tv_sec)>(st.mtime);
        out->st_ctim.tv_sec = static_cast<decltype(out->st_ctim.tv_sec)>(st.ctime);
    }

    static int opGetattr(const char* path, StatT* out, struct fuse_file_info*) {
        auto& s = self();
        std::lock_guard lock(s.mutex);
        auto ino = s.inodeFor(path);
        if (!ino) return toErrno(ino.error());
        auto st = s.reader->stat(*ino);
        if (!st) return toErrno(st.error());
        fillStat(*st, out);
        return 0;
    }
    static int opReaddir(const char* path, void* buf, fuse_fill_dir_t fill, OffT, struct fuse_file_info*, enum fuse_readdir_flags) {
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
    static int opRead(const char* path, char* buf, size_t size, OffT off, struct fuse_file_info* fi) {
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
    static int opStatfs(const char*, StatvfsT* st) {
        std::memset(st, 0, sizeof *st);
        st->f_bsize = st->f_frsize = 4096;
        st->f_namemax = 255;
        return 0;
    }
};

#if defined(_WIN32)
namespace {
// What WinFsp's FspLoad() does: find the install directory in the registry and load the DLL
// from there, so the delay-loaded import resolves against the already-loaded module.
bool loadWinFsp() {
    static bool loaded = [] {
        for (const wchar_t* key : {L"SOFTWARE\\WOW6432Node\\WinFsp", L"SOFTWARE\\WinFsp"}) {
            wchar_t dir[MAX_PATH] = {};
            DWORD size = sizeof dir;
            if (RegGetValueW(HKEY_LOCAL_MACHINE, key, L"InstallDir", RRF_RT_REG_SZ, nullptr, dir, &size) != ERROR_SUCCESS) continue;
            std::wstring path = dir;
            if (!path.empty() && path.back() != L'\\') path += L'\\';
            path += sizeof(void*) == 8 ? L"bin\\winfsp-x64.dll" : L"bin\\winfsp-x86.dll";
            if (LoadLibraryW(path.c_str())) return true;
        }
        return LoadLibraryW(L"winfsp-x64.dll") != nullptr;
    }();
    return loaded;
}
} // namespace
#endif

bool Mount::available() {
#if defined(_WIN32)
    return loadWinFsp();
#else
    return ::access("/dev/fuse", R_OK | W_OK) == 0;
#endif
}

Expected<std::unique_ptr<Mount>> Mount::create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options) {
    if (!reader) return fail(ErrorCategory::InvalidArgument, "no reader");
    std::error_code ec;
#if defined(_WIN32)
    // WinFsp mounts on a free drive letter ("X:") or on a directory that does not exist yet.
    const std::string mp = mountpoint.string();
    const bool driveLetter = mp.size() == 2 && mp[1] == ':' && std::isalpha(static_cast<unsigned char>(mp[0]));
    if (!driveLetter && std::filesystem::exists(mountpoint, ec)) return fail(ErrorCategory::InvalidArgument, "mountpoint " + mp + " exists; WinFsp needs a free drive letter or an absent directory");
#else
    if (!std::filesystem::is_directory(mountpoint, ec)) return fail(ErrorCategory::NotFound, "mountpoint " + mountpoint.string() + " is not a directory");
#endif
    auto m = std::unique_ptr<Mount>(new Mount());
    m->m_impl = std::make_unique<Impl>();
    m->m_impl->reader = std::move(reader);
    m->m_mountpoint = mountpoint;
    auto& a = m->m_impl->args;
    fuse_opt_add_arg(&a, "stein");
    fuse_opt_add_arg(&a, "-o");
#if defined(_WIN32)
    // uid/gid -1: present files as owned by the mounting user; volname shows in Explorer.
    fuse_opt_add_arg(&a, ("ro,uid=-1,gid=-1,volname=" + options.fsName + ",FileSystemName=stein").c_str());
#else
    fuse_opt_add_arg(&a, ("ro,fsname=" + options.fsName + ",subtype=stein" + (options.allowOther ? ",allow_other" : "")).c_str());
#endif
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
#if defined(_WIN32)
    if (!loadWinFsp()) return fail(ErrorCategory::Unsupported, "WinFsp is not installed (https://winfsp.dev)");
#endif
    const std::string mountpointText = mountpoint.string();
    if (fuse_mount(m->m_impl->fuse, mountpointText.c_str()) != 0) {
        fuse_destroy(m->m_impl->fuse);
        m->m_impl->fuse = nullptr;
#if defined(_WIN32)
        return fail(ErrorCategory::Permission, "cannot mount at " + mountpoint.string() + " (is WinFsp installed and the mount point a free drive letter or an absent directory?)");
#else
        return fail(ErrorCategory::Permission, "cannot mount at " + mountpoint.string() + " (is fusermount3 available and /dev/fuse accessible?)");
#endif
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
#if defined(_WIN32)
    // WinFsp's fuse_unmount() frees the file system object the loop was using, so it must run
    // after the loop has returned (stop() only signals the exit event there).
    if (m_impl->mounted) {
        fuse_unmount(m_impl->fuse);
        m_impl->mounted = false;
    }
#endif
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
#if defined(_WIN32)
    // WinFsp: fuse_exit() signals the loop's event; the loop thread stops the dispatcher and
    // run() unmounts afterwards. Unmounting here would free the object the loop still uses.
    fuse_exit(m_impl->fuse);
#else
    fuse_session_exit(fuse_get_session(m_impl->fuse));
    if (m_impl->mounted) {
        fuse_unmount(m_impl->fuse);
        m_impl->mounted = false;
    }
#endif
}

Mount::~Mount() {
    if (m_impl && m_impl->fuse) {
        if (m_impl->mounted) fuse_unmount(m_impl->fuse);
        fuse_destroy(m_impl->fuse);
    }
    if (m_impl) fuse_opt_free_args(&m_impl->args);
}

} // namespace stein::mount
