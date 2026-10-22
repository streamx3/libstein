// SPDX-License-Identifier: MIT
// macOS mount backend without a kext: serve the reader over NFSv3 on 127.0.0.1
// and let the system's own NFS client mount it (mount_nfs with explicit
// ports, so no portmapper or rpcbind is involved). The export is named after
// MountOptions::fsName ("127.0.0.1:/<name>"), which is what Finder shows.
#include "stein/mount/mount.hpp"
#include "stein/mount/nfs_server.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace stein::mount {

namespace {

// Run a program and return its exit status; stdout/stderr collected into `out`.
int runCapture(const std::vector<std::string>& argv, std::string& out) {
    int fds[2];
    if (::pipe(fds) != 0) return -1;
    const pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        ::dup2(fds[1], 1);
        ::dup2(fds[1], 2);
        ::close(fds[0]);
        ::close(fds[1]);
        std::vector<char*> args;
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        ::execv(argv[0].c_str(), args.data());
        _exit(127);
    }
    ::close(fds[1]);
    char buf[512];
    for (;;) {
        const auto n = ::read(fds[0], buf, sizeof buf);
        if (n <= 0) break;
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fds[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool exists(const char* p) {
    struct stat st;
    return ::stat(p, &st) == 0;
}

// The export path mount_nfs is given after "host:". The characters that would change the
// meaning of the argument go ("/" would nest, ":" splits host from path, so would control
// characters in the mount table); the name is trimmed, capped and never empty.
std::string exportPathFor(const std::string& fsName) {
    std::string name;
    for (unsigned char c : fsName) name.push_back(c < 0x20 || c == 0x7f || c == '/' || c == ':' ? '_' : static_cast<char>(c));
    while (!name.empty() && (name.front() == ' ' || name.front() == '.')) name.erase(name.begin());
    while (!name.empty() && name.back() == ' ') name.pop_back();
    if (name.size() > 255) name.resize(255);
    if (name.empty()) name = "stein";
    return "/" + name;
}

// Is `realMountpoint` still an NFS mount? getfsstat with MNT_NOWAIT reads the kernel's mount
// table without asking the servers (ours included) for fresh statistics, and unlike
// getmntinfo() it has no static buffer, so several mounts may poll at the same time.
bool mountedAt(const std::string& realMountpoint) {
    int n = ::getfsstat(nullptr, 0, MNT_NOWAIT);
    if (n <= 0) return false;
    std::vector<struct statfs> entries(static_cast<std::size_t>(n) + 8);   // room for mounts made meanwhile
    n = ::getfsstat(entries.data(), static_cast<int>(entries.size() * sizeof(struct statfs)), MNT_NOWAIT);
    for (int i = 0; i < n; ++i) {
        const auto& e = entries[static_cast<std::size_t>(i)];
        if (realMountpoint == e.f_mntonname) return std::strcmp(e.f_fstypename, "nfs") == 0;
    }
    return false;
}

} // namespace

struct Mount::Impl {
    std::unique_ptr<NfsServer> server;
    std::atomic<bool> mounted{false};
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> running{false}, stopRequested{false}, unmountHint{false};
    std::string mountpoint;       // as given
    std::string realMountpoint;   // as the mount table spells it

    void unmount() {
        if (!mounted.exchange(false)) return;
        std::string out;
        if (runCapture({"/sbin/umount", mountpoint}, out) != 0) runCapture({"/usr/sbin/diskutil", "unmount", "force", mountpoint}, out);
    }
};

bool Mount::available() { return exists("/sbin/mount_nfs"); }

Expected<std::unique_ptr<Mount>> Mount::create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options) {
    if (!available()) return fail(ErrorCategory::Unsupported, "mount_nfs is not available on this system");
    std::error_code ec;
    if (!std::filesystem::is_directory(mountpoint, ec)) return fail(ErrorCategory::NotFound, "mountpoint " + mountpoint.string() + " is not a directory");
    // The mount table records the resolved path (/tmp is /private/tmp), which run() compares against.
    const auto real = std::filesystem::canonical(mountpoint, ec);
    if (ec) return fail(ErrorCategory::NotFound, "cannot resolve mountpoint " + mountpoint.string() + ": " + ec.message());
    std::unique_ptr<Mount> m(new Mount());
    m->m_mountpoint = mountpoint;
    m->m_impl = std::make_unique<Impl>();
    m->m_impl->mountpoint = mountpoint.string();
    m->m_impl->realMountpoint = real.string();
    NfsServerOptions so;
    so.exportPath = exportPathFor(options.fsName);
    // The kernel sends UMNT while it takes the mount down: wake run() so it notices at once.
    // The server is stopped (threads joined) before Impl goes away, so the raw pointer holds.
    Impl* impl = m->m_impl.get();
    so.onUnmount = [impl] {
        impl->unmountHint.store(true);
        impl->cv.notify_all();
    };
    auto server = NfsServer::start(std::move(reader), so);
    if (!server) return fail(server.error());
    m->m_impl->server = std::move(*server);
    const std::string port = std::to_string(m->m_impl->server->port());
    // vers=3,tcp with both ports explicit; locallocks keeps lockd out; soft+intr so a dead server
    // never hangs the client; noresvport since we are not root. No nobrowse: the volume is meant
    // to show in Finder, under the export name.
    const std::string opts = "vers=3,tcp,port=" + port + ",mountport=" + port + ",locallocks,rdonly,soft,intr,noresvport,nosuid,nodev,rsize=131072,readahead=4";
    std::vector<std::string> argv{"/sbin/mount_nfs", "-o", opts, "127.0.0.1:" + so.exportPath, mountpoint.string()};
    std::string out;
    const int rc = runCapture(argv, out);
    if (rc != 0) {
        m->m_impl->server->stop();
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
        return fail(ErrorCategory::Permission, "mount_nfs failed (" + std::to_string(rc) + "): " + out);
    }
    m->m_impl->mounted.store(true);
    return m;
}

Expected<void> Mount::run() {
    if (!m_impl || !m_impl->server) return fail(ErrorCategory::InvalidArgument, "not mounted");
    Impl& im = *m_impl;
    im.running.store(true);
    bool gone = false;
    for (;;) {
        bool hinted = false;
        {
            std::unique_lock<std::mutex> lock(im.mutex);
            // Wake once a second to look at the mount table, sooner when the client said UMNT.
            im.cv.wait_for(lock, std::chrono::seconds(1), [&] { return im.stopRequested.load() || im.unmountHint.load(); });
            if (im.stopRequested.load()) break;
            hinted = im.unmountHint.exchange(false);
        }
        // UMNT arrives while the kernel is still taking the mount down: after one, look again
        // for up to two seconds instead of waiting for the next tick.
        for (int i = 0; i < (hinted ? 40 : 1) && !im.stopRequested.load(); ++i) {
            if (i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!mountedAt(im.realMountpoint)) {
                gone = true;
                break;
            }
        }
        if (gone) break;
    }
    if (gone) im.mounted.store(false);   // somebody else unmounted it; nothing of ours is left there
    else im.unmount();
    im.server->stop();
    im.running.store(false);
    return {};
}

bool Mount::running() const { return m_impl && m_impl->running.load(); }

void Mount::stop() {
    if (!m_impl) return;
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->stopRequested.store(true);
    }
    m_impl->cv.notify_all();
    if (!m_impl->running.load()) {
        m_impl->unmount();
        if (m_impl->server) m_impl->server->stop();
    }
}

Mount::~Mount() {
    if (m_impl) {
        m_impl->unmount();
        if (m_impl->server) m_impl->server->stop();
    }
}

} // namespace stein::mount
