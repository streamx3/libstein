// SPDX-License-Identifier: MIT
// macOS mount backend without a kext: serve the reader over NFSv3 on 127.0.0.1
// and let the system's own NFS client mount it (mount_nfs with explicit
// ports, so no portmapper or rpcbind is involved).
#include "stein/mount/mount.hpp"
#include "stein/mount/nfs_server.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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

} // namespace

struct Mount::Impl {
    std::unique_ptr<NfsServer> server;
    bool mounted = false;
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> running{false}, stopRequested{false};
    std::string mountpoint;

    void unmount() {
        if (!mounted) return;
        std::string out;
        if (runCapture({"/sbin/umount", mountpoint}, out) != 0) runCapture({"/usr/sbin/diskutil", "unmount", "force", mountpoint}, out);
        mounted = false;
    }
};

bool Mount::available() { return exists("/sbin/mount_nfs"); }

Expected<std::unique_ptr<Mount>> Mount::create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options) {
    if (!available()) return fail(ErrorCategory::Unsupported, "mount_nfs is not available on this system");
    std::error_code ec;
    if (!std::filesystem::is_directory(mountpoint, ec)) return fail(ErrorCategory::NotFound, "mountpoint " + mountpoint.string() + " is not a directory");
    std::unique_ptr<Mount> m(new Mount());
    m->m_mountpoint = mountpoint;
    m->m_impl = std::make_unique<Impl>();
    m->m_impl->mountpoint = mountpoint.string();
    auto server = NfsServer::start(std::move(reader));
    if (!server) return fail(server.error());
    m->m_impl->server = std::move(*server);
    const std::string port = std::to_string(m->m_impl->server->port());
    // vers=3,tcp with both ports explicit; locallocks keeps lockd out; soft+intr so a dead server
    // never hangs the client; noresvport since we are not root.
    std::string opts = "vers=3,tcp,port=" + port + ",mountport=" + port + ",locallocks,rdonly,soft,intr,noresvport,nosuid,nodev,rsize=131072,readahead=4";
    if (options.allowOther) opts += ",nobrowse";
    std::vector<std::string> argv{"/sbin/mount_nfs", "-o", opts, "127.0.0.1:/", mountpoint.string()};
    std::string out;
    const int rc = runCapture(argv, out);
    if (rc != 0) {
        m->m_impl->server->stop();
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
        return fail(ErrorCategory::Permission, "mount_nfs failed (" + std::to_string(rc) + "): " + out);
    }
    m->m_impl->mounted = true;
    return m;
}

Expected<void> Mount::run() {
    if (!m_impl || !m_impl->server) return fail(ErrorCategory::InvalidArgument, "not mounted");
    m_impl->running.store(true);
    std::unique_lock<std::mutex> lock(m_impl->mutex);
    m_impl->cv.wait(lock, [this] { return m_impl->stopRequested.load(); });
    lock.unlock();
    m_impl->unmount();
    m_impl->server->stop();
    m_impl->running.store(false);
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
