// SPDX-License-Identifier: MIT
#include "stein/platform/device_watcher.hpp"

#include <cerrno>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

namespace stein::platform {

namespace {

class LinuxDeviceWatcher final : public DeviceWatcher {
public:
    explicit LinuxDeviceWatcher(Callback cb) : m_callback(std::move(cb)) {}
    ~LinuxDeviceWatcher() override {
        stop();
        if (m_inotify >= 0) ::close(m_inotify);
        if (m_mounts >= 0) ::close(m_mounts);
        if (m_wake[0] >= 0) ::close(m_wake[0]);
        if (m_wake[1] >= 0) ::close(m_wake[1]);
    }

    Expected<void> start() {
        m_inotify = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_inotify < 0) return fail(ErrorCategory::Io, std::string("inotify_init1: ") + std::strerror(errno), errno);
        if (::inotify_add_watch(m_inotify, "/dev", IN_CREATE | IN_DELETE) < 0)
            return fail(ErrorCategory::Io, std::string("inotify_add_watch /dev: ") + std::strerror(errno), errno);
        m_mounts = ::open("/proc/self/mounts", O_RDONLY | O_CLOEXEC);   // POLLPRI when the mount table changes
        if (::pipe2(m_wake, O_CLOEXEC | O_NONBLOCK) != 0) return fail(ErrorCategory::Io, std::string("pipe2: ") + std::strerror(errno), errno);
        m_thread = std::thread([this] { run(); });
        return {};
    }

    void stop() override {
        if (!m_thread.joinable()) return;
        const char b = 1;
        (void)::write(m_wake[1], &b, 1);
        m_thread.join();
    }

private:
    void run() {
        char buf[4096];
        for (;;) {
            pollfd fds[3] = {{m_wake[0], POLLIN, 0}, {m_inotify, POLLIN, 0}, {m_mounts, POLLPRI, 0}};
            const int n = ::poll(fds, m_mounts >= 0 ? 3 : 2, -1);
            if (n < 0) {
                if (errno == EINTR) continue;
                return;
            }
            if (fds[0].revents) return;
            if (fds[1].revents & POLLIN) {
                const ssize_t got = ::read(m_inotify, buf, sizeof buf);
                for (ssize_t off = 0; off < got;) {
                    auto* ev = reinterpret_cast<const inotify_event*>(buf + off);
                    const std::string name = ev->len ? ev->name : "";
                    // Only block-device-looking names: sdX, nvmeXnY, mmcblkX, vdX, loopX, dm-X, md-X, srX.
                    const bool block = name.rfind("sd", 0) == 0 || name.rfind("nvme", 0) == 0 || name.rfind("mmcblk", 0) == 0 || name.rfind("vd", 0) == 0 ||
                                       name.rfind("loop", 0) == 0 || name.rfind("dm-", 0) == 0 || name.rfind("md", 0) == 0 || name.rfind("sr", 0) == 0 || name.rfind("nbd", 0) == 0;
                    if (block && m_callback) m_callback({(ev->mask & IN_DELETE) ? DeviceEvent::Kind::Disappeared : DeviceEvent::Kind::Appeared, name});
                    off += static_cast<ssize_t>(sizeof(inotify_event) + ev->len);
                }
            }
            if (m_mounts >= 0 && (fds[2].revents & (POLLPRI | POLLERR))) {
                // Re-arm: the kernel reports the change until the file is re-read.
                ::lseek(m_mounts, 0, SEEK_SET);
                while (::read(m_mounts, buf, sizeof buf) > 0) {}
                if (m_callback) m_callback({DeviceEvent::Kind::MountsChanged, ""});
            }
        }
    }

    Callback m_callback;
    std::thread m_thread;
    int m_inotify = -1, m_mounts = -1;
    int m_wake[2] = {-1, -1};
};

} // namespace

Expected<std::unique_ptr<DeviceWatcher>> DeviceWatcher::create(Callback callback) {
    auto w = std::make_unique<LinuxDeviceWatcher>(std::move(callback));
    if (auto r = w->start(); !r) return fail(r.error());
    return std::unique_ptr<DeviceWatcher>(std::move(w));
}

} // namespace stein::platform
