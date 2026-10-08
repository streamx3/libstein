// SPDX-License-Identifier: MIT
#include "stein/platform/device_watcher.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace stein::platform {

namespace {

class MacDeviceWatcher final : public DeviceWatcher {
public:
    explicit MacDeviceWatcher(Callback cb) : m_callback(std::move(cb)) {}
    ~MacDeviceWatcher() override { stop(); }

    Expected<void> start() {
        m_thread = std::thread([this] { run(); });
        std::unique_lock lock(m_mutex);
        m_ready.wait(lock, [this] { return m_started; });
        if (!m_loop) {
            m_thread.join();
            return fail(ErrorCategory::Internal, "DiskArbitration session could not be created");
        }
        return {};
    }

    void stop() override {
        {
            std::lock_guard lock(m_mutex);
            if (!m_loop || m_stopped) return;
            m_stopped = true;
            CFRunLoopStop(m_loop);
        }
        if (m_thread.joinable()) m_thread.join();
    }

private:
    static std::string bsdName(DADiskRef disk) {
        const char* name = DADiskGetBSDName(disk);
        return name ? name : "";
    }
    static void onAppeared(DADiskRef disk, void* ctx) { static_cast<MacDeviceWatcher*>(ctx)->emit({DeviceEvent::Kind::Appeared, bsdName(disk)}); }
    static void onDisappeared(DADiskRef disk, void* ctx) { static_cast<MacDeviceWatcher*>(ctx)->emit({DeviceEvent::Kind::Disappeared, bsdName(disk)}); }
    static void onChanged(DADiskRef disk, CFArrayRef keys, void* ctx) {
        // A change of the volume path is a mount or an unmount; anything else is a description change.
        bool mount = false;
        if (keys)
            for (CFIndex i = 0; i < CFArrayGetCount(keys); ++i)
                if (CFEqual(CFArrayGetValueAtIndex(keys, i), kDADiskDescriptionVolumePathKey)) mount = true;
        static_cast<MacDeviceWatcher*>(ctx)->emit({mount ? DeviceEvent::Kind::MountsChanged : DeviceEvent::Kind::Changed, bsdName(disk)});
    }
    void emit(const DeviceEvent& e) {
        // DiskArbitration replays every present disk right after registration; that is not a change.
        if (m_replaying) return;
        if (m_callback) m_callback(e);
    }

    void run() {
        DASessionRef session = DASessionCreate(kCFAllocatorDefault);
        {
            std::lock_guard lock(m_mutex);
            m_loop = session ? CFRunLoopGetCurrent() : nullptr;
            m_started = true;
        }
        m_ready.notify_all();
        if (!session) return;
        DARegisterDiskAppearedCallback(session, nullptr, onAppeared, this);
        DARegisterDiskDisappearedCallback(session, nullptr, onDisappeared, this);
        DARegisterDiskDescriptionChangedCallback(session, nullptr, nullptr, onChanged, this);
        DASessionScheduleWithRunLoop(session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        // Let the registration replay drain, then start reporting.
        m_replaying = true;
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, false);
        m_replaying = false;
        CFRunLoopRun();
        DAUnregisterCallback(session, reinterpret_cast<void*>(onAppeared), this);
        DAUnregisterCallback(session, reinterpret_cast<void*>(onDisappeared), this);
        DAUnregisterCallback(session, reinterpret_cast<void*>(onChanged), this);
        DASessionUnscheduleFromRunLoop(session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        CFRelease(session);
    }

    Callback m_callback;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_ready;
    CFRunLoopRef m_loop = nullptr;
    bool m_started = false, m_stopped = false;
    std::atomic<bool> m_replaying{false};
};

} // namespace

Expected<std::unique_ptr<DeviceWatcher>> DeviceWatcher::create(Callback callback) {
    auto w = std::make_unique<MacDeviceWatcher>(std::move(callback));
    if (auto r = w->start(); !r) return fail(r.error());
    return std::unique_ptr<DeviceWatcher>(std::move(w));
}

} // namespace stein::platform
