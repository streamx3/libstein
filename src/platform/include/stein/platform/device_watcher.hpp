// SPDX-License-Identifier: MIT
// Tells the caller when the OS's view of block devices changes: a disk appears
// or disappears, a volume is mounted or unmounted. The watcher runs its own
// thread and calls back from it; callers marshal to their own loop and should
// debounce (the OS sends several events per plug). Per platform:
//   macOS   DiskArbitration (appeared / disappeared / description changed) on a
//           private CFRunLoop
//   Linux   inotify on /dev for device nodes, poll(POLLPRI) on /proc/self/mounts
//           for the mount table; no libudev
//   Windows RegisterDeviceNotification for disk and volume interfaces on a
//           message-only window
// Other platforms: create() fails with Unsupported.
#pragma once

#include "stein/core/error.hpp"

#include <functional>
#include <memory>
#include <string>

namespace stein::platform {

struct DeviceEvent {
    enum class Kind { Appeared, Disappeared, Changed, MountsChanged };
    Kind kind = Kind::Changed;
    std::string device;   // "disk4", "sdb", a device interface path; empty when the OS gives none
};

class DeviceWatcher {
public:
    using Callback = std::function<void(const DeviceEvent&)>;
    virtual ~DeviceWatcher() = default;
    // Starts watching; the callback runs on the watcher's thread until stop() or destruction.
    static Expected<std::unique_ptr<DeviceWatcher>> create(Callback callback);
    virtual void stop() = 0;
};

std::string_view toString(DeviceEvent::Kind kind);

} // namespace stein::platform
