// SPDX-License-Identifier: MIT
#include "stein/platform/device_watcher.hpp"

namespace stein::platform {

std::string_view toString(DeviceEvent::Kind kind) {
    switch (kind) {
    case DeviceEvent::Kind::Appeared: return "appeared";
    case DeviceEvent::Kind::Disappeared: return "disappeared";
    case DeviceEvent::Kind::Changed: return "changed";
    case DeviceEvent::Kind::MountsChanged: return "mounts changed";
    }
    return "?";
}

#if !defined(__APPLE__) && !defined(__linux__) && !defined(_WIN32)
Expected<std::unique_ptr<DeviceWatcher>> DeviceWatcher::create(Callback) {
    return fail(ErrorCategory::Unsupported, "no device watcher on this platform");
}
#endif

} // namespace stein::platform
