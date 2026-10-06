// SPDX-License-Identifier: MIT
// Placeholder when no mount backend is compiled in (macOS without macFUSE, Windows without WinFsp).
#include "stein/mount/mount.hpp"

namespace stein::mount {

struct Mount::Impl {};
bool Mount::available() { return false; }
Expected<std::unique_ptr<Mount>> Mount::create(std::unique_ptr<fs::Reader>, const std::filesystem::path&, const MountOptions&) {
    return fail(ErrorCategory::Unsupported, "no mount backend on this platform yet (use stein ls/cat/cp)");
}
Expected<void> Mount::run() { return fail(ErrorCategory::Unsupported, "no mount backend"); }
void Mount::stop() {}
bool Mount::running() const { return false; }
Mount::~Mount() = default;

} // namespace stein::mount
