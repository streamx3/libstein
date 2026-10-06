// SPDX-License-Identifier: MIT
// Placeholder for platforms without an implementation yet (macOS, Windows):
// raw devices are unsupported, everything else answers honestly.
#include "stein/platform/platform.hpp"

namespace stein::platform {

namespace {

class GenericPlatform final : public Platform {
public:
    std::string_view name() const override { return "generic"; }
    Expected<std::vector<DiskInfo>> enumerate() override { return std::vector<DiskInfo>{}; }
    Expected<DiskInfo> describe(const std::string& p) override {
        return fail(ErrorCategory::Unsupported, "raw device access is not implemented on this platform yet: " + p);
    }
    Expected<std::shared_ptr<BlockDevice>> open(const std::string& p, OpenMode) override {
        return fail(ErrorCategory::Unsupported, "raw device access is not implemented on this platform yet: " + p);
    }
    Expected<std::vector<MountInfo>> mounts(const std::string&) override { return std::vector<MountInfo>{}; }
    Expected<void> unmount(const MountInfo&, bool) override { return fail(ErrorCategory::Unsupported, "not implemented"); }
    Expected<void> rereadPartitionTable(const std::string&) override { return fail(ErrorCategory::Unsupported, "not implemented"); }
    Expected<AttachedImage> attach(const std::filesystem::path&, const AttachOptions&) override {
        return fail(ErrorCategory::Unsupported, "image attach is not implemented on this platform yet");
    }
    Expected<void> detach(const AttachedImage&) override { return fail(ErrorCategory::Unsupported, "not implemented"); }
    bool isElevated() const override { return false; }
};

} // namespace

Platform& current() {
    static GenericPlatform instance;
    return instance;
}

} // namespace stein::platform
