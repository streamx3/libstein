// SPDX-License-Identifier: MIT
#pragma once

#include "stein/app/profile.hpp"
#include "stein/core/progress.hpp"
#include "stein/core/report.hpp"

namespace stein::app {

struct ResolvedTarget {
    platform::DiskInfo disk;           // identity as the platform reports it
    bool byPath = false;               // matched through osPath only (unlocked)
    bool isFile = false;               // a regular file stood in for a disk (tests, images)
};

struct RunOptions {
    std::string passphrase;            // for encrypted images (backup: required when image.encrypt)
    bool unlock = false;               // accept an osPath-only target despite policy.lockTarget
    bool dryRun = false;               // resolve and check, write nothing
    platform::Platform* platform = nullptr;   // override for tests; default platform::current()
};

struct ScenarioResult {
    Report report{"scenario"};
    std::optional<ResolvedTarget> target;
    std::optional<image::CreateResult> created;
    std::optional<image::RestoreResult> restored;
    std::optional<image::VerifyResult> verified;
    bool ok = false;
};

// Find the one disk the profile means. Fails when none or several match.
Expected<ResolvedTarget> resolveTarget(const Profile& profile, const RunOptions& options);

// What the Restore button should show before it is pressed.
struct Status {
    Expected<ResolvedTarget> target{fail(ErrorCategory::NotFound, "not resolved")};
    bool imageExists = false;
    bool imageComplete = false;
    ByteCount imageSourceBytes = 0;    // size of the disk the image was taken from
    std::string imageSourceName;
    std::string imageCreated;
    bool imageFitsTarget = false;
    std::vector<std::string> warnings;
};
Status status(const Profile& profile, const RunOptions& options);

Expected<ScenarioResult> backup(const Profile& profile, const RunOptions& options, Progress& progress);
Expected<ScenarioResult> restore(const Profile& profile, const RunOptions& options, Progress& progress);
Expected<ScenarioResult> verify(const Profile& profile, const RunOptions& options, Progress& progress);

// Text summary of a status for CLIs and dialogs.
std::string describe(const Profile& profile, const Status& status);

} // namespace stein::app
