// SPDX-License-Identifier: MIT
// Profiles: what dr_stein's config.ini becomes. A profile names a target disk
// by durable identity (serial / WWN / model / size), an image location and
// format, verification and safety policy. Scenarios (backup, restore, verify)
// are driven by it. See doc/research/04-dr-stein.md and design/10 §stein_app.
#pragma once

#include "stein/core/error.hpp"
#include "stein/core/json.hpp"
#include "stein/core/units.hpp"
#include "stein/image/operations.hpp"
#include "stein/platform/platform.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace stein::app {

// How a target disk is recognised. Every non-empty field must match
// (serial and WWN exactly, model as a case-insensitive substring, size within
// `sizeTolerance`). `osPath` alone is accepted only when the caller unlocks
// path matching: paths change, identities do not.
struct TargetSelector {
    std::string serial;
    std::string wwn;
    std::string model;
    std::optional<ByteCount> sizeBytes;
    double sizeTolerance = 0.0;        // 0.02 = ±2 %
    std::string osPath;                // last resort / regular files for testing
    bool allowRemovable = true;
    bool allowVirtual = false;         // loop/VHD/etc. (tests set this)

    bool hasIdentity() const { return !serial.empty() || !wwn.empty() || !model.empty() || sizeBytes.has_value(); }
    // True when `disk` satisfies every identity field set here (ignores osPath).
    bool matchesIdentity(const platform::DiskInfo& disk) const;
};

enum class VerifyLevel : std::uint8_t { None, Structure, Checksums, Full };
std::string_view toString(VerifyLevel v);
std::optional<VerifyLevel> parseVerifyLevel(std::string_view s);

struct ImageSpec {
    std::filesystem::path path;        // the .stein file (first segment)
    image::Compression compression = image::Compression::Lz4;
    std::uint32_t chunkSize = 4 * MiB;
    ByteCount splitSize = 0;
    bool usedOnly = true;              // skip free space of filesystems with readable allocation bitmaps
    bool encrypt = false;              // the passphrase is never stored; RunOptions::passphrase supplies it
    std::uint32_t kdfIterations = 600000;
};

struct Policy {
    bool lockTarget = true;            // refuse osPath-only targets unless unlocked
    bool requireElevated = false;      // scenarios fail early without root/Administrator
    bool allowSmallerTarget = false;   // restore to a smaller disk writes what fits
    VerifyLevel verifyBeforeRestore = VerifyLevel::Checksums;
    bool verifyAfterRestore = true;    // re-read the target and compare chunk CRCs
    bool verifyAfterBackup = true;
    bool rereadPartitionTable = true;
    bool repairTableAfterRestore = true;   // larger target: move the GPT backup to the new end
    bool unmountTarget = true;             // unmount the target's volumes before writing (else refuse while mounted)
};

struct Profile {
    std::string name;
    std::string description;
    TargetSelector target;
    ImageSpec image;
    Policy policy;
    std::vector<std::string> notes;

    static Expected<Profile> fromJson(const json::Value& v);
    json::Value toJson() const;
    static Expected<Profile> load(const std::filesystem::path& file);
    Expected<void> save(const std::filesystem::path& file) const;
    // Reject nonsense before anything runs (no image path, no target at all, ...).
    Expected<void> validate() const;
};

} // namespace stein::app
