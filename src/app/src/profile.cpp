// SPDX-License-Identifier: MIT
#include "stein/app/profile.hpp"

#include "stein/core/strings.hpp"

#include <cmath>
#include <fstream>
#include <sstream>

namespace stein::app {

std::string_view toString(VerifyLevel v) {
    switch (v) {
    case VerifyLevel::None: return "none";
    case VerifyLevel::Structure: return "structure";
    case VerifyLevel::Checksums: return "checksums";
    case VerifyLevel::Full: return "full";
    }
    return "?";
}

std::optional<VerifyLevel> parseVerifyLevel(std::string_view s) {
    const std::string l = toLower(s);
    if (l == "none" || l == "off" || l == "false") return VerifyLevel::None;
    if (l == "structure" || l == "1") return VerifyLevel::Structure;
    if (l == "checksums" || l == "payload" || l == "2") return VerifyLevel::Checksums;
    if (l == "full" || l == "content" || l == "3") return VerifyLevel::Full;
    return std::nullopt;
}

bool TargetSelector::matchesIdentity(const platform::DiskInfo& disk) const {
    if (!hasIdentity()) return false;
    if (!serial.empty() && toLower(trim(serial)) != toLower(trim(disk.serial))) return false;
    if (!wwn.empty() && toLower(trim(wwn)) != toLower(trim(disk.wwn))) return false;
    if (!model.empty() && toLower(disk.model).find(toLower(trim(model))) == std::string::npos) return false;
    if (sizeBytes) {
        const double want = static_cast<double>(*sizeBytes);
        const double have = static_cast<double>(disk.geometry.sizeBytes);
        if (std::fabs(have - want) > want * sizeTolerance) return false;
    }
    if (!allowRemovable && disk.removable) return false;
    if (!allowVirtual && disk.isVirtual) return false;
    return true;
}

namespace {

// "4M", "2G", "4194304"
Expected<ByteCount> parseBytes(const json::Value& v, ByteCount def) {
    if (v.isNull()) return def;
    if (v.isNumber()) return ByteCount{v.asUInt()};
    if (!v.isString()) return fail(ErrorCategory::InvalidFormat, "size must be a number or a string like \"4M\"");
    const std::string& s = v.asString();
    char* end = nullptr;
    const double n = std::strtod(s.c_str(), &end);
    if (end == s.c_str()) return fail(ErrorCategory::InvalidFormat, "bad size: " + s);
    const std::string unit = toLower(trim(std::string(end)));
    ByteCount mult = 1;
    if (unit == "k" || unit == "kib") mult = KiB;
    else if (unit == "m" || unit == "mib") mult = MiB;
    else if (unit == "g" || unit == "gib") mult = GiB;
    else if (unit == "t" || unit == "tib") mult = TiB;
    else if (unit == "kb") mult = 1000;
    else if (unit == "mb") mult = 1000 * 1000;
    else if (unit == "gb") mult = 1000ull * 1000 * 1000;
    else if (unit == "tb") mult = 1000ull * 1000 * 1000 * 1000;
    else if (!unit.empty() && unit != "b") return fail(ErrorCategory::InvalidFormat, "bad size unit: " + s);
    return static_cast<ByteCount>(n * static_cast<double>(mult));
}

} // namespace

Expected<Profile> Profile::fromJson(const json::Value& v) {
    if (!v.isObject()) return fail(ErrorCategory::InvalidFormat, "profile must be a JSON object");
    Profile p;
    p.name = v.get("name").asString();
    p.description = v.get("description").asString();
    const auto& t = v.get("target");
    p.target.serial = t.get("serial").asString();
    p.target.wwn = t.get("wwn").asString();
    p.target.model = t.get("model").asString();
    if (t.has("size")) {
        auto s = parseBytes(t.get("size"), 0);
        if (!s) return fail(s.error());
        p.target.sizeBytes = *s;
    }
    p.target.sizeTolerance = t.get("size_tolerance").asDouble(0.0);
    p.target.osPath = t.get("path").asString();
    p.target.allowRemovable = t.get("allow_removable").asBool(true);
    p.target.allowVirtual = t.get("allow_virtual").asBool(false);
    const auto& im = v.get("image");
    p.image.path = im.get("path").asString();
    if (im.has("compression")) {
        auto c = image::compressionFromString(im.get("compression").asString());
        if (!c) return fail(ErrorCategory::InvalidFormat, "unknown compression: " + im.get("compression").asString());
        p.image.compression = *c;
    }
    auto chunk = parseBytes(im.get("chunk_size"), 4 * MiB);
    if (!chunk) return fail(chunk.error());
    p.image.chunkSize = static_cast<std::uint32_t>(*chunk);
    auto split = parseBytes(im.get("split_size"), 0);
    if (!split) return fail(split.error());
    p.image.splitSize = *split;
    const auto& po = v.get("policy");
    p.policy.lockTarget = po.get("lock_target").asBool(true);
    p.policy.requireElevated = po.get("require_elevated").asBool(false);
    p.policy.allowSmallerTarget = po.get("allow_smaller_target").asBool(false);
    if (po.has("verify_before_restore")) {
        auto lv = parseVerifyLevel(po.get("verify_before_restore").asString());
        if (!lv) return fail(ErrorCategory::InvalidFormat, "bad verify_before_restore: " + po.get("verify_before_restore").asString());
        p.policy.verifyBeforeRestore = *lv;
    }
    p.policy.verifyAfterRestore = po.get("verify_after_restore").asBool(true);
    p.policy.verifyAfterBackup = po.get("verify_after_backup").asBool(true);
    p.policy.rereadPartitionTable = po.get("reread_partition_table").asBool(true);
    for (const auto& n : v.get("notes").asArray()) p.notes.push_back(n.asString());
    if (auto ok = p.validate(); !ok) return fail(ok.error());
    return p;
}

json::Value Profile::toJson() const {
    json::Value v = json::Value::object();
    v.set("name", name);
    if (!description.empty()) v.set("description", description);
    json::Value t = json::Value::object();
    if (!target.serial.empty()) t.set("serial", target.serial);
    if (!target.wwn.empty()) t.set("wwn", target.wwn);
    if (!target.model.empty()) t.set("model", target.model);
    if (target.sizeBytes) t.set("size", *target.sizeBytes);
    if (target.sizeTolerance > 0) t.set("size_tolerance", target.sizeTolerance);
    if (!target.osPath.empty()) t.set("path", target.osPath);
    t.set("allow_removable", target.allowRemovable);
    t.set("allow_virtual", target.allowVirtual);
    v.set("target", std::move(t));
    json::Value im = json::Value::object();
    im.set("path", image.path.string());
    im.set("compression", std::string(image::toString(image.compression)));
    im.set("chunk_size", static_cast<std::uint64_t>(image.chunkSize));
    im.set("split_size", image.splitSize);
    v.set("image", std::move(im));
    json::Value po = json::Value::object();
    po.set("lock_target", policy.lockTarget);
    po.set("require_elevated", policy.requireElevated);
    po.set("allow_smaller_target", policy.allowSmallerTarget);
    po.set("verify_before_restore", std::string(toString(policy.verifyBeforeRestore)));
    po.set("verify_after_restore", policy.verifyAfterRestore);
    po.set("verify_after_backup", policy.verifyAfterBackup);
    po.set("reread_partition_table", policy.rereadPartitionTable);
    v.set("policy", std::move(po));
    if (!notes.empty()) {
        json::Value n = json::Value::array();
        for (const auto& s : notes) n.push(s);
        v.set("notes", std::move(n));
    }
    return v;
}

Expected<Profile> Profile::load(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return fail(ErrorCategory::NotFound, "cannot open profile " + file.string());
    std::stringstream ss;
    ss << in.rdbuf();
    auto v = json::Value::parse(ss.str());
    if (!v) return fail(Error(ErrorCategory::InvalidFormat, file.string() + ": " + v.error().message()));
    auto p = fromJson(*v);
    if (!p) return fail(Error(p.error().category(), file.string() + ": " + p.error().message()));
    return p;
}

Expected<void> Profile::save(const std::filesystem::path& file) const {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) return fail(ErrorCategory::Io, "cannot write profile " + file.string());
    out << toJson().dump(2) << '\n';
    if (!out) return fail(ErrorCategory::Io, "write failed: " + file.string());
    return {};
}

Expected<void> Profile::validate() const {
    if (image.path.empty()) return fail(ErrorCategory::InvalidArgument, "profile has no image.path");
    if (!target.hasIdentity() && target.osPath.empty()) return fail(ErrorCategory::InvalidArgument, "profile target needs an identity (serial/wwn/model/size) or a path");
    if (image.chunkSize < 64 * KiB || image.chunkSize > 64 * MiB || (image.chunkSize & (image.chunkSize - 1)))
        return fail(ErrorCategory::InvalidArgument, "image.chunk_size must be a power of two between 64K and 64M");
    if (image.splitSize && image.splitSize < image.chunkSize) return fail(ErrorCategory::InvalidArgument, "image.split_size smaller than a chunk");
    if (target.sizeTolerance < 0 || target.sizeTolerance > 0.5) return fail(ErrorCategory::InvalidArgument, "target.size_tolerance must be within 0..0.5");
    return {};
}

} // namespace stein::app
