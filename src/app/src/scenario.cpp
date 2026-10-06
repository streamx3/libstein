// SPDX-License-Identifier: MIT
#include "stein/app/scenario.hpp"

#include "stein/block/file_device.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"
#include "stein/pt/partition_table.hpp"

#include <algorithm>

namespace stein::app {

namespace {

platform::Platform& plat(const RunOptions& o) { return o.platform ? *o.platform : platform::current(); }

int imageLevel(VerifyLevel v) {
    switch (v) {
    case VerifyLevel::None: return 0;
    case VerifyLevel::Structure: return 1;
    case VerifyLevel::Checksums: return 2;
    case VerifyLevel::Full: return 3;
    }
    return 2;
}

Expected<std::shared_ptr<BlockDevice>> openTarget(const ResolvedTarget& t, const RunOptions& o, bool writable) {
    if (t.isFile) {
        auto f = FileDevice::open(t.disk.osPath, writable ? FileDevice::Mode::ReadWrite : FileDevice::Mode::ReadOnly, t.disk.geometry.logicalSectorSize);
        if (!f) return fail(f.error());
        return std::shared_ptr<BlockDevice>(*f);
    }
    return plat(o).open(t.disk.osPath, writable ? platform::OpenMode::ReadWriteExclusive : platform::OpenMode::ReadOnly);
}

Expected<void> checkElevation(const Profile& p, const RunOptions& o, const ResolvedTarget& t) {
    if (p.policy.requireElevated && !t.isFile && !plat(o).isElevated()) return fail(ErrorCategory::Permission, "this profile requires root / Administrator privileges");
    return {};
}

// SHA-256 of the first `length` bytes of `dev`, for the after-restore check.
Expected<std::string> hashDevice(BlockDevice& dev, ByteCount length, Progress& progress) {
    auto sha = Hasher::create(HashAlgorithm::Sha256);
    std::vector<std::byte> buf(4 * MiB);
    progress.setPhase("Reading back target", length);
    for (ByteCount off = 0; off < length;) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount n = std::min<ByteCount>(buf.size(), length - off);
        auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(n));
        if (auto r = dev.readAt(off, chunk); !r) return fail(r.error());
        sha->update(chunk);
        off += n;
        progress.setDone(off);
    }
    progress.finishPhase();
    return Hasher::hex(sha->finish());
}

std::string diskLine(const platform::DiskInfo& d) {
    std::string s = d.osPath + "  " + formatSize(d.geometry.sizeBytes);
    if (!d.model.empty()) s += "  " + d.model;
    if (!d.serial.empty()) s += "  sn:" + d.serial;
    if (d.isVirtual) s += "  [virtual]";
    if (d.removable) s += "  [removable]";
    return s;
}

} // namespace

Expected<ResolvedTarget> resolveTarget(const Profile& profile, const RunOptions& options) {
    const auto& sel = profile.target;
    // A regular file as the target: tests, and "restore into an image file" workflows.
    if (!sel.osPath.empty()) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(sel.osPath, ec)) {
            if (!sel.allowVirtual && profile.policy.lockTarget && !options.unlock)
                return fail(ErrorCategory::Permission, "target is a regular file; set target.allow_virtual or run with --unlock");
            ResolvedTarget t;
            t.isFile = true;
            t.byPath = true;
            t.disk.osPath = sel.osPath;
            t.disk.kernelName = std::filesystem::path(sel.osPath).filename().string();
            t.disk.geometry.sizeBytes = std::filesystem::file_size(sel.osPath, ec);
            t.disk.isVirtual = true;
            t.disk.model = "regular file";
            return t;
        }
    }
    auto& p = plat(options);
    std::vector<platform::DiskInfo> matches;
    if (sel.hasIdentity()) {
        auto disks = p.enumerate();
        if (!disks) return fail(disks.error());
        for (const auto& d : *disks)
            if (sel.matchesIdentity(d)) matches.push_back(d);
        if (matches.size() == 1) {
            ResolvedTarget t;
            t.disk = matches.front();
            return t;
        }
        if (matches.size() > 1) {
            std::string msg = std::to_string(matches.size()) + " disks match the profile's identity:";
            for (const auto& d : matches) msg += "\n  " + diskLine(d);
            return fail(ErrorCategory::InvalidArgument, msg);
        }
    }
    if (sel.osPath.empty()) return fail(ErrorCategory::NotFound, "no attached disk matches the profile's target identity");
    // Path fallback: the dr_stein lock. Identity, when given, must still agree.
    if (profile.policy.lockTarget && !options.unlock)
        return fail(ErrorCategory::Permission, "no disk matches by identity; the profile only names a path (" + sel.osPath + ") and path matching is locked (use --unlock)");
    auto d = p.describe(sel.osPath);
    if (!d) return fail(d.error());
    if (sel.hasIdentity() && !sel.matchesIdentity(*d))
        return fail(ErrorCategory::InvalidArgument, "the disk at " + sel.osPath + " does not match the profile's identity: " + diskLine(*d));
    ResolvedTarget t;
    t.disk = *d;
    t.byPath = true;
    return t;
}

Status status(const Profile& profile, const RunOptions& options) {
    Status s;
    s.target = resolveTarget(profile, options);
    std::error_code ec;
    s.imageExists = std::filesystem::is_regular_file(profile.image.path, ec) && std::filesystem::file_size(profile.image.path, ec) > 0;
    if (s.imageExists) {
        if (auto info = image::imageInfo(profile.image.path)) {
            s.imageComplete = info->complete;
            s.imageSourceBytes = info->header.totalSize;
            s.imageSourceName = info->manifest.get("source").get("name").asString();
            s.imageCreated = info->manifest.get("created").asString();
            if (!info->complete) s.warnings.push_back("image is incomplete (no trailer): a backup was interrupted");
        } else {
            s.warnings.push_back("image unreadable: " + info.error().message());
        }
    }
    if (s.target && s.imageExists) {
        s.imageFitsTarget = s.imageSourceBytes <= s.target->disk.geometry.sizeBytes;
        if (!s.imageFitsTarget) s.warnings.push_back("image (" + formatSize(s.imageSourceBytes) + ") is larger than the target (" + formatSize(s.target->disk.geometry.sizeBytes) + ")");
        if (s.target->byPath && !s.target->isFile) s.warnings.push_back("target matched by path only; identity was not confirmed");
    }
    return s;
}

Expected<ScenarioResult> backup(const Profile& profile, const RunOptions& options, Progress& progress) {
    ScenarioResult r;
    r.report = Report("Backup: " + profile.name);
    r.report.start();
    auto t = resolveTarget(profile, options);
    if (!t) return fail(t.error());
    r.target = *t;
    r.report.addDetail("target", diskLine(t->disk));
    if (auto e = checkElevation(profile, options, *t); !e) return fail(e.error());
    if (options.dryRun) {
        r.report.addLine("dry run: would image " + t->disk.osPath + " to " + profile.image.path.string());
        r.report.finish(ReportStatus::Info);
        r.ok = true;
        return r;
    }
    auto dev = openTarget(*t, options, false);
    if (!dev) return fail(dev.error());
    image::CreateOptions co;
    co.compression = profile.image.compression;
    co.chunkSize = profile.image.chunkSize;
    co.splitSize = profile.image.splitSize;
    co.sourceName = t->disk.model.empty() ? t->disk.osPath : t->disk.model + " (" + t->disk.osPath + ")";
    co.sourceIdentity = t->isFile ? std::string() : t->disk.identity();
    co.notes = "profile: " + profile.name;
    std::error_code ec;
    std::filesystem::create_directories(profile.image.path.parent_path(), ec);
    auto& create = r.report.addChild("Create image " + profile.image.path.string());
    create.start();
    auto created = image::createImage(*dev, profile.image.path, co, progress);
    if (!created) {
        create.finish(ReportStatus::Error);
        create.addLine(created.error().toString());
        r.report.finish(ReportStatus::Error);
        return fail(created.error());
    }
    create.addDetail("stored", formatSize(created->storedBytes));
    create.addDetail("read", formatSize(created->stats.bytesRead));
    if (created->stats.unreadableSectors) create.addDetail("unreadable sectors", std::to_string(created->stats.unreadableSectors));
    create.finish(created->stats.unreadableSectors ? ReportStatus::Warning : ReportStatus::Success);
    r.created = *created;
    if (profile.policy.verifyAfterBackup) {
        auto& ver = r.report.addChild("Verify image checksums");
        ver.start();
        auto v = image::verifyImage(profile.image.path, 2, progress);
        if (!v || !v->structureOk || v->chunksBad) {
            ver.finish(ReportStatus::Error);
            ver.addLine(v ? std::to_string(v->chunksBad) + " bad chunks" : v.error().toString());
            r.report.finish(ReportStatus::Error);
            return fail(ErrorCategory::Integrity, "the new image failed verification");
        }
        ver.finish(ReportStatus::Success);
        r.verified = *v;
    }
    r.report.finish(created->stats.unreadableSectors ? ReportStatus::Warning : ReportStatus::Success);
    r.ok = true;
    return r;
}

Expected<ScenarioResult> restore(const Profile& profile, const RunOptions& options, Progress& progress) {
    ScenarioResult r;
    r.report = Report("Restore: " + profile.name);
    r.report.start();
    auto info = image::imageInfo(profile.image.path);
    if (!info) return fail(Error(info.error().category(), "image " + profile.image.path.string() + ": " + info.error().message()));
    if (!info->complete) return fail(ErrorCategory::InvalidFormat, "image is incomplete (interrupted backup); refusing to restore from it");
    auto t = resolveTarget(profile, options);
    if (!t) return fail(t.error());
    r.target = *t;
    r.report.addDetail("target", diskLine(t->disk));
    r.report.addDetail("image", profile.image.path.string() + " (" + formatSize(info->header.totalSize) + ", created " + info->manifest.get("created").asString() + ")");
    if (auto e = checkElevation(profile, options, *t); !e) return fail(e.error());
    const ByteCount targetSize = t->disk.geometry.sizeBytes;
    if (info->header.totalSize > targetSize && !profile.policy.allowSmallerTarget)
        return fail(ErrorCategory::OutOfRange, "image is " + formatSize(info->header.totalSize) + " but the target is only " + formatSize(targetSize));
    const std::string imageIdentity = info->manifest.get("source").get("identity").asString();
    if (!imageIdentity.empty() && !t->isFile && imageIdentity != t->disk.identity())
        r.report.addLine("note: the image was taken from a different disk (" + imageIdentity + "); restoring to " + t->disk.identity());
    if (profile.policy.verifyBeforeRestore != VerifyLevel::None) {
        auto& ver = r.report.addChild("Verify image before writing (" + std::string(toString(profile.policy.verifyBeforeRestore)) + ")");
        ver.start();
        auto v = image::verifyImage(profile.image.path, imageLevel(profile.policy.verifyBeforeRestore), progress);
        const bool ok = v && v->structureOk && v->chunksBad == 0 && (!v->imageHashChecked || v->imageHashOk);
        if (!ok) {
            ver.finish(ReportStatus::Error);
            ver.addLine(v ? std::to_string(v->chunksBad) + " bad chunks" : v.error().toString());
            r.report.finish(ReportStatus::Error);
            return fail(ErrorCategory::Integrity, "image failed verification; nothing was written");
        }
        ver.finish(ReportStatus::Success);
        r.verified = *v;
    }
    if (options.dryRun) {
        r.report.addLine("dry run: would write " + formatSize(std::min(info->header.totalSize, targetSize)) + " to " + t->disk.osPath);
        r.report.finish(ReportStatus::Info);
        r.ok = true;
        return r;
    }
    auto dev = openTarget(*t, options, true);
    if (!dev) return fail(dev.error());
    auto& wr = r.report.addChild("Write image to " + t->disk.osPath);
    wr.start();
    image::RestoreOptions ro;
    ro.allowSmallerTarget = profile.policy.allowSmallerTarget;
    auto restored = image::restoreImage(profile.image.path, **dev, ro, progress);
    if (!restored) {
        wr.finish(ReportStatus::Error);
        wr.addLine(restored.error().toString());
        r.report.finish(ReportStatus::Error);
        return fail(restored.error());
    }
    (void)(*dev)->flush();
    wr.addDetail("written", formatSize(restored->stats.bytesWritten));
    if (restored->targetLarger) wr.addLine("target is larger than the image; space beyond the image is untouched");
    wr.finish(ReportStatus::Success);
    r.restored = *restored;
    if (profile.policy.verifyAfterRestore && info->imageHashHex && !restored->targetSmaller) {
        auto& ver = r.report.addChild("Read back and compare with the image hash");
        ver.start();
        auto h = hashDevice(**dev, info->header.totalSize, progress);
        if (!h || *h != *info->imageHashHex) {
            ver.finish(ReportStatus::Error);
            ver.addLine(h ? "SHA-256 mismatch: target reads back differently from the image" : h.error().toString());
            r.report.finish(ReportStatus::Error);
            return fail(ErrorCategory::Integrity, "target does not read back as the image");
        }
        ver.finish(ReportStatus::Success);
    }
    // After the read-back check (the table change below would break the hash):
    // a GPT restored onto a larger disk has its backup header in the middle of
    // the disk and a wrong "last usable" sector. Fix it now, like sgdisk -e.
    if (profile.policy.repairTableAfterRestore && restored->targetLarger) {
        auto& fix = r.report.addChild("Adjust partition table to the larger target");
        fix.start();
        auto table = pt::PartitionTable::read(*dev);
        bool repairable = false;
        if (table)
            for (const auto& d : (*table)->diagnostics()) repairable = repairable || d.repairable;
        if (!table) {
            fix.finish(ReportStatus::Warning);
            fix.addLine(table.error().toString());
        } else if (!repairable) {
            fix.finish(ReportStatus::Info);
            fix.addLine("nothing to adjust for a " + std::string(pt::toString((*table)->type())) + " table");
        } else if (auto rep = (*table)->repair(**dev, pt::RepairOptions{}); !rep) {
            fix.finish(ReportStatus::Warning);
            fix.addLine(rep.error().toString());
        } else {
            for (const auto& d : (*table)->diagnostics())
                if (d.repairable) fix.addLine("fixed: " + d.message);
            fix.finish(ReportStatus::Success);
        }
    }
    if (profile.policy.rereadPartitionTable && !t->isFile) {
        dev->reset();
        if (auto rr = plat(options).rereadPartitionTable(t->disk.osPath); !rr) r.report.addLine("note: partition table re-read: " + rr.error().message());
    }
    r.report.finish(ReportStatus::Success);
    r.ok = true;
    return r;
}

Expected<ScenarioResult> verify(const Profile& profile, const RunOptions&, Progress& progress) {
    ScenarioResult r;
    r.report = Report("Verify: " + profile.name);
    r.report.start();
    auto v = image::verifyImage(profile.image.path, 3, progress);
    if (!v) {
        r.report.finish(ReportStatus::Error);
        return fail(v.error());
    }
    r.verified = *v;
    r.report.addDetail("chunks", std::to_string(v->chunksChecked) + " checked, " + std::to_string(v->chunksBad) + " bad");
    if (v->imageHashChecked) r.report.addDetail("sha256", v->imageHashOk ? "ok" : "MISMATCH");
    r.ok = v->structureOk && v->complete && v->chunksBad == 0 && (!v->imageHashChecked || v->imageHashOk);
    r.report.finish(r.ok ? ReportStatus::Success : ReportStatus::Error);
    return r;
}

std::string describe(const Profile& profile, const Status& s) {
    std::string out = "Profile: " + profile.name + "\n";
    if (!profile.description.empty()) out += "  " + profile.description + "\n";
    out += "Target:  ";
    if (s.target) out += diskLine(s.target->disk) + (s.target->byPath ? "  (by path)" : "  (by identity)") + "\n";
    else out += "NOT FOUND: " + s.target.error().message() + "\n";
    out += "Image:   " + profile.image.path.string();
    if (!s.imageExists) out += "  (missing)\n";
    else {
        out += "  " + formatSize(s.imageSourceBytes);
        if (!s.imageSourceName.empty()) out += "  from " + s.imageSourceName;
        if (!s.imageCreated.empty()) out += "  created " + s.imageCreated;
        out += s.imageComplete ? "\n" : "  INCOMPLETE\n";
    }
    for (const auto& w : s.warnings) out += "Warning: " + w + "\n";
    const bool canBackup = s.target.has_value();
    const bool canRestore = s.target && s.imageExists && s.imageComplete && (s.imageFitsTarget || profile.policy.allowSmallerTarget);
    out += std::string("Backup:  ") + (canBackup ? "ready" : "unavailable") + "\n";
    out += std::string("Restore: ") + (canRestore ? "ready" : "unavailable") + "\n";
    return out;
}

} // namespace stein::app
