// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/app/scenario.hpp"
#include "stein/block/file_device.hpp"
#include "stein/block/memory_device.hpp"
#include "stein/pt/partition_table.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

using namespace stein;
using stein::test::loadSparseFixture;

namespace {

std::filesystem::path tmpDir(const char* name) {
    auto d = std::filesystem::temp_directory_path() / name;
    stein::test::removeTree(d);
    std::filesystem::create_directories(d);
    return d;
}

platform::DiskInfo disk(std::string path, std::string model, std::string serial, ByteCount size, bool removable = false, bool virt = false) {
    platform::DiskInfo d;
    d.osPath = std::move(path);
    d.model = std::move(model);
    d.serial = std::move(serial);
    d.geometry.sizeBytes = size;
    d.removable = removable;
    d.isVirtual = virt;
    return d;
}

// A platform with a fixed set of disks and no raw access (tests never touch real devices).
class FakePlatform final : public platform::Platform {
public:
    std::vector<platform::DiskInfo> disks;
    std::vector<platform::MountInfo> mounted;
    std::shared_ptr<MemoryDevice> fakeDisk;     // served by open() for disks[0].osPath
    int unmounts = 0, rereads = 0;
    bool elevated = false;
    std::string_view name() const override { return "fake"; }
    Expected<std::vector<platform::DiskInfo>> enumerate() override { return disks; }
    Expected<platform::DiskInfo> describe(const std::string& p) override {
        for (const auto& d : disks)
            if (d.osPath == p) return d;
        return fail(ErrorCategory::NotFound, "no such disk " + p);
    }
    Expected<std::shared_ptr<BlockDevice>> open(const std::string& p, platform::OpenMode mode) override {
        if (fakeDisk && !disks.empty() && p == disks[0].osPath) {
            if (mode == platform::OpenMode::ReadWriteExclusive && !mounts(p)->empty()) return fail(ErrorCategory::Busy, "fake: still mounted");
            return std::shared_ptr<BlockDevice>(fakeDisk);
        }
        return fail(ErrorCategory::Unsupported, "fake: " + p);
    }
    Expected<std::vector<platform::MountInfo>> mounts(const std::string& prefix) override {
        std::vector<platform::MountInfo> out;
        for (const auto& m : mounted)
            if (prefix.empty() || m.source.rfind(prefix, 0) == 0) out.push_back(m);
        return out;
    }
    Expected<void> unmount(const platform::MountInfo& m, bool) override {
        for (auto it = mounted.begin(); it != mounted.end(); ++it)
            if (it->target == m.target) {
                mounted.erase(it);
                ++unmounts;
                return {};
            }
        return fail(ErrorCategory::NotFound, "not mounted");
    }
    Expected<void> rereadPartitionTable(const std::string&) override {
        ++rereads;
        return {};
    }
    Expected<platform::AttachedImage> attach(const std::filesystem::path&, const platform::AttachOptions&) override { return fail(ErrorCategory::Unsupported, "fake"); }
    Expected<void> detach(const platform::AttachedImage&) override { return {}; }
    bool isElevated() const override { return elevated; }
};

} // namespace

TEST_CASE("profile: JSON round trip and validation") {
    const char* text = R"({
      "name": "Office PC",
      "description": "Windows 11 on the Samsung SSD",
      "target": { "serial": "S6PZNS0W123456", "model": "Samsung SSD 980", "size": "1T", "size_tolerance": 0.05 },
      "image": { "path": "/opt/dr_stein/office.stein", "compression": "lz4", "chunk_size": "8M", "split_size": "4G" },
      "policy": { "verify_before_restore": "full", "allow_smaller_target": true },
      "notes": ["created by test"]
    })";
    auto v = json::Value::parse(text);
    REQUIRE(v);
    auto p = app::Profile::fromJson(*v);
    REQUIRE_MESSAGE(p, (p ? std::string() : p.error().toString()));
    CHECK(p->name == "Office PC");
    CHECK(p->target.serial == "S6PZNS0W123456");
    CHECK(*p->target.sizeBytes == TiB);
    CHECK(p->image.chunkSize == 8 * MiB);
    CHECK(p->image.splitSize == 4 * GiB);
    CHECK(p->policy.verifyBeforeRestore == app::VerifyLevel::Full);
    CHECK(p->policy.allowSmallerTarget);
    CHECK(p->policy.lockTarget);   // default
    auto again = app::Profile::fromJson(p->toJson());
    REQUIRE(again);
    CHECK(again->toJson().dump() == p->toJson().dump());
    // Invalid profiles are rejected with a reason.
    auto noImage = json::Value::parse(R"({"name":"x","target":{"serial":"a"}})");
    CHECK(app::Profile::fromJson(*noImage).error().category() == ErrorCategory::InvalidArgument);
    auto noTarget = json::Value::parse(R"({"name":"x","image":{"path":"a.stein"}})");
    CHECK_FALSE(app::Profile::fromJson(*noTarget));
    auto badChunk = json::Value::parse(R"({"name":"x","target":{"serial":"a"},"image":{"path":"a.stein","chunk_size":"3M"}})");
    CHECK_FALSE(app::Profile::fromJson(*badChunk));
    auto badLevel = json::Value::parse(R"({"name":"x","target":{"serial":"a"},"image":{"path":"a.stein"},"policy":{"verify_before_restore":"maybe"}})");
    CHECK_FALSE(app::Profile::fromJson(*badLevel));
}

TEST_CASE("target selection: identity first, path only when unlocked") {
    FakePlatform fake;
    fake.disks = {disk("/dev/sda", "Samsung SSD 980 PRO 1TB", "S6PZ-A", 1000204886016ull),
                  disk("/dev/sdb", "Kingston DataTraveler", "KT-1", 31 * GiB, true),
                  disk("/dev/sdc", "Samsung SSD 980 PRO 1TB", "S6PZ-B", 1000204886016ull),
                  disk("/dev/loop0", "", "", 64 * MiB, false, true)};
    app::Profile p;
    p.name = "t";
    p.image.path = "x.stein";
    app::RunOptions o;
    o.platform = &fake;

    SUBCASE("unique serial") {
        p.target.serial = "s6pz-b";   // case-insensitive
        auto t = app::resolveTarget(p, o);
        REQUIRE(t);
        CHECK(t->disk.osPath == "/dev/sdc");
        CHECK_FALSE(t->byPath);
    }
    SUBCASE("model + size is ambiguous") {
        p.target.model = "980 PRO";
        p.target.sizeBytes = 1000204886016ull;
        auto t = app::resolveTarget(p, o);
        REQUIRE_FALSE(t);
        CHECK(t.error().message().find("2 disks match") != std::string::npos);
    }
    SUBCASE("size with tolerance") {
        p.target.sizeBytes = 1 * TiB;
        p.target.sizeTolerance = 0.1;
        p.target.model = "Kingston";
        CHECK_FALSE(app::resolveTarget(p, o));   // Kingston is 31 GiB
        p.target.model = "";
        auto t = app::resolveTarget(p, o);
        REQUIRE_FALSE(t);   // two 1 TB Samsungs
    }
    SUBCASE("removable and virtual filters") {
        p.target.sizeBytes = 31 * GiB;
        p.target.allowRemovable = false;
        CHECK_FALSE(app::resolveTarget(p, o));
        p.target.allowRemovable = true;
        CHECK(app::resolveTarget(p, o)->disk.osPath == "/dev/sdb");
        p.target = {};
        p.target.sizeBytes = 64 * MiB;
        CHECK_FALSE(app::resolveTarget(p, o));   // virtual hidden by default
        p.target.allowVirtual = true;
        CHECK(app::resolveTarget(p, o)->disk.osPath == "/dev/loop0");
    }
    SUBCASE("path fallback is locked") {
        p.target.osPath = "/dev/sdb";
        auto locked = app::resolveTarget(p, o);
        REQUIRE_FALSE(locked);
        CHECK(locked.error().category() == ErrorCategory::Permission);
        o.unlock = true;
        auto t = app::resolveTarget(p, o);
        REQUIRE(t);
        CHECK(t->byPath);
        CHECK(t->disk.serial == "KT-1");
        // Identity given too: the disk at the path must agree with it.
        p.target.serial = "S6PZ-A";
        auto wrong = app::resolveTarget(p, o);   // /dev/sdb is not S6PZ-A, and S6PZ-A matches /dev/sda uniquely -> identity wins
        REQUIRE(wrong);
        CHECK(wrong->disk.osPath == "/dev/sda");
        p.target.serial = "nope";
        auto mismatch = app::resolveTarget(p, o);
        REQUIRE_FALSE(mismatch);
        CHECK(mismatch.error().message().find("does not match") != std::string::npos);
    }
    SUBCASE("nothing matches") {
        p.target.serial = "zzz";
        auto t = app::resolveTarget(p, o);
        REQUIRE_FALSE(t);
        CHECK(t.error().category() == ErrorCategory::NotFound);
    }
}

TEST_CASE("scenarios: backup, status, restore and verify on a file target") {
    auto dir = tmpDir("stein_test_app");
    // The "disk": a GPT fixture written out as a regular file.
    auto src = loadSparseFixture("pt/gpt_basic.sparse");
    const auto diskPath = dir / "disk.img";
    {
        std::ofstream out(diskPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(src->bytes().data()), static_cast<std::streamsize>(src->bytes().size()));
    }
    app::Profile p;
    p.name = "file test";
    p.target.osPath = diskPath.string();
    p.target.allowVirtual = true;
    p.image.path = dir / "backup" / "disk.stein";
    p.image.chunkSize = 1 * MiB;
    p.policy.requireElevated = false;
    REQUIRE(p.validate());
    app::RunOptions o;
    NullProgressSink sink;
    Progress progress(sink);

    auto before = app::status(p, o);
    REQUIRE(before.target);
    CHECK(before.target->isFile);
    CHECK_FALSE(before.imageExists);
    CHECK(app::describe(p, before).find("Restore: unavailable") != std::string::npos);

    auto b = app::backup(p, o, progress);
    REQUIRE_MESSAGE(b, (b ? std::string() : b.error().toString()));
    CHECK(b->ok);
    CHECK(b->created);
    CHECK(b->verified);
    CHECK(b->report.status() == ReportStatus::Success);

    auto mid = app::status(p, o);
    CHECK(mid.imageExists);
    CHECK(mid.imageComplete);
    CHECK(mid.imageFitsTarget);
    CHECK(mid.imageSourceBytes == src->size());
    CHECK(app::describe(p, mid).find("Restore: ready") != std::string::npos);

    // Damage the "disk": zero the first 2 MiB (both GPT copies' primary side and partition 1).
    {
        std::fstream f(diskPath, std::ios::in | std::ios::out | std::ios::binary);
        std::vector<char> zeros(2 * MiB, 0);
        f.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    }
    {
        auto broken = FileDevice::open(diskPath, FileDevice::Mode::ReadOnly);
        REQUIRE(broken);
        auto t = pt::PartitionTable::read(*broken);
        REQUIRE(t);
        CHECK((*t)->health() != layout::Validity::Ok);
    }
    auto dry = app::restore(p, app::RunOptions{.dryRun = true}, progress);
    REQUIRE(dry);
    CHECK(dry->ok);
    CHECK_FALSE(dry->restored);
    auto r = app::restore(p, o, progress);
    REQUIRE_MESSAGE(r, (r ? std::string() : r.error().toString()));
    CHECK(r->ok);
    REQUIRE(r->restored);
    CHECK(r->restored->stats.bytesWritten == src->size());
    CHECK(r->report.toText().find("Read back and compare") != std::string::npos);
    {
        auto fixed = FileDevice::open(diskPath, FileDevice::Mode::ReadOnly);
        REQUIRE(fixed);
        auto t = pt::PartitionTable::read(*fixed);
        REQUIRE(t);
        CHECK((*t)->health() == layout::Validity::Ok);
        CHECK((*t)->partitions().size() == 3);
        auto all = (*fixed)->read(0, (*fixed)->size());
        REQUIRE(all);
        CHECK(std::equal(all->begin(), all->end(), src->bytes().begin()));
    }
    auto v = app::verify(p, o, progress);
    REQUIRE(v);
    CHECK(v->ok);
    CHECK(v->verified->imageHashOk);

    // A larger target: the GPT backup is moved to the new end of the disk.
    const auto bigPath = dir / "big.img";
    {
        std::ofstream out(bigPath, std::ios::binary);
        out.seekp(static_cast<std::streamoff>(src->size() * 2 - 1));
        out.put(0);
    }
    p.target.osPath = bigPath.string();
    auto grown = app::restore(p, o, progress);
    REQUIRE_MESSAGE(grown, (grown ? std::string() : grown.error().toString()));
    CHECK(grown->restored->targetLarger);
    CHECK(grown->report.toText().find("Adjust partition table") != std::string::npos);
    {
        auto big = FileDevice::open(bigPath, FileDevice::Mode::ReadOnly);
        REQUIRE(big);
        auto t = pt::PartitionTable::read(*big);
        REQUIRE(t);
        CHECK((*t)->health() == layout::Validity::Ok);
        CHECK((*t)->lastUsableLba() == (*big)->geometry().sectors() - 34);
        CHECK((*t)->partitions().size() == 3);
    }

    // A smaller target is refused unless the policy allows it.
    const auto smallPath = dir / "small.img";
    {
        std::ofstream out(smallPath, std::ios::binary);
        out.seekp(static_cast<std::streamoff>(src->size() / 2 - 1));
        out.put(0);
    }
    p.target.osPath = smallPath.string();
    auto refused = app::restore(p, o, progress);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == ErrorCategory::OutOfRange);
    stein::test::removeTree(dir);
}

TEST_CASE("scenarios: used-only backup through a profile skips free space") {
    auto dir = tmpDir("stein_test_app_used");
    auto src = loadSparseFixture("alloc/ext4.sparse");
    const auto diskPath = dir / "ext4.img";
    {
        std::ofstream out(diskPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(src->bytes().data()), static_cast<std::streamsize>(src->bytes().size()));
    }
    app::Profile p;
    p.name = "used";
    p.target.osPath = diskPath.string();
    p.target.allowVirtual = true;
    p.image.path = dir / "ext4.stein";
    p.image.chunkSize = 256 * KiB;
    REQUIRE(p.validate());
    NullProgressSink sink;
    Progress progress(sink);
    auto b = app::backup(p, app::RunOptions{}, progress);
    REQUIRE_MESSAGE(b, (b ? std::string() : b.error().toString()));
    REQUIRE(b->created);
    CHECK(b->created->stats.freeBytesSkipped > 32 * MiB);
    CHECK(b->report.toText().find("allocation: ext4") != std::string::npos);
    auto info = image::imageInfo(p.image.path);
    REQUIRE(info);
    CHECK(info->manifest.get("used_blocks_only").asBool());
    // The profile round-trips the flag, and turning it off is honoured.
    CHECK(app::Profile::fromJson(p.toJson())->image.usedOnly);
    p.image.usedOnly = false;
    p.image.path = dir / "whole.stein";
    auto w = app::backup(p, app::RunOptions{}, progress);
    REQUIRE(w);
    CHECK(w->created->stats.freeBytesSkipped == 0);
    CHECK_FALSE(image::imageInfo(p.image.path)->manifest.has("used_blocks_only"));
    stein::test::removeTree(dir);
}

TEST_CASE("scenarios: restore through a platform unmounts the target's volumes first") {
    auto dir = tmpDir("stein_test_app_mounted");
    auto src = loadSparseFixture("pt/gpt_basic.sparse");
    FakePlatform fake;
    fake.disks = {disk("/dev/fake", "Fake Disk", "FAKE-1", src->size())};
    fake.fakeDisk = std::make_shared<MemoryDevice>(src->size());
    std::copy(src->bytes().begin(), src->bytes().end(), fake.fakeDisk->bytes().begin());
    fake.mounted = {platform::MountInfo{"/dev/fake1", "/mnt/efi", "vfat", "rw", false}, platform::MountInfo{"/dev/fake2", "/mnt/data", "ext4", "rw", false}};
    app::Profile p;
    p.name = "fake";
    p.target.serial = "FAKE-1";
    p.image.path = dir / "fake.stein";
    p.image.chunkSize = 1 * MiB;
    p.image.usedOnly = false;
    app::RunOptions o;
    o.platform = &fake;
    NullProgressSink sink;
    Progress progress(sink);
    auto b = app::backup(p, o, progress);
    REQUIRE_MESSAGE(b, (b ? std::string() : b.error().toString()));
    CHECK(b->report.toText().find("mounted; the image may be inconsistent") != std::string::npos);
    // Refuse while mounted when the policy says so.
    p.policy.unmountTarget = false;
    auto refused = app::restore(p, o, progress);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == ErrorCategory::Busy);
    CHECK(fake.unmounts == 0);
    // Default policy: unmount, write, re-read the table.
    p.policy.unmountTarget = true;
    std::fill(fake.fakeDisk->bytes().begin(), fake.fakeDisk->bytes().begin() + 1 * MiB, std::byte{0});
    auto r = app::restore(p, o, progress);
    REQUIRE_MESSAGE(r, (r ? std::string() : r.error().toString()));
    CHECK(r->ok);
    CHECK(fake.unmounts == 2);
    CHECK(fake.mounted.empty());
    CHECK(fake.rereads == 1);
    CHECK(r->report.toText().find("unmounted /mnt/efi") != std::string::npos);
    CHECK(std::equal(src->bytes().begin(), src->bytes().end(), fake.fakeDisk->bytes().begin()));
    stein::test::removeTree(dir);
}
