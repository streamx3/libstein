// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/platform/platform.hpp"
#include "stein/probe/topology.hpp"

#include <filesystem>
#include <fstream>

using namespace stein;
using namespace stein::platform;

TEST_CASE("platform: name, enumerate does not fail, openAny on a regular file") {
    auto& p = current();
    CHECK(!p.name().empty());
    auto disks = p.enumerate();
    CHECK(disks.has_value());
    auto dir = std::filesystem::temp_directory_path() / "stein_test_platform";
    std::filesystem::create_directories(dir);
    auto img = dir / "f.img";
    {
        std::ofstream o(img, std::ios::binary);
        o.seekp(4 * MiB - 1);
        o.put(0);
    }
    auto dev = openAny(img.string(), OpenMode::ReadOnly);
    REQUIRE(dev);
    CHECK((*dev)->size() == 4 * MiB);
    CHECK(!openAny((dir / "missing").string(), OpenMode::ReadOnly));
    if (dev) dev->reset();
    stein::test::removeTree(dir);
}

#ifdef __linux__
TEST_CASE("linux: loop attach, open raw device, probe, mounts, detach") {
    auto& p = current();
    if (!p.isElevated()) {
        MESSAGE("not root; skipping loop-device test");
        return;
    }
    // Materialise the GPT fixture into a file and attach it.
    auto mem = test::loadSparseFixture("pt/gpt_basic.sparse");
    REQUIRE(mem);
    auto dir = std::filesystem::temp_directory_path() / "stein_test_loop";
    std::filesystem::create_directories(dir);
    auto img = dir / "gpt.img";
    {
        std::ofstream o(img, std::ios::binary);
        o.write(reinterpret_cast<const char*>(mem->bytes().data()), static_cast<std::streamsize>(mem->size()));
    }
    auto attached = p.attach(img, AttachOptions{.readOnly = true, .partitionScan = true});
    if (!attached) {
        MESSAGE("loop attach unavailable here: ", attached.error().toString());
        stein::test::removeTree(dir);
        return;
    }
    CHECK(attached->osPath.rfind("/dev/loop", 0) == 0);
    auto info = p.describe(attached->osPath);
    REQUIRE(info);
    CHECK(info->bus == Bus::Loop);
    CHECK(info->isVirtual);
    CHECK(info->geometry.sizeBytes == 16 * MiB);
    CHECK(info->backingFile.has_value());
    CHECK(!info->identity().empty());

    auto dev = p.open(attached->osPath, OpenMode::ReadOnly);
    REQUIRE(dev);
    CHECK((*dev)->size() == 16 * MiB);
    CHECK((*dev)->sectorSize() == 512);
    CHECK((*dev)->writeAt(0, std::span<const std::byte>()).error().category() == ErrorCategory::Permission);
    auto tree = probe::probe(*dev);
    REQUIRE(tree);
    REQUIRE(tree->table);
    CHECK(tree->table->type() == pt::TableType::Gpt);
    CHECK(tree->table->partitions().size() == 3);

    auto all = p.enumerate();
    REQUIRE(all);
    bool found = false;
    for (const auto& d : *all) found = found || d.osPath == attached->osPath;
    CHECK(found);
    auto m = p.mounts(attached->osPath);
    CHECK(m.has_value());
    CHECK(p.rereadPartitionTable(attached->osPath));
    dev->reset();
    CHECK(p.detach(*attached));
    stein::test::removeTree(dir);
}
#endif

#include "../src/aligned_device.hpp"
#include "stein/block/memory_device.hpp"

namespace {
// A "raw" device that insists on sector alignment, like rdisk / PhysicalDrive.
class StrictRaw final : public stein::platform::AlignedDevice {
public:
    explicit StrictRaw(std::shared_ptr<MemoryDevice> m) : m_mem(std::move(m)) {}
    std::string name() const override { return "strict"; }
    Geometry geometry() const override { return m_mem->geometry(); }
    bool isReadOnly() const override { return false; }
    Expected<void> flush() override { return {}; }
    int rawCalls = 0;

protected:
    Expected<void> rawRead(ByteCount offset, std::span<std::byte> dst) override {
        ++rawCalls;
        if (offset % 512 || dst.size() % 512) return fail(ErrorCategory::Internal, "unaligned raw read");
        return m_mem->readAt(offset, dst);
    }
    Expected<void> rawWrite(ByteCount offset, std::span<const std::byte> src) override {
        ++rawCalls;
        if (offset % 512 || src.size() % 512) return fail(ErrorCategory::Internal, "unaligned raw write");
        return m_mem->writeAt(offset, src);
    }

private:
    std::shared_ptr<MemoryDevice> m_mem;
};
} // namespace

TEST_CASE("AlignedDevice: unaligned reads and writes become sector-aligned raw I/O") {
    auto mem = std::make_shared<MemoryDevice>(64 * KiB);
    for (std::size_t i = 0; i < mem->bytes().size(); ++i) mem->bytes()[i] = static_cast<std::byte>(i * 7 + 3);
    StrictRaw raw(mem);
    // Straddling several sectors with ragged ends.
    auto r = raw.read(1000, 3000);
    REQUIRE(r);
    for (std::size_t i = 0; i < 3000; ++i) REQUIRE(r->at(i) == mem->bytes()[1000 + i]);
    // Aligned read goes straight through.
    raw.rawCalls = 0;
    CHECK(raw.read(4096, 8192));
    CHECK(raw.rawCalls == 1);
    // Tail of the device, partial.
    auto t = raw.read(64 * KiB - 5, 5);
    REQUIRE(t);
    CHECK(t->at(4) == mem->bytes()[64 * KiB - 1]);
    CHECK(raw.read(64 * KiB - 5, 6).error().category() == ErrorCategory::OutOfRange);
    // Unaligned write: read-modify-write keeps the neighbours.
    std::vector<std::byte> w(700, std::byte{0xEE});
    REQUIRE(raw.writeAt(511, w));
    CHECK(mem->bytes()[510] == static_cast<std::byte>(510 * 7 + 3));
    CHECK(mem->bytes()[511] == std::byte{0xEE});
    CHECK(mem->bytes()[511 + 699] == std::byte{0xEE});
    CHECK(mem->bytes()[511 + 700] == static_cast<std::byte>((511 + 700) * 7 + 3));
    // Single byte in the middle of a sector.
    REQUIRE(raw.writeAt(12345, stein::test::bytesOf("Q")));
    CHECK(mem->bytes()[12345] == std::byte{'Q'});
    CHECK(mem->bytes()[12344] == static_cast<std::byte>(12344 * 7 + 3));
}

#include "stein/platform/device_watcher.hpp"

#include <atomic>
#include <chrono>
#include <thread>

TEST_CASE("device watcher: starts, idles and stops without events; create() answers Unsupported only where there is no backend") {
    std::atomic<int> events{0};
    auto w = stein::platform::DeviceWatcher::create([&](const stein::platform::DeviceEvent& e) {
        ++events;
        CHECK(!stein::platform::toString(e.kind).empty());
    });
#if defined(__APPLE__) || defined(__linux__) || defined(_WIN32)
    REQUIRE(w);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));   // past the macOS registration replay
    (*w)->stop();
    (*w)->stop();   // idempotent
    w->reset();
    MESSAGE("device events during the idle window: " << events.load());
#else
    CHECK(!w);
    CHECK(w.error().category() == stein::ErrorCategory::Unsupported);
#endif
    CHECK(stein::platform::toString(stein::platform::DeviceEvent::Kind::MountsChanged) == "mounts changed");
}
