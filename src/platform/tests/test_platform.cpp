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
    std::filesystem::remove_all(dir);
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
        std::filesystem::remove_all(dir);
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
    std::filesystem::remove_all(dir);
}
#endif
