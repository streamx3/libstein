// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/hash.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/mount/mount.hpp"

#include <filesystem>
#include <fstream>
#include <random>
#include <chrono>
#include <cstdlib>
#include <thread>
#if defined(_WIN32)
#include <windows.h>
#endif

using namespace stein;
using stein::test::loadSparseFixture;

namespace {
// CI sets STEIN_REQUIRE_MOUNT where a backend is expected to work, so a silent skip there is a failure.
void skipOrFail(const std::string& why) {
    if (std::getenv("STEIN_REQUIRE_MOUNT")) FAIL(why);
    else MESSAGE(why);
}
} // namespace

TEST_CASE("mount: an ext4 fixture mounted through FUSE reads like the kernel mount did") {
    if (!mount::Mount::available()) {
        skipOrFail("no usable FUSE/WinFsp on this machine; skipping");
        return;
    }
    auto dev = loadSparseFixture("extfs/ext4.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
#if defined(_WIN32)
    // WinFsp: a free drive letter; files are then reached through "X:\\".
    std::filesystem::path mp;
    {
        const unsigned long drives = GetLogicalDrives();
        for (char letter = 'Z'; letter >= 'E'; --letter)
            if (!(drives & (1u << (letter - 'A')))) {
                mp = std::string(1, letter) + ":";
                break;
            }
    }
    REQUIRE_FALSE(mp.empty());
    const std::filesystem::path base = mp.string() + "\\";
#else
    const auto mp = std::filesystem::temp_directory_path() / ("stein_mount_test_" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(mp);
    const std::filesystem::path base = mp;
#endif
    auto m = mount::Mount::create(std::move(*reader), mp);
    if (!m) {
        skipOrFail("mount failed (" + m.error().toString() + "); skipping");
#if !defined(_WIN32)
        std::filesystem::remove(mp);
#endif
        return;
    }
    Expected<void> loopResult;
    std::thread loop([&] { loopResult = (*m)->run(); });
    // Never touch the mountpoint unless the loop is serving: a request with no server blocks forever.
    for (int i = 0; i < 200 && !(*m)->running() && loop.joinable(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (!(*m)->running()) {
        loop.join();
        skipOrFail("fuse loop did not start: " + (loopResult ? std::string("exited cleanly") : loopResult.error().toString()));
        m->reset();
        std::error_code ec0;
#if !defined(_WIN32)
        std::filesystem::remove(mp, ec0);
#endif
        return;
    }
    // Compare with the oracle through ordinary file APIs.
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/extfs/ext4.oracle.txt");
    std::string line;
    int files = 0, dirs = 0, links = 0;
    while (std::getline(in, line)) {
        if (line.rfind("sha256 ", 0) == 0) {
            const auto sp = line.find(' ', 7);
            const std::string path = line.substr(sp + 1), want = line.substr(7, sp - 7);
            std::ifstream f(base / path, std::ios::binary);
            REQUIRE(f);
            std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()))) == want);
            ++files;
        } else if (line.rfind("link ", 0) == 0) {
            const auto arrow = line.find(" -> ");
            std::error_code ec;
            CHECK(std::filesystem::read_symlink(base / line.substr(5, arrow - 5), ec).string() == line.substr(arrow + 4));
            ++links;
        } else if (line.size() > 2 && line[0] == 'd') {
            std::error_code ec;
            CHECK(std::filesystem::is_directory(base / line.substr(line.find(' ', 2) + 1), ec));
            ++dirs;
        }
    }
    CHECK(files > 300);
    CHECK(dirs >= 5);
    CHECK(links == 2);
    std::error_code ec;
    CHECK_FALSE(std::filesystem::exists(base / "does-not-exist", ec));
    // Read-only: creating a file fails.
    std::ofstream nope(base / "new.txt");
    CHECK_FALSE(nope);
    (*m)->stop();
    loop.join();
    CHECK(loopResult);
    m->reset();
#if !defined(_WIN32)
    std::filesystem::remove(mp, ec);
#endif
}
