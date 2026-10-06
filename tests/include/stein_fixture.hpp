// SPDX-License-Identifier: MIT
// Loads tests/fixtures/**/*.sparse (see tools/fixtures/sparsify.py) into a
// MemoryDevice so tests run on every OS without root or real devices.
#pragma once

#include "stein/block/memory_device.hpp"
#include "stein/core/endian.hpp"

#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace stein::test {

inline std::shared_ptr<MemoryDevice> loadSparseFixture(const std::string& relativePath) {
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/" + relativePath, std::ios::binary);
    if (!in) return nullptr;
    std::vector<char> chars((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<std::byte> data(chars.size());
    std::memcpy(data.data(), chars.data(), chars.size());
    if (data.size() < 24 || std::memcmp(data.data(), "STEINSPARSE1", 12) != 0) return nullptr;
    const std::uint64_t total = loadLe64(data.data() + 12);
    const std::uint32_t sector = loadLe32(data.data() + 20);
    auto dev = std::make_shared<MemoryDevice>(total, sector);
    std::size_t pos = 24;
    while (pos + 16 <= data.size()) {
        const std::uint64_t off = loadLe64(data.data() + pos);
        const std::uint64_t len = loadLe64(data.data() + pos + 8);
        pos += 16;
        if (pos + len > data.size() || off + len > total) return nullptr;
        std::memcpy(dev->bytes().data() + off, data.data() + pos, static_cast<std::size_t>(len));
        pos += static_cast<std::size_t>(len);
    }
    return dev;
}

} // namespace stein::test
