// SPDX-License-Identifier: MIT
// Loads tests/fixtures/**/*.sparse (see tools/fixtures/sparsify.py) into a
// MemoryDevice so tests run on every OS without root or real devices.
#pragma once

#include "stein/block/sparse_file.hpp"

#include <memory>
#include <string>

namespace stein::test {

inline std::shared_ptr<MemoryDevice> loadSparseFixture(const std::string& relativePath) {
    auto dev = SparseFile::loadIntoMemory(std::string(STEIN_FIXTURE_DIR) + "/" + relativePath);
    return dev ? *dev : nullptr;
}

} // namespace stein::test
