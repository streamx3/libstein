// SPDX-License-Identifier: MIT
// The STEINSPARSE1 container: a list of (offset, bytes) runs plus the total
// size and sector size. Used for test fixtures (tools/fixtures/sparsify.py)
// and as the first "piece" format for dumping and restoring partition-table
// metadata (doc/design/14-imaging.md §2a). Not the full .stein image format.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/block/memory_device.hpp"

#include <filesystem>
#include <memory>
#include <vector>

namespace stein {

class SparseFile {
public:
    struct Run {
        ByteCount offset;
        std::vector<std::byte> bytes;
    };
    struct Contents {
        ByteCount totalSize = 0;
        std::uint32_t sectorSize = 512;
        std::vector<Run> runs;
    };

    static constexpr const char* kMagic = "STEINSPARSE1";

    static Expected<Contents> read(const std::filesystem::path& path);
    static Expected<void> write(const std::filesystem::path& path, const Contents& contents);

    // Load into a fresh in-memory device (fixtures).
    static Expected<std::shared_ptr<MemoryDevice>> loadIntoMemory(const std::filesystem::path& path);
    // Capture the given regions of `device` (e.g. PartitionTable::metadataRegions()).
    static Expected<Contents> capture(BlockDevice& device, const std::vector<Region>& regions);
    // Write every run back onto `device`. Fails before writing anything if a run does not fit.
    static Expected<void> apply(const Contents& contents, BlockDevice& device);
};

} // namespace stein
