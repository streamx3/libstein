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
    static constexpr const char* kEncryptedMagic = "STEINPIECE1E";   // key area + AEAD(STEINSPARSE1 body)

    // `passphrase` opens encrypted pieces (Permission error when missing, Integrity when wrong).
    static Expected<Contents> read(const std::filesystem::path& path, const std::string& passphrase = {});
    // Non-empty `passphrase`: write an encrypted piece with one key slot.
    static Expected<void> write(const std::filesystem::path& path, const Contents& contents, const std::string& passphrase = {},
                                std::uint32_t kdfIterations = 600000);
    static bool isEncrypted(const std::filesystem::path& path);

    std::vector<std::byte> static serialize(const Contents& contents);
    static Expected<Contents> parse(std::span<const std::byte> bytes, const std::string& what);

    // Load into a fresh in-memory device (fixtures).
    static Expected<std::shared_ptr<MemoryDevice>> loadIntoMemory(const std::filesystem::path& path);
    // Capture the given regions of `device` (e.g. PartitionTable::metadataRegions()).
    static Expected<Contents> capture(BlockDevice& device, const std::vector<Region>& regions);
    // Write every run back onto `device`. Fails before writing anything if a run does not fit.
    static Expected<void> apply(const Contents& contents, BlockDevice& device);
};

} // namespace stein
