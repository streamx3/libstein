// SPDX-License-Identifier: MIT
// The copy engine: chunked, zero-aware, bad-sector tolerant transfer from a
// BlockDevice to a chunk sink or another BlockDevice. One engine serves image
// creation, restore and cloning. See doc/design/14-imaging.md §3.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/progress.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace stein::image {

enum class BadSectorPolicy : std::uint8_t {
    Fail,        // first unreadable sector aborts
    SkipZero,    // retry sector by sector, zero-fill what stays unreadable, continue (recorded)
};

struct CopyOptions {
    std::uint32_t chunkSize = 4 * MiB;
    BadSectorPolicy badSectors = BadSectorPolicy::Fail;
    bool skipZeroChunksOnWrite = false;   // device->device: do not write all-zero chunks (target known to be zero / discarded)
    bool discardZeroChunks = false;       // device->device: try discard() for zero chunks before writing zeros
    ByteCount limit = 0;                  // copy only the first `limit` bytes (0 = all)
};

struct CopyStats {
    ByteCount bytesRead = 0;
    ByteCount bytesWritten = 0;
    std::uint64_t chunks = 0;
    std::uint64_t zeroChunks = 0;
    std::uint64_t unreadableSectors = 0;
    std::vector<Region> badRegions;       // zero-filled ranges (coalesced)
};

class ChunkSink {
public:
    virtual ~ChunkSink() = default;
    virtual Expected<void> writeChunk(std::uint64_t index, std::span<const std::byte> raw) = 0;
};

// Read `source` chunk by chunk and hand each chunk to `sink` (in order).
Expected<CopyStats> copyToSink(BlockDevice& source, ChunkSink& sink, const CopyOptions& options, Progress& progress);
// Device to device (restore, clone). Sizes may differ; copies min(size) or `limit`.
Expected<CopyStats> copyDevice(BlockDevice& source, BlockDevice& target, const CopyOptions& options, Progress& progress);

// Read a chunk honouring the bad-sector policy. Returns the number of unreadable sectors zero-filled.
Expected<std::uint64_t> readChunkTolerant(BlockDevice& source, ByteCount offset, std::span<std::byte> out, BadSectorPolicy policy,
                                          std::vector<Region>* badRegions);

bool isAllZero(std::span<const std::byte> bytes);

} // namespace stein::image
