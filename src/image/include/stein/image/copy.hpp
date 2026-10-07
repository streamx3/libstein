// SPDX-License-Identifier: MIT
// The copy engine: chunked, zero-aware, bad-sector tolerant transfer from a
// BlockDevice to a chunk sink or another BlockDevice. One engine serves image
// creation, restore and cloning. See doc/design/14-imaging.md §3.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/progress.hpp"
#include "stein/fs/allocation_map.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace stein::image {

enum class BadSectorPolicy : std::uint8_t {
    Fail,        // first unreadable sector aborts
    SkipZero,    // retry sector by sector, zero-fill what stays unreadable, continue (recorded)
};

// A filesystem's allocation map placed at its byte range on the source device.
struct MappedAllocation {
    Region region;
    const fs::AllocationMap* map = nullptr;
};

// What to do with an all-zero chunk when writing device to device.
enum class ZeroPolicy : std::uint8_t {
    Write,        // write the zeros: the target becomes byte-identical (the default)
    Skip,         // write nothing: the target keeps whatever it held there (blank or disposable target)
    SkipInside,   // write zeros only outside `keepRegions` (gaps the partition table calls free); inside, keep
};

struct CopyOptions {
    std::uint32_t chunkSize = 4 * MiB;
    // Used-block-only: free blocks of these filesystems are zeroed before the
    // chunk is handed on, so whole-free chunks become zero chunks.
    std::vector<MappedAllocation> allocations;
    BadSectorPolicy badSectors = BadSectorPolicy::Fail;
    bool skipZeroChunksOnWrite = false;   // deprecated alias of zeroPolicy = Skip; kept for callers of the first release
    ZeroPolicy zeroPolicy = ZeroPolicy::Write;
    std::vector<Region> keepRegions;      // SkipInside: ranges whose zeros are not written (partitions); any order, may overlap
    bool discardZeroChunks = false;       // device->device: try discard() for zero chunks before writing zeros
    ByteCount limit = 0;                  // copy only the first `limit` bytes (0 = all)
};

struct CopyStats {
    ByteCount bytesRead = 0;
    ByteCount bytesWritten = 0;
    std::uint64_t chunks = 0;
    std::uint64_t zeroChunks = 0;
    std::uint64_t unreadableSectors = 0;
    ByteCount freeBytesSkipped = 0;       // bytes zeroed because an allocation map said "free"
    ByteCount zeroBytesWritten = 0;       // bytes of all-zero chunks that were written (or discarded) on the target
    ByteCount zeroBytesSkipped = 0;       // bytes of all-zero chunks left untouched on the target
    std::vector<Region> badRegions;       // zero-filled ranges (coalesced)
};

// The parts of `range` not covered by any of `keep`: sorted, disjoint, sector-exact.
std::vector<Region> regionsOutside(const Region& range, std::vector<Region> keep);

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
