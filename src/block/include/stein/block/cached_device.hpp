// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

#include <cstdint>
#include <list>
#include <mutex>
#include <unordered_map>

namespace stein {

// Read cache in front of a slow device; in practice above a decrypting payload, so a directory
// walk or a file read that touches the same sectors twice decrypts them once. Fixed-size chunks
// (the last one ragged when the device size is not a multiple) in a bounded LRU. Writes pass
// through to the inner device and drop the chunks they touch, so a reader never sees bytes the
// inner device no longer holds. A chunk the inner device cannot read whole (a bad sector in it)
// is not cached; the bytes asked for are read on their own, so only reads touching the bad sector
// fail. Safe to share between threads: the NFS server and the UI both read through the same
// payload. Everything else forwards to the inner device.
class CachedDevice final : public BlockDevice {
public:
    struct Options {
        std::uint32_t chunkSize = 256 * KiB;   // bytes per chunk; also what a miss reads from the inner device
        ByteCount budget = 64 * MiB;           // most bytes held at once; raised to one chunk if smaller
    };
    // hits/misses count chunk lookups: a read spanning two chunks is two lookups.
    struct Stats {
        std::uint64_t hits = 0, misses = 0;
        std::uint64_t evictions = 0;   // chunks dropped to stay within the budget (not by writes)
        ByteCount cachedBytes = 0;
        std::size_t chunks = 0;
    };

    // A zero chunkSize takes the default; a budget below one chunk is raised to one chunk.
    static std::shared_ptr<CachedDevice> create(BlockDevicePtr inner, Options options);
    static std::shared_ptr<CachedDevice> create(BlockDevicePtr inner);   // default Options

    std::string name() const override { return m_inner->name(); }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return m_inner->isReadOnly(); }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override { return m_inner->flush(); }
    Expected<void> discard(ByteCount offset, ByteCount length) override;
    Expected<void> zeroRange(ByteCount offset, ByteCount length) override;
    std::shared_ptr<BlockDevice> parent() const override { return m_inner; }
    std::vector<Region> extentsOnParent() const override { return {Region{0, m_size}}; }

    const Options& options() const { return m_options; }   // as applied (defaults and clamps included)
    Stats stats() const;
    // Drop every cached chunk, or those overlapping a range: for when the inner device changed
    // behind the cache (a write that did not go through it).
    void invalidate();
    void invalidate(ByteCount offset, ByteCount length);

private:
    CachedDevice(BlockDevicePtr inner, Options options);
    struct Chunk {
        ByteCount index;
        std::vector<std::byte> bytes;
    };
    using Lru = std::list<Chunk>;   // most recently used at the front
    Expected<void> readWithinChunk(ByteCount index, ByteCount within, std::span<std::byte> dst);
    void dropLocked(ByteCount firstIndex, ByteCount lastIndex);

    BlockDevicePtr m_inner;
    Options m_options;
    ByteCount m_size;
    mutable std::mutex m_mutex;
    Lru m_lru;
    std::unordered_map<ByteCount, Lru::iterator> m_index;
    ByteCount m_cachedBytes = 0;
    // Bumped by every invalidation. A miss reads the inner device without the lock; if a write
    // happened meanwhile the bytes it read may predate it, so they are returned but not kept.
    std::uint64_t m_generation = 0;
    Stats m_stats;
};

} // namespace stein
