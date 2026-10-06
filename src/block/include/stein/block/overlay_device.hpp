// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

#include <map>
#include <mutex>
#include <vector>

namespace stein {

// Copy-on-write overlay: reads come from the overlay where written, else from
// the base; writes never reach the base until commit(). This is how operations
// are simulated on the *real* code path (jobs write to the overlay, then the
// result is probed), and how a batch of writes can be previewed, diffed and
// applied as one step. Granularity: `blockSize` (default 4 KiB).
class OverlayDevice final : public BlockDevice {
public:
    static std::shared_ptr<OverlayDevice> create(BlockDevicePtr base, std::uint32_t blockSize = 4096);

    std::string name() const override { return m_base->name() + " (overlay)"; }
    Geometry geometry() const override { return m_base->geometry(); }
    bool isReadOnly() const override { return false; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override { return {}; }
    Expected<void> discard(ByteCount offset, ByteCount length) override;   // zeroes in the overlay
    std::shared_ptr<BlockDevice> parent() const override { return m_base; }
    std::vector<Region> extentsOnParent() const override { return {Region{0, m_base->size()}}; }

    // Byte ranges that differ from the base (coalesced, block-aligned).
    std::vector<Region> dirtyRegions() const;
    ByteCount dirtyBytes() const;
    bool hasChanges() const { return !m_blocks.empty(); }
    // Write every dirty block to the base and clear the overlay. Stops at the first error.
    Expected<void> commit();
    void discardChanges() { m_blocks.clear(); }

private:
    OverlayDevice(BlockDevicePtr base, std::uint32_t blockSize) : m_base(std::move(base)), m_blockSize(blockSize) {}
    Expected<std::vector<std::byte>*> blockFor(ByteCount blockIndex);

    BlockDevicePtr m_base;
    std::uint32_t m_blockSize;
    std::map<ByteCount, std::vector<std::byte>> m_blocks;   // block index -> bytes
    mutable std::mutex m_mutex;
};

} // namespace stein
