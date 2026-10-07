// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

namespace stein {

// Several devices laid end to end: split raw images (disk.img.000, .001, ...),
// a RAID-0/linear LV built from PV extents, or any multi-file container.
// Every part but the last must be a whole number of logical sectors long.
class ConcatDevice final : public BlockDevice {
public:
    static Expected<std::shared_ptr<ConcatDevice>> create(std::vector<BlockDevicePtr> parts, std::string name = {});

    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override;
    Expected<void> discard(ByteCount offset, ByteCount length) override;
    Expected<void> zeroRange(ByteCount offset, ByteCount length) override;

    const std::vector<BlockDevicePtr>& parts() const { return m_parts; }
    // Part index and offset inside that part for a byte offset.
    std::pair<std::size_t, ByteCount> locate(ByteCount offset) const;

private:
    ConcatDevice() = default;
    // Call `fn(part, offsetInPart, length)` for every piece of [offset, offset+length).
    template <class Fn> Expected<void> forEachPiece(ByteCount offset, ByteCount length, Fn fn);

    std::vector<BlockDevicePtr> m_parts;
    std::vector<ByteCount> m_starts;   // cumulative start of each part
    Geometry m_geometry;
    std::string m_name;
    bool m_readOnly = false;
};

} // namespace stein
