// SPDX-License-Identifier: MIT
// BlockDevice: the hub abstraction of libstein. Everything that has a linear
// byte-addressable space is one: a physical disk, a partition (SliceDevice),
// a file, an opened image, a decrypted container, a logical volume.
// See doc/design/12-class-hierarchies.md §1.
#pragma once

#include "stein/core/error.hpp"
#include "stein/core/units.hpp"

#include <memory>
#include <span>
#include <string>
#include <vector>

namespace stein {

class BlockDevice {
public:
    virtual ~BlockDevice() = default;

    // Human-readable name: an OS path, a file path, "memory", "slice@offset".
    virtual std::string name() const = 0;
    virtual Geometry geometry() const = 0;
    virtual bool isReadOnly() const = 0;

    // Full-length read or an error. A read past the end is OutOfRange, never a
    // short read; callers that want "as much as exists" clamp with size() first.
    virtual Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) = 0;
    virtual Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) = 0;
    virtual Expected<void> flush() = 0;
    // TRIM / zero a range. Default: unsupported (callers fall back to writing zeros).
    virtual Expected<void> discard(ByteCount offset, ByteCount length);

    // The device this one is a view of (SliceDevice, DecryptedDevice...), or null.
    virtual std::shared_ptr<BlockDevice> parent() const { return nullptr; }
    // Where this device's bytes live on its parent, if it is a view. Empty when not a view.
    virtual std::vector<Region> extentsOnParent() const { return {}; }

    // ---- non-virtual conveniences ------------------------------------------------
    ByteCount size() const { return geometry().sizeBytes; }
    std::uint32_t sectorSize() const { return geometry().logicalSectorSize; }
    Expected<void> checkRange(ByteCount offset, ByteCount length) const;
    Expected<std::vector<std::byte>> read(ByteCount offset, ByteCount length);
    Expected<std::vector<std::byte>> readSectors(Lba first, SectorCount count);
    Expected<void> writeSectors(Lba first, std::span<const std::byte> src);
    Expected<void> zero(ByteCount offset, ByteCount length);   // discard() or write zeros
};

// Devices are shared between the topology tree, slices and jobs.
using BlockDevicePtr = std::shared_ptr<BlockDevice>;

} // namespace stein
