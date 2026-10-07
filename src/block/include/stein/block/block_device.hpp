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
    // TRIM hint. Default: unsupported. A device may keep old data after a discard;
    // use zeroRange() when the range must read back as zeros.
    virtual Expected<void> discard(ByteCount offset, ByteCount length);
    // Make [offset, offset + length) read back as zeros, as cheaply as the device
    // allows: a hole for files, WRITE ZEROES / unmap-with-read-back for disks, plain
    // zero writes everywhere else. Unlike discard(), the outcome is guaranteed.
    virtual Expected<void> zeroRange(ByteCount offset, ByteCount length);

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
    Expected<void> zero(ByteCount offset, ByteCount length) { return zeroRange(offset, length); }

protected:
    // What every zeroRange() falls back to: zeros written in 1 MiB pieces through writeAt().
    Expected<void> writeZeros(ByteCount offset, ByteCount length);
    // After a discard hint: read the range back and write zeros only where it is not zero yet.
    Expected<void> zeroWhereNotZero(ByteCount offset, ByteCount length);
    // Splits a range at `align`: head and tail go through writeZeros(), the aligned middle
    // through `fast(offset, length)`; when `fast` fails the middle is written too.
    template <class Fast>
    Expected<void> zeroWithFastPath(ByteCount offset, ByteCount length, ByteCount align, Fast fast) {
        const ByteCount end = offset + length;
        const ByteCount a = alignUp(offset, align), b = end >= a ? alignDown(end, align) : a;
        if (b <= a) return writeZeros(offset, length);
        if (a > offset)
            if (auto r = writeZeros(offset, a - offset); !r) return r;
        if (!fast(a, b - a))
            if (auto r = writeZeros(a, b - a); !r) return r;
        if (end > b)
            if (auto r = writeZeros(b, end - b); !r) return r;
        return {};
    }
};

// Devices are shared between the topology tree, slices and jobs.
using BlockDevicePtr = std::shared_ptr<BlockDevice>;

} // namespace stein
