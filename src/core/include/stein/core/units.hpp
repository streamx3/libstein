// SPDX-License-Identifier: MIT
// Plain integer units and the few small structs every module shares.
// Deliberately not "strong types": they would need templates and conversions
// everywhere; instead the names say what they are and functions validate.
#pragma once

#include <cstdint>
#include <string>

namespace stein {

using ByteCount = std::uint64_t;   // a size or an absolute byte offset
using Lba = std::uint64_t;         // logical block address, in sectors of the owning device
using SectorCount = std::uint64_t;

inline constexpr ByteCount KiB = 1024;
inline constexpr ByteCount MiB = 1024 * KiB;
inline constexpr ByteCount GiB = 1024 * MiB;
inline constexpr ByteCount TiB = 1024 * GiB;

// A contiguous byte range on some device. Half-open: [offset, offset + length).
struct Region {
    ByteCount offset = 0;
    ByteCount length = 0;

    ByteCount end() const { return offset + length; }
    bool empty() const { return length == 0; }
    bool contains(ByteCount pos) const { return pos >= offset && pos < end(); }
    bool contains(const Region& r) const { return r.offset >= offset && r.end() <= end(); }
    bool overlaps(const Region& r) const { return offset < r.end() && r.offset < end(); }
    bool operator==(const Region&) const = default;
};

// Geometry of a block device as the platform reports it.
struct Geometry {
    ByteCount sizeBytes = 0;
    std::uint32_t logicalSectorSize = 512;   // the unit of LBAs on this device
    std::uint32_t physicalSectorSize = 512;  // 4096 on "512e" disks
    std::uint32_t optimalIoSize = 0;         // 0 = unknown
    ByteCount alignmentOffset = 0;           // first physical sector offset (usually 0)

    SectorCount sectors() const {
        return logicalSectorSize ? sizeBytes / logicalSectorSize : 0;
    }
    ByteCount lbaToByte(Lba lba) const { return lba * logicalSectorSize; }
};

// Round helpers (power-of-two or not; `align` must be > 0).
inline ByteCount alignDown(ByteCount v, ByteCount align) { return align ? v - (v % align) : v; }
inline ByteCount alignUp(ByteCount v, ByteCount align) {
    if (!align) return v;
    ByteCount r = v % align;
    return r ? v + (align - r) : v;
}
inline bool isAligned(ByteCount v, ByteCount align) { return align == 0 || v % align == 0; }

// "1.50 GiB", "512 B"; binary units (IEC). `decimal` = true gives kB/MB/GB (SI).
std::string formatSize(ByteCount bytes, bool decimal = false);
// "1.50 GiB (1,610,612,736 bytes)"
std::string formatSizeExact(ByteCount bytes);

} // namespace stein
