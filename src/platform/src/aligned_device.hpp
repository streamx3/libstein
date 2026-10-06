// SPDX-License-Identifier: MIT
// Raw devices on macOS (/dev/rdiskN) and Windows (\\.\PhysicalDriveN) accept
// only sector-aligned offsets and lengths. This base turns arbitrary
// readAt/writeAt calls into aligned rawRead/rawWrite calls with a bounce
// buffer (read-modify-write for partial sectors). Platform-independent and
// unit-tested against a MemoryDevice.
#pragma once

#include "stein/block/block_device.hpp"

#include <mutex>

namespace stein::platform {

class AlignedDevice : public BlockDevice {
public:
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;

protected:
    // offset and span size are multiples of alignment(); the span may be any size up to kBounceBytes.
    virtual Expected<void> rawRead(ByteCount offset, std::span<std::byte> dst) = 0;
    virtual Expected<void> rawWrite(ByteCount offset, std::span<const std::byte> src) = 0;
    // The I/O unit: the logical sector size.
    std::uint32_t alignment() const { return sectorSize() ? sectorSize() : 512; }

    static constexpr ByteCount kBounceBytes = 4 * MiB;

private:
    std::vector<std::byte> m_bounce;
    std::mutex m_mutex;
};

} // namespace stein::platform
