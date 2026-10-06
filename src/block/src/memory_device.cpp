// SPDX-License-Identifier: MIT
#include "stein/block/memory_device.hpp"

#include <algorithm>

namespace stein {

MemoryDevice::MemoryDevice(ByteCount size, std::uint32_t sectorSize)
    : m_bytes(static_cast<std::size_t>(size), std::byte{0}) {
    m_geometry.sizeBytes = size;
    m_geometry.logicalSectorSize = sectorSize;
    m_geometry.physicalSectorSize = sectorSize;
}

MemoryDevice::MemoryDevice(std::vector<std::byte> bytes, std::uint32_t sectorSize) : m_bytes(std::move(bytes)) {
    m_geometry.sizeBytes = m_bytes.size();
    m_geometry.logicalSectorSize = sectorSize;
    m_geometry.physicalSectorSize = sectorSize;
}

Expected<void> MemoryDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(offset), dst.size(), dst.begin());
    return {};
}

Expected<void> MemoryDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (m_readOnly) return fail(ErrorCategory::Permission, "memory device is read-only");
    if (auto r = checkRange(offset, src.size()); !r) return r;
    std::copy(src.begin(), src.end(), m_bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    return {};
}

Expected<void> MemoryDevice::discard(ByteCount offset, ByteCount length) {
    if (m_readOnly) return fail(ErrorCategory::Permission, "memory device is read-only");
    if (auto r = checkRange(offset, length); !r) return r;
    std::fill_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(offset), static_cast<std::ptrdiff_t>(length),
                std::byte{0});
    return {};
}

} // namespace stein
