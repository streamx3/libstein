// SPDX-License-Identifier: MIT
#include "stein/block/slice_device.hpp"

namespace stein {

Expected<std::shared_ptr<SliceDevice>> SliceDevice::create(BlockDevicePtr parent, Region region, std::string name) {
    if (!parent) return fail(ErrorCategory::InvalidArgument, "slice needs a parent device");
    if (auto r = parent->checkRange(region.offset, region.length); !r) return fail(r.error());
    auto dev = std::shared_ptr<SliceDevice>(new SliceDevice());
    dev->m_parent = std::move(parent);
    dev->m_region = region;
    dev->m_geometry = dev->m_parent->geometry();
    dev->m_geometry.sizeBytes = region.length;
    // Alignment of the slice start relative to physical sectors, for the alignment policy.
    const auto phys = dev->m_geometry.physicalSectorSize;
    dev->m_geometry.alignmentOffset = phys ? (dev->m_geometry.alignmentOffset + region.offset) % phys : 0;
    dev->m_name = name.empty() ? dev->m_parent->name() + "@" + std::to_string(region.offset) : std::move(name);
    return dev;
}

Expected<void> SliceDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    return m_parent->readAt(m_region.offset + offset, dst);
}

Expected<void> SliceDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (auto r = checkRange(offset, src.size()); !r) return r;
    return m_parent->writeAt(m_region.offset + offset, src);
}

Expected<void> SliceDevice::discard(ByteCount offset, ByteCount length) {
    if (auto r = checkRange(offset, length); !r) return r;
    return m_parent->discard(m_region.offset + offset, length);
}

} // namespace stein
