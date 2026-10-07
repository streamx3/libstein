// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

namespace stein {

// A [offset, offset+length) window on a parent device: a partition, a nested
// table's area, a LUKS payload region. Shares the parent's sector size.
class SliceDevice final : public BlockDevice {
public:
    // Fails with OutOfRange if the region does not fit inside the parent.
    static Expected<std::shared_ptr<SliceDevice>> create(BlockDevicePtr parent, Region region,
                                                         std::string name = {});

    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_parent->isReadOnly(); }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override { return m_parent->flush(); }
    Expected<void> discard(ByteCount offset, ByteCount length) override;
    Expected<void> zeroRange(ByteCount offset, ByteCount length) override;
    std::shared_ptr<BlockDevice> parent() const override { return m_parent; }
    std::vector<Region> extentsOnParent() const override { return {m_region}; }

    const Region& region() const { return m_region; }

private:
    SliceDevice() = default;
    BlockDevicePtr m_parent;
    Region m_region;
    Geometry m_geometry;
    std::string m_name;
};

// Decorator that refuses writes. The default posture for probing.
class ReadOnlyDevice final : public BlockDevice {
public:
    explicit ReadOnlyDevice(BlockDevicePtr inner) : m_inner(std::move(inner)) {}
    std::string name() const override { return m_inner->name(); }
    Geometry geometry() const override { return m_inner->geometry(); }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        return m_inner->readAt(offset, dst);
    }
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override {
        return fail(ErrorCategory::Permission, "device is opened read-only");
    }
    Expected<void> flush() override { return {}; }
    std::shared_ptr<BlockDevice> parent() const override { return m_inner; }
    std::vector<Region> extentsOnParent() const override { return {Region{0, m_inner->size()}}; }

private:
    BlockDevicePtr m_inner;
};

} // namespace stein
