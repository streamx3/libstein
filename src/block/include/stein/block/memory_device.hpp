// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

namespace stein {

// A block device backed by a std::vector. Tests, simulation, and in-memory
// construction of partition tables before they are written.
class MemoryDevice final : public BlockDevice {
public:
    explicit MemoryDevice(ByteCount size, std::uint32_t sectorSize = 512);
    MemoryDevice(std::vector<std::byte> bytes, std::uint32_t sectorSize = 512);

    std::string name() const override { return "memory"; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override { return {}; }
    Expected<void> discard(ByteCount offset, ByteCount length) override;

    void setReadOnly(bool ro) { m_readOnly = ro; }
    std::span<std::byte> bytes() { return m_bytes; }
    std::span<const std::byte> bytes() const { return m_bytes; }

private:
    std::vector<std::byte> m_bytes;
    Geometry m_geometry;
    bool m_readOnly = false;
};

} // namespace stein
