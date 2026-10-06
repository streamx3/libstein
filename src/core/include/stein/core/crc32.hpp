// SPDX-License-Identifier: MIT
// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) as used by GPT, zlib, PNG;
// CRC-32C (Castagnoli, poly 0x82F63B78) as used by ext4 metadata_csum, btrfs, iSCSI.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein {

class Crc32 {
public:
    // Incremental use: Crc32 c; c.update(a); c.update(b); c.value();
    void update(std::span<const std::byte> data);
    std::uint32_t value() const { return ~m_state; }
    void reset() { m_state = 0xFFFFFFFFu; }

    static std::uint32_t compute(std::span<const std::byte> data) {
        Crc32 c;
        c.update(data);
        return c.value();
    }

private:
    std::uint32_t m_state = 0xFFFFFFFFu;
};

class Crc32c {
public:
    void update(std::span<const std::byte> data);
    std::uint32_t value() const { return ~m_state; }
    void reset() { m_state = 0xFFFFFFFFu; }
    static std::uint32_t compute(std::span<const std::byte> data) {
        Crc32c c;
        c.update(data);
        return c.value();
    }

private:
    std::uint32_t m_state = 0xFFFFFFFFu;
};

} // namespace stein
