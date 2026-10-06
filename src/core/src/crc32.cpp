// SPDX-License-Identifier: MIT
#include "stein/core/crc32.hpp"

#include "hash_impl.hpp"
#include "stein/core/cpu.hpp"

#include <array>
#include <cstring>

namespace stein {

namespace {

// Slice-by-8: eight 256-entry tables, 8 bytes per step.
struct Tables {
    std::array<std::array<std::uint32_t, 256>, 8> t{};
    explicit Tables(std::uint32_t poly) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
            t[0][i] = c;
        }
        for (std::uint32_t i = 0; i < 256; ++i)
            for (int k = 1; k < 8; ++k) t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xFF];
    }
};

const Tables& ieee() {
    static const Tables tables(0xEDB88320u);
    return tables;
}
const Tables& castagnoli() {
    static const Tables tables(0x82F63B78u);
    return tables;
}

std::uint32_t sliceBy8(const Tables& tb, std::uint32_t crc, std::span<const std::byte> data) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t n = data.size();
    // Align to 8 for the fast loop (not required for correctness; keeps loads aligned).
    while (n && (reinterpret_cast<std::uintptr_t>(p) & 7)) {
        crc = tb.t[0][(crc ^ *p++) & 0xFF] ^ (crc >> 8);
        --n;
    }
    while (n >= 8) {
        std::uint32_t lo, hi;
        std::memcpy(&lo, p, 4);
        std::memcpy(&hi, p + 4, 4);
        crc ^= lo;   // little-endian hosts; big-endian would need a byte swap here
        crc = tb.t[7][crc & 0xFF] ^ tb.t[6][(crc >> 8) & 0xFF] ^ tb.t[5][(crc >> 16) & 0xFF] ^ tb.t[4][crc >> 24] ^ tb.t[3][hi & 0xFF] ^
              tb.t[2][(hi >> 8) & 0xFF] ^ tb.t[1][(hi >> 16) & 0xFF] ^ tb.t[0][hi >> 24];
        p += 8;
        n -= 8;
    }
    while (n--) crc = tb.t[0][(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc;
}

} // namespace

namespace detail {
std::uint32_t crc32Portable(std::uint32_t state, std::span<const std::byte> data) { return sliceBy8(ieee(), state, data); }
std::uint32_t crc32cPortable(std::uint32_t state, std::span<const std::byte> data) { return sliceBy8(castagnoli(), state, data); }
} // namespace detail

void Crc32::update(std::span<const std::byte> data) { m_state = detail::crc32Portable(m_state, data); }

void Crc32c::update(std::span<const std::byte> data) {
    static const bool hw = detail::crc32cHardwareAvailable();
    m_state = hw ? detail::crc32cHardware(m_state, data) : detail::crc32cPortable(m_state, data);
}

} // namespace stein
