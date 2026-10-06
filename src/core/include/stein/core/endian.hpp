// SPDX-License-Identifier: MIT
// Unaligned little/big-endian loads and stores on byte spans.
#pragma once

#include <cstdint>
#include <cstring>
#include <span>

namespace stein {

inline std::uint16_t loadLe16(const std::byte* p) {
    return static_cast<std::uint16_t>(std::to_integer<unsigned>(p[0]) |
                                      (std::to_integer<unsigned>(p[1]) << 8));
}
inline std::uint32_t loadLe32(const std::byte* p) {
    return std::to_integer<std::uint32_t>(p[0]) | (std::to_integer<std::uint32_t>(p[1]) << 8) |
           (std::to_integer<std::uint32_t>(p[2]) << 16) | (std::to_integer<std::uint32_t>(p[3]) << 24);
}
inline std::uint64_t loadLe64(const std::byte* p) {
    return static_cast<std::uint64_t>(loadLe32(p)) | (static_cast<std::uint64_t>(loadLe32(p + 4)) << 32);
}
inline std::uint16_t loadBe16(const std::byte* p) {
    return static_cast<std::uint16_t>((std::to_integer<unsigned>(p[0]) << 8) |
                                      std::to_integer<unsigned>(p[1]));
}
inline std::uint32_t loadBe32(const std::byte* p) {
    return (std::to_integer<std::uint32_t>(p[0]) << 24) | (std::to_integer<std::uint32_t>(p[1]) << 16) |
           (std::to_integer<std::uint32_t>(p[2]) << 8) | std::to_integer<std::uint32_t>(p[3]);
}
inline std::uint64_t loadBe64(const std::byte* p) {
    return (static_cast<std::uint64_t>(loadBe32(p)) << 32) | static_cast<std::uint64_t>(loadBe32(p + 4));
}

inline void storeLe16(std::byte* p, std::uint16_t v) {
    p[0] = std::byte(v & 0xff);
    p[1] = std::byte((v >> 8) & 0xff);
}
inline void storeLe32(std::byte* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = std::byte((v >> (8 * i)) & 0xff);
}
inline void storeLe64(std::byte* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = std::byte((v >> (8 * i)) & 0xff);
}
inline void storeBe16(std::byte* p, std::uint16_t v) {
    p[0] = std::byte((v >> 8) & 0xff);
    p[1] = std::byte(v & 0xff);
}
inline void storeBe32(std::byte* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[3 - i] = std::byte((v >> (8 * i)) & 0xff);
}
inline void storeBe64(std::byte* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[7 - i] = std::byte((v >> (8 * i)) & 0xff);
}

// Span-checked variants: return false if the span is too short.
inline bool loadLe16(std::span<const std::byte> s, std::size_t off, std::uint16_t& out) {
    if (off + 2 > s.size()) return false;
    out = loadLe16(s.data() + off);
    return true;
}
inline bool loadLe32(std::span<const std::byte> s, std::size_t off, std::uint32_t& out) {
    if (off + 4 > s.size()) return false;
    out = loadLe32(s.data() + off);
    return true;
}
inline bool loadLe64(std::span<const std::byte> s, std::size_t off, std::uint64_t& out) {
    if (off + 8 > s.size()) return false;
    out = loadLe64(s.data() + off);
    return true;
}
inline bool loadBe16(std::span<const std::byte> s, std::size_t off, std::uint16_t& out) {
    if (off + 2 > s.size()) return false;
    out = loadBe16(s.data() + off);
    return true;
}
inline bool loadBe32(std::span<const std::byte> s, std::size_t off, std::uint32_t& out) {
    if (off + 4 > s.size()) return false;
    out = loadBe32(s.data() + off);
    return true;
}
inline bool loadBe64(std::span<const std::byte> s, std::size_t off, std::uint64_t& out) {
    if (off + 8 > s.size()) return false;
    out = loadBe64(s.data() + off);
    return true;
}

} // namespace stein
