// SPDX-License-Identifier: MIT
#include "stein/core/guid.hpp"

#include <cstdio>

namespace stein {

namespace {
int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // namespace

std::optional<Uuid> Uuid::parse(std::string_view text) {
    if (!text.empty() && text.front() == '{' && text.back() == '}') {
        text.remove_prefix(1);
        text.remove_suffix(1);
    }
    // Groups of 8-4-4-4-12 hex digits.
    static constexpr int groups[5] = {8, 4, 4, 4, 12};
    Bytes out{};
    std::size_t pos = 0, bi = 0;
    for (int g = 0; g < 5; ++g) {
        if (g > 0) {
            if (pos >= text.size() || text[pos] != '-') return std::nullopt;
            ++pos;
        }
        for (int i = 0; i < groups[g]; i += 2) {
            if (pos + 1 >= text.size()) return std::nullopt;
            int hi = hexVal(text[pos]), lo = hexVal(text[pos + 1]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out[bi++] = static_cast<std::uint8_t>(hi * 16 + lo);
            pos += 2;
        }
    }
    if (pos != text.size()) return std::nullopt;
    return Uuid(out);
}

Uuid Uuid::fromRfcBytes(std::span<const std::byte, 16> b) {
    Bytes out{};
    for (int i = 0; i < 16; ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    return Uuid(out);
}

Uuid Uuid::fromGptBytes(std::span<const std::byte, 16> b) {
    Bytes out{};
    // time_low (4 bytes LE), time_mid (2 LE), time_hi (2 LE), rest as-is.
    out[0] = std::to_integer<std::uint8_t>(b[3]);
    out[1] = std::to_integer<std::uint8_t>(b[2]);
    out[2] = std::to_integer<std::uint8_t>(b[1]);
    out[3] = std::to_integer<std::uint8_t>(b[0]);
    out[4] = std::to_integer<std::uint8_t>(b[5]);
    out[5] = std::to_integer<std::uint8_t>(b[4]);
    out[6] = std::to_integer<std::uint8_t>(b[7]);
    out[7] = std::to_integer<std::uint8_t>(b[6]);
    for (int i = 8; i < 16; ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    return Uuid(out);
}

void Uuid::toRfcBytes(std::span<std::byte, 16> out) const {
    for (int i = 0; i < 16; ++i) out[i] = std::byte(m_bytes[i]);
}

void Uuid::toGptBytes(std::span<std::byte, 16> out) const {
    out[0] = std::byte(m_bytes[3]);
    out[1] = std::byte(m_bytes[2]);
    out[2] = std::byte(m_bytes[1]);
    out[3] = std::byte(m_bytes[0]);
    out[4] = std::byte(m_bytes[5]);
    out[5] = std::byte(m_bytes[4]);
    out[6] = std::byte(m_bytes[7]);
    out[7] = std::byte(m_bytes[6]);
    for (int i = 8; i < 16; ++i) out[i] = std::byte(m_bytes[i]);
}

bool Uuid::isNil() const {
    for (auto b : m_bytes)
        if (b) return false;
    return true;
}

std::string Uuid::toString(bool upper) const {
    char buf[40];
    const auto& b = m_bytes;
    if (upper)
        std::snprintf(buf, sizeof buf, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                      b[14], b[15]);
    else
        std::snprintf(buf, sizeof buf, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                      b[14], b[15]);
    return buf;
}

} // namespace stein
