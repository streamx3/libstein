// SPDX-License-Identifier: MIT
#include "stein/core/crc32.hpp"

#include <array>

namespace stein {

namespace {

struct Table {
    std::array<std::uint32_t, 256> t{};
    explicit Table(std::uint32_t poly) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};

const Table& ieeeTable() {
    static const Table table(0xEDB88320u);
    return table;
}
const Table& castagnoliTable() {
    static const Table table(0x82F63B78u);
    return table;
}

std::uint32_t run(const Table& tbl, std::uint32_t state, std::span<const std::byte> data) {
    for (std::byte b : data) state = tbl.t[(state ^ std::to_integer<std::uint32_t>(b)) & 0xFF] ^ (state >> 8);
    return state;
}

} // namespace

void Crc32::update(std::span<const std::byte> data) { m_state = run(ieeeTable(), m_state, data); }
void Crc32c::update(std::span<const std::byte> data) { m_state = run(castagnoliTable(), m_state, data); }

} // namespace stein
