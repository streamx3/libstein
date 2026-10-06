// SPDX-License-Identifier: MIT
#include "stein/fs/allocation_map.hpp"

#include <algorithm>
#include <bit>
#include <cstring>

namespace stein::fs {

AllocationMap::AllocationMap(ByteCount origin, ByteCount blockSize, std::uint64_t blocks, bool initiallyUsed)
    : m_origin(origin), m_blockSize(blockSize), m_blocks(blocks), m_words((blocks + 63) / 64, initiallyUsed ? ~std::uint64_t{0} : 0) {
    if (initiallyUsed && blocks % 64) m_words.back() = (std::uint64_t{1} << (blocks % 64)) - 1;
}

bool AllocationMap::isUsed(std::uint64_t block) const {
    if (block >= m_blocks) return true;
    return (m_words[block / 64] >> (block % 64)) & 1;
}

void AllocationMap::set(std::uint64_t block, bool used) {
    if (block >= m_blocks) return;
    const std::uint64_t bit = std::uint64_t{1} << (block % 64);
    if (used) m_words[block / 64] |= bit;
    else m_words[block / 64] &= ~bit;
}

void AllocationMap::setRange(std::uint64_t first, std::uint64_t count, bool used) {
    const std::uint64_t end = std::min(m_blocks, first + count);
    for (std::uint64_t b = first; b < end; ++b) set(b, used);
}

void AllocationMap::importBitmap(std::uint64_t first, std::uint64_t count, std::span<const std::byte> bits, bool invert, bool msbFirst) {
    const std::uint64_t end = std::min(m_blocks, first + count);
    for (std::uint64_t b = first; b < end; ++b) {
        const std::uint64_t i = b - first;
        if (i / 8 >= bits.size()) break;
        const unsigned shift = msbFirst ? 7 - (i % 8) : (i % 8);
        bool used = (std::to_integer<std::uint8_t>(bits[i / 8]) >> shift) & 1;
        set(b, used != invert);
    }
}

std::uint64_t AllocationMap::usedBlocks() const {
    std::uint64_t n = 0;
    for (auto w : m_words) n += static_cast<std::uint64_t>(std::popcount(w));
    return n;
}

bool AllocationMap::isFree(ByteCount offset, ByteCount length) const {
    if (length == 0) return true;
    if (offset < m_origin || offset + length > coveredEnd()) return false;
    const std::uint64_t first = (offset - m_origin) / m_blockSize;
    const std::uint64_t last = (offset + length - 1 - m_origin) / m_blockSize;
    for (std::uint64_t b = first; b <= last; ++b)
        if (isUsed(b)) return false;
    return true;
}

ByteCount AllocationMap::zeroFree(ByteCount offset, std::span<std::byte> data) const {
    ByteCount zeroed = 0;
    const ByteCount end = offset + data.size();
    const ByteCount from = std::max(offset, m_origin);
    const ByteCount to = std::min(end, coveredEnd());
    if (from >= to) return 0;
    std::uint64_t b = (from - m_origin) / m_blockSize;
    ByteCount pos = from;
    while (pos < to) {
        const ByteCount blockEnd = std::min(to, m_origin + (b + 1) * m_blockSize);
        if (!isUsed(b)) {
            std::memset(data.data() + (pos - offset), 0, static_cast<std::size_t>(blockEnd - pos));
            zeroed += blockEnd - pos;
        }
        pos = blockEnd;
        ++b;
    }
    return zeroed;
}

std::vector<Region> AllocationMap::usedRegions() const {
    std::vector<Region> out;
    auto add = [&](ByteCount off, ByteCount len) {
        if (!len) return;
        if (!out.empty() && out.back().end() == off) out.back().length += len;
        else out.push_back(Region{off, len});
    };
    add(0, m_origin);
    for (std::uint64_t b = 0; b < m_blocks; ++b)
        if (isUsed(b)) add(m_origin + b * m_blockSize, m_blockSize);
    return out;
}

} // namespace stein::fs
