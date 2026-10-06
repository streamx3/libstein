// SPDX-License-Identifier: MIT
// AllocationMap: which blocks of a filesystem hold data (L1). Imaging uses it
// to skip free space; UIs use it for usage bars. Coverage is
// [origin, origin + blocks * blockSize) with one bit per block; bytes before
// the origin (boot sectors, FATs, root directory) and after the covered
// range (slack, NTFS backup boot sector) count as used.
#pragma once

#include "stein/core/units.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace stein::fs {

class AllocationMap {
public:
    AllocationMap() = default;
    AllocationMap(ByteCount origin, ByteCount blockSize, std::uint64_t blocks, bool initiallyUsed);

    ByteCount origin() const { return m_origin; }
    ByteCount blockSize() const { return m_blockSize; }
    std::uint64_t blocks() const { return m_blocks; }
    ByteCount coveredEnd() const { return m_origin + m_blocks * m_blockSize; }

    bool isUsed(std::uint64_t block) const;
    void set(std::uint64_t block, bool used);
    void setRange(std::uint64_t first, std::uint64_t count, bool used);
    // Import a packed little-endian bitmap (bit i of byte i/8 = block first+i), 1 = used.
    void importBitmap(std::uint64_t first, std::uint64_t count, std::span<const std::byte> bits, bool invert = false, bool msbFirst = false);

    std::uint64_t usedBlocks() const;
    ByteCount usedBytes() const { return usedBlocks() * m_blockSize; }
    ByteCount freeBytes() const { return (m_blocks - usedBlocks()) * m_blockSize; }

    // True when every byte of [offset, offset+length) (filesystem-relative) is free.
    bool isFree(ByteCount offset, ByteCount length) const;
    // Zero the free bytes inside `data`, which starts at `offset`. Returns the
    // number of bytes zeroed.
    ByteCount zeroFree(ByteCount offset, std::span<std::byte> data) const;
    // Coalesced used byte ranges including the head and tail.
    std::vector<Region> usedRegions() const;

private:
    ByteCount m_origin = 0;
    ByteCount m_blockSize = 0;
    std::uint64_t m_blocks = 0;
    std::vector<std::uint64_t> m_words;
};

} // namespace stein::fs
