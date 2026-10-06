// SPDX-License-Identifier: MIT
// Internal NTFS helpers shared by the detector, the allocation map and the reader.
#pragma once

#include "stein/layout/gen/ntfs.hpp"
#include "stein/core/endian.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace stein::fs::detail {

namespace gen = layout::gen;

// Apply the update sequence array ("fixups") to a FILE record in place.
inline bool applyFixups(std::vector<std::byte>& rec, std::uint32_t sectorSize) {
    gen::NtfsMftRecordHeader h(rec);
    const std::uint16_t usaOff = h.usaOffset(), usaCount = h.usaCount();
    if (usaCount < 2 || usaOff + usaCount * 2u > rec.size()) return false;
    const std::uint16_t usn = loadLe16(rec.data() + usaOff);
    for (std::uint16_t i = 1; i < usaCount; ++i) {
        const std::size_t pos = static_cast<std::size_t>(i) * sectorSize - 2;
        if (pos + 2 > rec.size()) return false;
        if (loadLe16(rec.data() + pos) != usn) return false;   // torn record
        rec[pos] = rec[usaOff + i * 2];
        rec[pos + 1] = rec[usaOff + i * 2 + 1];
    }
    return true;
}

// Decode an NTFS run list into (lcn, clusters) pairs; sparse runs have lcn == UINT64_MAX.
struct Run {
    std::uint64_t lcn;
    std::uint64_t count;
};
inline std::vector<Run> decodeRuns(std::span<const std::byte> r) {
    std::vector<Run> runs;
    std::int64_t lcn = 0;
    std::size_t pos = 0;
    while (pos < r.size()) {
        const auto hdr = std::to_integer<std::uint8_t>(r[pos++]);
        if (hdr == 0) break;
        const unsigned lenSize = hdr & 0xF, offSize = hdr >> 4;
        if (lenSize == 0 || lenSize > 8 || offSize > 8 || pos + lenSize + offSize > r.size()) break;
        std::uint64_t len = 0;
        for (unsigned i = 0; i < lenSize; ++i) len |= std::uint64_t{std::to_integer<std::uint8_t>(r[pos + i])} << (8 * i);
        pos += lenSize;
        if (offSize == 0) {
            runs.push_back(Run{~std::uint64_t{0}, len});   // sparse
            continue;
        }
        std::int64_t delta = 0;
        for (unsigned i = 0; i < offSize; ++i) delta |= std::int64_t{std::to_integer<std::uint8_t>(r[pos + i])} << (8 * i);
        if (std::to_integer<std::uint8_t>(r[pos + offSize - 1]) & 0x80) delta -= std::int64_t{1} << (8 * offSize);   // sign-extend
        pos += offSize;
        lcn += delta;
        runs.push_back(Run{static_cast<std::uint64_t>(lcn), len});
    }
    return runs;
}


} // namespace stein::fs::detail
