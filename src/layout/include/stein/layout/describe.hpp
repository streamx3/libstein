// SPDX-License-Identifier: MIT
// Generic decoder: StructSpec + bytes -> Node tree with per-field validity
// from the manifest's simple rules. Format modules add cross-field checks.
#pragma once

#include "stein/layout/node.hpp"
#include "stein/layout/spec.hpp"

#include <span>

namespace stein::layout {

// `bytes` must be at least spec.size long; extra bytes are ignored.
// `absOffset` is where byte 0 of the struct sits on the device.
Node describe(const StructSpec& spec, std::span<const std::byte> bytes, std::uint64_t absOffset);

// Decode a single field (used by describe() and by generated accessors' pretty-printers).
Node describeField(const FieldSpec& field, std::span<const std::byte> structBytes, std::uint64_t structAbsOffset);

// Integer readers honouring the field's size and endianness. Return 0 if out of range.
std::uint64_t readUnsigned(const FieldSpec& field, std::span<const std::byte> structBytes);
void writeUnsigned(const FieldSpec& field, std::span<std::byte> structBytes, std::uint64_t value);

} // namespace stein::layout

namespace stein::layout {

// MBR cylinder/head/sector triple (3 bytes). 1023/254/63 means "use LBA".
struct ChsAddress {
    std::uint16_t cylinder = 0;   // 0..1023
    std::uint8_t head = 0;        // 0..255
    std::uint8_t sector = 0;      // 1..63
    bool operator==(const ChsAddress&) const = default;
    bool isLbaMarker() const { return cylinder == 1023 && head == 254 && sector == 63; }
};
ChsAddress decodeChs(std::span<const std::byte> three);
void encodeChs(std::span<std::byte> three, const ChsAddress& chs);
// Classic 255-heads / 63-sectors mapping; the LBA marker (1023/254/63) when out of range.
ChsAddress chsFromLba(std::uint64_t lba, unsigned heads = 255, unsigned sectorsPerTrack = 63);

} // namespace stein::layout
