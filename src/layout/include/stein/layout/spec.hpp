// SPDX-License-Identifier: MIT
// Static descriptions of on-disk structures. Instances are generated from the
// *.layout.toml manifests by tools/layout_gen; nothing here is written by hand
// except this header. See doc/design/18-structure-layouts.md.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace stein::layout {

enum class FieldType : std::uint8_t {
    U8, U16, U32, U64,       // unsigned integers (endianness from FieldSpec)
    I8, I16, I32, I64,       // signed
    Ascii,                   // fixed-width ASCII/Latin-1, NUL or space padded
    Utf16le,                 // fixed-width UTF-16LE, NUL padded
    Guid,                    // 16 bytes, Microsoft/UEFI mixed-endian
    Uuid,                    // 16 bytes, RFC 4122 big-endian
    Bytes,                   // opaque
    Bits,                    // unsigned integer interpreted as a bit set (size 1..8)
    Crc32,                   // u32 whose correctness code verifies
    Lba,                     // u64 sector address
    Chs,                     // 3-byte MBR cylinder/head/sector triple
};

std::string_view toString(FieldType t);

struct EnumValue {
    std::uint64_t value;
    const char* name;
};

struct BitName {
    std::uint8_t bit;
    const char* name;
};

struct FieldSpec {
    const char* name;
    std::uint32_t offset;       // relative to the struct start
    std::uint32_t size;
    FieldType type;
    bool bigEndian;
    const char* doc;            // may be ""
    // Simple validity rules (0/null = not set).
    const char* expectAscii;    // Ascii/Bytes field must equal this literal
    bool hasExpectValue;
    std::uint64_t expectValue;  // integer field must equal
    bool hasMin, hasMax;
    std::uint64_t minValue, maxValue;
    bool nonZero;
    const EnumValue* enums;
    std::size_t enumCount;
    const BitName* bits;
    std::size_t bitCount;
};

struct StructSpec {
    const char* name;
    const char* doc;
    std::uint32_t size;
    const FieldSpec* fields;
    std::size_t fieldCount;

    const FieldSpec* find(std::string_view fieldName) const;
};

} // namespace stein::layout
