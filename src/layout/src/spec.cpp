// SPDX-License-Identifier: MIT
#include "stein/layout/spec.hpp"

#include <cstring>

namespace stein::layout {

std::string_view toString(FieldType t) {
    switch (t) {
    case FieldType::U8: return "u8";
    case FieldType::U16: return "u16";
    case FieldType::U32: return "u32";
    case FieldType::U64: return "u64";
    case FieldType::I8: return "i8";
    case FieldType::I16: return "i16";
    case FieldType::I32: return "i32";
    case FieldType::I64: return "i64";
    case FieldType::Ascii: return "ascii";
    case FieldType::Utf16le: return "utf16le";
    case FieldType::Guid: return "guid";
    case FieldType::Uuid: return "uuid";
    case FieldType::Bytes: return "bytes";
    case FieldType::Bits: return "bits";
    case FieldType::Crc32: return "crc32";
    case FieldType::Lba: return "lba";
    case FieldType::Chs: return "chs";
    }
    return "?";
}

const FieldSpec* StructSpec::find(std::string_view fieldName) const {
    for (std::size_t i = 0; i < fieldCount; ++i)
        if (fieldName == fields[i].name) return &fields[i];
    return nullptr;
}

} // namespace stein::layout
