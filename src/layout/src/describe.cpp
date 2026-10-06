// SPDX-License-Identifier: MIT
#include "stein/layout/describe.hpp"

#include "stein/core/endian.hpp"
#include "stein/core/guid.hpp"
#include "stein/core/strings.hpp"

#include <cstdio>

namespace stein::layout {

namespace {

bool isUnsignedType(FieldType t) {
    switch (t) {
    case FieldType::U8:
    case FieldType::U16:
    case FieldType::U32:
    case FieldType::U64:
    case FieldType::Bits:
    case FieldType::Crc32:
    case FieldType::Lba:
        return true;
    default:
        return false;
    }
}

bool isSignedType(FieldType t) {
    return t == FieldType::I8 || t == FieldType::I16 || t == FieldType::I32 || t == FieldType::I64;
}

std::string hexOf(std::uint64_t v, std::uint32_t size) {
    return toHex(v, static_cast<int>(size * 2));
}

} // namespace

std::uint64_t readUnsigned(const FieldSpec& f, std::span<const std::byte> s) {
    if (f.offset + f.size > s.size()) return 0;
    const std::byte* p = s.data() + f.offset;
    switch (f.size) {
    case 1: return std::to_integer<std::uint64_t>(p[0]);
    case 2: return f.bigEndian ? loadBe16(p) : loadLe16(p);
    case 3: {   // 24-bit (CHS is handled separately; this is for odd formats)
        std::uint64_t v = 0;
        for (int i = 0; i < 3; ++i)
            v |= std::to_integer<std::uint64_t>(p[i]) << (f.bigEndian ? 8 * (2 - i) : 8 * i);
        return v;
    }
    case 4: return f.bigEndian ? loadBe32(p) : loadLe32(p);
    case 8: return f.bigEndian ? loadBe64(p) : loadLe64(p);
    default: return 0;
    }
}

void writeUnsigned(const FieldSpec& f, std::span<std::byte> s, std::uint64_t v) {
    if (f.offset + f.size > s.size()) return;
    std::byte* p = s.data() + f.offset;
    switch (f.size) {
    case 1: p[0] = std::byte(v & 0xFF); break;
    case 2: f.bigEndian ? storeBe16(p, static_cast<std::uint16_t>(v)) : storeLe16(p, static_cast<std::uint16_t>(v)); break;
    case 4: f.bigEndian ? storeBe32(p, static_cast<std::uint32_t>(v)) : storeLe32(p, static_cast<std::uint32_t>(v)); break;
    case 8: f.bigEndian ? storeBe64(p, v) : storeLe64(p, v); break;
    default: break;
    }
}

Node describeField(const FieldSpec& f, std::span<const std::byte> s, std::uint64_t structAbs) {
    Node n;
    n.name = f.name;
    n.absOffset = structAbs + f.offset;
    n.size = f.size;
    n.type = f.type;
    n.doc = f.doc ? f.doc : "";
    if (f.offset + f.size > s.size()) {
        n.flag(Validity::Error, "field extends past the available bytes");
        return n;
    }
    auto bytes = s.subspan(f.offset, f.size);
    if (f.size <= 256) n.raw.assign(bytes.begin(), bytes.end());

    if (isUnsignedType(f.type)) {
        const std::uint64_t v = readUnsigned(f, s);
        n.value = (f.type == FieldType::Crc32 || f.type == FieldType::Bits) ? hexOf(v, f.size) : std::to_string(v);
        if (f.type != FieldType::Crc32 && f.type != FieldType::Bits && f.size >= 4 && !f.enums) n.pretty = hexOf(v, f.size);
        if (f.enums) {
            bool known = false;
            for (std::size_t i = 0; i < f.enumCount; ++i)
                if (f.enums[i].value == v) {
                    n.pretty = f.enums[i].name;
                    known = true;
                }
            if (!known) n.flag(Validity::Warning, "unknown value " + hexOf(v, f.size));
        }
        if (f.type == FieldType::Bits) {
            std::string names;
            std::uint64_t unknown = v;
            for (std::size_t i = 0; i < f.bitCount; ++i) {
                const std::uint64_t mask = std::uint64_t{1} << f.bits[i].bit;
                if (v & mask) {
                    if (!names.empty()) names += "|";
                    names += f.bits[i].name;
                    unknown &= ~mask;
                }
            }
            if (unknown) {
                if (!names.empty()) names += "|";
                names += "unknown:" + hexOf(unknown, f.size);
            }
            n.pretty = names.empty() ? "none" : names;
        }
        if (f.hasExpectValue && v != f.expectValue)
            n.flag(Validity::Error, "expected " + hexOf(f.expectValue, f.size));
        if (f.hasMin && v < f.minValue) n.flag(Validity::Warning, "below minimum " + std::to_string(f.minValue));
        if (f.hasMax && v > f.maxValue) n.flag(Validity::Warning, "above maximum " + std::to_string(f.maxValue));
        if (f.nonZero && v == 0) n.flag(Validity::Warning, "must not be zero");
        if (f.type == FieldType::Crc32) n.flag(Validity::Info, "not verified");
    } else if (isSignedType(f.type)) {
        std::uint64_t raw = readUnsigned(f, s);
        std::int64_t v;
        switch (f.size) {
        case 1: v = static_cast<std::int8_t>(raw); break;
        case 2: v = static_cast<std::int16_t>(raw); break;
        case 4: v = static_cast<std::int32_t>(raw); break;
        default: v = static_cast<std::int64_t>(raw); break;
        }
        n.value = std::to_string(v);
    } else {
        switch (f.type) {
        case FieldType::Ascii: {
            n.value = asciiField(bytes);
            if (f.expectAscii) {
                std::string_view expect(f.expectAscii);
                bool match = expect.size() <= bytes.size();
                for (std::size_t i = 0; match && i < expect.size(); ++i)
                    match = std::to_integer<char>(bytes[i]) == expect[i];
                if (!match) n.flag(Validity::Error, "expected \"" + std::string(expect) + "\"");
            }
            break;
        }
        case FieldType::Utf16le: n.value = utf16leToUtf8(bytes); break;
        case FieldType::Guid: {
            std::span<const std::byte, 16> g(bytes.data(), 16);
            n.value = Uuid::fromGptBytes(g).toString();
            break;
        }
        case FieldType::Uuid: {
            std::span<const std::byte, 16> g(bytes.data(), 16);
            n.value = Uuid::fromRfcBytes(g).toString(false);
            break;
        }
        case FieldType::Chs: {
            // MBR CHS: byte0 = head, byte1 = sector (bits 0-5) | cylinder high (bits 6-7), byte2 = cylinder low.
            const unsigned head = std::to_integer<unsigned>(bytes[0]);
            const unsigned sector = std::to_integer<unsigned>(bytes[1]) & 0x3F;
            const unsigned cyl = ((std::to_integer<unsigned>(bytes[1]) & 0xC0) << 2) | std::to_integer<unsigned>(bytes[2]);
            n.value = "C" + std::to_string(cyl) + "/H" + std::to_string(head) + "/S" + std::to_string(sector);
            if (cyl == 1023 && head == 254 && sector == 63) n.pretty = "beyond CHS range (LBA only)";
            break;
        }
        case FieldType::Bytes:
        default:
            n.value = bytes.size() <= 32 ? toHex(bytes) : "<" + std::to_string(bytes.size()) + " bytes>";
            if (f.expectAscii) {
                std::string_view expect(f.expectAscii);
                bool match = expect.size() <= bytes.size();
                for (std::size_t i = 0; match && i < expect.size(); ++i)
                    match = std::to_integer<char>(bytes[i]) == expect[i];
                if (!match) n.flag(Validity::Error, "unexpected magic");
            }
            if (f.nonZero) {
                bool allZero = true;
                for (auto b : bytes)
                    if (b != std::byte{0}) allZero = false;
                if (allZero) n.flag(Validity::Warning, "all zero");
            }
            break;
        }
    }
    return n;
}

Node describe(const StructSpec& spec, std::span<const std::byte> bytes, std::uint64_t absOffset) {
    Node root;
    root.name = spec.name;
    root.isStruct = true;
    root.absOffset = absOffset;
    root.size = spec.size;
    root.doc = spec.doc ? spec.doc : "";
    if (bytes.size() < spec.size) {
        root.flag(Validity::Error, "only " + std::to_string(bytes.size()) + " of " + std::to_string(spec.size) + " bytes available");
    }
    for (std::size_t i = 0; i < spec.fieldCount; ++i) root.children.push_back(describeField(spec.fields[i], bytes, absOffset));
    return root;
}

} // namespace stein::layout

namespace stein::layout {

ChsAddress decodeChs(std::span<const std::byte> b) {
    ChsAddress c;
    if (b.size() < 3) return c;
    c.head = std::to_integer<std::uint8_t>(b[0]);
    c.sector = std::to_integer<std::uint8_t>(b[1]) & 0x3F;
    c.cylinder = static_cast<std::uint16_t>(((std::to_integer<unsigned>(b[1]) & 0xC0) << 2) | std::to_integer<unsigned>(b[2]));
    return c;
}

ChsAddress chsFromLba(std::uint64_t lba, unsigned heads, unsigned spt) {
    const std::uint64_t perCyl = static_cast<std::uint64_t>(heads) * spt;
    const std::uint64_t cyl = perCyl ? lba / perCyl : 0;
    if (cyl > 1023) return ChsAddress{1023, 254, 63};
    const std::uint64_t rem = lba % perCyl;
    return ChsAddress{static_cast<std::uint16_t>(cyl), static_cast<std::uint8_t>(rem / spt),
                      static_cast<std::uint8_t>(rem % spt + 1)};
}

void encodeChs(std::span<std::byte> b, const ChsAddress& c) {
    if (b.size() < 3) return;
    b[0] = std::byte(c.head);
    b[1] = std::byte((c.sector & 0x3F) | ((c.cylinder >> 2) & 0xC0));
    b[2] = std::byte(c.cylinder & 0xFF);
}

} // namespace stein::layout
