// SPDX-License-Identifier: MIT
// 128-bit identifiers. Two on-disk conventions exist and we keep them apart:
//   * Guid  — Microsoft/UEFI "mixed-endian": first three groups little-endian
//             on disk (GPT headers and entries, NTFS, VHDX).
//   * Uuid  — RFC 4122 big-endian on disk (ext4, XFS, LUKS, LVM, btrfs...).
// Both print as 8-4-4-4-12 hex. Both are stored here as the 16 *printed* bytes
// (i.e. big-endian/RFC order) so that comparisons and text are uniform; the
// conversion happens only in fromGptBytes()/toGptBytes().
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace stein {

class Uuid {
public:
    using Bytes = std::array<std::uint8_t, 16>;

    Uuid() = default;
    explicit Uuid(const Bytes& b) : m_bytes(b) {}

    // Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (case-insensitive, braces tolerated).
    static std::optional<Uuid> parse(std::string_view text);
    // From 16 bytes in RFC 4122 (big-endian) order as found in ext4/XFS/LUKS.
    static Uuid fromRfcBytes(std::span<const std::byte, 16> b);
    // From 16 bytes in GPT/Microsoft mixed-endian order as found on disk in GPT.
    static Uuid fromGptBytes(std::span<const std::byte, 16> b);

    void toRfcBytes(std::span<std::byte, 16> out) const;
    void toGptBytes(std::span<std::byte, 16> out) const;

    const Bytes& bytes() const { return m_bytes; }
    bool isNil() const;
    std::string toString(bool upper = true) const;   // UEFI prints upper-case

    bool operator==(const Uuid&) const = default;
    auto operator<=>(const Uuid&) const = default;

private:
    Bytes m_bytes{};
};

using Guid = Uuid; // same value type; the name documents intent at call sites

} // namespace stein
