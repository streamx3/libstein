// SPDX-License-Identifier: MIT
// String helpers. UTF-8 std::string is the library standard (DECISIONS D4);
// UTF-16LE conversion exists for the on-disk formats that need it (GPT names,
// NTFS, FAT LFN, exFAT, HFS+). Plus the handful of Python-style conveniences
// that keep code readable without Qt.
#pragma once

#include <cstdint>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace stein {

// --- encodings ---------------------------------------------------------------

// Decode UTF-16LE bytes to UTF-8. Stops at the first NUL code unit when
// `stopAtNul` is set (GPT names are NUL-padded). Invalid surrogates become U+FFFD.
std::string utf16leToUtf8(std::span<const std::byte> bytes, bool stopAtNul = true);
// Encode UTF-8 to UTF-16LE into `out` (exactly out.size() bytes, NUL-padded,
// truncated to fit). Returns false if truncation happened or input was invalid.
bool utf8ToUtf16le(std::string_view text, std::span<std::byte> out);
// Number of UTF-16 code units a UTF-8 string needs (for max-length checks).
std::size_t utf16Length(std::string_view utf8);
bool isValidUtf8(std::string_view s);

// Latin-1 / ASCII fixed-width fields (MBR/APM/FAT labels): trim trailing spaces/NULs.
std::string asciiField(std::span<const std::byte> bytes);
// Fill a fixed-width field with ASCII text padded with `pad` (space for FAT, NUL for APM).
void setAsciiField(std::span<std::byte> field, std::string_view text, std::byte pad);

// --- conveniences ------------------------------------------------------------

std::vector<std::string> split(std::string_view s, char sep, bool keepEmpty = false);
std::string join(const std::vector<std::string>& parts, std::string_view sep);
std::string_view trim(std::string_view s);
std::string toLower(std::string_view s);
std::string toUpper(std::string_view s);
bool startsWith(std::string_view s, std::string_view prefix);
bool endsWith(std::string_view s, std::string_view suffix);
bool iequals(std::string_view a, std::string_view b);

// Hex dump helpers.
std::string toHex(std::span<const std::byte> bytes, bool upper = false);
// Inverse of toHex; nullopt on odd length or non-hex characters.
std::optional<std::vector<std::byte>> fromHex(std::string_view hex);
std::string toHex(std::uint64_t value, int minDigits = 0);   // "0x1A2B"
// Multi-line "offset: hex  ascii" dump, 16 bytes per line, `base` added to offsets.
std::string hexDump(std::span<const std::byte> bytes, std::uint64_t base = 0);

} // namespace stein
