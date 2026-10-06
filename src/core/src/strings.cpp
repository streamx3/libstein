// SPDX-License-Identifier: MIT
#include "stein/core/strings.hpp"

#include <cctype>
#include <cstdio>

namespace stein {

namespace {

void appendUtf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Decode one UTF-8 code point; returns bytes consumed (0 = invalid).
std::size_t decodeUtf8(std::string_view s, std::size_t i, std::uint32_t& cp) {
    auto b0 = static_cast<unsigned char>(s[i]);
    std::size_t n;
    if (b0 < 0x80) {
        cp = b0;
        return 1;
    } else if ((b0 & 0xE0) == 0xC0) {
        n = 2;
        cp = b0 & 0x1F;
    } else if ((b0 & 0xF0) == 0xE0) {
        n = 3;
        cp = b0 & 0x0F;
    } else if ((b0 & 0xF8) == 0xF0) {
        n = 4;
        cp = b0 & 0x07;
    } else {
        return 0;
    }
    if (i + n > s.size()) return 0;
    for (std::size_t k = 1; k < n; ++k) {
        auto b = static_cast<unsigned char>(s[i + k]);
        if ((b & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (b & 0x3F);
    }
    // Reject overlong encodings and surrogates.
    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10FFFF ||
        (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

} // namespace

std::string utf16leToUtf8(std::span<const std::byte> bytes, bool stopAtNul) {
    std::string out;
    std::size_t n = bytes.size() / 2;
    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t u = std::to_integer<std::uint32_t>(bytes[2 * i]) |
                          (std::to_integer<std::uint32_t>(bytes[2 * i + 1]) << 8);
        if (u == 0 && stopAtNul) break;
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 1 < n) {
                std::uint32_t lo = std::to_integer<std::uint32_t>(bytes[2 * i + 2]) |
                                   (std::to_integer<std::uint32_t>(bytes[2 * i + 3]) << 8);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    appendUtf8(out, 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
                    ++i;
                    continue;
                }
            }
            appendUtf8(out, 0xFFFD);
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            appendUtf8(out, 0xFFFD);
        } else {
            appendUtf8(out, u);
        }
    }
    return out;
}

bool utf8ToUtf16le(std::string_view text, std::span<std::byte> out) {
    for (auto& b : out) b = std::byte{0};
    std::size_t pos = 0;
    bool ok = true;
    for (std::size_t i = 0; i < text.size();) {
        std::uint32_t cp;
        std::size_t n = decodeUtf8(text, i, cp);
        if (n == 0) {
            cp = 0xFFFD;
            n = 1;
            ok = false;
        }
        i += n;
        std::uint16_t units[2];
        int count = 1;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            units[0] = static_cast<std::uint16_t>(0xD800 + (cp >> 10));
            units[1] = static_cast<std::uint16_t>(0xDC00 + (cp & 0x3FF));
            count = 2;
        } else {
            units[0] = static_cast<std::uint16_t>(cp);
        }
        if (pos + static_cast<std::size_t>(count) * 2 > out.size()) return false;   // truncated
        for (int k = 0; k < count; ++k) {
            out[pos++] = std::byte(units[k] & 0xFF);
            out[pos++] = std::byte(units[k] >> 8);
        }
    }
    return ok;
}

std::size_t utf16Length(std::string_view utf8) {
    std::size_t units = 0;
    for (std::size_t i = 0; i < utf8.size();) {
        std::uint32_t cp;
        std::size_t n = decodeUtf8(utf8, i, cp);
        if (n == 0) {
            n = 1;
            cp = 0xFFFD;
        }
        i += n;
        units += cp >= 0x10000 ? 2 : 1;
    }
    return units;
}

bool isValidUtf8(std::string_view s) {
    for (std::size_t i = 0; i < s.size();) {
        std::uint32_t cp;
        std::size_t n = decodeUtf8(s, i, cp);
        if (n == 0) return false;
        i += n;
    }
    return true;
}

std::string asciiField(std::span<const std::byte> bytes) {
    std::size_t end = bytes.size();
    while (end > 0 && (bytes[end - 1] == std::byte{0} || bytes[end - 1] == std::byte{' '})) --end;
    std::string out;
    out.reserve(end);
    for (std::size_t i = 0; i < end; ++i) {
        auto c = std::to_integer<unsigned char>(bytes[i]);
        if (c == 0) break;
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else {
            appendUtf8(out, c);   // treat as Latin-1
        }
    }
    return out;
}

void setAsciiField(std::span<std::byte> field, std::string_view text, std::byte pad) {
    std::size_t i = 0;
    for (; i < field.size() && i < text.size(); ++i) field[i] = std::byte(static_cast<unsigned char>(text[i]));
    for (; i < field.size(); ++i) field[i] = pad;
}

std::vector<std::string> split(std::string_view s, char sep, bool keepEmpty) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        std::size_t pos = s.find(sep, start);
        std::string_view part = s.substr(start, pos == std::string_view::npos ? std::string_view::npos : pos - start);
        if (keepEmpty || !part.empty()) out.emplace_back(part);
        if (pos == std::string_view::npos) break;
        start = pos + 1;
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

std::string toLower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

std::string toUpper(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

bool startsWith(std::string_view s, std::string_view prefix) { return s.substr(0, prefix.size()) == prefix; }
bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
    return true;
}

std::string toHex(std::span<const std::byte> bytes, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        auto v = std::to_integer<unsigned>(b);
        s.push_back(digits[v >> 4]);
        s.push_back(digits[v & 0xF]);
    }
    return s;
}

std::string toHex(std::uint64_t value, int minDigits) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%0*llX", minDigits, static_cast<unsigned long long>(value));
    return buf;
}

std::string hexDump(std::span<const std::byte> bytes, std::uint64_t base) {
    std::string out;
    char line[128];
    for (std::size_t off = 0; off < bytes.size(); off += 16) {
        int n = std::snprintf(line, sizeof line, "%08llx  ", static_cast<unsigned long long>(base + off));
        out.append(line, static_cast<std::size_t>(n));
        for (std::size_t i = 0; i < 16; ++i) {
            if (off + i < bytes.size()) {
                n = std::snprintf(line, sizeof line, "%02x ", std::to_integer<unsigned>(bytes[off + i]));
                out.append(line, static_cast<std::size_t>(n));
            } else {
                out += "   ";
            }
            if (i == 7) out += ' ';
        }
        out += " |";
        for (std::size_t i = 0; i < 16 && off + i < bytes.size(); ++i) {
            auto c = std::to_integer<unsigned char>(bytes[off + i]);
            out.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.');
        }
        out += "|\n";
    }
    return out;
}

} // namespace stein

namespace stein {
std::optional<std::vector<std::byte>> fromHex(std::string_view hex) {
    if (hex.size() % 2) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(std::byte(static_cast<std::uint8_t>((hi << 4) | lo)));
    }
    return out;
}
} // namespace stein
