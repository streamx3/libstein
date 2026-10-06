// SPDX-License-Identifier: MIT
// Common test include: doctest plus string makers for stein enums, so that
// CHECK(a == b) prints readable values. Explicit specialisations only.
#pragma once

#include <filesystem>
#include <system_error>

#include <doctest.h>

#include "stein/core/error.hpp"

#include <ostream>
#include <span>
#include <string>
#include <string_view>

// Our modules define `toString(Enum) -> std::string_view` for their enums.
// doctest finds those by ADL; with DOCTEST_CONFIG_DOUBLE_STRINGIFY it then
// calls toString() again on the result, which this overload handles.
namespace doctest {
inline String toString(std::string_view v) { return String(v.data(), static_cast<String::size_type>(v.size())); }
} // namespace doctest

namespace stein::test {
inline std::span<const std::byte> bytesOf(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

// Non-throwing recursive delete for test scratch dirs. On Windows a file that
// is still open cannot be deleted; callers release their devices first.
inline void removeTree(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

} // namespace stein::test
