// SPDX-License-Identifier: MIT
// Error type and Expected<T>: the only error-reporting mechanism in libstein.
// No function in libstein throws; see doc/DECISIONS.md D2.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// Expected<T> is std::expected wherever the standard library ships it. GCC's
// libstdc++ hides <expected> from Clang before 19 (Clang 18 still reports
// __cpp_concepts below 202002L), so Ubuntu 24.04's default Clang cannot build
// it; there the bundled tl::expected (third_party/expected, CC0) stands in and
// only the API common to both is used. The choice is made once, when the
// library is configured, and recorded in the generated expected_config.hpp so
// that every consumer sees the same type across the library boundary.
#include <stein/core/expected_config.hpp>

#if STEIN_BUILT_WITH_TL_EXPECTED
#include <tl/expected.hpp>
namespace stein {
template <class T, class E> using expected = tl::expected<T, E>;
template <class E> using unexpected = tl::unexpected<E>;
} // namespace stein
#else
#include <version>
#if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
#error "libstein was built with std::expected, which this compiler's standard library does not provide (Clang before 19 on GCC's libstdc++). Update to Clang 19 or newer, build with GCC 13 or newer, or rebuild libstein with this compiler."
#endif
#include <expected>
namespace stein {
template <class T, class E> using expected = std::expected<T, E>;
template <class E> using unexpected = std::unexpected<E>;
} // namespace stein
#endif

namespace stein {

enum class ErrorCategory : std::uint8_t {
    None = 0,
    Io,            // read/write failure on a device or file (osCode carries errno/GetLastError)
    NotFound,      // device, file, partition, key slot... does not exist
    InvalidArgument,
    InvalidFormat, // on-disk structure is malformed (bad magic, bad CRC, inconsistent fields)
    Unsupported,   // valid, but we do not implement this (feature flag, version, operation)
    Busy,          // device in use / mounted / locked
    Permission,    // needs elevation
    OutOfRange,    // offset/length outside the device or region
    Cancelled,     // CancelToken fired
    Integrity,     // hash/checksum mismatch on data (not on-disk format)
    Internal,      // bug or caught exception from third-party code
};

std::string_view toString(ErrorCategory c);

class Error {
public:
    Error() = default;
    Error(ErrorCategory category, std::string message, std::int64_t osCode = 0)
        : m_category(category), m_message(std::move(message)), m_osCode(osCode) {}

    ErrorCategory category() const { return m_category; }
    const std::string& message() const { return m_message; }
    std::int64_t osCode() const { return m_osCode; }
    bool ok() const { return m_category == ErrorCategory::None; }

    // "InvalidFormat: GPT header CRC mismatch (os error 0)"
    std::string toString() const;

private:
    ErrorCategory m_category = ErrorCategory::None;
    std::string m_message;
    std::int64_t m_osCode = 0;
};

template <class T>
using Expected = expected<T, Error>;

// Convenience constructors. Usage:  return fail(ErrorCategory::Io, "short read", errno);
inline unexpected<Error> fail(ErrorCategory c, std::string message, std::int64_t osCode = 0) {
    return unexpected<Error>(Error(c, std::move(message), osCode));
}
inline unexpected<Error> fail(Error e) { return unexpected<Error>(std::move(e)); }

// Propagate: if (auto r = f(); !r) return fail(r.error());  -- written out, no macro magic.

} // namespace stein
