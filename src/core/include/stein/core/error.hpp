// SPDX-License-Identifier: MIT
// Error type and Expected<T>: the only error-reporting mechanism in libstein.
// No function in libstein throws; see doc/DECISIONS.md D2.
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

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
using Expected = std::expected<T, Error>;

// Convenience constructors. Usage:  return fail(ErrorCategory::Io, "short read", errno);
inline std::unexpected<Error> fail(ErrorCategory c, std::string message, std::int64_t osCode = 0) {
    return std::unexpected<Error>(Error(c, std::move(message), osCode));
}
inline std::unexpected<Error> fail(Error e) { return std::unexpected<Error>(std::move(e)); }

// Propagate: if (auto r = f(); !r) return fail(r.error());  -- written out, no macro magic.

} // namespace stein
