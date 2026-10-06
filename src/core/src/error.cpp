// SPDX-License-Identifier: MIT
#include "stein/core/error.hpp"

namespace stein {

std::string_view toString(ErrorCategory c) {
    switch (c) {
    case ErrorCategory::None: return "None";
    case ErrorCategory::Io: return "Io";
    case ErrorCategory::NotFound: return "NotFound";
    case ErrorCategory::InvalidArgument: return "InvalidArgument";
    case ErrorCategory::InvalidFormat: return "InvalidFormat";
    case ErrorCategory::Unsupported: return "Unsupported";
    case ErrorCategory::Busy: return "Busy";
    case ErrorCategory::Permission: return "Permission";
    case ErrorCategory::OutOfRange: return "OutOfRange";
    case ErrorCategory::Cancelled: return "Cancelled";
    case ErrorCategory::Integrity: return "Integrity";
    case ErrorCategory::Internal: return "Internal";
    }
    return "?";
}

std::string Error::toString() const {
    std::string s(stein::toString(m_category));
    s += ": ";
    s += m_message;
    if (m_osCode != 0) {
        s += " (os error ";
        s += std::to_string(m_osCode);
        s += ")";
    }
    return s;
}

} // namespace stein
