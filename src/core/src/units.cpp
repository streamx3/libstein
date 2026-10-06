// SPDX-License-Identifier: MIT
#include "stein/core/units.hpp"

#include <array>
#include <cstdio>

namespace stein {

std::string formatSize(ByteCount bytes, bool decimal) {
    static constexpr std::array<const char*, 7> binUnits{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    static constexpr std::array<const char*, 7> decUnits{"B", "kB", "MB", "GB", "TB", "PB", "EB"};
    const double base = decimal ? 1000.0 : 1024.0;
    const auto& units = decimal ? decUnits : binUnits;
    double v = static_cast<double>(bytes);
    std::size_t i = 0;
    while (v >= base && i + 1 < units.size()) {
        v /= base;
        ++i;
    }
    char buf[64];
    if (i == 0) {
        std::snprintf(buf, sizeof buf, "%llu %s", static_cast<unsigned long long>(bytes), units[0]);
    } else {
        std::snprintf(buf, sizeof buf, "%.2f %s", v, units[i]);
    }
    return buf;
}

std::string formatSizeExact(ByteCount bytes) {
    std::string digits = std::to_string(bytes);
    std::string grouped;
    int n = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (n && n % 3 == 0) grouped.insert(grouped.begin(), ',');
        grouped.insert(grouped.begin(), *it);
        ++n;
    }
    return formatSize(bytes) + " (" + grouped + " bytes)";
}

} // namespace stein
