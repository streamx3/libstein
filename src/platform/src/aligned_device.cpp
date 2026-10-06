// SPDX-License-Identifier: MIT
#include "aligned_device.hpp"

#include <algorithm>
#include <cstring>

namespace stein::platform {

Expected<void> AlignedDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    if (dst.empty()) return {};
    const ByteCount a = alignment();
    std::lock_guard lock(m_mutex);
    ByteCount done = 0;
    while (done < dst.size()) {
        const ByteCount pos = offset + done;
        const ByteCount remaining = dst.size() - done;
        const ByteCount alignedPos = pos / a * a;
        if (alignedPos == pos && remaining >= a) {
            // Aligned stretch: straight into the caller's buffer, whole sectors only.
            const ByteCount n = std::min<ByteCount>(remaining / a * a, kBounceBytes);
            if (auto r = rawRead(pos, dst.subspan(done, n)); !r) return r;
            done += n;
            continue;
        }
        // Partial sector(s): bounce through an aligned read of the covering sectors.
        const ByteCount alignedEnd = std::min<ByteCount>((pos + remaining + a - 1) / a * a, alignedPos + kBounceBytes);
        const ByteCount span = std::min<ByteCount>(alignedEnd - alignedPos, size() - alignedPos);   // devices are whole sectors
        m_bounce.resize(span);
        if (auto r = rawRead(alignedPos, m_bounce); !r) return r;
        const ByteCount skip = pos - alignedPos;
        const ByteCount n = std::min<ByteCount>(span - skip, remaining);
        std::memcpy(dst.data() + done, m_bounce.data() + skip, n);
        done += n;
    }
    return {};
}

Expected<void> AlignedDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (isReadOnly()) return fail(ErrorCategory::Permission, "device is opened read-only");
    if (auto r = checkRange(offset, src.size()); !r) return r;
    if (src.empty()) return {};
    const ByteCount a = alignment();
    std::lock_guard lock(m_mutex);
    ByteCount done = 0;
    while (done < src.size()) {
        const ByteCount pos = offset + done;
        const ByteCount remaining = src.size() - done;
        const ByteCount alignedPos = pos / a * a;
        if (alignedPos == pos && remaining >= a) {
            const ByteCount n = std::min<ByteCount>(remaining / a * a, kBounceBytes);
            if (auto r = rawWrite(pos, src.subspan(done, n)); !r) return r;
            done += n;
            continue;
        }
        // Read-modify-write of the one sector holding the partial piece.
        m_bounce.resize(a);
        if (auto r = rawRead(alignedPos, m_bounce); !r) return r;
        const ByteCount skip = pos - alignedPos;
        const ByteCount n = std::min<ByteCount>(a - skip, remaining);
        std::memcpy(m_bounce.data() + skip, src.data() + done, n);
        if (auto r = rawWrite(alignedPos, m_bounce); !r) return r;
        done += n;
    }
    return {};
}

} // namespace stein::platform
