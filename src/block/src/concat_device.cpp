// SPDX-License-Identifier: MIT
#include "stein/block/concat_device.hpp"

#include <algorithm>

namespace stein {

Expected<std::shared_ptr<ConcatDevice>> ConcatDevice::create(std::vector<BlockDevicePtr> parts, std::string name) {
    if (parts.empty()) return fail(ErrorCategory::InvalidArgument, "concat needs at least one part");
    for (const auto& p : parts)
        if (!p) return fail(ErrorCategory::InvalidArgument, "concat part is null");
    auto dev = std::shared_ptr<ConcatDevice>(new ConcatDevice());
    dev->m_geometry = parts.front()->geometry();
    dev->m_geometry.sizeBytes = 0;
    const auto ss = dev->m_geometry.logicalSectorSize;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const auto& p = parts[i];
        if (p->sectorSize() != ss) return fail(ErrorCategory::InvalidArgument, "concat parts have different sector sizes");
        if (i + 1 < parts.size() && ss && p->size() % ss)
            return fail(ErrorCategory::InvalidArgument, "part " + std::to_string(i) + " (" + p->name() + ") is not a whole number of sectors");
        dev->m_starts.push_back(dev->m_geometry.sizeBytes);
        dev->m_geometry.sizeBytes += p->size();
        dev->m_readOnly = dev->m_readOnly || p->isReadOnly();
    }
    dev->m_name = name.empty() ? parts.front()->name() + " (+" + std::to_string(parts.size() - 1) + " parts)" : std::move(name);
    dev->m_parts = std::move(parts);
    return dev;
}

std::pair<std::size_t, ByteCount> ConcatDevice::locate(ByteCount offset) const {
    auto it = std::upper_bound(m_starts.begin(), m_starts.end(), offset);
    const auto index = static_cast<std::size_t>(std::distance(m_starts.begin(), it)) - 1;
    return {index, offset - m_starts[index]};
}

template <class Fn> Expected<void> ConcatDevice::forEachPiece(ByteCount offset, ByteCount length, Fn fn) {
    if (auto r = checkRange(offset, length); !r) return r;
    ByteCount done = 0;
    while (done < length) {
        auto [index, inPart] = locate(offset + done);
        const ByteCount avail = m_parts[index]->size() - inPart;
        const ByteCount n = std::min(avail, length - done);
        if (auto r = fn(*m_parts[index], inPart, done, n); !r) return r;
        done += n;
    }
    return {};
}

Expected<void> ConcatDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    return forEachPiece(offset, dst.size(), [&](BlockDevice& part, ByteCount inPart, ByteCount done, ByteCount n) {
        return part.readAt(inPart, dst.subspan(done, n));
    });
}

Expected<void> ConcatDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (m_readOnly) return fail(ErrorCategory::Permission, "device is opened read-only");
    return forEachPiece(offset, src.size(), [&](BlockDevice& part, ByteCount inPart, ByteCount done, ByteCount n) {
        return part.writeAt(inPart, src.subspan(done, n));
    });
}

Expected<void> ConcatDevice::discard(ByteCount offset, ByteCount length) {
    if (m_readOnly) return fail(ErrorCategory::Permission, "device is opened read-only");
    return forEachPiece(offset, length, [&](BlockDevice& part, ByteCount inPart, ByteCount, ByteCount n) { return part.discard(inPart, n); });
}

Expected<void> ConcatDevice::zeroRange(ByteCount offset, ByteCount length) {
    if (m_readOnly) return fail(ErrorCategory::Permission, "device is opened read-only");
    if (auto r = checkRange(offset, length); !r) return r;
    return forEachPiece(offset, length, [&](BlockDevice& part, ByteCount inPart, ByteCount, ByteCount n) { return part.zeroRange(inPart, n); });
}

Expected<void> ConcatDevice::flush() {
    for (auto& p : m_parts)
        if (auto r = p->flush(); !r) return r;
    return {};
}

} // namespace stein
