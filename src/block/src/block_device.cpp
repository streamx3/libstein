// SPDX-License-Identifier: MIT
#include "stein/block/block_device.hpp"

#include "stein/core/strings.hpp"

namespace stein {

Expected<void> BlockDevice::discard(ByteCount, ByteCount) {
    return fail(ErrorCategory::Unsupported, "discard not supported by " + name());
}

Expected<void> BlockDevice::checkRange(ByteCount offset, ByteCount length) const {
    const ByteCount sz = size();
    if (offset > sz || length > sz - offset)
        return fail(ErrorCategory::OutOfRange, "range " + std::to_string(offset) + "+" + std::to_string(length) +
                                                   " exceeds device size " + std::to_string(sz) + " on " + name());
    return {};
}

Expected<std::vector<std::byte>> BlockDevice::read(ByteCount offset, ByteCount length) {
    std::vector<std::byte> buf(static_cast<std::size_t>(length));
    if (auto r = readAt(offset, buf); !r) return fail(r.error());
    return buf;
}

Expected<std::vector<std::byte>> BlockDevice::readSectors(Lba first, SectorCount count) {
    const auto ss = sectorSize();
    return read(first * ss, count * ss);
}

Expected<void> BlockDevice::writeSectors(Lba first, std::span<const std::byte> src) {
    return writeAt(first * sectorSize(), src);
}

Expected<void> BlockDevice::zero(ByteCount offset, ByteCount length) {
    if (auto r = checkRange(offset, length); !r) return r;
    if (auto d = discard(offset, length); d) return {};
    static constexpr ByteCount kChunk = 1 * MiB;
    std::vector<std::byte> zeros(static_cast<std::size_t>(std::min(kChunk, length)), std::byte{0});
    while (length > 0) {
        const ByteCount n = std::min<ByteCount>(length, zeros.size());
        if (auto r = writeAt(offset, std::span<const std::byte>(zeros).first(static_cast<std::size_t>(n))); !r)
            return r;
        offset += n;
        length -= n;
    }
    return {};
}

} // namespace stein
