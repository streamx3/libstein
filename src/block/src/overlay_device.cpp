// SPDX-License-Identifier: MIT
#include "stein/block/overlay_device.hpp"

#include <algorithm>

namespace stein {

std::shared_ptr<OverlayDevice> OverlayDevice::create(BlockDevicePtr base, std::uint32_t blockSize) {
    if (blockSize < 512 || (blockSize & (blockSize - 1)) != 0) blockSize = 4096;
    return std::shared_ptr<OverlayDevice>(new OverlayDevice(std::move(base), blockSize));
}

Expected<std::vector<std::byte>*> OverlayDevice::blockFor(ByteCount index) {
    auto it = m_blocks.find(index);
    if (it != m_blocks.end()) return &it->second;
    const ByteCount off = index * m_blockSize;
    const ByteCount len = std::min<ByteCount>(m_blockSize, m_base->size() - off);
    std::vector<std::byte> bytes(static_cast<std::size_t>(len));
    if (auto r = m_base->readAt(off, bytes); !r) return fail(r.error());
    auto [pos, _] = m_blocks.emplace(index, std::move(bytes));
    return &pos->second;
}

Expected<void> OverlayDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    std::lock_guard lock(m_mutex);
    std::size_t done = 0;
    while (done < dst.size()) {
        const ByteCount pos = offset + done;
        const ByteCount index = pos / m_blockSize;
        const ByteCount inBlock = pos % m_blockSize;
        const ByteCount blockLen = std::min<ByteCount>(m_blockSize, m_base->size() - index * m_blockSize);
        const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>(blockLen - inBlock, dst.size() - done));
        auto it = m_blocks.find(index);
        if (it != m_blocks.end()) {
            std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(inBlock), n, dst.begin() + static_cast<std::ptrdiff_t>(done));
        } else {
            if (auto r = m_base->readAt(pos, dst.subspan(done, n)); !r) return r;
        }
        done += n;
    }
    return {};
}

Expected<void> OverlayDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (auto r = checkRange(offset, src.size()); !r) return r;
    std::lock_guard lock(m_mutex);
    std::size_t done = 0;
    while (done < src.size()) {
        const ByteCount pos = offset + done;
        const ByteCount index = pos / m_blockSize;
        const ByteCount inBlock = pos % m_blockSize;
        auto block = blockFor(index);
        if (!block) return fail(block.error());
        const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>((*block)->size() - inBlock, src.size() - done));
        std::copy_n(src.begin() + static_cast<std::ptrdiff_t>(done), n, (*block)->begin() + static_cast<std::ptrdiff_t>(inBlock));
        done += n;
    }
    return {};
}

Expected<void> OverlayDevice::discard(ByteCount offset, ByteCount length) {
    if (auto r = checkRange(offset, length); !r) return r;
    std::vector<std::byte> zeros(static_cast<std::size_t>(std::min<ByteCount>(length, m_blockSize)), std::byte{0});
    while (length) {
        const ByteCount n = std::min<ByteCount>(length, zeros.size());
        if (auto r = writeAt(offset, std::span<const std::byte>(zeros).first(static_cast<std::size_t>(n))); !r) return r;
        offset += n;
        length -= n;
    }
    return {};
}

std::vector<Region> OverlayDevice::dirtyRegions() const {
    std::lock_guard lock(m_mutex);
    std::vector<Region> out;
    for (const auto& [index, bytes] : m_blocks) {
        const Region r{index * m_blockSize, bytes.size()};
        if (!out.empty() && out.back().end() == r.offset) out.back().length += r.length;
        else out.push_back(r);
    }
    return out;
}

ByteCount OverlayDevice::dirtyBytes() const {
    std::lock_guard lock(m_mutex);
    ByteCount n = 0;
    for (const auto& [index, bytes] : m_blocks) n += bytes.size();
    return n;
}

Expected<void> OverlayDevice::commit() {
    std::lock_guard lock(m_mutex);
    for (const auto& [index, bytes] : m_blocks)
        if (auto r = m_base->writeAt(index * m_blockSize, bytes); !r) return r;
    if (auto f = m_base->flush(); !f) return f;
    m_blocks.clear();
    return {};
}

} // namespace stein
