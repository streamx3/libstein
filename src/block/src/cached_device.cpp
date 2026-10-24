// SPDX-License-Identifier: MIT
#include "stein/block/cached_device.hpp"

#include <algorithm>
#include <cstring>

namespace stein {

std::shared_ptr<CachedDevice> CachedDevice::create(BlockDevicePtr inner, Options options) {
    if (options.chunkSize == 0) options.chunkSize = Options{}.chunkSize;
    options.budget = std::max<ByteCount>(options.budget, options.chunkSize);
    return std::shared_ptr<CachedDevice>(new CachedDevice(std::move(inner), options));
}

std::shared_ptr<CachedDevice> CachedDevice::create(BlockDevicePtr inner) { return create(std::move(inner), Options{}); }

CachedDevice::CachedDevice(BlockDevicePtr inner, Options options) : m_inner(std::move(inner)), m_options(options), m_size(m_inner->size()) {}

Expected<void> CachedDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    while (!dst.empty()) {
        const ByteCount index = offset / m_options.chunkSize;
        const ByteCount within = offset - index * m_options.chunkSize;
        const auto n = static_cast<std::size_t>(std::min<ByteCount>(dst.size(), m_options.chunkSize - within));
        if (auto r = readWithinChunk(index, within, dst.first(n)); !r) return r;
        offset += n;
        dst = dst.subspan(n);
    }
    return {};
}

Expected<void> CachedDevice::readWithinChunk(ByteCount index, ByteCount within, std::span<std::byte> dst) {
    std::uint64_t generation;
    {
        std::lock_guard lock(m_mutex);
        if (auto it = m_index.find(index); it != m_index.end()) {
            m_lru.splice(m_lru.begin(), m_lru, it->second);   // most recently used
            std::memcpy(dst.data(), it->second->bytes.data() + within, dst.size());
            ++m_stats.hits;
            return {};
        }
        ++m_stats.misses;
        generation = m_generation;
    }
    // Miss: fetch the whole chunk with the lock released, so other threads keep hitting (and a
    // second miss on the same chunk costs a duplicate read rather than a wait).
    const ByteCount start = index * m_options.chunkSize;
    const auto length = static_cast<std::size_t>(std::min<ByteCount>(m_options.chunkSize, m_size - start));
    std::vector<std::byte> bytes(length);
    if (auto r = m_inner->readAt(start, bytes); !r) {
        // One bad sector fails the whole chunk read, but the window asked for may lie nowhere near
        // it: a disk with a single unreadable sector must not lose the 256 KiB around it. Read just
        // that window, uncached (the chunk is incomplete), and let only its own error through.
        return m_inner->readAt(start + within, dst);
    }
    std::memcpy(dst.data(), bytes.data() + within, dst.size());
    std::lock_guard lock(m_mutex);
    if (generation != m_generation || m_index.contains(index)) return {};
    while (!m_lru.empty() && m_cachedBytes + length > m_options.budget) {
        const auto& victim = m_lru.back();
        m_cachedBytes -= victim.bytes.size();
        m_index.erase(victim.index);
        m_lru.pop_back();
        ++m_stats.evictions;
    }
    m_lru.push_front(Chunk{index, std::move(bytes)});
    m_index[index] = m_lru.begin();
    m_cachedBytes += length;
    return {};
}

Expected<void> CachedDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (auto r = checkRange(offset, src.size()); !r) return r;
    if (src.empty()) return {};
    // Before and after: a miss that read the inner device before the write must not be kept, and
    // one that reads it after the first invalidation but before the write lands must not be either.
    invalidate(offset, src.size());
    auto r = m_inner->writeAt(offset, src);
    invalidate(offset, src.size());
    return r;
}

Expected<void> CachedDevice::discard(ByteCount offset, ByteCount length) {
    if (auto r = checkRange(offset, length); !r) return r;
    if (length == 0) return {};
    invalidate(offset, length);
    auto r = m_inner->discard(offset, length);
    invalidate(offset, length);
    return r;
}

Expected<void> CachedDevice::zeroRange(ByteCount offset, ByteCount length) {
    if (auto r = checkRange(offset, length); !r) return r;
    if (length == 0) return {};
    invalidate(offset, length);
    auto r = m_inner->zeroRange(offset, length);
    invalidate(offset, length);
    return r;
}

void CachedDevice::invalidate() {
    std::lock_guard lock(m_mutex);
    ++m_generation;
    m_lru.clear();
    m_index.clear();
    m_cachedBytes = 0;
}

void CachedDevice::invalidate(ByteCount offset, ByteCount length) {
    if (length == 0 || offset >= m_size) return;   // nothing cached past the end (and no underflow below)
    const ByteCount first = offset / m_options.chunkSize;
    const ByteCount last = (std::min(offset + length, m_size) - 1) / m_options.chunkSize;
    std::lock_guard lock(m_mutex);
    ++m_generation;
    dropLocked(first, last);
}

void CachedDevice::dropLocked(ByteCount firstIndex, ByteCount lastIndex) {
    // Walk the range when it is short, the cache when the range is the longer of the two.
    if (lastIndex - firstIndex + 1 <= m_index.size()) {
        for (ByteCount i = firstIndex; i <= lastIndex; ++i)
            if (auto it = m_index.find(i); it != m_index.end()) {
                m_cachedBytes -= it->second->bytes.size();
                m_lru.erase(it->second);
                m_index.erase(it);
            }
        return;
    }
    for (auto it = m_lru.begin(); it != m_lru.end();) {
        if (it->index >= firstIndex && it->index <= lastIndex) {
            m_cachedBytes -= it->bytes.size();
            m_index.erase(it->index);
            it = m_lru.erase(it);
        } else {
            ++it;
        }
    }
}

CachedDevice::Stats CachedDevice::stats() const {
    std::lock_guard lock(m_mutex);
    Stats s = m_stats;
    s.cachedBytes = m_cachedBytes;
    s.chunks = m_lru.size();
    return s;
}

} // namespace stein
