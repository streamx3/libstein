// SPDX-License-Identifier: MIT
#include "stein/image/copy.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>

namespace stein::image {

bool isAllZero(std::span<const std::byte> b) {
    std::size_t i = 0;
    for (; i + 8 <= b.size(); i += 8)
        if (loadLe64(b.data() + i) != 0) return false;
    for (; i < b.size(); ++i)
        if (b[i] != std::byte{0}) return false;
    return true;
}

Expected<std::uint64_t> readChunkTolerant(BlockDevice& source, ByteCount offset, std::span<std::byte> out, BadSectorPolicy policy,
                                          std::vector<Region>* badRegions) {
    if (auto r = source.readAt(offset, out)) return 0;
    else if (policy == BadSectorPolicy::Fail) return fail(r.error());
    // Retry sector by sector; zero what cannot be read.
    const ByteCount ss = source.sectorSize() ? source.sectorSize() : 512;
    std::uint64_t bad = 0;
    for (ByteCount pos = 0; pos < out.size(); pos += ss) {
        const ByteCount len = std::min<ByteCount>(ss, out.size() - pos);
        auto sector = out.subspan(static_cast<std::size_t>(pos), static_cast<std::size_t>(len));
        if (source.readAt(offset + pos, sector)) continue;
        std::fill(sector.begin(), sector.end(), std::byte{0});
        ++bad;
        if (badRegions) {
            if (!badRegions->empty() && badRegions->back().end() == offset + pos) badRegions->back().length += len;
            else badRegions->push_back(Region{offset + pos, len});
        }
    }
    return bad;
}

namespace {
// Zero the free blocks of every mapped filesystem inside the chunk at `off`.
ByteCount applyAllocations(const CopyOptions& options, ByteCount off, std::span<std::byte> chunk) {
    ByteCount zeroed = 0;
    for (const auto& m : options.allocations) {
        if (!m.map) continue;
        const ByteCount from = std::max(off, m.region.offset);
        const ByteCount to = std::min(off + chunk.size(), m.region.end());
        if (from >= to) continue;
        zeroed += m.map->zeroFree(from - m.region.offset, chunk.subspan(static_cast<std::size_t>(from - off), static_cast<std::size_t>(to - from)));
    }
    return zeroed;
}
} // namespace

Expected<CopyStats> copyToSink(BlockDevice& source, ChunkSink& sink, const CopyOptions& options, Progress& progress) {
    CopyStats stats;
    const ByteCount total = options.limit ? std::min(options.limit, source.size()) : source.size();
    const ByteCount cs = options.chunkSize;
    progress.setPhase("Reading", total);
    std::vector<std::byte> buf(cs);
    for (ByteCount off = 0, idx = 0; off < total; off += cs, ++idx) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount len = std::min<ByteCount>(cs, total - off);
        auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(len));
        auto bad = readChunkTolerant(source, off, chunk, options.badSectors, &stats.badRegions);
        if (!bad) return fail(bad.error());
        stats.unreadableSectors += *bad;
        stats.bytesRead += len;
        ++stats.chunks;
        stats.freeBytesSkipped += applyAllocations(options, off, chunk);
        if (isAllZero(chunk)) ++stats.zeroChunks;
        if (auto w = sink.writeChunk(idx, chunk); !w) return fail(w.error());
        stats.bytesWritten += len;
        progress.advance(len);
    }
    progress.finishPhase();
    return stats;
}

std::vector<Region> regionsOutside(const Region& range, std::vector<Region> keep) {
    std::vector<Region> out;
    if (range.empty()) return out;
    std::sort(keep.begin(), keep.end(), [](const Region& a, const Region& b) { return a.offset < b.offset; });
    ByteCount cursor = range.offset;
    for (const auto& k : keep) {
        if (k.empty() || k.end() <= cursor) continue;
        if (k.offset >= range.end()) break;
        if (k.offset > cursor) out.push_back({cursor, k.offset - cursor});
        cursor = std::max(cursor, k.end());
        if (cursor >= range.end()) break;
    }
    if (cursor < range.end()) out.push_back({cursor, range.end() - cursor});
    return out;
}

namespace {

// The adaptive compare-before-write policy of CopyOptions::skipIdentical.
class IdenticalSkipper {
public:
    static constexpr int kWarmup = 32;     // comparisons before the hit rate is judged
    static constexpr int kProbeEvery = 64; // while paused, one chunk in this many is still compared
    bool wantCompare() {
        if (!m_paused) return true;
        return ++m_sinceProbe % kProbeEvery == 0;
    }
    void record(bool hit) {
        if (m_paused) {
            if (hit) {   // the target matches again: resume comparing with a clean slate
                m_paused = false;
                m_hits = m_tries = 0;
            }
            return;
        }
        ++m_tries;
        if (hit) ++m_hits;
        if (m_tries >= kWarmup && m_hits * 2 < m_tries) {
            m_paused = true;
            m_sinceProbe = 0;
        }
    }

private:
    bool m_paused = false;
    int m_hits = 0, m_tries = 0;
    int m_sinceProbe = 0;
};

} // namespace

Expected<CopyStats> copyDevice(BlockDevice& source, BlockDevice& target, const CopyOptions& options, Progress& progress) {
    CopyStats stats;
    IdenticalSkipper skipper;
    std::vector<std::byte> targetBuf;
    ByteCount total = std::min(source.size(), target.size());
    if (options.limit) total = std::min(total, options.limit);
    const ByteCount cs = options.chunkSize;
    progress.setPhase("Copying", total);
    std::vector<std::byte> buf(cs);
    for (ByteCount off = 0; off < total; off += cs) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount len = std::min<ByteCount>(cs, total - off);
        auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(len));
        auto bad = readChunkTolerant(source, off, chunk, options.badSectors, &stats.badRegions);
        if (!bad) return fail(bad.error());
        stats.unreadableSectors += *bad;
        stats.bytesRead += len;
        ++stats.chunks;
        stats.freeBytesSkipped += applyAllocations(options, off, chunk);
        const bool zero = isAllZero(chunk);
        const ZeroPolicy policy = options.skipZeroChunksOnWrite ? ZeroPolicy::Skip : options.zeroPolicy;
        if (zero) ++stats.zeroChunks;
        if (zero && policy == ZeroPolicy::Skip) {
            stats.zeroBytesSkipped += len;
            progress.advance(len);
            continue;
        }
        // Compare before writing: a chunk the target already holds is not written at all.
        if (options.skipIdentical && skipper.wantCompare()) {
            targetBuf.resize(static_cast<std::size_t>(len));
            const bool same = target.readAt(off, targetBuf) && std::equal(targetBuf.begin(), targetBuf.end(), chunk.begin());
            stats.compareBytesRead += len;
            skipper.record(same);
            if (same) {
                ++stats.identicalChunks;
                stats.identicalBytes += len;
                if (zero) stats.zeroBytesSkipped += len;
                progress.advance(len);
                continue;
            }
        }
        if (zero) {
            if (policy == ZeroPolicy::SkipInside) {
                // Only the parts the partition table calls free are zeroed; a chunk that straddles
                // a partition boundary is split at that boundary, never one byte past it.
                ByteCount written = 0;
                for (const auto& part : regionsOutside(Region{off, len}, options.keepRegions)) {
                    if (auto w = target.zeroRange(part.offset, part.length); !w) return fail(w.error());
                    written += part.length;
                }
                stats.bytesWritten += written;
                stats.zeroBytesWritten += written;
                stats.zeroBytesSkipped += len - written;
                progress.advance(len);
                continue;
            }
            // Write: the device's cheapest guaranteed way to read back zeros (holes, WRITE ZEROES,
            // unmap with read-back), zero writes where it has nothing better.
            if (auto w = target.zeroRange(off, len); !w) return fail(w.error());
            stats.bytesWritten += len;
            stats.zeroBytesWritten += len;
            progress.advance(len);
            continue;
        }
        if (auto w = target.writeAt(off, chunk); !w) return fail(w.error());
        stats.bytesWritten += len;
        progress.advance(len);
    }
    if (auto f = target.flush(); !f) return fail(f.error());
    progress.finishPhase();
    return stats;
}

} // namespace stein::image
