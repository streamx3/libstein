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
        if (isAllZero(chunk)) ++stats.zeroChunks;
        if (auto w = sink.writeChunk(idx, chunk); !w) return fail(w.error());
        stats.bytesWritten += len;
        progress.advance(len);
    }
    progress.finishPhase();
    return stats;
}

Expected<CopyStats> copyDevice(BlockDevice& source, BlockDevice& target, const CopyOptions& options, Progress& progress) {
    CopyStats stats;
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
        if (isAllZero(chunk)) {
            ++stats.zeroChunks;
            if (options.skipZeroChunksOnWrite) {
                progress.advance(len);
                continue;
            }
            if (options.discardZeroChunks && target.discard(off, len)) {
                progress.advance(len);
                continue;
            }
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
