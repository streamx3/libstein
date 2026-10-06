// SPDX-License-Identifier: MIT
#include "stein/ops/media_test.hpp"

#include "stein/core/crypto.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/units.hpp"
#include "stein/image/copy.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace stein::ops {

namespace {
using Clock = std::chrono::steady_clock;
double secondsSince(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

crypto::Key256 patternKey(std::uint64_t seed) {
    crypto::Key256 key{};
    storeLe64(reinterpret_cast<std::byte*>(key.data()), seed);
    storeLe64(reinterpret_cast<std::byte*>(key.data()) + 8, ~seed);
    std::memcpy(key.data() + 16, "stein-media-test", 16);
    return key;
}

// The 16-byte header every pattern chunk starts with: a seed-derived tag and
// the chunk's own offset. Reading it back tells where the data was written.
constexpr std::size_t kPatternHeader = 16;
std::array<std::byte, 8> patternTag(std::uint64_t seed) {
    std::array<std::byte, 8> tag{};
    std::array<std::byte, 8> zero{};
    crypto::Nonce96 nonce{};
    std::memcpy(nonce.data() + 8, "MTAG", 4);
    crypto::chacha20Xor(patternKey(seed), nonce, 0, zero, tag);
    return tag;
}

// If `buf` carries our header, the offset it claims to be the pattern of.
std::optional<ByteCount> identifyPattern(std::uint64_t seed, std::span<const std::byte> buf) {
    if (buf.size() < kPatternHeader) return std::nullopt;
    const auto tag = patternTag(seed);
    if (std::memcmp(buf.data(), tag.data(), 8) != 0) return std::nullopt;
    return loadLe64(buf.data() + 8);
}

std::uint64_t gcd64(std::uint64_t a, std::uint64_t b) {
    while (b) {
        const std::uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}
} // namespace

void fillPattern(std::uint64_t seed, ByteCount offset, std::span<std::byte> out) {
    crypto::Nonce96 nonce{};
    storeLe64(reinterpret_cast<std::byte*>(nonce.data()), offset);
    std::memcpy(nonce.data() + 8, "MDIA", 4);
    std::fill(out.begin(), out.end(), std::byte{0});
    crypto::chacha20Xor(patternKey(seed), nonce, 0, out, out);
    const auto tag = patternTag(seed);
    const std::size_t n = std::min(out.size(), kPatternHeader);
    if (n >= 8) std::memcpy(out.data(), tag.data(), 8);
    if (n >= 16) storeLe64(out.data() + 8, offset);
}

Expected<SurfaceScanResult> surfaceScan(BlockDevice& device, Progress& progress, Report& report) {
    SurfaceScanResult r;
    const auto t0 = Clock::now();
    const ByteCount cs = 4 * MiB;
    std::vector<std::byte> buf(cs);
    progress.setPhase("Surface scan", device.size());
    report.addDetail("device", device.name());
    report.addDetail("size", formatSizeExact(device.size()));
    for (ByteCount off = 0; off < device.size(); off += cs) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount len = std::min<ByteCount>(cs, device.size() - off);
        auto bad = image::readChunkTolerant(device, off, std::span<std::byte>(buf).first(static_cast<std::size_t>(len)), image::BadSectorPolicy::SkipZero, &r.badRegions);
        if (!bad) return fail(bad.error());
        r.unreadableSectors += *bad;
        r.bytesRead += len;
        progress.advance(len);
    }
    progress.finishPhase();
    r.seconds = secondsSince(t0);
    report.addDetail("unreadable sectors", std::to_string(r.unreadableSectors));
    for (const auto& b : r.badRegions) report.addLine("unreadable: " + std::to_string(b.offset) + " + " + formatSize(b.length));
    return r;
}

Expected<CapacityTestResult> capacityTest(BlockDevice& device, const CapacityTestOptions& options, Progress& progress, Report& report) {
    if (device.isReadOnly()) return fail(ErrorCategory::Permission, "device is read-only");
    if (options.chunkSize < 4096 || (options.chunkSize & (options.chunkSize - 1))) return fail(ErrorCategory::InvalidArgument, "chunk size must be a power of two >= 4096");
    CapacityTestResult r;
    r.claimedBytes = device.size();
    std::uint64_t seed = options.seed;
    if (!seed) {
        std::array<std::uint8_t, 8> rnd{};
        if (auto e = crypto::randomBytes(rnd); !e) return fail(e.error());
        std::memcpy(&seed, rnd.data(), 8);
        if (!seed) seed = 1;
    }
    const ByteCount cs = options.chunkSize;
    const std::uint64_t chunks = (device.size() + cs - 1) / cs;
    // Chunk selection: all, or every Nth plus the last eight (fake flash lies about the tail).
    std::vector<std::uint64_t> selected;
    for (std::uint64_t i = 0; i < chunks; ++i)
        if (!options.quickStride || i % options.quickStride == 0 || i + 8 >= chunks) selected.push_back(i);
    report.addDetail("device", device.name());
    report.addDetail("claimed size", formatSizeExact(device.size()));
    report.addDetail("seed", std::to_string(seed));
    report.addDetail("chunks tested", std::to_string(selected.size()) + " of " + std::to_string(chunks));

    std::vector<std::byte> buf(cs);
    auto t0 = Clock::now();
    progress.setPhase("Writing pattern", selected.size() * cs);
    for (auto i : selected) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount off = i * cs;
        const ByteCount len = std::min<ByteCount>(cs, device.size() - off);
        auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(len));
        fillPattern(seed, off, chunk);
        if (auto w = device.writeAt(off, chunk); !w) {
            report.addLine("write failed at " + std::to_string(off) + ": " + w.error().message());
            r.badRegions.push_back(Region{off, len});
            ++r.chunksBad;
        } else {
            r.bytesWritten += len;
        }
        progress.advance(len);
    }
    (void)device.flush();
    progress.finishPhase();
    const double wsec = secondsSince(t0);
    r.writeMiBps = wsec > 0 ? static_cast<double>(r.bytesWritten) / MiB / wsec : 0;

    t0 = Clock::now();
    progress.setPhase("Reading back", selected.size() * cs);
    std::vector<std::byte> expect(cs);
    std::uint64_t displacementGcd = 0;   // gcd of (address whose pattern we found - address we read): a multiple of the real capacity
    std::uint64_t foreign = 0, garbage = 0;
    for (auto i : selected) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        const ByteCount off = i * cs;
        const ByteCount len = std::min<ByteCount>(cs, device.size() - off);
        auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(len));
        ++r.chunksTested;
        if (auto rd = device.readAt(off, chunk); !rd) {
            report.addLine("read failed at " + std::to_string(off) + ": " + rd.error().message());
            r.badRegions.push_back(Region{off, len});
            ++r.chunksBad;
            progress.advance(len);
            continue;
        }
        auto want = std::span<std::byte>(expect).first(static_cast<std::size_t>(len));
        fillPattern(seed, off, want);
        if (std::memcmp(want.data(), chunk.data(), chunk.size()) == 0) {
            r.bytesVerified += len;
        } else {
            ++r.chunksBad;
            if (!r.firstMismatch) r.firstMismatch = off;
            // Fake flash: the data here is the pattern written to another address (wraparound).
            if (auto other = identifyPattern(seed, chunk); other && *other != off && *other < device.size()) {
                ++foreign;
                r.wraparound = true;
                const std::uint64_t d = *other > off ? *other - off : off - *other;
                displacementGcd = gcd64(displacementGcd, d);
            } else {
                ++garbage;
            }
            if (r.badRegions.empty() || r.badRegions.back().end() != off) r.badRegions.push_back(Region{off, len});
            else r.badRegions.back().length += len;
        }
        progress.advance(len);
    }
    progress.finishPhase();
    const double rsec = secondsSince(t0);
    r.readMiBps = rsec > 0 ? static_cast<double>(r.bytesVerified + r.badRegions.size() * cs) / MiB / rsec : 0;

    if (r.firstMismatch) {
        if (r.wraparound && displacementGcd) {
            // Addresses wrap modulo the real capacity: every displacement is a multiple of it.
            r.realCapacityEstimate = displacementGcd;
            report.addLine("FAKE CAPACITY: " + std::to_string(foreign) + " chunk(s) hold data written to other addresses (wraparound every " + formatSize(displacementGcd) + ")");
        } else if (garbage && !r.wraparound) {
            // Writes beyond some point were dropped: usable capacity ends at the first mismatch if all below it is good.
            bool allGoodBelow = true;
            for (const auto& b : r.badRegions)
                if (b.offset < *r.firstMismatch) allGoodBelow = false;
            if (allGoodBelow && *r.firstMismatch > 0) r.realCapacityEstimate = *r.firstMismatch;
            report.addLine(std::to_string(garbage) + " chunk(s) read back as something other than our pattern (dropped writes or dead cells), first at " + std::to_string(*r.firstMismatch));
        }
        report.addLine("pattern mismatch first seen at " + std::to_string(*r.firstMismatch) + " (" + formatSize(*r.firstMismatch) + ")");
        if (r.realCapacityEstimate) report.addDetail("real capacity (estimate)", formatSizeExact(*r.realCapacityEstimate));
    }
    report.addDetail("verified", formatSize(r.bytesVerified));
    report.addDetail("write speed", std::to_string(static_cast<int>(r.writeMiBps)) + " MiB/s");
    report.addDetail("read speed", std::to_string(static_cast<int>(r.readMiBps)) + " MiB/s");

    if (!options.keepPattern) {
        progress.setPhase("Clearing pattern", selected.size() * cs);
        std::fill(buf.begin(), buf.end(), std::byte{0});
        for (auto i : selected) {
            const ByteCount off = i * cs;
            const ByteCount len = std::min<ByteCount>(cs, device.size() - off);
            (void)device.zero(off, len);
            progress.advance(len);
        }
        (void)device.flush();
        progress.finishPhase();
    }
    return r;
}

} // namespace stein::ops
