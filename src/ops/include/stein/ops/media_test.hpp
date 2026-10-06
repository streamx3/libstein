// SPDX-License-Identifier: MIT
// Native-drive verification (D-list: "native-drive verification incl. fake
// flash"). Two tests:
//  * surfaceScan: read-only; reads the whole device and lists unreadable
//    sectors (the bad-sector policy of the copy engine, no writes).
//  * capacityTest: DESTRUCTIVE; writes a keyed pseudo-random pattern across
//    the device, reads it back and reports where it stops matching. A fake
//    flash drive that wraps or drops addresses beyond its real capacity
//    shows up as "pattern ok up to X, then wrong/foreign data", and X is the
//    real capacity. Quick mode writes every Nth chunk plus the tail.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/progress.hpp"
#include "stein/core/report.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace stein::ops {

struct SurfaceScanResult {
    ByteCount bytesRead = 0;
    std::uint64_t unreadableSectors = 0;
    std::vector<Region> badRegions;
    double seconds = 0;
    bool healthy() const { return unreadableSectors == 0; }
};

Expected<SurfaceScanResult> surfaceScan(BlockDevice& device, Progress& progress, Report& report);

struct CapacityTestOptions {
    std::uint64_t seed = 0;            // 0 = random
    std::uint32_t chunkSize = 4 * MiB;
    std::uint32_t quickStride = 0;     // 0 = full test; N = write/read every Nth chunk plus the last 8
    bool keepPattern = false;          // leave the pattern on the device (default: zero the tested chunks afterwards)
};

struct CapacityTestResult {
    ByteCount claimedBytes = 0;
    ByteCount bytesWritten = 0, bytesVerified = 0;
    std::uint64_t chunksTested = 0, chunksBad = 0;
    std::optional<ByteCount> firstMismatch;      // offset where the pattern stopped matching
    std::optional<ByteCount> realCapacityEstimate;   // when the device looks like fake flash
    bool wraparound = false;                     // data beyond the estimate was the pattern of a lower address
    std::vector<Region> badRegions;
    double writeMiBps = 0, readMiBps = 0;
    bool healthy() const { return chunksBad == 0 && !firstMismatch; }
};

Expected<CapacityTestResult> capacityTest(BlockDevice& device, const CapacityTestOptions& options, Progress& progress, Report& report);

// The pattern for a chunk: ChaCha20 keystream keyed by (seed, offset); exposed for tests.
void fillPattern(std::uint64_t seed, ByteCount offset, std::span<std::byte> out);

} // namespace stein::ops
