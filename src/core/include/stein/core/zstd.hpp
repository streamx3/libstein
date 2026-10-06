// SPDX-License-Identifier: MIT
// Zstandard decoder (RFC 8878): frames with raw, RLE and compressed blocks,
// Huffman literals (1 or 4 streams, FSE-compressed or direct weights),
// FSE sequence tables (predefined, RLE, compressed, repeat), repeat offsets,
// skippable frames, optional XXH64 content checksum. No dictionaries. Own
// implementation for btrfs zstd extents and qcow2 zstd clusters.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Decode every frame in `in` into `out`; returns the number of bytes produced. Fails with
// InvalidFormat on corrupt input, Integrity on a checksum mismatch, Unsupported for
// dictionary frames and OutOfRange when `out` is too small.
Expected<std::size_t> zstdDecompress(std::span<const std::byte> in, std::span<std::byte> out);
// Decode only the first frame (after any skippable frames) and ignore what follows it: for
// containers that pack frames back to back with sector padding, such as qcow2 clusters.
Expected<std::size_t> zstdDecompressFrame(std::span<const std::byte> in, std::span<std::byte> out);

// The content size announced by the first frame header, if present.
Expected<std::uint64_t> zstdContentSize(std::span<const std::byte> in);

std::uint64_t xxh64(std::span<const std::byte> data, std::uint64_t seed = 0);

} // namespace stein::compress
