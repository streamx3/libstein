// SPDX-License-Identifier: MIT
// LZ4 block format (https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md),
// implemented from the specification so that libstein images compressed with
// it can be read by any LZ4 tool, and vice versa. Correctness and simplicity
// over speed; a vendored zstd arrives later for better ratios.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace stein::lz4 {

// Worst-case compressed size for `inputSize` bytes (LZ4_COMPRESSBOUND).
std::size_t compressBound(std::size_t inputSize);

// Compress `input` into `output` (must be at least compressBound(input.size()) bytes).
// Returns the number of bytes written. `acceleration` 1 = default; higher = faster, worse ratio.
std::size_t compress(std::span<const std::byte> input, std::span<std::byte> output, int acceleration = 1);
std::vector<std::byte> compress(std::span<const std::byte> input, int acceleration = 1);

// Decompress a block into `output`, which must be exactly the original size.
// Fails with InvalidFormat on malformed input (never reads or writes out of bounds).
Expected<void> decompress(std::span<const std::byte> input, std::span<std::byte> output);
// Like decompress() but the block may produce fewer bytes than `output` holds; returns the count.
Expected<std::size_t> decompressUpTo(std::span<const std::byte> input, std::span<std::byte> output);
Expected<std::vector<std::byte>> decompress(std::span<const std::byte> input, std::size_t originalSize);

} // namespace stein::lz4
