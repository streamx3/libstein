// SPDX-License-Identifier: MIT
// LZO1X decoder (the format liblzo2's lzo1x_1..999 compressors emit). Own
// implementation for btrfs compressed extents and other LZO-framed data.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Decode one LZO1X block into `out`; returns the number of bytes produced. Fails with
// InvalidFormat on corrupt or truncated input and OutOfRange when `out` is too small.
Expected<std::size_t> lzo1xDecompress(std::span<const std::byte> in, std::span<std::byte> out);

} // namespace stein::compress
