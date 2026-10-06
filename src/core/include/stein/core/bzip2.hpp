// SPDX-License-Identifier: MIT
// bzip2 decoder (the .bz2 stream format: Burrows-Wheeler, MTF, RLE, Huffman).
// Own implementation for DMG UDBZ blocks and bzip2-compressed archives.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Decode a complete bzip2 stream ("BZh1".."BZh9" header, one or more blocks, end-of-stream
// marker) into `out`. Returns the number of bytes produced. Block and stream CRCs are verified.
Expected<std::size_t> bunzip2(std::span<const std::byte> in, std::span<std::byte> out);

} // namespace stein::compress
