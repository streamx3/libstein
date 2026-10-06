// SPDX-License-Identifier: MIT
// LZFSE decoder (Apple's lzfse stream format: uncompressed, LZVN and FSE
// compressed blocks, v1 and v2 headers). Own implementation for DMG ULFO
// blocks and Apple archives.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Decode a complete lzfse stream (blocks up to the end-of-stream marker) into `out`; returns
// the number of bytes produced. Fails with InvalidFormat on corrupt input and OutOfRange when
// `out` is too small.
Expected<std::size_t> lzfseDecompress(std::span<const std::byte> in, std::span<std::byte> out);

// Decode one raw LZVN payload (no block header) into `out`; returns the bytes produced.
Expected<std::size_t> lzvnDecompress(std::span<const std::byte> in, std::span<std::byte> out);

} // namespace stein::compress
