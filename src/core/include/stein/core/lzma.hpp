// SPDX-License-Identifier: MIT
// LZMA family decoders: raw LZMA1, the .lzma file format, LZMA2 chunks and the
// .xz container (LZMA2 filter only, CRC32/CRC64/SHA-256 checks verified). Own
// implementation for DMG ULMO blocks, squashfs xz and xz-compressed data.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Raw LZMA1 stream with the given properties byte (lc/lp/pb). Decodes until `out` is full or
// the end marker appears; returns the bytes produced.
Expected<std::size_t> lzmaDecompressRaw(std::span<const std::byte> in, std::span<std::byte> out, std::uint8_t props);
// MicroLZMA (EROFS, xz's lzma_microlzma): the inverted properties byte sits where the range
// coder's leading zero would be, no size fields, no end marker; `out` is the exact size unless
// `partial`.
Expected<std::size_t> lzmaMicroDecompress(std::span<const std::byte> in, std::span<std::byte> out, bool partial = false);
// .lzma format: 13-byte header (properties, dictionary size, uncompressed size or -1).
Expected<std::size_t> lzmaDecompress(std::span<const std::byte> in, std::span<std::byte> out);
// LZMA2 chunk stream (as used inside .xz): returns the bytes produced; `consumed` receives the
// input bytes used including the end marker.
Expected<std::size_t> lzma2Decompress(std::span<const std::byte> in, std::span<std::byte> out, std::size_t* consumed = nullptr);
// .xz container (one or more streams); fails with Unsupported on filters other than LZMA2.
Expected<std::size_t> xzDecompress(std::span<const std::byte> in, std::span<std::byte> out);

std::uint64_t crc64(std::span<const std::byte> data, std::uint64_t seed = 0);

} // namespace stein::compress
