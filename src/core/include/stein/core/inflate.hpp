// SPDX-License-Identifier: MIT
// DEFLATE decoder (RFC 1951) with the zlib (RFC 1950) and gzip (RFC 1952)
// wrappers. Own implementation, no dependency: qcow2 compressed clusters, VMDK
// stream-optimized grains, E01 chunks and DMG blocks all speak deflate.
#pragma once

#include "stein/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::compress {

// Decode raw deflate data into `out`; returns the number of bytes produced. Fails with
// InvalidFormat on corrupt input and OutOfRange when `out` is too small.
Expected<std::size_t> inflateRaw(std::span<const std::byte> in, std::span<std::byte> out);
// zlib stream: 2-byte header, raw deflate, Adler-32 trailer (verified).
Expected<std::size_t> inflateZlib(std::span<const std::byte> in, std::span<std::byte> out);
// gzip member: header with optional fields, raw deflate, CRC-32 and size trailer (verified).
Expected<std::size_t> inflateGzip(std::span<const std::byte> in, std::span<std::byte> out);

std::uint32_t adler32(std::span<const std::byte> data, std::uint32_t seed = 1);

// Apple Data Compression (ADC, the UDCO DMG codec): literal runs and short/long back-references.
Expected<std::size_t> adcDecompress(std::span<const std::byte> in, std::span<std::byte> out);

} // namespace stein::compress
