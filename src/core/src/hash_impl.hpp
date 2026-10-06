// SPDX-License-Identifier: MIT
// Internal: portable and hardware kernels behind Crc32/Crc32c/Sha256. The
// public classes dispatch on cpuFeatures(); tests include this header to
// cross-check the kernels against each other.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace stein::detail {

std::uint32_t crc32Portable(std::uint32_t state, std::span<const std::byte> data);     // IEEE, slice-by-8
std::uint32_t crc32cPortable(std::uint32_t state, std::span<const std::byte> data);    // Castagnoli, slice-by-8
// Hardware CRC32C (SSE4.2 / ARMv8 CRC). Only valid when the feature is present.
bool crc32cHardwareAvailable();
std::uint32_t crc32cHardware(std::uint32_t state, std::span<const std::byte> data);

// SHA-256 compression over `blocks` 64-byte blocks.
void sha256Portable(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks);
bool sha256HardwareAvailable();
void sha256Hardware(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks);

} // namespace stein::detail
