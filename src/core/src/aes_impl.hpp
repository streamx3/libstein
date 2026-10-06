// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

namespace stein::crypto::detail {
// Portable kernels (aes.cpp) and hardware kernels (aes_hw.cpp) over an expanded encryption key schedule.
void aesEncryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
bool aesHardware();
void aesEncryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptHardware(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
} // namespace stein::crypto::detail
