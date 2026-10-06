// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

namespace stein::crypto::detail {
// Portable kernels (aes.cpp) and hardware kernels (aes_hw.cpp) over an expanded encryption key schedule.
void aesEncryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
bool aesHardware();
// The hardware kernels take the round keys as bytes, prepared once per key by aesPrepareHardware:
// `enc` is the schedule as 16-byte round keys, `dec` the equivalent-inverse-cipher schedule
// (InvMixColumns applied to the middle round keys), so a block costs no per-call key work.
void aesPrepareHardware(const std::uint32_t* rk, unsigned rounds, std::uint8_t* enc, std::uint8_t* dec);
void aesEncryptHardware(const std::uint8_t* enc, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
void aesDecryptHardware(const std::uint8_t* dec, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]);
} // namespace stein::crypto::detail
