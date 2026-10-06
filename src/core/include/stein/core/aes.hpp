// SPDX-License-Identifier: MIT
// AES-128/192/256 block cipher and AES-XTS (IEEE 1619) as dm-crypt uses it
// for LUKS ("aes-xts-plain64"): the tweak is the little-endian 64-bit sector
// number. Portable implementation plus AES-NI / ARMv8 Crypto Extension
// kernels selected at runtime (see cpu.hpp).
#pragma once

#include "stein/core/error.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace stein::crypto {

class Aes {
public:
    // Key of 16, 24 or 32 bytes.
    static Expected<Aes> create(std::span<const std::uint8_t> key);
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const;
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const;
    unsigned rounds() const { return m_rounds; }
    const std::uint32_t* roundKeys() const { return m_rk.data(); }   // (rounds + 1) * 4 words, encryption schedule

private:
    std::array<std::uint32_t, 60> m_rk{};
    unsigned m_rounds = 0;
};

// XTS with two AES keys (key = k1 || k2, 32 or 64 bytes). `data` must be a
// multiple of 16 bytes (disk sectors are); `sector` is the plain64 tweak.
class AesXts {
public:
    static Expected<AesXts> create(std::span<const std::uint8_t> key);
    Expected<void> encrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const;
    Expected<void> decrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const;
    // Convenience for a run of equally sized sectors starting at `firstSector`.
    Expected<void> encryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const;
    Expected<void> decryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const;

private:
    Aes m_data, m_tweak;
};

bool aesHardwareAvailable();

} // namespace stein::crypto
