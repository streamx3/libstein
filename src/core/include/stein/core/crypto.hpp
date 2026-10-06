// SPDX-License-Identifier: MIT
// Primitives for encrypted images and pieces: ChaCha20-Poly1305 AEAD
// (RFC 8439), HMAC-SHA256, PBKDF2-HMAC-SHA256 and OS randomness. Own
// implementations, no exceptions, constant-time tag comparison. See
// doc/design/14-imaging.md §2b and DECISIONS.md D16.
#pragma once

#include "stein/core/error.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace stein::crypto {

using Key256 = std::array<std::uint8_t, 32>;
using Nonce96 = std::array<std::uint8_t, 12>;
using Tag128 = std::array<std::uint8_t, 16>;

// XOR `in` with the ChaCha20 keystream for (key, nonce) starting at block `counter`.
void chacha20Xor(const Key256& key, const Nonce96& nonce, std::uint32_t counter, std::span<const std::byte> in, std::span<std::byte> out);
// One-shot Poly1305 MAC with a 32-byte one-time key.
Tag128 poly1305(const Key256& key, std::span<const std::byte> message);

// AEAD_CHACHA20_POLY1305. `out` must have plaintext.size() + 16 bytes; returns the tag separately too.
constexpr std::size_t kTagSize = 16;
void aeadEncrypt(const Key256& key, const Nonce96& nonce, std::span<const std::byte> aad, std::span<const std::byte> plaintext, std::span<std::byte> out);
// `in` is ciphertext || tag; `out` must have in.size() - 16 bytes. Integrity error on a bad tag (out is zeroed then).
Expected<void> aeadDecrypt(const Key256& key, const Nonce96& nonce, std::span<const std::byte> aad, std::span<const std::byte> in, std::span<std::byte> out);

std::array<std::uint8_t, 32> hmacSha256(std::span<const std::byte> key, std::span<const std::byte> message);
void pbkdf2Sha256(std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out);

// BLAKE2b (RFC 7693): 1..64 byte digest, optional key up to 64 bytes.
void blake2b(std::span<std::uint8_t> out, std::span<const std::byte> message, std::span<const std::byte> key = {});

// Argon2id (RFC 9106, version 0x13). memoryKiB >= 8 * parallelism; passes >= 1.
Expected<void> argon2id(std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t passes, std::uint32_t memoryKiB,
                        std::uint32_t parallelism, std::span<std::uint8_t> out, std::span<const std::byte> secret = {}, std::span<const std::byte> ad = {});

// Cryptographically secure random bytes from the OS.
Expected<void> randomBytes(std::span<std::uint8_t> out);

// Constant-time equality.
bool equalConstantTime(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b);

} // namespace stein::crypto
