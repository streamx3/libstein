// SPDX-License-Identifier: MIT
// Key area of an encrypted .stein image or piece: LUKS2-style. One random 256-bit
// master key encrypts the image; each slot wraps it under a key derived from
// a passphrase (PBKDF2-HMAC-SHA256 for now, "kdf" names it so Argon2id can
// follow). A digest of the master key lets a reader tell a wrong passphrase
// from a corrupted slot. Stored as plaintext JSON in segment 0.
#pragma once

#include "stein/core/crypto.hpp"
#include "stein/core/error.hpp"
#include "stein/core/json.hpp"

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace stein {

// Passphrase stretching. Argon2id is the default (LUKS2's choice); PBKDF2
// stays readable and selectable for very small devices.
struct KdfParams {
    enum class Kind : std::uint8_t { Argon2id, Pbkdf2Sha256 };
    Kind kind = Kind::Argon2id;
    std::uint32_t cost = 3;            // Argon2id passes, or PBKDF2 iterations
    std::uint32_t memoryKiB = 262144;  // Argon2id only (256 MiB; ~0.7 s on a 2 GHz core, fits a 1 GB single-board computer)
    std::uint32_t parallelism = 4;     // Argon2id only

    static KdfParams argon2id(std::uint32_t passes = 3, std::uint32_t memoryKiB = 262144, std::uint32_t parallelism = 4) {
        return KdfParams{Kind::Argon2id, passes, memoryKiB, parallelism};
    }
    static KdfParams pbkdf2(std::uint32_t iterations = 600000) { return KdfParams{Kind::Pbkdf2Sha256, iterations, 0, 0}; }
    // Cheap parameters for unit tests only.
    static KdfParams fast() { return KdfParams{Kind::Argon2id, 1, 64, 1}; }
    std::string describe() const;
};

struct KeySlot {
    int id = 0;
    std::string label;
    std::array<std::uint8_t, 16> salt{};
    KdfParams kdf;
    crypto::Nonce96 nonce{};
    std::vector<std::uint8_t> wrapped;   // master key (32) + tag (16)
};

class Keys {
public:
    static constexpr std::size_t kAreaCapacity = 4096;   // bytes reserved in the image for the JSON

    // New key area with a fresh random master key and one passphrase slot.
    static Expected<Keys> create(const std::string& passphrase, const KdfParams& kdf = {}, std::string label = {});
    static Expected<Keys> fromJson(std::string_view text);
    std::string toJson() const;

    // Try every slot; Integrity when no slot opens (wrong passphrase).
    Expected<crypto::Key256> unlock(const std::string& passphrase) const;
    bool verifyMaster(const crypto::Key256& key) const;

    Expected<int> addSlot(const crypto::Key256& master, const std::string& passphrase, const KdfParams& kdf = {}, std::string label = {});
    Expected<void> removeSlot(int id);
    const std::vector<KeySlot>& slots() const { return m_slots; }

    // Only meaningful right after create(): the key the writer must use.
    const std::optional<crypto::Key256>& master() const { return m_master; }

private:
    std::array<std::uint8_t, 16> m_digestSalt{};
    std::uint32_t m_digestIterations = 0;
    std::array<std::uint8_t, 32> m_digest{};
    std::vector<KeySlot> m_slots;
    std::optional<crypto::Key256> m_master;
};

// Nonce convention for everything the key protects: 8-byte index + 4-byte domain tag.
crypto::Nonce96 domainNonce(const char tag[4], std::uint64_t index);

} // namespace stein
