// SPDX-License-Identifier: MIT
// LUKS1 and LUKS2 in-process: parse the header, unlock a key slot with a
// passphrase (PBKDF2 / Argon2 + anti-forensic merge + digest check) and
// expose the payload as a decrypting BlockDevice (aes-xts-plain64). This is
// what lets an ext4-in-LUKS be read on Windows or macOS without dm-crypt.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace stein::container {

struct LuksSlotInfo {
    int id = 0;
    bool active = true;
    std::string kdf;             // "pbkdf2", "argon2id", "argon2i"
    std::string kdfDetail;       // "sha256 1000 iterations" / "t=4 m=64KiB p=1"
};

struct LuksInfo {
    int version = 0;             // 1 or 2
    std::string cipher;          // "aes"
    std::string mode;            // "xts-plain64"
    std::string hash;            // LUKS1 header hash / LUKS2 AF hash
    std::uint32_t keyBytes = 0;  // master key size (64 for aes-xts-512)
    ByteCount payloadOffset = 0;
    ByteCount payloadSize = 0;
    std::uint32_t sectorSize = 512;
    std::uint64_t ivTweak = 0;
    std::string uuid, label;
    std::vector<LuksSlotInfo> slots;
    bool supported = true;       // cipher/mode/kdf/hash all implemented
    std::string unsupportedWhy;
};

class Luks {
public:
    static Expected<Luks> open(std::shared_ptr<BlockDevice> device);
    const LuksInfo& info() const { return m_info; }

    // Try every active slot. Integrity when none opens; Unsupported for ciphers/kdfs we lack.
    Expected<std::vector<std::uint8_t>> unlock(const std::string& passphrase) const;
    // The payload as a device decrypting on read (and encrypting on write unless readOnly).
    Expected<std::shared_ptr<BlockDevice>> openPayload(std::span<const std::uint8_t> masterKey, bool readOnly = true) const;
    // Convenience: unlock + openPayload.
    Expected<std::shared_ptr<BlockDevice>> openPayload(const std::string& passphrase, bool readOnly = true) const;

private:
    struct Slot {
        int id = 0;
        std::string kdf, hash;                 // kdf: pbkdf2|argon2id|argon2i ; hash: for pbkdf2 and AF
        std::uint32_t iterations = 0, time = 0, memoryKiB = 0, cpus = 0;
        std::vector<std::uint8_t> salt;
        std::uint32_t stripes = 4000;
        std::string afHash;
        ByteCount areaOffset = 0, areaSize = 0;
        std::uint32_t areaKeySize = 0;        // key bytes used to decrypt the area (LUKS2) / = keyBytes (LUKS1)
    };
    struct Digest {
        std::string hash;
        std::uint32_t iterations = 0;
        std::vector<std::uint8_t> salt, digest;
    };
    Expected<void> parseV1(std::span<const std::byte> hdr);
    Expected<void> parseV2(std::span<const std::byte> hdr);
    Expected<std::vector<std::uint8_t>> trySlot(const Slot& slot, const std::string& passphrase) const;
    bool digestMatches(std::span<const std::uint8_t> key) const;

    std::shared_ptr<BlockDevice> m_device;
    LuksInfo m_info;
    std::vector<Slot> m_slots;
    Digest m_digest;
};

// Anti-forensic merge (LUKS1 AFmerge): `src` holds `stripes` blocks of `blockSize` bytes.
Expected<std::vector<std::uint8_t>> afMerge(std::span<const std::uint8_t> src, std::size_t blockSize, std::uint32_t stripes, const std::string& hash);

} // namespace stein::container
