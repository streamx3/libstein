// SPDX-License-Identifier: MIT
// LUKS1 and LUKS2 in-process: parse the header, unlock a key slot with a
// passphrase (PBKDF2 / Argon2 + anti-forensic merge + digest check) and
// expose the payload as a decrypting BlockDevice (<cipher>-xts-plain64 with
// aes, serpent, twofish or camellia). This is what lets an ext4-in-LUKS be
// read on Windows or macOS without dm-crypt.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/cipher.hpp"
#include "stein/core/error.hpp"
#include "stein/core/hash.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace stein::container {

struct LuksSlotInfo {
    int id = 0;
    bool active = true;          // LUKS1: the slot is enabled. LUKS2: a "luks2" passphrase slot (false for other types, e.g. "reencrypt")
    int priority = 1;            // LUKS2 keyslot priority: 2 = preferred (tried first), 1 = normal, 0 = ignored unless no other slot opens
    std::string kdf;             // "pbkdf2", "argon2id", "argon2i"; "disabled" / the keyslot type for inactive slots
    std::string kdfDetail;       // "sha256 1000 iterations" / "t=4 m=64KiB p=1"
    std::vector<std::string> tokens;   // LUKS2 token types bound to this slot: "systemd-tpm2", "systemd-fido2", "systemd-recovery", "clevis"...
    // Non-empty when unlock() cannot try this slot: a KDF, AF hash or area cipher we lack, Argon2
    // parameters outside RFC 9106's bounds or memory above the machine's cap, a key size that is not
    // the volume key's or not one XTS takes (64 bytes, or 32 with aes), implausible key material
    // (stripes * key size), a key material area inside the header or beyond the device, no digest
    // binding. Settled when the header is parsed, so a slot that cannot open the volume costs no KDF.
    std::string unsupportedWhy;
};

struct LuksInfo {
    int version = 0;             // 1 or 2
    std::string cipher;          // "aes", "serpent", "twofish", "camellia"
    std::string mode;            // "xts-plain64"
    std::string hash;            // LUKS1 header hash / LUKS2 digest hash
    std::uint32_t keyBytes = 0;  // volume (master) key size: 64 for aes-xts-512. LUKS2: the key_size of the segment digest's first slot
    ByteCount payloadOffset = 0; // on the data device (see Luks::open(header, data)); a multiple of 512, past the header and key material when they share the device
    ByteCount payloadSize = 0;   // whole sectors of sectorSize; 0 when headerOnly
    // The payload offset is 0 and the header was opened by itself: what cryptsetup writes for a detached
    // header (luksFormat --header), so this is a header file or backup, not a volume. info() and unlock()
    // work (the digest vouches for a key); openPayload() is OutOfRange, since decrypting the header's own
    // bytes would only produce garbage. Open it with Luks::open(header, data) to reach the payload.
    bool headerOnly = false;
    std::uint32_t sectorSize = 512;
    std::uint64_t ivTweak = 0;   // LUKS2 segment iv_tweak as stored: dm-crypt's iv_offset, in 512-byte sectors (a multiple of sectorSize / 512)
    std::string uuid, label;
    std::vector<LuksSlotInfo> slots;
    std::vector<std::string> flags;          // LUKS2 config.flags as stored ("allow-discards", "no-journal"...)
    std::vector<std::string> requirements;   // LUKS2 config.requirements.mandatory ("online-reencrypt"...): any entry makes the volume unsupported
    // LUKS2 keeps two copies of the binary header + JSON area, the second at hdr_size. Each copy is
    // checked (csum_alg over the binary header with the csum field zeroed, then the JSON area) and
    // the valid copy with the highest seqid is used, so a damaged primary opens from the secondary;
    // when the first 4 KiB are zeroed, overwritten or unreadable, the secondary is looked for at
    // every metadata size cryptsetup writes (16 KiB .. 4 MiB). LUKS1 has one header: headerCopyUsed 0 and both flags true.
    int headerCopyUsed = 0;      // 0 = primary, 1 = secondary
    bool primaryValid = true;
    bool secondaryValid = true;
    std::uint64_t headerSize = 0;   // LUKS2 hdr_size (binary header + JSON area, 16 KiB .. 4 MiB); 0 for LUKS1
    // The payload can be decrypted (cipher/mode, one plain crypt segment, no integrity, no mandatory
    // requirements, known flags) and at least one slot can be tried. unsupportedWhy says what is missing;
    // when only the slots are the problem it lists every slot's reason.
    bool supported = true;
    std::string unsupportedWhy;
};

// Hooks for a long unlock: `cancelled` is polled between Argon2 slices and between key slots.
struct UnlockOptions {
    std::function<bool()> cancelled;
};

class Luks {
public:
    static Expected<Luks> open(std::shared_ptr<BlockDevice> device);
    // Detached header (cryptsetup --header): header, key material and digest come from `header`, the
    // payload lives on `data`. The payload offset stored in the header (LUKS1 payload_offset, LUKS2
    // segment offset) is applied to the data device, exactly as dm-crypt does; cryptsetup writes 0
    // there when it formats with a detached header (unless --offset is given), so the payload normally
    // starts at byte 0 of `data`. open(device) is open(device, device).
    static Expected<Luks> open(std::shared_ptr<BlockDevice> header, std::shared_ptr<BlockDevice> data);
    const LuksInfo& info() const { return m_info; }

    // Try every usable slot, priority 2 first and 0 last. Integrity when every usable slot was tried and
    // none opens; Unsupported when no slot is usable (the message lists why); Cancelled from the hook.
    // Every intermediate (the derived area key, the decrypted key material, a rejected candidate key)
    // is wiped before its buffer is freed; the returned key is the caller's to wipe (stein/core/secure.hpp).
    Expected<std::vector<std::uint8_t>> unlock(const std::string& passphrase, const UnlockOptions& options = {}) const;
    // The payload as a device decrypting on read (and encrypting on write unless readOnly).
    Expected<std::shared_ptr<BlockDevice>> openPayload(std::span<const std::uint8_t> masterKey, bool readOnly = true) const;
    // Convenience: unlock + openPayload.
    Expected<std::shared_ptr<BlockDevice>> openPayload(const std::string& passphrase, bool readOnly = true, const UnlockOptions& options = {}) const;

private:
    struct Slot {
        int id = 0;
        int priority = 1;
        std::string kdf, hash;                 // kdf: pbkdf2|argon2id|argon2i ; hash: for pbkdf2
        std::uint32_t iterations = 0, time = 0, memoryKiB = 0, cpus = 0;
        std::vector<std::uint8_t> salt;
        std::uint32_t stripes = 4000;
        std::string afHash;
        ByteCount areaOffset = 0, areaSize = 0;
        std::uint32_t areaKeySize = 0;        // key bytes used to decrypt the area (LUKS2) / = keyBytes (LUKS1)
        crypto::CipherAlgorithm areaCipher = crypto::CipherAlgorithm::Aes;
    };
    struct Digest {
        std::string hash;
        std::uint32_t iterations = 0;
        std::vector<std::uint8_t> salt, digest;
    };
    struct HeaderCopy;
    static HeaderCopy readHeaderCopy(BlockDevice& dev, ByteCount at, bool secondary);
    Expected<void> parseV1(std::span<const std::byte> hdr);
    Expected<void> loadV2();
    Expected<void> parseV2(std::span<const std::byte> binary, std::string_view jsonText);
    Expected<std::vector<std::uint8_t>> trySlot(const Slot& slot, const std::string& passphrase, const UnlockOptions& options) const;
    bool digestMatches(std::span<const std::uint8_t> key) const;

    std::shared_ptr<BlockDevice> m_header, m_data;
    LuksInfo m_info;
    std::vector<Slot> m_slots;                 // the slots unlock() may try, in id order
    Digest m_digest;
    crypto::CipherAlgorithm m_cipher = crypto::CipherAlgorithm::Aes;
    bool m_payloadSupported = true;            // the segment itself (independent of the slots)
};

// Anti-forensic merge (LUKS1 AFmerge): `src` holds `stripes` blocks of `blockSize` bytes.
Expected<std::vector<std::uint8_t>> afMerge(std::span<const std::uint8_t> src, std::size_t blockSize, std::uint32_t stripes, const std::string& hash);

// cryptsetup's cipher spec split in two (LUKS1 cipher_name + cipher_mode, LUKS2 "encryption" at its
// first '-'): the block cipher we run XTS with, or Unsupported saying why (cbc-essiv, plain64be,
// 32-bit plain, capi: notation, ciphers the crypto core lacks).
Expected<crypto::CipherAlgorithm> luksCipher(const std::string& cipher, const std::string& mode);
// LUKS hash names ("sha256", "sha1", "sha512", "ripemd160", "whirlpool") to our Hasher; nullopt otherwise.
std::optional<HashAlgorithm> luksHash(const std::string& name);

} // namespace stein::container
