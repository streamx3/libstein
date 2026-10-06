// SPDX-License-Identifier: MIT
// VeraCrypt / TrueCrypt volumes ("tcrypt", the cryptsetup name). There is no
// signature on disk: a header is found by trial decryption with the
// passphrase, so open() needs it. Supported: every XTS cipher and cascade of
// VeraCrypt 1.26 (AES, Serpent, Twofish, Camellia, Kuznyechik and their ten
// cascades) and TrueCrypt 7 (AES, Serpent, Twofish and their five cascades),
// every PRF (SHA-512, SHA-256, BLAKE2s-256, RIPEMD-160, Whirlpool,
// Streebog-512; with PIM), normal and hidden volumes, primary and backup
// headers. System encryption and the legacy TrueCrypt 4 ciphers/modes are
// reported, not opened.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/cipher.hpp"
#include "stein/core/error.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace stein::container {

struct TcryptOptions {
    std::uint32_t pim = 0;          // VeraCrypt Personal Iterations Multiplier (0 = default count)
    bool veracrypt = true;          // try VeraCrypt headers
    bool truecrypt = true;          // try TrueCrypt headers too
    bool hidden = true;             // try the hidden-volume header locations
    bool backupHeaders = true;      // fall back to the backup headers at the end of the volume
    std::string prf;                // restrict the trial to one PRF ("sha512", "whirlpool", ...); empty = try all
};

struct TcryptInfo {
    std::string variant;            // "VeraCrypt" / "TrueCrypt"
    std::string prf;                // "sha512", "sha256", "blake2s", "ripemd160", "whirlpool", "streebog"
    std::string cipher = "aes-xts-plain64";   // cryptsetup's spelling: "serpent-twofish-aes-xts-plain64" for a cascade
    std::vector<crypto::CipherAlgorithm> cascade{crypto::CipherAlgorithm::Aes};   // XTS layers in VeraCrypt table order
    std::uint32_t iterations = 0;
    std::uint16_t headerVersion = 0, minProgramVersion = 0;
    ByteCount payloadOffset = 0;    // data area start inside the container
    ByteCount payloadSize = 0;
    std::uint32_t sectorSize = 512;
    std::uint32_t flags = 0;
    bool hidden = false;            // opened through the hidden-volume header
    bool backupHeader = false;      // the primary header was unusable; the backup copy opened it
    ByteCount headerOffset = 0;
};

class Tcrypt {
public:
    static Expected<Tcrypt> unlock(std::shared_ptr<BlockDevice> device, const std::string& passphrase, const TcryptOptions& options = {});
    const TcryptInfo& info() const { return m_info; }
    const std::vector<std::uint8_t>& masterKey() const { return m_masterKey; }   // 64 bytes per cascade layer
    // Names of the supported PRFs and encryption algorithms, for help text and option validation.
    static std::vector<std::string> prfNames();
    static std::vector<std::string> cipherNames();
    Expected<std::shared_ptr<BlockDevice>> openPayload(bool readOnly = true) const;

private:
    std::shared_ptr<BlockDevice> m_device;
    TcryptInfo m_info;
    std::vector<std::uint8_t> m_masterKey;
};

} // namespace stein::container
