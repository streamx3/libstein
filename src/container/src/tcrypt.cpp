// SPDX-License-Identifier: MIT
#include "stein/container/tcrypt.hpp"
#include "xts_device.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/crypto.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"

#include <algorithm>
#include <cstring>

namespace stein::container {

namespace {
constexpr ByteCount kHeaderSize = 512, kSaltSize = 64, kHiddenHeaderOffset = 65536, kBackupAreaSize = 131072;
constexpr std::size_t kEncryptedHeaderSize = kHeaderSize - kSaltSize;   // 448 bytes
constexpr std::uint32_t kFlagSystemEncryption = 0x1;

struct Candidate {
    const char* variant;
    const char* magic;
    HashAlgorithm prf;
    const char* prfName;
    std::uint32_t iterations;
};

std::uint32_t veracryptIterations(std::uint32_t pim) { return pim == 0 ? 500000 : 15000 + pim * 1000; }

std::vector<Candidate> candidates(const TcryptOptions& o) {
    std::vector<Candidate> c;
    // Cheapest first: a TrueCrypt trial costs 1000 iterations, a VeraCrypt one up to 500000.
    if (o.truecrypt) c.push_back({"TrueCrypt", "TRUE", HashAlgorithm::Sha512, "sha512", 1000});
    if (o.veracrypt) {
        c.push_back({"VeraCrypt", "VERA", HashAlgorithm::Sha512, "sha512", veracryptIterations(o.pim)});
        c.push_back({"VeraCrypt", "VERA", HashAlgorithm::Sha256, "sha256", veracryptIterations(o.pim)});
    }
    return c;
}

std::span<const std::byte> bytesOf(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
} // namespace

Expected<Tcrypt> Tcrypt::unlock(std::shared_ptr<BlockDevice> device, const std::string& passphrase, const TcryptOptions& options) {
    const ByteCount size = device->size();
    if (size < 2 * kBackupAreaSize) return fail(ErrorCategory::InvalidFormat, "device too small for a VeraCrypt/TrueCrypt volume");
    struct Location {
        ByteCount offset;
        bool hidden, backup;
    };
    std::vector<Location> locations{{0, false, false}};
    if (options.hidden) locations.push_back({kHiddenHeaderOffset, true, false});
    if (options.backupHeaders) {
        locations.push_back({size - kBackupAreaSize, false, true});
        if (options.hidden) locations.push_back({size - kHiddenHeaderOffset, true, true});
    }
    const auto cands = candidates(options);
    if (cands.empty()) return fail(ErrorCategory::InvalidArgument, "no header variant enabled");
    for (const auto& loc : locations) {
        auto raw = device->read(loc.offset, kHeaderSize);
        if (!raw) return fail(raw.error());
        const std::span<const std::byte> salt(raw->data(), kSaltSize);
        const std::span<const std::byte> cipher(raw->data() + kSaltSize, kEncryptedHeaderSize);
        bool allZero = std::all_of(raw->begin(), raw->end(), [](std::byte b) { return b == std::byte{0}; });
        if (allZero) continue;   // nothing was ever written here (no hidden volume, for instance)
        for (const auto& c : cands) {
            std::vector<std::uint8_t> headerKey(64);
            crypto::pbkdf2(c.prf, bytesOf(passphrase), salt, c.iterations, headerKey);
            auto xts = crypto::AesXts::create(headerKey);
            if (!xts) return fail(xts.error());
            std::vector<std::byte> plain(kEncryptedHeaderSize);
            if (auto d = xts->decrypt(0, cipher, plain); !d) return fail(d.error());
            if (std::memcmp(plain.data(), c.magic, 4) != 0) continue;
            // Header CRC over bytes 64..251 of the header = plain[0..188), stored big-endian at plain[188].
            if (Crc32::compute(std::span<const std::byte>(plain.data(), 188)) != loadBe32(plain.data() + 188)) continue;
            const std::span<const std::byte> keys(plain.data() + 192, 256);
            if (Crc32::compute(keys) != loadBe32(plain.data() + 8)) continue;
            Tcrypt t;
            t.m_device = device;
            t.m_info.variant = c.variant;
            t.m_info.prf = c.prfName;
            t.m_info.iterations = c.iterations;
            t.m_info.headerVersion = loadBe16(plain.data() + 4);
            t.m_info.minProgramVersion = loadBe16(plain.data() + 6);
            const std::uint64_t hiddenSize = loadBe64(plain.data() + 28);
            t.m_info.payloadSize = loadBe64(plain.data() + 36);
            t.m_info.payloadOffset = loadBe64(plain.data() + 44);
            t.m_info.flags = loadBe32(plain.data() + 60);
            t.m_info.sectorSize = loadBe32(plain.data() + 64);
            t.m_info.hidden = loc.hidden || hiddenSize != 0;
            t.m_info.backupHeader = loc.backup;
            t.m_info.headerOffset = loc.offset;
            if (t.m_info.flags & kFlagSystemEncryption) return fail(ErrorCategory::Unsupported, "system-encryption volumes are not supported");
            if (t.m_info.sectorSize == 0) t.m_info.sectorSize = 512;
            if (t.m_info.headerVersion < 4) {
                // Legacy TrueCrypt (< 6.0): no area start/size fields; data follows the header area.
                t.m_info.payloadOffset = kBackupAreaSize;
                t.m_info.payloadSize = size - 2 * kBackupAreaSize;
            }
            if (t.m_info.payloadOffset + t.m_info.payloadSize > size || t.m_info.payloadSize == 0)
                return fail(ErrorCategory::InvalidFormat, "decrypted header describes a data area outside the device");
            t.m_masterKey.assign(reinterpret_cast<const std::uint8_t*>(plain.data() + 192), reinterpret_cast<const std::uint8_t*>(plain.data() + 192 + 64));
            return t;
        }
    }
    return fail(ErrorCategory::Integrity, "no VeraCrypt/TrueCrypt header opens with this passphrase (wrong passphrase or PIM, or a cipher/PRF other than AES-XTS with SHA-512/SHA-256)");
}

Expected<std::shared_ptr<BlockDevice>> Tcrypt::openPayload(bool readOnly) const {
    auto xts = crypto::AesXts::create(m_masterKey);
    if (!xts) return fail(xts.error());
    // XTS data units are always 512 bytes and numbered from the start of the container.
    return std::shared_ptr<BlockDevice>(std::make_shared<detail::XtsDevice>(m_device, Region{m_info.payloadOffset, m_info.payloadSize}, 512, m_info.payloadOffset / 512, std::move(*xts), readOnly,
                                                                            m_info.variant == "TrueCrypt" ? "truecrypt" : "veracrypt"));
}

} // namespace stein::container
