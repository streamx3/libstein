// SPDX-License-Identifier: MIT
#include "stein/container/tcrypt.hpp"
#include "xts_device.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/crypto.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>

namespace stein::container {

namespace {
constexpr ByteCount kHeaderSize = 512, kSaltSize = 64, kHiddenHeaderOffset = 65536, kBackupAreaSize = 131072;
constexpr std::size_t kEncryptedHeaderSize = kHeaderSize - kSaltSize;   // 448 bytes
constexpr std::size_t kMaxHeaderKey = 192;                               // three ciphers, primary and tweak keys
constexpr std::uint32_t kFlagSystemEncryption = 0x1;

struct Candidate {
    const char* variant;
    const char* magic;
    HashAlgorithm prf;
    const char* prfName;
    std::uint32_t iterations;
};

std::uint32_t veracryptIterations(std::uint32_t pim, HashAlgorithm prf) {
    if (pim != 0) return 15000 + pim * 1000;
    return prf == HashAlgorithm::Ripemd160 ? 655331 : 500000;   // VeraCrypt defaults for non-system volumes
}

std::vector<Candidate> candidates(const TcryptOptions& o) {
    std::vector<Candidate> c;
    // Cheapest first: TrueCrypt trials cost 1000-2000 iterations, VeraCrypt ones up to 655331.
    if (o.truecrypt) {
        c.push_back({"TrueCrypt", "TRUE", HashAlgorithm::Ripemd160, "ripemd160", 2000});   // TrueCrypt's default PRF
        c.push_back({"TrueCrypt", "TRUE", HashAlgorithm::Sha512, "sha512", 1000});
        c.push_back({"TrueCrypt", "TRUE", HashAlgorithm::Whirlpool, "whirlpool", 1000});
    }
    if (o.veracrypt) {
        using H = HashAlgorithm;
        for (auto [h, name] : {std::pair{H::Sha512, "sha512"}, std::pair{H::Sha256, "sha256"}, std::pair{H::Blake2s256, "blake2s"}, std::pair{H::Whirlpool, "whirlpool"},
                               std::pair{H::Ripemd160, "ripemd160"}, std::pair{H::Streebog512, "streebog"}})
            c.push_back({"VeraCrypt", "VERA", h, name, veracryptIterations(o.pim, h)});
    }
    if (!o.prf.empty()) std::erase_if(c, [&](const Candidate& x) { return o.prf != x.prfName; });
    return c;
}

// Encryption algorithms in VeraCrypt's table order; the key material lists the layers in this order.
struct Ea {
    const char* name;
    std::vector<crypto::CipherAlgorithm> ciphers;
    bool truecrypt;   // also valid in TrueCrypt 7 volumes
};

const std::vector<Ea>& encryptionAlgorithms() {
    using C = crypto::CipherAlgorithm;
    static const std::vector<Ea> eas = {
        {"aes", {C::Aes}, true},
        {"serpent", {C::Serpent}, true},
        {"twofish", {C::Twofish}, true},
        {"camellia", {C::Camellia}, false},
        {"kuznyechik", {C::Kuznyechik}, false},
        {"aes-twofish", {C::Aes, C::Twofish}, true},
        {"aes-twofish-serpent", {C::Aes, C::Twofish, C::Serpent}, true},
        {"camellia-kuznyechik", {C::Camellia, C::Kuznyechik}, false},
        {"camellia-serpent", {C::Camellia, C::Serpent}, false},
        {"kuznyechik-aes", {C::Kuznyechik, C::Aes}, false},
        {"kuznyechik-serpent-camellia", {C::Kuznyechik, C::Serpent, C::Camellia}, false},
        {"kuznyechik-twofish", {C::Kuznyechik, C::Twofish}, false},
        {"serpent-aes", {C::Serpent, C::Aes}, true},
        {"serpent-twofish-aes", {C::Serpent, C::Twofish, C::Aes}, true},
        {"twofish-serpent", {C::Twofish, C::Serpent}, true},
    };
    return eas;
}

std::span<const std::byte> bytesOf(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

// Decrypt the header with one algorithm's share of the derived key and check magic and CRCs.
bool tryHeader(const Ea& ea, std::span<const std::uint8_t> derived, std::span<const std::byte> cipher, const char* magic, std::vector<std::byte>& plain) {
    const std::size_t n = ea.ciphers.size();
    std::vector<std::uint8_t> key(64 * n);
    std::copy_n(derived.begin(), 32 * n, key.begin());                        // primary keys
    std::copy_n(derived.begin() + static_cast<std::ptrdiff_t>(32 * n), 32 * n, key.begin() + static_cast<std::ptrdiff_t>(32 * n));   // tweak keys
    auto xts = crypto::Xts::create(ea.ciphers, key);
    if (!xts) return false;   // equal halves and the like: cannot be this algorithm
    plain.assign(kEncryptedHeaderSize, std::byte{0});
    if (!xts->decrypt(0, cipher, plain)) return false;
    if (std::memcmp(plain.data(), magic, 4) != 0) return false;
    // Header CRC over bytes 64..251 of the header = plain[0..188), stored big-endian at plain[188].
    if (Crc32::compute(std::span<const std::byte>(plain.data(), 188)) != loadBe32(plain.data() + 188)) return false;
    return Crc32::compute(std::span<const std::byte>(plain.data() + 192, 256)) == loadBe32(plain.data() + 8);
}
} // namespace

std::vector<std::string> Tcrypt::prfNames() { return {"sha512", "sha256", "blake2s", "ripemd160", "whirlpool", "streebog"}; }

std::vector<std::string> Tcrypt::cipherNames() {
    std::vector<std::string> v;
    for (const auto& ea : encryptionAlgorithms()) v.emplace_back(ea.name);
    return v;
}

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
    if (cands.empty()) {
        if (!options.prf.empty()) return fail(ErrorCategory::InvalidArgument, "unknown PRF \"" + options.prf + "\" (sha512, sha256, blake2s, ripemd160, whirlpool, streebog)");
        return fail(ErrorCategory::InvalidArgument, "no header variant enabled");
    }
    const auto& eas = encryptionAlgorithms();
    for (const auto& loc : locations) {
        auto raw = device->read(loc.offset, kHeaderSize);
        if (!raw) return fail(raw.error());
        const std::span<const std::byte> salt(raw->data(), kSaltSize);
        const std::span<const std::byte> cipher(raw->data() + kSaltSize, kEncryptedHeaderSize);
        bool allZero = std::all_of(raw->begin(), raw->end(), [](std::byte b) { return b == std::byte{0}; });
        if (allZero) continue;   // nothing was ever written here (no hidden volume, for instance)
        for (const auto& c : cands) {
            const bool vera = std::string_view(c.magic) == "VERA";
            // The PBKDF2 output is independent per block, so derive the 64 bytes every single-cipher
            // algorithm needs, and the remaining 128 only when no single cipher opens the header.
            std::vector<std::uint8_t> derived(kMaxHeaderKey);
            crypto::pbkdf2Range(c.prf, bytesOf(passphrase), salt, c.iterations, 0, std::span<std::uint8_t>(derived).first(64));
            bool extended = false;
            std::vector<std::byte> plain;
            const Ea* found = nullptr;
            for (int pass = 0; pass < 2 && !found; ++pass) {
                for (const auto& ea : eas) {
                    const bool cascade = ea.ciphers.size() > 1;
                    if (cascade != (pass == 1)) continue;
                    if (!vera && !ea.truecrypt) continue;
                    if (cascade && !extended) {
                        crypto::pbkdf2Range(c.prf, bytesOf(passphrase), salt, c.iterations, 64, std::span<std::uint8_t>(derived).subspan(64));
                        extended = true;
                    }
                    if (tryHeader(ea, derived, cipher, c.magic, plain)) {
                        found = &ea;
                        break;
                    }
                }
            }
            if (!found) continue;
            Tcrypt t;
            t.m_device = device;
            t.m_info.variant = c.variant;
            t.m_info.prf = c.prfName;
            t.m_info.iterations = c.iterations;
            t.m_info.cipher = std::string(found->name) + "-xts-plain64";
            t.m_info.cascade = found->ciphers;
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
            const std::size_t keyBytes = 64 * found->ciphers.size();
            t.m_masterKey.assign(reinterpret_cast<const std::uint8_t*>(plain.data() + 192), reinterpret_cast<const std::uint8_t*>(plain.data() + 192 + keyBytes));
            return t;
        }
    }
    return fail(ErrorCategory::Integrity, "no VeraCrypt/TrueCrypt header opens with this passphrase (wrong passphrase or PIM; system encryption and TrueCrypt 4 ciphers are not supported)");
}

Expected<std::shared_ptr<BlockDevice>> Tcrypt::openPayload(bool readOnly) const {
    auto xts = crypto::Xts::create(m_info.cascade, m_masterKey);
    if (!xts) return fail(xts.error());
    // XTS data units are always 512 bytes and numbered from the start of the container.
    return std::shared_ptr<BlockDevice>(std::make_shared<detail::XtsDevice>(m_device, Region{m_info.payloadOffset, m_info.payloadSize}, 512, m_info.payloadOffset / 512, std::move(*xts), readOnly,
                                                                            m_info.variant == "TrueCrypt" ? "truecrypt" : "veracrypt"));
}

} // namespace stein::container
