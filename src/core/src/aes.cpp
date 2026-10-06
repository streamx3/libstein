// SPDX-License-Identifier: MIT
#include "stein/core/aes.hpp"

#include "aes_impl.hpp"
#include "stein/core/endian.hpp"

#include <cstring>

namespace stein::crypto {

namespace {

constexpr std::uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

struct InvSbox {
    std::uint8_t t[256];
    InvSbox() {
        for (int i = 0; i < 256; ++i) t[kSbox[i]] = static_cast<std::uint8_t>(i);
    }
};
const InvSbox& invSbox() {
    static const InvSbox s;
    return s;
}

inline std::uint8_t xtime(std::uint8_t x) { return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
inline std::uint8_t mul(std::uint8_t a, std::uint8_t b) {
    std::uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

inline std::uint32_t subWord(std::uint32_t w) {
    return (std::uint32_t{kSbox[(w >> 24) & 0xFF]} << 24) | (std::uint32_t{kSbox[(w >> 16) & 0xFF]} << 16) | (std::uint32_t{kSbox[(w >> 8) & 0xFF]} << 8) | kSbox[w & 0xFF];
}
inline std::uint32_t rotWord(std::uint32_t w) { return (w << 8) | (w >> 24); }

} // namespace

namespace detail {

// Round keys are stored as big-endian words (FIPS-197 column order).
void aesEncryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    std::uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ static_cast<std::uint8_t>(rk[i / 4] >> (24 - 8 * (i % 4)));
    for (unsigned r = 1; r <= rounds; ++r) {
        std::uint8_t t[16];
        // SubBytes + ShiftRows
        for (int c = 0; c < 4; ++c)
            for (int row = 0; row < 4; ++row) t[4 * c + row] = kSbox[s[4 * ((c + row) % 4) + row]];
        // MixColumns (not in the last round)
        if (r != rounds) {
            for (int c = 0; c < 4; ++c) {
                const std::uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                t[4 * c] = static_cast<std::uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
                t[4 * c + 1] = static_cast<std::uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
                t[4 * c + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
                t[4 * c + 3] = static_cast<std::uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            }
        }
        for (int i = 0; i < 16; ++i) s[i] = t[i] ^ static_cast<std::uint8_t>(rk[4 * r + i / 4] >> (24 - 8 * (i % 4)));
    }
    std::memcpy(out, s, 16);
}

void aesDecryptPortable(const std::uint32_t* rk, unsigned rounds, const std::uint8_t in[16], std::uint8_t out[16]) {
    const auto& inv = invSbox();
    std::uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ static_cast<std::uint8_t>(rk[4 * rounds + i / 4] >> (24 - 8 * (i % 4)));
    for (unsigned r = rounds; r-- > 0;) {
        std::uint8_t t[16];
        // InvShiftRows + InvSubBytes
        for (int c = 0; c < 4; ++c)
            for (int row = 0; row < 4; ++row) t[4 * ((c + row) % 4) + row] = inv.t[s[4 * c + row]];
        for (int i = 0; i < 16; ++i) t[i] ^= static_cast<std::uint8_t>(rk[4 * r + i / 4] >> (24 - 8 * (i % 4)));
        if (r != 0) {
            for (int c = 0; c < 4; ++c) {
                const std::uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                t[4 * c] = static_cast<std::uint8_t>(mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9));
                t[4 * c + 1] = static_cast<std::uint8_t>(mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13));
                t[4 * c + 2] = static_cast<std::uint8_t>(mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11));
                t[4 * c + 3] = static_cast<std::uint8_t>(mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14));
            }
        }
        std::memcpy(s, t, 16);
    }
    std::memcpy(out, s, 16);
}

} // namespace detail

Expected<Aes> Aes::create(std::span<const std::uint8_t> key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) return fail(ErrorCategory::InvalidArgument, "AES key must be 16, 24 or 32 bytes");
    Aes a;
    const unsigned nk = static_cast<unsigned>(key.size() / 4);
    a.m_rounds = nk + 6;
    const unsigned total = 4 * (a.m_rounds + 1);
    for (unsigned i = 0; i < nk; ++i) a.m_rk[i] = loadBe32(reinterpret_cast<const std::byte*>(key.data()) + 4 * i);
    std::uint32_t rcon = 1;
    for (unsigned i = nk; i < total; ++i) {
        std::uint32_t t = a.m_rk[i - 1];
        if (i % nk == 0) {
            t = subWord(rotWord(t)) ^ (rcon << 24);
            rcon = xtime(static_cast<std::uint8_t>(rcon));
        } else if (nk > 6 && i % nk == 4) {
            t = subWord(t);
        }
        a.m_rk[i] = a.m_rk[i - nk] ^ t;
    }
    return a;
}

void Aes::encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    static const bool hw = detail::aesHardware();
    if (hw) detail::aesEncryptHardware(m_rk.data(), m_rounds, in, out);
    else detail::aesEncryptPortable(m_rk.data(), m_rounds, in, out);
}

void Aes::decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
    static const bool hw = detail::aesHardware();
    if (hw) detail::aesDecryptHardware(m_rk.data(), m_rounds, in, out);
    else detail::aesDecryptPortable(m_rk.data(), m_rounds, in, out);
}

bool aesHardwareAvailable() { return detail::aesHardware(); }

// ----------------------------------------------------------------------------- XTS

Expected<AesXts> AesXts::create(std::span<const std::uint8_t> key) {
    if (key.size() != 32 && key.size() != 64) return fail(ErrorCategory::InvalidArgument, "AES-XTS key must be 32 or 64 bytes (two AES keys)");
    const std::size_t half = key.size() / 2;
    if (std::memcmp(key.data(), key.data() + half, half) == 0) return fail(ErrorCategory::InvalidArgument, "AES-XTS keys must differ");
    auto k1 = Aes::create(key.first(half));
    auto k2 = Aes::create(key.subspan(half));
    if (!k1) return fail(k1.error());
    if (!k2) return fail(k2.error());
    AesXts x;
    x.m_data = *k1;
    x.m_tweak = *k2;
    return x;
}

namespace {
inline void gfMul(std::uint8_t t[16]) {
    std::uint8_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        const std::uint8_t c = t[i] >> 7;
        t[i] = static_cast<std::uint8_t>((t[i] << 1) | carry);
        carry = c;
    }
    if (carry) t[0] ^= 0x87;
}
} // namespace

Expected<void> AesXts::encrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    std::uint8_t tweak[16] = {}, t[16];
    storeLe64(reinterpret_cast<std::byte*>(tweak), sector);
    m_tweak.encryptBlock(tweak, t);
    for (std::size_t off = 0; off < in.size(); off += 16) {
        std::uint8_t x[16], y[16];
        for (int i = 0; i < 16; ++i) x[i] = std::to_integer<std::uint8_t>(in[off + i]) ^ t[i];
        m_data.encryptBlock(x, y);
        for (int i = 0; i < 16; ++i) out[off + i] = std::byte(y[i] ^ t[i]);
        gfMul(t);
    }
    return {};
}

Expected<void> AesXts::decrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    std::uint8_t tweak[16] = {}, t[16];
    storeLe64(reinterpret_cast<std::byte*>(tweak), sector);
    m_tweak.encryptBlock(tweak, t);
    for (std::size_t off = 0; off < in.size(); off += 16) {
        std::uint8_t x[16], y[16];
        for (int i = 0; i < 16; ++i) x[i] = std::to_integer<std::uint8_t>(in[off + i]) ^ t[i];
        m_data.decryptBlock(x, y);
        for (int i = 0; i < 16; ++i) out[off + i] = std::byte(y[i] ^ t[i]);
        gfMul(t);
    }
    return {};
}

Expected<void> AesXts::encryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (sectorSize % 16 || in.size() % sectorSize) return fail(ErrorCategory::InvalidArgument, "data must be whole sectors");
    for (std::size_t off = 0; off < in.size(); off += sectorSize)
        if (auto r = encrypt(firstSector + off / sectorSize, in.subspan(off, sectorSize), out.subspan(off, sectorSize)); !r) return r;
    return {};
}

Expected<void> AesXts::decryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (sectorSize % 16 || in.size() % sectorSize) return fail(ErrorCategory::InvalidArgument, "data must be whole sectors");
    for (std::size_t off = 0; off < in.size(); off += sectorSize)
        if (auto r = decrypt(firstSector + off / sectorSize, in.subspan(off, sectorSize), out.subspan(off, sectorSize)); !r) return r;
    return {};
}

} // namespace stein::crypto
