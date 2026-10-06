// SPDX-License-Identifier: MIT
#include "stein/core/cipher.hpp"

#include "stein/core/aes.hpp"
#include "stein/core/endian.hpp"

#include <cstring>

namespace stein::crypto {

std::string_view toString(CipherAlgorithm c) {
    switch (c) {
    case CipherAlgorithm::Aes: return "aes";
    case CipherAlgorithm::Serpent: return "serpent";
    case CipherAlgorithm::Twofish: return "twofish";
    case CipherAlgorithm::Camellia: return "camellia";
    case CipherAlgorithm::Kuznyechik: return "kuznyechik";
    }
    return "?";
}

std::optional<CipherAlgorithm> cipherFromString(std::string_view s) {
    if (s == "aes") return CipherAlgorithm::Aes;
    if (s == "serpent") return CipherAlgorithm::Serpent;
    if (s == "twofish") return CipherAlgorithm::Twofish;
    if (s == "camellia") return CipherAlgorithm::Camellia;
    if (s == "kuznyechik") return CipherAlgorithm::Kuznyechik;
    return std::nullopt;
}

namespace {

class AesBlock final : public BlockCipher {
public:
    explicit AesBlock(Aes aes) : m_aes(std::move(aes)) {}
    CipherAlgorithm algorithm() const override { return CipherAlgorithm::Aes; }
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override { m_aes.encryptBlock(in, out); }
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override { m_aes.decryptBlock(in, out); }

private:
    Aes m_aes;
};

template <class C>
Expected<std::unique_ptr<BlockCipher>> make(std::span<const std::uint8_t> key) {
    auto c = C::create(key);
    if (!c) return fail(c.error());
    return std::unique_ptr<BlockCipher>(std::make_unique<C>(std::move(*c)));
}

inline void gfMulTweak(std::uint8_t t[16]) {
    std::uint8_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        const std::uint8_t c = t[i] >> 7;
        t[i] = static_cast<std::uint8_t>((t[i] << 1) | carry);
        carry = c;
    }
    if (carry) t[0] ^= 0x87;
}

} // namespace

Expected<std::unique_ptr<BlockCipher>> BlockCipher::create(CipherAlgorithm algorithm, std::span<const std::uint8_t> key) {
    switch (algorithm) {
    case CipherAlgorithm::Aes: {
        auto a = Aes::create(key);
        if (!a) return fail(a.error());
        return std::unique_ptr<BlockCipher>(std::make_unique<AesBlock>(std::move(*a)));
    }
    case CipherAlgorithm::Serpent: return make<Serpent>(key);
    case CipherAlgorithm::Twofish: return make<Twofish>(key);
    case CipherAlgorithm::Camellia: return make<Camellia>(key);
    case CipherAlgorithm::Kuznyechik: return make<Kuznyechik>(key);
    }
    return fail(ErrorCategory::InvalidArgument, "unknown block cipher");
}

Expected<Xts> Xts::create(CipherAlgorithm cipher, std::span<const std::uint8_t> key) {
    const CipherAlgorithm one[1] = {cipher};
    return create(one, key);
}

Expected<Xts> Xts::create(std::span<const CipherAlgorithm> cascade, std::span<const std::uint8_t> key) {
    if (cascade.empty() || cascade.size() > 3) return fail(ErrorCategory::InvalidArgument, "XTS cascade must have one to three ciphers");
    std::size_t per = 32;
    if (cascade.size() == 1 && key.size() == 32) {
        if (cascade[0] != CipherAlgorithm::Aes) return fail(ErrorCategory::InvalidArgument, std::string(toString(cascade[0])) + "-XTS needs a 64-byte key (two 256-bit keys)");
        per = 16;   // AES-128 XTS (LUKS aes-xts-plain64 with a 256-bit master key)
    } else if (key.size() != cascade.size() * 64) {
        return fail(ErrorCategory::InvalidArgument, "XTS key must be 64 bytes per cipher (primary keys, then tweak keys)");
    }
    Xts x;
    const std::size_t secondary = per * cascade.size();
    for (std::size_t i = 0; i < cascade.size(); ++i) {
        const auto k1 = key.subspan(per * i, per), k2 = key.subspan(secondary + per * i, per);
        if (std::memcmp(k1.data(), k2.data(), per) == 0) return fail(ErrorCategory::InvalidArgument, "XTS data and tweak keys must differ");
        auto data = BlockCipher::create(cascade[i], k1);
        if (!data) return fail(data.error());
        auto tweak = BlockCipher::create(cascade[i], k2);
        if (!tweak) return fail(tweak.error());
        x.m_layers.push_back(Layer{std::move(*data), std::move(*tweak)});
    }
    return x;
}

std::vector<CipherAlgorithm> Xts::cascade() const {
    std::vector<CipherAlgorithm> v;
    for (const auto& l : m_layers) v.push_back(l.data->algorithm());
    return v;
}

void Xts::layerEncrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) {
    std::uint8_t tweak[16] = {}, t[16];
    storeLe64(reinterpret_cast<std::byte*>(tweak), sector);
    l.tweak->encryptBlock(tweak, t);
    for (std::size_t off = 0; off < in.size(); off += 16) {
        std::uint8_t x[16], y[16];
        for (int i = 0; i < 16; ++i) x[i] = std::to_integer<std::uint8_t>(in[off + i]) ^ t[i];
        l.data->encryptBlock(x, y);
        for (int i = 0; i < 16; ++i) out[off + i] = std::byte(y[i] ^ t[i]);
        gfMulTweak(t);
    }
}

void Xts::layerDecrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) {
    std::uint8_t tweak[16] = {}, t[16];
    storeLe64(reinterpret_cast<std::byte*>(tweak), sector);
    l.tweak->encryptBlock(tweak, t);
    for (std::size_t off = 0; off < in.size(); off += 16) {
        std::uint8_t x[16], y[16];
        for (int i = 0; i < 16; ++i) x[i] = std::to_integer<std::uint8_t>(in[off + i]) ^ t[i];
        l.data->decryptBlock(x, y);
        for (int i = 0; i < 16; ++i) out[off + i] = std::byte(y[i] ^ t[i]);
        gfMulTweak(t);
    }
}

Expected<void> Xts::encrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    // Last layer first (VeraCrypt: "AES-Twofish" encrypts with Twofish, then AES).
    for (std::size_t i = m_layers.size(); i-- > 0;) {
        layerEncrypt(m_layers[i], sector, in, out);
        in = out.first(in.size());
    }
    return {};
}

Expected<void> Xts::decrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    for (const auto& layer : m_layers) {
        layerDecrypt(layer, sector, in, out);
        in = out.first(in.size());
    }
    return {};
}

Expected<void> Xts::encryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (sectorSize % 16 || in.size() % sectorSize) return fail(ErrorCategory::InvalidArgument, "data must be whole sectors");
    for (std::size_t off = 0; off < in.size(); off += sectorSize)
        if (auto r = encrypt(firstSector + off / sectorSize, in.subspan(off, sectorSize), out.subspan(off, sectorSize)); !r) return r;
    return {};
}

Expected<void> Xts::decryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (sectorSize % 16 || in.size() % sectorSize) return fail(ErrorCategory::InvalidArgument, "data must be whole sectors");
    for (std::size_t off = 0; off < in.size(); off += sectorSize)
        if (auto r = decrypt(firstSector + off / sectorSize, in.subspan(off, sectorSize), out.subspan(off, sectorSize)); !r) return r;
    return {};
}

} // namespace stein::crypto
