// SPDX-License-Identifier: MIT
#include "stein/core/cipher.hpp"

#include "aes_impl.hpp"
#include "stein/core/aes.hpp"
#include "stein/core/endian.hpp"

#include <algorithm>
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
    const Aes& aes() const { return m_aes; }

private:
    Aes m_aes;
};

template <class C>
Expected<std::unique_ptr<BlockCipher>> make(std::span<const std::uint8_t> key) {
    auto c = C::create(key);
    if (!c) return fail(c.error());
    return std::unique_ptr<BlockCipher>(std::make_unique<C>(std::move(*c)));
}

using detail::XtsTweak;
inline void xorTweak(const std::byte* in, const XtsTweak& t, std::uint8_t out[16]) {
    const std::uint64_t a = loadLe64(in) ^ t.lo, b = loadLe64(in + 8) ^ t.hi;
    storeLe64(reinterpret_cast<std::byte*>(out), a);
    storeLe64(reinterpret_cast<std::byte*>(out + 8), b);
}
inline void xorTweak(const std::uint8_t in[16], const XtsTweak& t, std::byte* out) {
    const std::uint64_t a = loadLe64(reinterpret_cast<const std::byte*>(in)) ^ t.lo, b = loadLe64(reinterpret_cast<const std::byte*>(in + 8)) ^ t.hi;
    storeLe64(out, a);
    storeLe64(out + 8, b);
}

// E_K2(sector) as the little-endian plain64 tweak of the data unit's first block.
inline void firstTweak(const BlockCipher& tweakCipher, std::uint64_t sector, std::uint8_t out[16]) {
    std::uint8_t tweakIn[16] = {};
    storeLe64(reinterpret_cast<std::byte*>(tweakIn), sector);
    tweakCipher.encryptBlock(tweakIn, out);
}

// Generic layer: any BlockCipher, one virtual call per block (cascades, non-AES ciphers).
template <bool Encrypt>
inline void xtsLayer(const BlockCipher& data, const BlockCipher& tweakCipher, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) {
    std::uint8_t tweakOut[16];
    firstTweak(tweakCipher, sector, tweakOut);
    XtsTweak t = detail::xtsTweakLoad(tweakOut);
    for (std::size_t off = 0; off < in.size(); off += 16) {
        std::uint8_t x[16], y[16];
        xorTweak(in.data() + off, t, x);
        if constexpr (Encrypt) data.encryptBlock(x, y);
        else data.decryptBlock(x, y);
        xorTweak(y, t, out.data() + off);
        detail::xtsTweakDouble(t);
    }
}

// Single AES layer: the hardware kernel takes the whole data unit; without hardware AES the
// portable kernel still runs eight blocks per step on precomputed tweaks, no virtual call per block.
template <bool Encrypt>
inline void xtsAesLayer(const Aes& data, const BlockCipher& tweakCipher, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) {
    std::uint8_t tweakOut[16];
    firstTweak(tweakCipher, sector, tweakOut);
    const auto* src = reinterpret_cast<const std::uint8_t*>(in.data());
    auto* dst = reinterpret_cast<std::uint8_t*>(out.data());
    const std::size_t blocks = in.size() / 16;
    static const bool hw = detail::aesHardware();
    if (hw) {
        if constexpr (Encrypt) detail::aesXtsEncryptHardware(data.encryptKeyBytes(), data.rounds(), tweakOut, src, dst, blocks);
        else detail::aesXtsDecryptHardware(data.decryptKeyBytes(), data.rounds(), tweakOut, src, dst, blocks);
        return;
    }
    constexpr std::size_t kGroup = 8;
    XtsTweak t = detail::xtsTweakLoad(tweakOut);
    for (std::size_t done = 0; done < blocks;) {
        const std::size_t n = std::min(kGroup, blocks - done);
        XtsTweak tw[kGroup];
        for (std::size_t i = 0; i < n; ++i) {
            tw[i] = t;
            detail::xtsTweakDouble(t);
        }
        for (std::size_t i = 0; i < n; ++i) {
            std::uint8_t x[16], y[16];
            xorTweak(in.data() + 16 * (done + i), tw[i], x);
            if constexpr (Encrypt) detail::aesEncryptPortable(data.roundKeys(), data.rounds(), x, y);
            else detail::aesDecryptPortable(data.roundKeys(), data.rounds(), x, y);
            xorTweak(y, tw[i], out.data() + 16 * (done + i));
        }
        done += n;
    }
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
        Layer layer{std::move(*data), std::move(*tweak)};
        if (cascade[i] == CipherAlgorithm::Aes) {
            // The multi-block kernels need the schedule, not the interface; the pointer stays valid
            // for as long as the shared_ptr above (copied along with it). The tweak cipher runs once
            // per sector and stays behind the interface.
            layer.aesData = &dynamic_cast<const AesBlock&>(*layer.data).aes();
        }
        x.m_layers.push_back(std::move(layer));
    }
    return x;
}

std::vector<CipherAlgorithm> Xts::cascade() const {
    std::vector<CipherAlgorithm> v;
    for (const auto& l : m_layers) v.push_back(l.data->algorithm());
    return v;
}

std::string_view Xts::implementation() const {
    if (!fastPath()) return "generic";
    static const bool hw = detail::aesHardware();
    return hw ? detail::aesHardwareName() : "aes-portable";
}

void Xts::layerEncrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) { xtsLayer<true>(*l.data, *l.tweak, sector, in, out); }

void Xts::layerDecrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) { xtsLayer<false>(*l.data, *l.tweak, sector, in, out); }

Expected<void> Xts::encrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    if (fastPath()) {
        xtsAesLayer<true>(*m_layers[0].aesData, *m_layers[0].tweak, sector, in, out);
        return {};
    }
    // Last layer first (VeraCrypt: "AES-Twofish" encrypts with Twofish, then AES).
    for (std::size_t i = m_layers.size(); i-- > 0;) {
        layerEncrypt(m_layers[i], sector, in, out);
        in = out.first(in.size());
    }
    return {};
}

Expected<void> Xts::decrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const {
    if (in.size() % 16 || out.size() < in.size()) return fail(ErrorCategory::InvalidArgument, "XTS data must be a multiple of 16 bytes");
    if (fastPath()) {
        xtsAesLayer<false>(*m_layers[0].aesData, *m_layers[0].tweak, sector, in, out);
        return {};
    }
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
