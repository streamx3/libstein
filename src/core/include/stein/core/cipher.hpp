// SPDX-License-Identifier: MIT
// 128-bit block ciphers behind one interface (AES, Serpent, Twofish,
// Camellia-256, Kuznyechik) and XTS (IEEE 1619, plain64 tweak) over any of
// them, including VeraCrypt's cascades. Own implementations, verified
// against Botan and the GOST reference (tests/cipher_vectors.hpp).
#pragma once

#include "stein/core/error.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace stein::crypto {

enum class CipherAlgorithm : std::uint8_t { Aes, Serpent, Twofish, Camellia, Kuznyechik };
std::string_view toString(CipherAlgorithm c);   // "aes", "serpent", "twofish", "camellia", "kuznyechik"
std::optional<CipherAlgorithm> cipherFromString(std::string_view s);

class BlockCipher {
public:
    static constexpr std::size_t kBlockSize = 16;
    virtual ~BlockCipher() = default;
    virtual CipherAlgorithm algorithm() const = 0;
    virtual void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const = 0;
    virtual void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const = 0;
    // 32-byte keys everywhere; AES also takes 16 or 24, Serpent and Twofish 16 or 24 as well.
    static Expected<std::unique_ptr<BlockCipher>> create(CipherAlgorithm algorithm, std::span<const std::uint8_t> key);
};

// Serpent (AES finalist; 32 rounds, bitsliced). Keys of 16, 24 or 32 bytes.
class Serpent final : public BlockCipher {
public:
    static Expected<Serpent> create(std::span<const std::uint8_t> key);
    CipherAlgorithm algorithm() const override { return CipherAlgorithm::Serpent; }
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;

private:
    std::array<std::uint32_t, 132> m_k{};   // 33 subkeys of 4 words
};

// Twofish (AES finalist; 16 rounds, full keying). Keys of 16, 24 or 32 bytes.
class Twofish final : public BlockCipher {
public:
    static Expected<Twofish> create(std::span<const std::uint8_t> key);
    CipherAlgorithm algorithm() const override { return CipherAlgorithm::Twofish; }
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;

private:
    std::uint32_t g(std::uint32_t x) const;
    std::array<std::uint32_t, 40> m_k{};
    std::array<std::array<std::uint32_t, 256>, 4> m_sbox{};   // key-dependent S-boxes with the MDS folded in
};

// Camellia with a 256-bit key (RFC 3713; 24 rounds).
class Camellia final : public BlockCipher {
public:
    static Expected<Camellia> create(std::span<const std::uint8_t> key);
    CipherAlgorithm algorithm() const override { return CipherAlgorithm::Camellia; }
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;

private:
    void run(const std::uint8_t in[16], std::uint8_t out[16], const std::uint64_t kw[4], const std::uint64_t k[24], const std::uint64_t ke[6]) const;
    std::uint64_t m_kw[4]{}, m_k[24]{}, m_ke[6]{};
};

// Kuznyechik, GOST R 34.12-2015 (RFC 7801; 10 rounds, 256-bit key).
class Kuznyechik final : public BlockCipher {
public:
    static Expected<Kuznyechik> create(std::span<const std::uint8_t> key);
    CipherAlgorithm algorithm() const override { return CipherAlgorithm::Kuznyechik; }
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;
    void decryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const override;

private:
    std::array<std::array<std::uint8_t, 16>, 10> m_rk{};
};

// XTS over one cipher or a cascade. `cascade` lists the layers in VeraCrypt's
// table order: decryption applies them first to last, encryption last to
// first ("AES-Twofish" encrypts with Twofish, then AES). `key` holds the
// primary (data) keys of all layers in that order, followed by the secondary
// (tweak) keys in the same order: 64 bytes for one 256-bit cipher (32 for
// AES-128), 128 for two, 192 for three. The tweak is the little-endian
// 64-bit sector / data-unit number (dm-crypt plain64, VeraCrypt).
class Xts {
public:
    static Expected<Xts> create(CipherAlgorithm cipher, std::span<const std::uint8_t> key);
    static Expected<Xts> create(std::span<const CipherAlgorithm> cascade, std::span<const std::uint8_t> key);

    // `in` must be a multiple of 16 bytes; `out` at least as long.
    Expected<void> encrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const;
    Expected<void> decrypt(std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out) const;
    // A run of equally sized sectors starting at `firstSector`.
    Expected<void> encryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const;
    Expected<void> decryptSectors(std::uint64_t firstSector, std::uint32_t sectorSize, std::span<const std::byte> in, std::span<std::byte> out) const;

    std::size_t layers() const { return m_layers.size(); }
    std::vector<CipherAlgorithm> cascade() const;
    static std::size_t keySize(std::span<const CipherAlgorithm> cascade) { return cascade.size() * 64; }

private:
    struct Layer {
        std::shared_ptr<const BlockCipher> data, tweak;
    };
    static void layerEncrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out);
    static void layerDecrypt(const Layer& l, std::uint64_t sector, std::span<const std::byte> in, std::span<std::byte> out);
    std::vector<Layer> m_layers;
};

} // namespace stein::crypto
