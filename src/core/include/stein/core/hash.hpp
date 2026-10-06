// SPDX-License-Identifier: MIT
// Streaming hashes. MD5 for interoperability with existing images/checksums;
// SHA-256 as the default content hash. BLAKE3 and xxh3 arrive with stein_image
// (vendored permissive implementations) behind the same Hasher interface.
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace stein {

enum class HashAlgorithm : std::uint8_t { Md5, Sha256 };

std::string_view toString(HashAlgorithm a);

class Hasher {
public:
    virtual ~Hasher() = default;
    virtual HashAlgorithm algorithm() const = 0;
    virtual std::size_t digestSize() const = 0;
    virtual void update(std::span<const std::byte> data) = 0;
    // Finalises and returns the digest; the hasher must be reset() before reuse.
    virtual std::vector<std::uint8_t> finish() = 0;
    virtual void reset() = 0;

    static std::unique_ptr<Hasher> create(HashAlgorithm a);
    // One-shot helpers.
    static std::vector<std::uint8_t> digest(HashAlgorithm a, std::span<const std::byte> data);
    static std::string hex(std::span<const std::uint8_t> digest);
};

class Md5 final : public Hasher {
public:
    Md5() { reset(); }
    HashAlgorithm algorithm() const override { return HashAlgorithm::Md5; }
    std::size_t digestSize() const override { return 16; }
    void update(std::span<const std::byte> data) override;
    std::vector<std::uint8_t> finish() override;
    void reset() override;

private:
    void transform(const std::uint8_t block[64]);
    std::array<std::uint32_t, 4> m_state{};
    std::uint64_t m_bits = 0;
    std::array<std::uint8_t, 64> m_buffer{};
    std::size_t m_bufferLen = 0;
};

class Sha256 final : public Hasher {
public:
    Sha256() { reset(); }
    HashAlgorithm algorithm() const override { return HashAlgorithm::Sha256; }
    std::size_t digestSize() const override { return 32; }
    void update(std::span<const std::byte> data) override;
    std::vector<std::uint8_t> finish() override;
    void reset() override;

private:
    void transform(const std::uint8_t block[64]);
    void transformBlocks(const std::uint8_t* data, std::size_t blocks);
    std::array<std::uint32_t, 8> m_state{};
    std::uint64_t m_bits = 0;
    std::array<std::uint8_t, 64> m_buffer{};
    std::size_t m_bufferLen = 0;
};

} // namespace stein
