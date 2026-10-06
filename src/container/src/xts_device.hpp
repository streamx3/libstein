// SPDX-License-Identifier: MIT
// Decrypting/encrypting view over an XTS payload (LUKS aes-xts-plain64,
// VeraCrypt/TrueCrypt ciphers and cascades): one tweak per sector, starting at ivTweak.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/cipher.hpp"

#include <cstring>
#include <string>

namespace stein::container::detail {

// Decrypting view over the payload: one XTS tweak per sector.
class XtsDevice final : public BlockDevice {
public:
    XtsDevice(std::shared_ptr<BlockDevice> parent, Region region, std::uint32_t sectorSize, std::uint64_t ivTweak, crypto::Xts xts, bool readOnly, std::string label)
        : m_parent(std::move(parent)), m_region(region), m_sectorSize(sectorSize), m_ivTweak(ivTweak), m_xts(std::move(xts)), m_readOnly(readOnly), m_label(std::move(label)) {
        m_geometry = m_parent->geometry();
        m_geometry.sizeBytes = region.length;
        m_geometry.logicalSectorSize = sectorSize;
        if (m_geometry.physicalSectorSize < sectorSize) m_geometry.physicalSectorSize = sectorSize;
    }
    std::string name() const override { return m_parent->name() + " (" + m_label + ")"; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly || m_parent->isReadOnly(); }
    std::shared_ptr<BlockDevice> parent() const override { return m_parent; }
    std::vector<Region> extentsOnParent() const override { return {m_region}; }
    Expected<void> flush() override { return m_parent->flush(); }

    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        if (dst.empty()) return {};
        // Whole sectors covering the request, then copy the window out.
        const ByteCount first = offset / m_sectorSize;
        const ByteCount last = (offset + dst.size() - 1) / m_sectorSize;
        const ByteCount span = (last - first + 1) * m_sectorSize;
        std::vector<std::byte> cipher(span), plain(span);
        if (auto r = m_parent->readAt(m_region.offset + first * m_sectorSize, cipher); !r) return r;
        if (auto d = m_xts.decryptSectors(first + m_ivTweak, m_sectorSize, cipher, plain); !d) return d;
        std::memcpy(dst.data(), plain.data() + (offset - first * m_sectorSize), dst.size());
        return {};
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        if (isReadOnly()) return fail(ErrorCategory::Permission, m_label + " payload opened read-only");
        if (auto r = checkRange(offset, src.size()); !r) return r;
        if (src.empty()) return {};
        const ByteCount first = offset / m_sectorSize;
        const ByteCount last = (offset + src.size() - 1) / m_sectorSize;
        const ByteCount span = (last - first + 1) * m_sectorSize;
        std::vector<std::byte> plain(span), cipher(span);
        // Read-modify-write for partial sectors.
        if (offset % m_sectorSize || src.size() % m_sectorSize)
            if (auto r = readAt(first * m_sectorSize, plain); !r) return r;
        std::memcpy(plain.data() + (offset - first * m_sectorSize), src.data(), src.size());
        if (auto e = m_xts.encryptSectors(first + m_ivTweak, m_sectorSize, plain, cipher); !e) return e;
        return m_parent->writeAt(m_region.offset + first * m_sectorSize, cipher);
    }

private:
    std::shared_ptr<BlockDevice> m_parent;
    Region m_region;
    std::uint32_t m_sectorSize;
    std::uint64_t m_ivTweak;
    crypto::Xts m_xts;
    bool m_readOnly;
    std::string m_label;
    Geometry m_geometry;
};


} // namespace stein::container::detail
