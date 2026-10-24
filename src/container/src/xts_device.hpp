// SPDX-License-Identifier: MIT
// Decrypting/encrypting view over an XTS payload (LUKS aes-xts-plain64,
// VeraCrypt/TrueCrypt ciphers and cascades): one tweak per sector, starting at ivTweak.
// ivTweak counts sectors of `sectorSize`, the unit the tweaks themselves are in. dm-crypt's
// iv_offset (LUKS2 iv_tweak) is in 512-byte sectors whatever the sector size; the LUKS layer
// divides it by sectorSize / 512 before building this device.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/cipher.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
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
        // Whole sectors covering the request, at most kChunk bytes at a time through two scratch
        // buffers kept on the device: a 128 MiB read must not allocate 256 MiB, and the lock is
        // taken per chunk so the UI thread and the NFS server thread, which read through the same
        // device, interleave instead of one waiting for the other's whole request.
        const ByteCount chunkSectors = std::max<ByteCount>(1, kChunk / m_sectorSize);
        const ByteCount end = offset + dst.size();
        ByteCount sector = offset / m_sectorSize;
        const ByteCount lastSector = (end - 1) / m_sectorSize;
        while (sector <= lastSector) {
            const ByteCount n = std::min<ByteCount>(chunkSectors, lastSector - sector + 1);
            const ByteCount chunkStart = sector * m_sectorSize, chunkBytes = n * m_sectorSize;
            // The part of this chunk the caller asked for (the first and last chunk may be partial).
            const ByteCount from = std::max(chunkStart, offset), to = std::min(chunkStart + chunkBytes, end);
            const std::span<std::byte> window = dst.subspan(static_cast<std::size_t>(from - offset), static_cast<std::size_t>(to - from));
            std::lock_guard lock(m_scratchMutex);
            if (m_cipher.size() < chunkBytes) m_cipher.resize(static_cast<std::size_t>(chunkBytes));
            const std::span<std::byte> cipher(m_cipher.data(), static_cast<std::size_t>(chunkBytes));
            if (auto r = m_parent->readAt(m_region.offset + chunkStart, cipher); !r) return r;
            if (window.size() == chunkBytes) {
                // Sector-aligned on both ends: decrypt straight into the caller's buffer.
                if (auto d = m_xts.decryptSectors(sector + m_ivTweak, m_sectorSize, cipher, window); !d) return d;
            } else {
                if (m_plain.size() < chunkBytes) m_plain.resize(static_cast<std::size_t>(chunkBytes));
                const std::span<std::byte> plain(m_plain.data(), static_cast<std::size_t>(chunkBytes));
                if (auto d = m_xts.decryptSectors(sector + m_ivTweak, m_sectorSize, cipher, plain); !d) return d;
                std::memcpy(window.data(), plain.data() + (from - chunkStart), window.size());
            }
            sector += n;
        }
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
    static constexpr ByteCount kChunk = 1 * MiB;   // a multiple of every LUKS sector size (512 to 4096)

    std::shared_ptr<BlockDevice> m_parent;
    Region m_region;
    std::uint32_t m_sectorSize;
    std::uint64_t m_ivTweak;
    crypto::Xts m_xts;
    bool m_readOnly;
    std::string m_label;
    Geometry m_geometry;
    // Scratch for readAt: ciphertext and, for partial chunks, plaintext; each grows to kChunk at most.
    std::mutex m_scratchMutex;
    std::vector<std::byte> m_cipher, m_plain;
};


} // namespace stein::container::detail
