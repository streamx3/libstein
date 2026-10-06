// SPDX-License-Identifier: MIT
// Helper base for L0 modules: holds info, diagnostics, parsed regions and the
// describe() tree so each detector is a short parse function.
#pragma once

#include "stein/fs/filesystem.hpp"

namespace stein::fs::detail {

// How a detector provides L1: a small object that knows where the bitmap is.
class AllocationSource {
public:
    virtual ~AllocationSource() = default;
    virtual Expected<AllocationMap> load(BlockDevice& device) const = 0;
};

// How a detector provides L3: a factory for Reader objects over the device.
class ReaderSource {
public:
    virtual ~ReaderSource() = default;
    virtual Expected<std::unique_ptr<Reader>> open(std::shared_ptr<BlockDevice> device) const = 0;
};

class SimpleFileSystem : public FileSystem {
public:
    explicit SimpleFileSystem(std::shared_ptr<BlockDevice> device) : FileSystem(std::move(device)) {
        m_tree.isStruct = true;
    }

    FsType type() const override { return m_info.type; }
    const FsInfo& info() const override { return m_info; }
    std::span<const FsDiagnostic> diagnostics() const override { return m_diagnostics; }
    std::vector<Region> metadataRegions() const override { return m_regions; }
    layout::Node describe() const override { return m_tree; }
    std::uint32_t capabilities() const override;
    Expected<AllocationMap> allocationMap() const override;
    Expected<std::unique_ptr<Reader>> openReader() const override;

    // Construction helpers used by detectors.
    FsInfo& mutableInfo() { return m_info; }
    void addRegion(Region r) { m_regions.push_back(r); }
    void addNode(layout::Node n) { m_tree.children.push_back(std::move(n)); }
    void setTreeName(std::string name) { m_tree.name = std::move(name); }
    void setAllocationSource(std::unique_ptr<AllocationSource> src) { m_alloc = std::move(src); }
    void setReaderSource(std::unique_ptr<ReaderSource> src) { m_reader = std::move(src); }
    void diag(layout::Validity sev, std::string code, std::string message) {
        if (sev >= layout::Validity::Warning) m_tree.flag(sev, message);
        m_diagnostics.push_back(FsDiagnostic{sev, std::move(code), std::move(message)});
    }

protected:
    FsInfo m_info;
    std::vector<FsDiagnostic> m_diagnostics;
    std::vector<Region> m_regions;
    layout::Node m_tree;
    std::unique_ptr<AllocationSource> m_alloc;
    std::unique_ptr<ReaderSource> m_reader;
};

// Read `length` bytes at `offset`; NotFound (not Io) when the device is too
// small, so detectors simply return "not mine" on tiny devices.
Expected<std::vector<std::byte>> readOrNotFound(BlockDevice& device, ByteCount offset, ByteCount length);

// Format helpers shared by modules.
std::string serialHex(std::uint32_t serial);                   // "DEAD-BEEF" (FAT/exFAT)
std::string hex64(std::uint64_t v);                            // "65A58D893612B17C" (NTFS)
std::string uuidText(std::span<const std::byte> rfc16, bool upper = false);
std::string hyphenateLvmUuid(std::string_view raw32);          // 6-4-4-4-4-4-6

} // namespace stein::fs::detail
