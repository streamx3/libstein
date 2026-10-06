// SPDX-License-Identifier: MIT
// Virtual-disk containers as read-only block devices: qcow2 (v2/v3, deflate
// compressed clusters), VHD (fixed/dynamic), VHDX, VMDK (sparse extents,
// stream-optimized compressed grains, multi-extent descriptors), VDI and
// EWF/E01 (EnCase 5/6 segments, deflate chunks, stored MD5/SHA-1) and Apple
// DMG/UDIF (raw, zlib and ADC blocks; bzip2/lzfse/lzma reported).
// Differencing/backing chains, encryption and zstd are reported, not opened.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace stein::image {

enum class VdiskFormat : std::uint8_t { Raw, Stein, Qcow2, Vhd, Vhdx, Vmdk, Vdi, Ewf, Dmg };
std::string_view toString(VdiskFormat f);

struct VdiskInfo {
    VdiskFormat format = VdiskFormat::Raw;
    ByteCount virtualSize = 0;
    std::uint32_t clusterSize = 0;      // allocation unit of the container (0 = n/a)
    bool compressed = false;
    std::string variant;                // "v3", "dynamic", "monolithicSparse", ...
    std::vector<std::string> notes;
    std::vector<std::filesystem::path> files;   // every file the container spans (segments, extents)
    std::string storedMd5, storedSha1;          // digests recorded by the acquisition tool (EWF), hex
};

// Sniff the container format from its header (and, for VHD, its footer).
Expected<VdiskFormat> detectVdiskFormat(const std::filesystem::path& path);
// Open any supported container (or a raw file) as a block device. Containers other than raw open read-only.
Expected<std::shared_ptr<BlockDevice>> openVdisk(const std::filesystem::path& path, VdiskInfo* info = nullptr);

} // namespace stein::image
