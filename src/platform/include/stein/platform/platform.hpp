// SPDX-License-Identifier: MIT
// The platform layer: the only place with OS-specific code. Everything above
// it talks to these interfaces. See doc/design/16-platform.md.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/units.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace stein::platform {

enum class Bus : std::uint8_t { Unknown, Ata, Scsi, Nvme, Usb, Sd, Mmc, Virtual, Loop, Nbd, DeviceMapper, Md, Other };
std::string_view toString(Bus b);

struct DiskInfo {
    std::string osPath;                          // "/dev/sda", "/dev/rdisk2", "\\\\.\\PhysicalDrive0"
    std::string kernelName;                      // "sda", "nvme0n1", "loop3"
    Geometry geometry;
    Bus bus = Bus::Unknown;
    std::string model, vendor, serial, firmware, wwn;
    bool removable = false;
    bool rotational = false;
    bool readOnly = false;
    bool isVirtual = false;                      // loop, nbd, dm, md, zram, ram
    std::optional<std::filesystem::path> backingFile;   // loop devices
    // A stable identity string built from the most durable fields available.
    std::string identity() const;
};

struct MountInfo {
    std::string source;        // "/dev/sda1"
    std::string target;        // "/boot/efi"
    std::string fsType;        // "vfat"
    std::string options;       // "rw,relatime"
    bool readOnly = false;
};

enum class OpenMode { ReadOnly, ReadWrite, ReadWriteExclusive };

struct AttachOptions {
    bool readOnly = false;
    bool partitionScan = true;
    std::uint32_t sectorSize = 0;   // 0 = default (512)
};

struct AttachedImage {
    std::string osPath;             // the block device the image appears as
    std::filesystem::path file;
};

class Platform {
public:
    virtual ~Platform() = default;
    virtual std::string_view name() const = 0;             // "linux", "macos", "windows", "generic"

    // Enumerate whole disks (not partitions). Includes loop/virtual devices, flagged.
    virtual Expected<std::vector<DiskInfo>> enumerate() = 0;
    // Describe one device by OS path (also works for paths not returned by enumerate()).
    virtual Expected<DiskInfo> describe(const std::string& osPath) = 0;
    // Open a raw device (or a regular file) as a BlockDevice with correct geometry.
    virtual Expected<std::shared_ptr<BlockDevice>> open(const std::string& osPath, OpenMode mode) = 0;
    // Mount table as the OS sees it, optionally filtered to a device and its partitions.
    virtual Expected<std::vector<MountInfo>> mounts(const std::string& osPathPrefix = {}) = 0;
    // Unmount one entry of mounts(). Busy when files are open (force detaches anyway where the OS
    // allows). Unsupported on Windows: there, an exclusive open locks and dismounts the volumes.
    virtual Expected<void> unmount(const MountInfo& mount, bool force) = 0;
    // Ask the kernel to re-read a device's partition table after we wrote one.
    virtual Expected<void> rereadPartitionTable(const std::string& osPath) = 0;
    // Expose an image file as a block device (loop on Linux).
    virtual Expected<AttachedImage> attach(const std::filesystem::path& file, const AttachOptions& options) = 0;
    virtual Expected<void> detach(const AttachedImage& attached) = 0;
    // True when the process has the privileges raw device access needs (root / Administrator).
    virtual bool isElevated() const = 0;
};

Platform& current();

// Convenience: open `pathOrFile` as a BlockDevice — a raw device through the
// platform when it is one, otherwise a regular file (FileDevice).
// True for OS device-namespace paths that std::filesystem cannot stat (Windows "\\.\PhysicalDrive0").
bool isDevicePath(const std::string& path);
Expected<std::shared_ptr<BlockDevice>> openAny(const std::string& pathOrFile, OpenMode mode, std::uint32_t fileSectorSize = 512);

} // namespace stein::platform
