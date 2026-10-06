// SPDX-License-Identifier: MIT
// FileSystem: abstract base for every filesystem (and for the "content
// markers" of containers and volume managers, until their own modules take
// over). Level L0 = detect, identify, geometry, label, UUID, state.
// Capability objects (resize, label, read, write...) arrive with L2–L4 and
// are null until then. See doc/design/11 and 12.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/units.hpp"
#include "stein/layout/node.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace stein::fs {

enum class FsType : std::uint8_t {
    Unknown,
    // filesystems
    Ext2, Ext3, Ext4, Fat12, Fat16, Fat32, ExFat, Ntfs, ReFs,
    Hfs, HfsPlus, HfsX, Apfs,
    Btrfs, Xfs, F2fs, Jfs, ReiserFs, Reiser4, Nilfs2, Bcachefs, Ocfs2, Minix, Erofs, SquashFs,
    Udf, Iso9660, Zfs, Ufs, Swap,
    // content markers for containers / volume managers
    Luks1, Luks2, BitLocker, Lvm2Pv, MdRaidMember, BcacheMember,
};
std::string_view toString(FsType t);            // "ext4", "vfat"-style short names as blkid prints them
std::string_view displayName(FsType t);         // "ext4", "FAT32", "NTFS", "LUKS2 encrypted"...
bool isContainerMarker(FsType t);

enum class Usage : std::uint8_t { Filesystem, Swap, Crypto, Raid, Other };

// Cheap, always-available facts about an instance. Everything optional stays
// empty when the format does not have it.
struct FsInfo {
    FsType type = FsType::Unknown;
    Usage usage = Usage::Filesystem;
    std::string version;                 // "1.0", "FAT32", "3.1", "5"
    std::string label;                   // UTF-8
    std::string uuid;                    // as blkid prints it: RFC text, "XXXX-XXXX" serials, 16 hex for NTFS...
    std::optional<ByteCount> blockSize;  // fundamental allocation unit
    std::optional<ByteCount> totalBytes; // size the filesystem believes it has
    std::optional<ByteCount> usedBytes;  // when the superblock says so (ext, xfs, btrfs...)
    std::optional<bool> clean;           // cleanly unmounted / not dirty
    std::vector<std::string> features;   // feature flags worth showing
    std::string extra;                   // free-form one-liner (e.g. cipher spec for LUKS)
};

struct FsDiagnostic {
    layout::Validity severity = layout::Validity::Info;
    std::string code;
    std::string message;
};

// What this instance can do right now. L0 modules have only the first three.
enum class Capability : std::uint32_t {
    Identify = 1u << 0,     // type/version
    Label = 1u << 1,        // read label
    Uuid = 1u << 2,         // read uuid
    UsedBlocks = 1u << 3,   // L1
    SetLabel = 1u << 4,     // L2
    SetUuid = 1u << 5,
    Grow = 1u << 6,
    Shrink = 1u << 7,
    Check = 1u << 8,
    Create = 1u << 9,
    Read = 1u << 10,        // L3
    Write = 1u << 11,       // L4
};
inline std::uint32_t operator|(Capability a, Capability b) { return static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b); }
inline bool has(std::uint32_t set, Capability c) { return (set & static_cast<std::uint32_t>(c)) != 0; }

class FileSystem {
public:
    virtual ~FileSystem() = default;

    virtual FsType type() const = 0;
    virtual const FsInfo& info() const = 0;
    virtual std::span<const FsDiagnostic> diagnostics() const = 0;
    virtual std::uint32_t capabilities() const;    // default: Identify | Label | Uuid as info() allows
    // Byte ranges of the metadata we parsed (superblocks, boot sectors and
    // their backups): the "filesystem header piece" for dump/restore.
    virtual std::vector<Region> metadataRegions() const = 0;
    // Hexinator-style tree of the structures we parsed.
    virtual layout::Node describe() const = 0;

    const std::shared_ptr<BlockDevice>& device() const { return m_device; }
    layout::Validity health() const;

protected:
    explicit FileSystem(std::shared_ptr<BlockDevice> device) : m_device(std::move(device)) {}
    std::shared_ptr<BlockDevice> m_device;
};

// A detector tries to recognise one family on a device. NotFound = "not mine";
// any other error aborts probing (I/O failure).
using Detector = Expected<std::unique_ptr<FileSystem>> (*)(std::shared_ptr<BlockDevice>);

struct DetectorEntry {
    const char* name;
    Detector detect;
};

// The registry: ordered list of detectors (containers and markers before
// filesystems, specific formats before permissive ones).
std::span<const DetectorEntry> detectors();

// Probe a device: first detector that claims it wins. Returns nullptr (not an
// error) when nothing matched.
Expected<std::unique_ptr<FileSystem>> probe(std::shared_ptr<BlockDevice> device);

} // namespace stein::fs
