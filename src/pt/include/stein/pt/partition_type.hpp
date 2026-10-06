// SPDX-License-Identifier: MIT
// Partition table kinds, partition types (scheme-specific codes) and the
// registry that maps them to semantic roles and display names.
#pragma once

#include "stein/core/guid.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace stein::pt {

enum class TableType : std::uint8_t {
    None,      // whole-device content, no table
    Mbr, Gpt, Apm, Bsd, Sun, Sgi, Amiga, Pc98, Aix, Atari,
    Unknown,
};
std::string_view toString(TableType t);

// What a partition is *for*, independent of the scheme that encodes it.
enum class Role : std::uint8_t {
    Unknown, Empty, Extended, GptProtective,
    EfiSystem, BiosBoot, IntelFastFlash, PrepBoot, SonyBoot, LenovoBoot,
    MicrosoftReserved, WindowsBasicData, WindowsRecovery, WindowsLdmMetadata, WindowsLdmData, WindowsStorageSpaces,
    LinuxFilesystem, LinuxSwap, LinuxLvm, LinuxRaid, LinuxHome, LinuxServerData, LinuxRoot, LinuxUsr, LinuxVar,
    LinuxVarTmp, LinuxLuks, LinuxDmCrypt, LinuxReserved, LinuxExtendedBoot,
    AppleHfsPlus, AppleApfs, AppleUfs, AppleBoot, AppleLabel, AppleTvRecovery, AppleCoreStorage, AppleRaid,
    AppleRaidOffline, AppleZfs,
    FreeBsdDisklabel, FreeBsdBoot, FreeBsdSwap, FreeBsdUfs, FreeBsdZfs, FreeBsdVinum,
    NetBsd, OpenBsd, Solaris, HpUx, Haiku, Vmware, ChromeOs, Qnx, IbmGpfs,
    Fat12, Fat16, Fat32, NtfsHpfsExfat, HiddenFat, HiddenNtfs, Minix, Plan9, Hibernation, Diagnostics, NonFsData,
    Other,
};
std::string_view toString(Role r);

struct PartitionType {
    TableType scheme = TableType::Unknown;
    std::uint8_t mbrId = 0;      // scheme == Mbr
    Uuid gptGuid;                // scheme == Gpt
    std::string apmType;         // scheme == Apm, e.g. "Apple_HFS"

    static PartitionType mbr(std::uint8_t id);
    static PartitionType gpt(const Uuid& guid);
    static PartitionType apm(std::string type);

    bool isEmpty() const;
    std::string code() const;    // "0x83", the GUID text, or the APM string
    bool operator==(const PartitionType&) const = default;
};

struct PartitionTypeInfo {
    PartitionType type;
    Role role;
    const char* name;            // "EFI System", "Linux filesystem"
    const char* group;           // "Windows", "Linux", "Apple", "BSD", "Generic"...
    const char* sgdiskCode;      // "EF00" for GPT types; "" otherwise
};

namespace types {
const PartitionTypeInfo* find(const PartitionType& type);
std::string name(const PartitionType& type);     // registry name or "Unknown (<code>)"
Role role(const PartitionType& type);
std::span<const PartitionTypeInfo> all();
// The canonical type for a role on a scheme (e.g. LinuxFilesystem on GPT), if there is one.
std::optional<PartitionType> forRole(Role role, TableType scheme);
// Look up a GPT type by its sgdisk two-byte code ("8300").
std::optional<PartitionType> fromSgdiskCode(std::string_view code);
} // namespace types

} // namespace stein::pt
