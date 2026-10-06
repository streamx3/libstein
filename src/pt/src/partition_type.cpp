// SPDX-License-Identifier: MIT
// Partition type registry. GPT GUIDs from the UEFI specification, the
// systemd Discoverable Partitions Specification, Apple/Microsoft/BSD public
// documentation; MBR ids from the de-facto list every fdisk ships.
#include "stein/pt/partition_type.hpp"

#include "stein/core/strings.hpp"

#include <vector>

namespace stein::pt {

std::string_view toString(TableType t) {
    switch (t) {
    case TableType::None: return "none";
    case TableType::Mbr: return "mbr";
    case TableType::Gpt: return "gpt";
    case TableType::Apm: return "apm";
    case TableType::Bsd: return "bsd";
    case TableType::Sun: return "sun";
    case TableType::Sgi: return "sgi";
    case TableType::Amiga: return "amiga";
    case TableType::Pc98: return "pc98";
    case TableType::Aix: return "aix";
    case TableType::Atari: return "atari";
    case TableType::Unknown: return "unknown";
    }
    return "?";
}

std::string_view toString(Role r) {
    switch (r) {
    case Role::Unknown: return "unknown";
    case Role::Empty: return "empty";
    case Role::Extended: return "extended";
    case Role::GptProtective: return "gpt-protective";
    case Role::EfiSystem: return "efi-system";
    case Role::BiosBoot: return "bios-boot";
    case Role::IntelFastFlash: return "intel-fast-flash";
    case Role::PrepBoot: return "prep-boot";
    case Role::SonyBoot: return "sony-boot";
    case Role::LenovoBoot: return "lenovo-boot";
    case Role::MicrosoftReserved: return "microsoft-reserved";
    case Role::WindowsBasicData: return "windows-basic-data";
    case Role::WindowsRecovery: return "windows-recovery";
    case Role::WindowsLdmMetadata: return "windows-ldm-metadata";
    case Role::WindowsLdmData: return "windows-ldm-data";
    case Role::WindowsStorageSpaces: return "windows-storage-spaces";
    case Role::LinuxFilesystem: return "linux-filesystem";
    case Role::LinuxSwap: return "linux-swap";
    case Role::LinuxLvm: return "linux-lvm";
    case Role::LinuxRaid: return "linux-raid";
    case Role::LinuxHome: return "linux-home";
    case Role::LinuxServerData: return "linux-server-data";
    case Role::LinuxRoot: return "linux-root";
    case Role::LinuxUsr: return "linux-usr";
    case Role::LinuxVar: return "linux-var";
    case Role::LinuxVarTmp: return "linux-var-tmp";
    case Role::LinuxLuks: return "linux-luks";
    case Role::LinuxDmCrypt: return "linux-dm-crypt";
    case Role::LinuxReserved: return "linux-reserved";
    case Role::LinuxExtendedBoot: return "linux-extended-boot";
    case Role::AppleHfsPlus: return "apple-hfs-plus";
    case Role::AppleApfs: return "apple-apfs";
    case Role::AppleUfs: return "apple-ufs";
    case Role::AppleBoot: return "apple-boot";
    case Role::AppleLabel: return "apple-label";
    case Role::AppleTvRecovery: return "apple-tv-recovery";
    case Role::AppleCoreStorage: return "apple-core-storage";
    case Role::AppleRaid: return "apple-raid";
    case Role::AppleRaidOffline: return "apple-raid-offline";
    case Role::AppleZfs: return "apple-zfs";
    case Role::FreeBsdDisklabel: return "freebsd-disklabel";
    case Role::FreeBsdBoot: return "freebsd-boot";
    case Role::FreeBsdSwap: return "freebsd-swap";
    case Role::FreeBsdUfs: return "freebsd-ufs";
    case Role::FreeBsdZfs: return "freebsd-zfs";
    case Role::FreeBsdVinum: return "freebsd-vinum";
    case Role::NetBsd: return "netbsd";
    case Role::OpenBsd: return "openbsd";
    case Role::Solaris: return "solaris";
    case Role::HpUx: return "hp-ux";
    case Role::Haiku: return "haiku";
    case Role::Vmware: return "vmware";
    case Role::ChromeOs: return "chromeos";
    case Role::Qnx: return "qnx";
    case Role::IbmGpfs: return "ibm-gpfs";
    case Role::Fat12: return "fat12";
    case Role::Fat16: return "fat16";
    case Role::Fat32: return "fat32";
    case Role::NtfsHpfsExfat: return "ntfs-hpfs-exfat";
    case Role::HiddenFat: return "hidden-fat";
    case Role::HiddenNtfs: return "hidden-ntfs";
    case Role::Minix: return "minix";
    case Role::Plan9: return "plan9";
    case Role::Hibernation: return "hibernation";
    case Role::Diagnostics: return "diagnostics";
    case Role::NonFsData: return "non-fs-data";
    case Role::Other: return "other";
    }
    return "?";
}

PartitionType PartitionType::mbr(std::uint8_t id) {
    PartitionType t;
    t.scheme = TableType::Mbr;
    t.mbrId = id;
    return t;
}

PartitionType PartitionType::gpt(const Uuid& guid) {
    PartitionType t;
    t.scheme = TableType::Gpt;
    t.gptGuid = guid;
    return t;
}

PartitionType PartitionType::apm(std::string type) {
    PartitionType t;
    t.scheme = TableType::Apm;
    t.apmType = std::move(type);
    return t;
}

bool PartitionType::isEmpty() const {
    switch (scheme) {
    case TableType::Mbr: return mbrId == 0;
    case TableType::Gpt: return gptGuid.isNil();
    case TableType::Apm: return apmType.empty() || apmType == "Apple_Free";
    default: return true;
    }
}

std::string PartitionType::code() const {
    switch (scheme) {
    case TableType::Mbr: return toHex(mbrId, 2);
    case TableType::Gpt: return gptGuid.toString();
    case TableType::Apm: return apmType;
    default: return "?";
    }
}

namespace {

struct GptRow {
    const char* guid;
    Role role;
    const char* name;
    const char* group;
    const char* code;
};

// clang-format off
const GptRow kGptRows[] = {
    {"00000000-0000-0000-0000-000000000000", Role::Empty,                "Unused entry",                 "Generic",  "0000"},
    {"024DEE41-33E7-11D3-9D69-0008C781F39F", Role::Other,                "MBR partition scheme",         "Generic",  "0100"},
    {"C12A7328-F81F-11D2-BA4B-00A0C93EC93B", Role::EfiSystem,            "EFI System",                   "Generic",  "EF00"},
    {"21686148-6449-6E6F-744E-656564454649", Role::BiosBoot,             "BIOS boot",                    "Generic",  "EF02"},
    {"D3BFE2DE-3DAF-11DF-BA40-E3A556D89593", Role::IntelFastFlash,       "Intel Fast Flash (iFFS)",      "Generic",  "EF01"},
    {"9E1A2D38-C612-4316-AA26-8B49521E5A8B", Role::PrepBoot,             "PowerPC PReP boot",            "Generic",  "4100"},
    {"F4019732-066E-4E12-8273-346C5641494F", Role::SonyBoot,             "Sony system partition",        "Generic",  "EF03"},
    {"BFBFAFE7-A34F-448A-9A5B-6213EB736C22", Role::LenovoBoot,           "Lenovo system partition",      "Generic",  "EF04"},
    {"E3C9E316-0B5C-4DB8-817D-F92DF00215AE", Role::MicrosoftReserved,    "Microsoft reserved",           "Windows",  "0C01"},
    {"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", Role::WindowsBasicData,     "Microsoft basic data",         "Windows",  "0700"},
    {"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", Role::WindowsLdmMetadata,   "Windows LDM metadata",         "Windows",  "4201"},
    {"AF9B60A0-1431-4F62-BC68-3311714A69AD", Role::WindowsLdmData,       "Windows LDM data",             "Windows",  "4200"},
    {"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", Role::WindowsRecovery,      "Windows Recovery Environment", "Windows",  "2700"},
    {"E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D", Role::WindowsStorageSpaces, "Windows Storage Spaces",       "Windows",  "4202"},
    {"0FC63DAF-8483-4772-8E79-3D69D8477DE4", Role::LinuxFilesystem,      "Linux filesystem",             "Linux",    "8300"},
    {"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", Role::LinuxSwap,            "Linux swap",                   "Linux",    "8200"},
    {"E6D6D379-F507-44C2-A23C-238F2A3DF928", Role::LinuxLvm,             "Linux LVM",                    "Linux",    "8E00"},
    {"A19D880F-05FC-4D3B-A006-743F0F84911E", Role::LinuxRaid,            "Linux RAID",                   "Linux",    "FD00"},
    {"933AC7E1-2EB4-4F13-B844-0E14E2AEF915", Role::LinuxHome,            "Linux /home",                  "Linux",    "8302"},
    {"3B8F8425-20E0-4F3B-907F-1A25A76F98E8", Role::LinuxServerData,      "Linux /srv",                   "Linux",    "8306"},
    {"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", Role::LinuxRoot,            "Linux root (x86-64)",          "Linux",    "8304"},
    {"44479540-F297-41B2-9AF7-D131D5F0458A", Role::LinuxRoot,            "Linux root (x86)",             "Linux",    "8303"},
    {"69DAD710-2CE4-4E3C-B16C-21A1D49ABED3", Role::LinuxRoot,            "Linux root (ARM 32-bit)",      "Linux",    "8307"},
    {"B921B045-1DF0-41C3-AF44-4C6F280D3FAE", Role::LinuxRoot,            "Linux root (ARM 64-bit)",      "Linux",    "8305"},
    {"8484680C-9521-48C6-9C11-B0720656F69E", Role::LinuxUsr,             "Linux /usr (x86-64)",          "Linux",    "8314"},
    {"4D21B016-B534-45C2-A9FB-5C16E091FD2D", Role::LinuxVar,             "Linux /var",                   "Linux",    "8310"},
    {"7EC6F557-3BC5-4ACA-B293-16EF5DF639D1", Role::LinuxVarTmp,          "Linux /var/tmp",               "Linux",    "8311"},
    {"CA7D7CCB-63ED-4C53-861C-1742536059CC", Role::LinuxLuks,            "Linux LUKS",                   "Linux",    "8309"},
    {"7FFEC5C9-2D00-49B7-8941-3EA10A5586B7", Role::LinuxDmCrypt,         "Linux dm-crypt",               "Linux",    "8308"},
    {"8DA63339-0007-60C0-C436-083AC8230908", Role::LinuxReserved,        "Linux reserved",               "Linux",    "8301"},
    {"BC13C2FF-59E6-4262-A352-B275FD6F7172", Role::LinuxExtendedBoot,    "Linux extended boot (XBOOTLDR)", "Linux",  "EA00"},
    {"48465300-0000-11AA-AA11-00306543ECAC", Role::AppleHfsPlus,         "Apple HFS/HFS+",               "Apple",    "AF00"},
    {"7C3457EF-0000-11AA-AA11-00306543ECAC", Role::AppleApfs,            "Apple APFS",                   "Apple",    "AF0A"},
    {"55465300-0000-11AA-AA11-00306543ECAC", Role::AppleUfs,             "Apple UFS",                    "Apple",    "AF01"},
    {"426F6F74-0000-11AA-AA11-00306543ECAC", Role::AppleBoot,            "Apple boot (Recovery HD)",     "Apple",    "AB00"},
    {"4C616265-6C00-11AA-AA11-00306543ECAC", Role::AppleLabel,           "Apple label",                  "Apple",    "AF03"},
    {"5265636F-7665-11AA-AA11-00306543ECAC", Role::AppleTvRecovery,      "Apple TV recovery",            "Apple",    "AF04"},
    {"53746F72-6167-11AA-AA11-00306543ECAC", Role::AppleCoreStorage,     "Apple Core Storage",           "Apple",    "AF05"},
    {"52414944-0000-11AA-AA11-00306543ECAC", Role::AppleRaid,            "Apple RAID",                   "Apple",    "AF02"},
    {"52414944-5F4F-11AA-AA11-00306543ECAC", Role::AppleRaidOffline,     "Apple RAID offline",           "Apple",    "AF06"},
    {"6A898CC3-1DD2-11B2-99A6-080020736631", Role::AppleZfs,             "Solaris /usr & Apple ZFS",     "Solaris",  "BF01"},
    {"6A82CB45-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris boot",                 "Solaris",  "BE00"},
    {"6A85CF4D-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris root",                 "Solaris",  "BF00"},
    {"6A87C46F-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris swap",                 "Solaris",  "BF02"},
    {"6A8B642B-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris backup",               "Solaris",  "BF03"},
    {"6A8EF2E9-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris /var",                 "Solaris",  "BF04"},
    {"6A90BA39-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris /home",                "Solaris",  "BF05"},
    {"6A9283A5-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris alternate sector",     "Solaris",  "BF06"},
    {"6A945A3B-1DD2-11B2-99A6-080020736631", Role::Solaris,              "Solaris reserved",             "Solaris",  "BF07"},
    {"516E7CB4-6ECF-11D6-8FF8-00022D09712B", Role::FreeBsdDisklabel,     "FreeBSD disklabel",            "BSD",      "A500"},
    {"83BD6B9D-7F41-11DC-BE0B-001560B84F0F", Role::FreeBsdBoot,          "FreeBSD boot",                 "BSD",      "A501"},
    {"516E7CB5-6ECF-11D6-8FF8-00022D09712B", Role::FreeBsdSwap,          "FreeBSD swap",                 "BSD",      "A502"},
    {"516E7CB6-6ECF-11D6-8FF8-00022D09712B", Role::FreeBsdUfs,           "FreeBSD UFS",                  "BSD",      "A503"},
    {"516E7CBA-6ECF-11D6-8FF8-00022D09712B", Role::FreeBsdZfs,           "FreeBSD ZFS",                  "BSD",      "A504"},
    {"516E7CB8-6ECF-11D6-8FF8-00022D09712B", Role::FreeBsdVinum,         "FreeBSD Vinum/RAID",           "BSD",      "A505"},
    {"49F48D32-B10E-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD swap",                  "BSD",      "A901"},
    {"49F48D5A-B10E-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD FFS",                   "BSD",      "A902"},
    {"49F48D82-B10E-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD LFS",                   "BSD",      "A903"},
    {"49F48DAA-B10E-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD RAID",                  "BSD",      "A904"},
    {"2DB519C4-B10F-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD concatenated",          "BSD",      "A905"},
    {"2DB519EC-B10F-11DC-B99B-0019D1879648", Role::NetBsd,               "NetBSD encrypted",             "BSD",      "A906"},
    {"824CC7A0-36A8-11E3-890A-952519AD3F61", Role::OpenBsd,              "OpenBSD data",                 "BSD",      "A600"},
    {"75894C1E-3AEB-11D3-B7C1-7B03A0000000", Role::HpUx,                 "HP-UX data",                   "HP-UX",    "C001"},
    {"E2A1E728-32E3-11D6-A682-7B03A0000000", Role::HpUx,                 "HP-UX service",                "HP-UX",    "C002"},
    {"42465331-3BA3-10F1-802A-4861696B7521", Role::Haiku,                "Haiku BFS",                    "Haiku",    "EB00"},
    {"AA31E02A-400F-11DB-9590-000C2911D1B8", Role::Vmware,               "VMware VMFS",                  "VMware",   "FB00"},
    {"9D275380-40AD-11DB-BF97-000C2911D1B8", Role::Vmware,               "VMware kcore crash protection", "VMware",  "FC00"},
    {"9198EFFC-31C0-11DB-8F78-000C2911D1B8", Role::Vmware,               "VMware reserved",              "VMware",   "FB01"},
    {"FE3A2A5D-4F32-41A7-B725-ACCC3285A309", Role::ChromeOs,             "ChromeOS kernel",              "ChromeOS", "7F00"},
    {"3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC", Role::ChromeOs,             "ChromeOS root",                "ChromeOS", "7F01"},
    {"2E0A753D-9E48-43B0-8337-B15192CB1B5E", Role::ChromeOs,             "ChromeOS reserved",            "ChromeOS", "7F02"},
    {"CEF5A9AD-73BC-4601-89F3-CDEEEEE321A1", Role::Qnx,                  "QNX6 power-safe filesystem",   "QNX",      "B300"},
    {"37AFFC90-EF7D-4E96-91C3-2D7AE055B174", Role::IbmGpfs,              "IBM General Parallel FS",      "IBM",      "7501"},
};

struct MbrRow {
    std::uint8_t id;
    Role role;
    const char* name;
    const char* group;
};

const MbrRow kMbrRows[] = {
    {0x00, Role::Empty,             "Empty",                        "Generic"},
    {0x01, Role::Fat12,             "FAT12",                        "DOS"},
    {0x04, Role::Fat16,             "FAT16 <32M",                   "DOS"},
    {0x05, Role::Extended,          "Extended",                     "Generic"},
    {0x06, Role::Fat16,             "FAT16",                        "DOS"},
    {0x07, Role::NtfsHpfsExfat,     "HPFS/NTFS/exFAT",              "Windows"},
    {0x0B, Role::Fat32,             "W95 FAT32",                    "Windows"},
    {0x0C, Role::Fat32,             "W95 FAT32 (LBA)",              "Windows"},
    {0x0E, Role::Fat16,             "W95 FAT16 (LBA)",              "Windows"},
    {0x0F, Role::Extended,          "W95 Extended (LBA)",           "Generic"},
    {0x11, Role::HiddenFat,         "Hidden FAT12",                 "DOS"},
    {0x12, Role::Diagnostics,       "Compaq diagnostics",           "Generic"},
    {0x14, Role::HiddenFat,         "Hidden FAT16 <32M",            "DOS"},
    {0x16, Role::HiddenFat,         "Hidden FAT16",                 "DOS"},
    {0x17, Role::HiddenNtfs,        "Hidden HPFS/NTFS",             "Windows"},
    {0x1B, Role::HiddenFat,         "Hidden W95 FAT32",             "Windows"},
    {0x1C, Role::HiddenFat,         "Hidden W95 FAT32 (LBA)",       "Windows"},
    {0x1E, Role::HiddenFat,         "Hidden W95 FAT16 (LBA)",       "Windows"},
    {0x27, Role::WindowsRecovery,   "Hidden NTFS WinRE",            "Windows"},
    {0x39, Role::Plan9,             "Plan 9",                       "Other"},
    {0x3C, Role::Other,             "PartitionMagic recovery",      "Other"},
    {0x41, Role::PrepBoot,          "PPC PReP Boot",                "Generic"},
    {0x42, Role::WindowsLdmData,    "SFS / Windows LDM",            "Windows"},
    {0x4D, Role::Qnx,               "QNX4.x",                       "QNX"},
    {0x4E, Role::Qnx,               "QNX4.x 2nd part",              "QNX"},
    {0x4F, Role::Qnx,               "QNX4.x 3rd part",              "QNX"},
    {0x52, Role::Other,             "CP/M",                         "Other"},
    {0x63, Role::Other,             "GNU HURD or SysV",             "Other"},
    {0x64, Role::Other,             "Novell Netware 286",           "Other"},
    {0x65, Role::Other,             "Novell Netware 386",           "Other"},
    {0x80, Role::Minix,             "Old Minix",                    "Linux"},
    {0x81, Role::Minix,             "Minix / old Linux",            "Linux"},
    {0x82, Role::LinuxSwap,         "Linux swap / Solaris",         "Linux"},
    {0x83, Role::LinuxFilesystem,   "Linux",                        "Linux"},
    {0x84, Role::Hibernation,       "OS/2 hidden or Intel hibernation", "Other"},
    {0x85, Role::Extended,          "Linux extended",               "Linux"},
    {0x86, Role::NtfsHpfsExfat,     "NTFS volume set",              "Windows"},
    {0x87, Role::NtfsHpfsExfat,     "NTFS volume set",              "Windows"},
    {0x88, Role::Other,             "Linux plaintext",              "Linux"},
    {0x8E, Role::LinuxLvm,          "Linux LVM",                    "Linux"},
    {0x9F, Role::Other,             "BSD/OS",                       "BSD"},
    {0xA0, Role::Hibernation,       "IBM Thinkpad hibernation",     "Other"},
    {0xA5, Role::FreeBsdDisklabel,  "FreeBSD",                      "BSD"},
    {0xA6, Role::OpenBsd,           "OpenBSD",                      "BSD"},
    {0xA7, Role::Other,             "NeXTSTEP",                     "Other"},
    {0xA8, Role::AppleUfs,          "Darwin UFS",                   "Apple"},
    {0xA9, Role::NetBsd,            "NetBSD",                       "BSD"},
    {0xAB, Role::AppleBoot,         "Darwin boot",                  "Apple"},
    {0xAF, Role::AppleHfsPlus,      "HFS / HFS+",                   "Apple"},
    {0xB7, Role::Other,             "BSDI fs",                      "BSD"},
    {0xB8, Role::Other,             "BSDI swap",                    "BSD"},
    {0xBC, Role::Other,             "Acronis FAT32 LBA",            "Other"},
    {0xBE, Role::Solaris,           "Solaris boot",                 "Solaris"},
    {0xBF, Role::Solaris,           "Solaris",                      "Solaris"},
    {0xDA, Role::NonFsData,         "Non-FS data",                  "Generic"},
    {0xDB, Role::Other,             "CP/M / CTOS",                  "Other"},
    {0xDE, Role::Diagnostics,       "Dell Utility",                 "Other"},
    {0xDF, Role::Other,             "BootIt",                       "Other"},
    {0xE1, Role::Other,             "DOS access",                   "DOS"},
    {0xE3, Role::Other,             "DOS R/O",                      "DOS"},
    {0xE4, Role::Other,             "SpeedStor",                    "Other"},
    {0xEA, Role::LinuxExtendedBoot, "Linux extended boot",          "Linux"},
    {0xEB, Role::Haiku,             "BeOS/Haiku fs",                "Haiku"},
    {0xEE, Role::GptProtective,     "GPT protective",               "Generic"},
    {0xEF, Role::EfiSystem,         "EFI (FAT-12/16/32)",           "Generic"},
    {0xF0, Role::Other,             "Linux/PA-RISC boot",           "Linux"},
    {0xF2, Role::Other,             "DOS secondary",                "DOS"},
    {0xFB, Role::Vmware,            "VMware VMFS",                  "VMware"},
    {0xFC, Role::Vmware,            "VMware VMKCORE",               "VMware"},
    {0xFD, Role::LinuxRaid,         "Linux raid autodetect",        "Linux"},
    {0xFE, Role::Other,             "LANstep",                      "Other"},
    {0xFF, Role::Other,             "BBT",                          "Other"},
};
// clang-format on

const std::vector<PartitionTypeInfo>& registry() {
    static const std::vector<PartitionTypeInfo> table = [] {
        std::vector<PartitionTypeInfo> v;
        for (const auto& r : kGptRows) {
            auto g = Uuid::parse(r.guid);
            v.push_back({PartitionType::gpt(*g), r.role, r.name, r.group, r.code});
        }
        for (const auto& r : kMbrRows) v.push_back({PartitionType::mbr(r.id), r.role, r.name, r.group, ""});
        return v;
    }();
    return table;
}

} // namespace

namespace types {

const PartitionTypeInfo* find(const PartitionType& type) {
    for (const auto& info : registry())
        if (info.type == type) return &info;
    return nullptr;
}

std::string name(const PartitionType& type) {
    if (const auto* info = find(type)) return info->name;
    return "Unknown (" + type.code() + ")";
}

Role role(const PartitionType& type) {
    if (const auto* info = find(type)) return info->role;
    return type.isEmpty() ? Role::Empty : Role::Unknown;
}

std::span<const PartitionTypeInfo> all() { return registry(); }

std::optional<PartitionType> forRole(Role r, TableType scheme) {
    for (const auto& info : registry())
        if (info.role == r && info.type.scheme == scheme) return info.type;
    return std::nullopt;
}

std::optional<PartitionType> fromSgdiskCode(std::string_view code) {
    for (const auto& info : registry())
        if (info.type.scheme == TableType::Gpt && iequals(info.sgdiskCode, code)) return info.type;
    return std::nullopt;
}

} // namespace types

} // namespace stein::pt
