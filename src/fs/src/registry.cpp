// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/fs/filesystem.hpp"

namespace stein::fs {

std::span<const DetectorEntry> detectors() {
    using namespace detail;
    // Order matters: containers and markers first (their signatures are unambiguous and they may
    // wrap a filesystem), then formats with magic at fixed offsets, then boot-sector formats from
    // most to least specific (FAT last: its heuristics are the loosest), then optical and odd ones.
    static const DetectorEntry kEntries[] = {
        {"luks", detectLuks},         {"lvm2", detectLvm},          {"md", detectMd},
        {"bitlocker", detectBitLocker}, {"swap", detectSwap},       {"zfs", detectZfs},
        {"ext", detectExt},           {"btrfs", detectBtrfs},       {"xfs", detectXfs},
        {"f2fs", detectF2fs},         {"jfs", detectJfs},           {"reiserfs", detectReiserFs},
        {"reiser4", detectReiser4},   {"nilfs2", detectNilfs2},     {"bcachefs", detectBcachefs},
        {"ocfs2", detectOcfs2},       {"erofs", detectErofs},       {"hfsplus", detectHfsPlus},
        {"hfs", detectHfs},           {"apfs", detectApfs},         {"ntfs", detectNtfs},
        {"exfat", detectExFat},       {"refs", detectReFs},         {"fat", detectFat},
        {"iso9660", detectIso9660},   {"udf", detectUdf},           {"squashfs", detectSquashFs},
        {"minix", detectMinix},       {"ufs", detectUfs},
    };
    return kEntries;
}

} // namespace stein::fs
