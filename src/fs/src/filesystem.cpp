// SPDX-License-Identifier: MIT
#include "stein/fs/filesystem.hpp"

#include "stein/core/guid.hpp"
#include "stein/core/strings.hpp"
#include "stein/fs/detail/simple_fs.hpp"

#include <cstdio>

namespace stein::fs {

std::string_view toString(FsType t) {
    switch (t) {
    case FsType::Unknown: return "unknown";
    case FsType::Ext2: return "ext2";
    case FsType::Ext3: return "ext3";
    case FsType::Ext4: return "ext4";
    case FsType::Fat12: return "vfat";
    case FsType::Fat16: return "vfat";
    case FsType::Fat32: return "vfat";
    case FsType::ExFat: return "exfat";
    case FsType::Ntfs: return "ntfs";
    case FsType::ReFs: return "refs";
    case FsType::Hfs: return "hfs";
    case FsType::HfsPlus: return "hfsplus";
    case FsType::HfsX: return "hfsplus";
    case FsType::Apfs: return "apfs";
    case FsType::Btrfs: return "btrfs";
    case FsType::Xfs: return "xfs";
    case FsType::F2fs: return "f2fs";
    case FsType::Jfs: return "jfs";
    case FsType::ReiserFs: return "reiserfs";
    case FsType::Reiser4: return "reiser4";
    case FsType::Nilfs2: return "nilfs2";
    case FsType::Bcachefs: return "bcachefs";
    case FsType::Ocfs2: return "ocfs2";
    case FsType::Minix: return "minix";
    case FsType::Erofs: return "erofs";
    case FsType::SquashFs: return "squashfs";
    case FsType::Udf: return "udf";
    case FsType::Iso9660: return "iso9660";
    case FsType::Zfs: return "zfs_member";
    case FsType::Ufs: return "ufs";
    case FsType::Swap: return "swap";
    case FsType::Luks1: return "crypto_LUKS";
    case FsType::Luks2: return "crypto_LUKS";
    case FsType::BitLocker: return "BitLocker";
    case FsType::Lvm2Pv: return "LVM2_member";
    case FsType::MdRaidMember: return "linux_raid_member";
    case FsType::BcacheMember: return "bcache";
    }
    return "?";
}

std::string_view displayName(FsType t) {
    switch (t) {
    case FsType::Fat12: return "FAT12";
    case FsType::Fat16: return "FAT16";
    case FsType::Fat32: return "FAT32";
    case FsType::ExFat: return "exFAT";
    case FsType::Ntfs: return "NTFS";
    case FsType::ReFs: return "ReFS";
    case FsType::Hfs: return "HFS";
    case FsType::HfsPlus: return "HFS+";
    case FsType::HfsX: return "HFSX";
    case FsType::Apfs: return "APFS";
    case FsType::Udf: return "UDF";
    case FsType::Iso9660: return "ISO 9660";
    case FsType::Zfs: return "ZFS member";
    case FsType::Ufs: return "UFS";
    case FsType::Swap: return "Linux swap";
    case FsType::Luks1: return "LUKS1 encrypted";
    case FsType::Luks2: return "LUKS2 encrypted";
    case FsType::BitLocker: return "BitLocker encrypted";
    case FsType::Lvm2Pv: return "LVM2 physical volume";
    case FsType::MdRaidMember: return "Linux RAID member";
    case FsType::BcacheMember: return "bcache member";
    case FsType::Unknown: return "unknown";
    default: return toString(t);
    }
}

bool isContainerMarker(FsType t) {
    switch (t) {
    case FsType::Luks1:
    case FsType::Luks2:
    case FsType::BitLocker:
    case FsType::Lvm2Pv:
    case FsType::MdRaidMember:
    case FsType::BcacheMember:
        return true;
    default:
        return false;
    }
}

std::uint32_t FileSystem::capabilities() const {
    std::uint32_t c = static_cast<std::uint32_t>(Capability::Identify);
    if (!info().label.empty()) c |= static_cast<std::uint32_t>(Capability::Label);
    if (!info().uuid.empty()) c |= static_cast<std::uint32_t>(Capability::Uuid);
    return c;
}

Expected<AllocationMap> FileSystem::allocationMap() const {
    return fail(ErrorCategory::Unsupported, std::string(displayName(type())) + ": allocation map not supported");
}

Expected<std::unique_ptr<Reader>> FileSystem::openReader(const ReaderOptions&) const {
    return fail(ErrorCategory::Unsupported, std::string(displayName(type())) + ": reading files is not supported yet");
}

std::uint32_t detail::SimpleFileSystem::capabilities() const {
    std::uint32_t c = FileSystem::capabilities();
    if (m_alloc) c |= static_cast<std::uint32_t>(Capability::UsedBlocks);
    if (m_reader) c |= static_cast<std::uint32_t>(Capability::Read);
    return c;
}

Expected<std::unique_ptr<Reader>> detail::SimpleFileSystem::openReader(const ReaderOptions& options) const {
    if (!m_reader) return FileSystem::openReader(options);
    return m_reader->openWith(m_device, options);
}

Expected<AllocationMap> detail::SimpleFileSystem::allocationMap() const {
    if (!m_alloc) return FileSystem::allocationMap();
    if (m_info.clean && !*m_info.clean)
        return fail(ErrorCategory::Busy, std::string(displayName(type())) + " was not cleanly unmounted; its allocation bitmap may be stale");
    return m_alloc->load(*m_device);
}

layout::Validity FileSystem::health() const {
    layout::Validity worst = layout::Validity::Ok;
    for (const auto& d : diagnostics())
        if (d.severity > worst) worst = d.severity;
    return worst;
}

Expected<std::unique_ptr<FileSystem>> probe(std::shared_ptr<BlockDevice> device) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    for (const auto& entry : detectors()) {
        auto r = entry.detect(device);
        if (r) return r;
        if (r.error().category() != ErrorCategory::NotFound) return fail(r.error());
    }
    return std::unique_ptr<FileSystem>(nullptr);
}

namespace detail {

Expected<std::vector<std::byte>> readOrNotFound(BlockDevice& device, ByteCount offset, ByteCount length) {
    if (auto chk = device.checkRange(offset, length); !chk) return fail(ErrorCategory::NotFound, "device too small");
    return device.read(offset, length);
}

std::string serialHex(std::uint32_t serial) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04X-%04X", serial >> 16, serial & 0xFFFF);
    return buf;
}

std::string hex64(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%016llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string uuidText(std::span<const std::byte> rfc16, bool upper) {
    if (rfc16.size() < 16) return {};
    return Uuid::fromRfcBytes(std::span<const std::byte, 16>(rfc16.data(), 16)).toString(upper);
}

std::string hyphenateLvmUuid(std::string_view raw) {
    if (raw.size() < 32) return std::string(raw);
    std::string s(raw.substr(0, 32));
    // 6-4-4-4-4-4-6
    std::string out;
    static constexpr int groups[] = {6, 4, 4, 4, 4, 4, 6};
    std::size_t pos = 0;
    for (int g : groups) {
        if (!out.empty()) out += '-';
        out += s.substr(pos, static_cast<std::size_t>(g));
        pos += static_cast<std::size_t>(g);
    }
    return out;
}

} // namespace detail

} // namespace stein::fs
