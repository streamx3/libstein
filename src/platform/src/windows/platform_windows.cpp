// SPDX-License-Identifier: MIT
// Windows: \\.\PhysicalDriveN enumeration and raw access (sector-aligned, see
// AlignedDevice), storage properties through IOCTL_STORAGE_QUERY_PROPERTY,
// volumes mapped to disks through IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
// Image attach is not implemented (Windows has no raw-image loop device;
// VHD/VHDX attach comes with the VHD reader in M3).
#include "stein/platform/platform.hpp"

#include "../aligned_device.hpp"
#include "stein/core/strings.hpp"

#include <windows.h>
#include <winioctl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>

namespace stein::platform {

namespace {

std::string lastErrorText(DWORD code) {
    char* buf = nullptr;
    const DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
                                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string s = n && buf ? std::string(buf, n) : "error " + std::to_string(code);
    if (buf) LocalFree(buf);
    return std::string(trim(s));
}

ErrorCategory categoryFor(DWORD code) {
    switch (code) {
    case ERROR_ACCESS_DENIED: return ErrorCategory::Permission;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_NOT_READY: return ErrorCategory::NotFound;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_BUSY: return ErrorCategory::Busy;
    case ERROR_WRITE_PROTECT: return ErrorCategory::Permission;
    default: return ErrorCategory::Io;
    }
}

Error winError(const std::string& what, DWORD code) { return Error(categoryFor(code), what + ": " + lastErrorText(code), static_cast<int>(code)); }

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE v) : h(v) {}
    ~Handle() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool ok() const { return h != INVALID_HANDLE_VALUE; }
    HANDLE release() {
        HANDLE v = h;
        h = INVALID_HANDLE_VALUE;
        return v;
    }
};

Bus busFromStorage(STORAGE_BUS_TYPE t) {
    switch (t) {
    case BusTypeAta:
    case BusTypeAtapi:
    case BusTypeSata: return Bus::Ata;
    case BusTypeScsi:
    case BusTypeSas:
    case BusTypeFibre:
    case BusTypeiScsi:
    case BusTypeRAID: return Bus::Scsi;
    case BusTypeNvme: return Bus::Nvme;
    case BusTypeUsb: return Bus::Usb;
    case BusTypeSd: return Bus::Sd;
    case BusTypeMmc: return Bus::Mmc;
    case BusTypeVirtual:
    case BusTypeFileBackedVirtual: return Bus::Virtual;
    case BusType1394:
    case BusTypeSsa: return Bus::Other;
    default: return Bus::Unknown;
    }
}

std::string physicalPath(unsigned n) { return "\\\\.\\PhysicalDrive" + std::to_string(n); }

// Accepts "\\.\PhysicalDrive3", "PhysicalDrive3", "3".
std::optional<unsigned> driveNumber(const std::string& path) {
    std::string s = path;
    const char* prefixes[] = {"\\\\.\\PhysicalDrive", "\\\\?\\PhysicalDrive", "PhysicalDrive", "physicaldrive"};
    for (const char* p : prefixes) {
        const std::string pre = p;
        if (toLower(s).rfind(toLower(pre), 0) == 0) {
            s = s.substr(pre.size());
            break;
        }
    }
    if (s.empty() || !std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) return std::nullopt;
    return static_cast<unsigned>(std::stoul(s));
}

Expected<Geometry> queryGeometry(HANDLE h) {
    Geometry geo;
    DISK_GEOMETRY_EX dg{};
    DWORD got = 0;
    if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &dg, sizeof dg, &got, nullptr)) {
        geo.sizeBytes = static_cast<ByteCount>(dg.DiskSize.QuadPart);
        if (dg.Geometry.BytesPerSector) geo.logicalSectorSize = dg.Geometry.BytesPerSector;
    }
    GET_LENGTH_INFORMATION li{};
    if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &li, sizeof li, &got, nullptr)) geo.sizeBytes = static_cast<ByteCount>(li.Length.QuadPart);
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageAccessAlignmentProperty;
    q.QueryType = PropertyStandardQuery;
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR al{};
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &al, sizeof al, &got, nullptr) && al.BytesPerLogicalSector) {
        geo.logicalSectorSize = al.BytesPerLogicalSector;
        geo.physicalSectorSize = al.BytesPerPhysicalSector ? al.BytesPerPhysicalSector : al.BytesPerLogicalSector;
        geo.alignmentOffset = al.BytesOffsetForSectorAlignment;
    } else {
        geo.physicalSectorSize = geo.logicalSectorSize;
    }
    if (geo.sizeBytes == 0) return fail(ErrorCategory::Io, "cannot determine disk size");
    return geo;
}

Expected<DiskInfo> describeHandle(HANDLE h, unsigned n) {
    DiskInfo d;
    d.osPath = physicalPath(n);
    d.kernelName = "PhysicalDrive" + std::to_string(n);
    auto geo = queryGeometry(h);
    if (!geo) return fail(geo.error());
    d.geometry = *geo;
    DWORD got = 0;
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    STORAGE_DESCRIPTOR_HEADER hdr{};
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &hdr, sizeof hdr, &got, nullptr) && hdr.Size >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        std::vector<std::byte> buf(hdr.Size);
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf.data(), hdr.Size, &got, nullptr)) {
            auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
            auto str = [&](DWORD off) {
                if (!off || off >= buf.size()) return std::string();
                const char* p = reinterpret_cast<const char*>(buf.data()) + off;
                return std::string(trim(std::string(p, strnlen(p, buf.size() - off))));
            };
            d.vendor = str(desc->VendorIdOffset);
            d.model = str(desc->ProductIdOffset);
            d.firmware = str(desc->ProductRevisionOffset);
            d.serial = str(desc->SerialNumberOffset);
            d.removable = desc->RemovableMedia != 0;
            d.bus = busFromStorage(desc->BusType);
            d.isVirtual = desc->BusType == BusTypeVirtual || desc->BusType == BusTypeFileBackedVirtual;
        }
    }
    q.PropertyId = StorageDeviceSeekPenaltyProperty;
    DEVICE_SEEK_PENALTY_DESCRIPTOR sp{};
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &sp, sizeof sp, &got, nullptr)) d.rotational = sp.IncursSeekPenalty != 0;
    DISK_GEOMETRY_EX dg{};
    if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &dg, sizeof dg, &got, nullptr))
        d.removable = d.removable || dg.Geometry.MediaType == RemovableMedia;
    if (DeviceIoControl(h, IOCTL_DISK_IS_WRITABLE, nullptr, 0, nullptr, 0, &got, nullptr) == 0 && GetLastError() == ERROR_WRITE_PROTECT) d.readOnly = true;
    return d;
}

class WinDisk final : public AlignedDevice {
public:
    WinDisk(HANDLE h, std::string path, Geometry geo, bool ro) : m_h(h), m_path(std::move(path)), m_geometry(geo), m_readOnly(ro) {}
    ~WinDisk() override {
        if (m_h != INVALID_HANDLE_VALUE) CloseHandle(m_h);
    }
    std::string name() const override { return m_path; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly; }
    Expected<void> flush() override {
        if (!m_readOnly && !FlushFileBuffers(m_h)) return fail(winError("flush " + m_path, GetLastError()));
        return {};
    }

protected:
    Expected<void> rawRead(ByteCount offset, std::span<std::byte> dst) override {
        std::size_t done = 0;
        while (done < dst.size()) {
            OVERLAPPED ov{};
            const ByteCount pos = offset + done;
            ov.Offset = static_cast<DWORD>(pos & 0xFFFFFFFFu);
            ov.OffsetHigh = static_cast<DWORD>(pos >> 32);
            DWORD n = 0;
            const DWORD want = static_cast<DWORD>(std::min<std::size_t>(dst.size() - done, 32u * 1024 * 1024));
            if (!ReadFile(m_h, dst.data() + done, want, &n, &ov)) return fail(winError("read " + m_path + " @" + std::to_string(pos), GetLastError()));
            if (n == 0) return fail(ErrorCategory::OutOfRange, "short read at " + std::to_string(pos));
            done += n;
        }
        return {};
    }
    Expected<void> rawWrite(ByteCount offset, std::span<const std::byte> src) override {
        std::size_t done = 0;
        while (done < src.size()) {
            OVERLAPPED ov{};
            const ByteCount pos = offset + done;
            ov.Offset = static_cast<DWORD>(pos & 0xFFFFFFFFu);
            ov.OffsetHigh = static_cast<DWORD>(pos >> 32);
            DWORD n = 0;
            const DWORD want = static_cast<DWORD>(std::min<std::size_t>(src.size() - done, 32u * 1024 * 1024));
            if (!WriteFile(m_h, src.data() + done, want, &n, &ov)) return fail(winError("write " + m_path + " @" + std::to_string(pos), GetLastError()));
            if (n == 0) return fail(ErrorCategory::Io, "zero-length write at " + std::to_string(pos));
            done += n;
        }
        return {};
    }

private:
    HANDLE m_h;
    std::string m_path;
    Geometry m_geometry;
    bool m_readOnly;
};

class WinPlatform final : public Platform {
public:
    std::string_view name() const override { return "windows"; }

    Expected<std::vector<DiskInfo>> enumerate() override {
        std::vector<DiskInfo> disks;
        unsigned misses = 0;
        for (unsigned n = 0; n < 256 && misses < 16; ++n) {
            Handle h(CreateFileW(widen(physicalPath(n)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
            if (!h.ok()) {
                ++misses;
                continue;
            }
            misses = 0;
            if (auto d = describeHandle(h.h, n)) disks.push_back(std::move(*d));
        }
        return disks;
    }

    Expected<DiskInfo> describe(const std::string& osPath) override {
        auto n = driveNumber(osPath);
        if (!n) return fail(ErrorCategory::InvalidArgument, "not a physical drive path: " + osPath);
        Handle h(CreateFileW(widen(physicalPath(*n)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h.ok()) return fail(winError("open " + physicalPath(*n), GetLastError()));
        return describeHandle(h.h, *n);
    }

    Expected<std::shared_ptr<BlockDevice>> open(const std::string& osPath, OpenMode mode) override {
        auto n = driveNumber(osPath);
        const std::string path = n ? physicalPath(*n) : osPath;
        const bool ro = mode == OpenMode::ReadOnly;
        const DWORD access = GENERIC_READ | (ro ? 0 : GENERIC_WRITE);
        const DWORD share = mode == OpenMode::ReadWriteExclusive ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE);
        Handle h(CreateFileW(widen(path).c_str(), access, share, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h.ok()) {
            const DWORD e = GetLastError();
            if (e == ERROR_ACCESS_DENIED) return fail(Error(ErrorCategory::Permission, "open " + path + ": access denied (run as Administrator)", static_cast<int>(e)));
            return fail(winError("open " + path, e));
        }
        auto geo = queryGeometry(h.h);
        if (!geo) {
            // A regular file given by a device-style path.
            LARGE_INTEGER sz{};
            if (!GetFileSizeEx(h.h, &sz) || sz.QuadPart <= 0) return fail(geo.error());
            geo = Geometry{};
            geo->sizeBytes = static_cast<ByteCount>(sz.QuadPart);
        }
        if (!ro) {
            // Windows refuses writes to sectors covered by mounted volumes unless they are
            // locked or dismounted; locking happens per volume in stein_ops later (M2).
            DWORD got = 0;
            DeviceIoControl(h.h, FSCTL_ALLOW_EXTENDED_DASD_IO, nullptr, 0, nullptr, 0, &got, nullptr);
        }
        return std::shared_ptr<BlockDevice>(std::make_shared<WinDisk>(h.release(), path, *geo, ro));
    }

    Expected<std::vector<MountInfo>> mounts(const std::string& prefix) override {
        std::vector<MountInfo> out;
        std::optional<unsigned> want;
        if (!prefix.empty()) want = driveNumber(prefix);
        const DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (!(mask & (1u << i))) continue;
            const std::string letter = std::string(1, static_cast<char>('A' + i)) + ":";
            Handle h(CreateFileW(widen("\\\\.\\" + letter).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
            MountInfo m;
            m.source = "\\\\.\\" + letter;
            m.target = letter + "\\";
            std::optional<unsigned> disk;
            if (h.ok()) {
                std::vector<std::byte> buf(sizeof(VOLUME_DISK_EXTENTS) + 32 * sizeof(DISK_EXTENT));
                DWORD got = 0;
                if (DeviceIoControl(h.h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
                    auto* ext = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buf.data());
                    if (ext->NumberOfDiskExtents >= 1) {
                        disk = ext->Extents[0].DiskNumber;
                        m.options = "disk=" + std::to_string(ext->Extents[0].DiskNumber) + " offset=" + std::to_string(ext->Extents[0].StartingOffset.QuadPart) +
                                    " length=" + std::to_string(ext->Extents[0].ExtentLength.QuadPart);
                        if (ext->NumberOfDiskExtents > 1) m.options += " spanned";
                    }
                }
            }
            wchar_t fsName[64] = {};
            DWORD flags = 0;
            if (GetVolumeInformationW(widen(m.target).c_str(), nullptr, 0, nullptr, nullptr, &flags, fsName, 64)) {
                m.fsType = toLower(narrow(fsName));
                m.readOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;
            } else {
                continue;   // no media / not ready
            }
            m.options = (m.readOnly ? std::string("ro") : std::string("rw")) + (m.options.empty() ? "" : " " + m.options);
            if (want && disk != want) continue;
            out.push_back(std::move(m));
        }
        return out;
    }

    Expected<void> rereadPartitionTable(const std::string& osPath) override {
        auto n = driveNumber(osPath);
        if (!n) return fail(ErrorCategory::InvalidArgument, "not a physical drive path: " + osPath);
        Handle h(CreateFileW(widen(physicalPath(*n)).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h.ok()) return fail(winError("open " + physicalPath(*n), GetLastError()));
        DWORD got = 0;
        if (!DeviceIoControl(h.h, IOCTL_DISK_UPDATE_PROPERTIES, nullptr, 0, nullptr, 0, &got, nullptr)) return fail(winError("IOCTL_DISK_UPDATE_PROPERTIES", GetLastError()));
        return {};
    }

    Expected<AttachedImage> attach(const std::filesystem::path&, const AttachOptions&) override {
        return fail(ErrorCategory::Unsupported, "Windows cannot attach raw images natively; VHD/VHDX attach arrives with the VHD reader");
    }
    Expected<void> detach(const AttachedImage&) override { return fail(ErrorCategory::Unsupported, "not implemented"); }

    bool isElevated() const override {
        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        PSID admins = nullptr;
        BOOL member = FALSE;
        if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins)) {
            if (!CheckTokenMembership(nullptr, admins, &member)) member = FALSE;
            FreeSid(admins);
        }
        return member != FALSE;
    }
};

} // namespace

Platform& current() {
    static WinPlatform instance;
    return instance;
}

} // namespace stein::platform
