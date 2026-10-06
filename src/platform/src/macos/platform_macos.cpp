// SPDX-License-Identifier: MIT
// macOS: IOKit enumeration of whole-disk IOMedia objects, raw access through
// /dev/rdiskN (sector-aligned, see AlignedDevice), mounts from getmntinfo(),
// image attach through hdiutil (raw images, no mount).
#include "stein/platform/platform.hpp"

#include "../aligned_device.hpp"
#include "stein/core/strings.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>
#include <IOKit/storage/IOStorageProtocolCharacteristics.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace stein::platform {

namespace {

std::string cfString(CFTypeRef ref) {
    if (!ref || CFGetTypeID(ref) != CFStringGetTypeID()) return {};
    auto s = static_cast<CFStringRef>(ref);
    char buf[512];
    if (CFStringGetCString(s, buf, sizeof buf, kCFStringEncodingUTF8)) return std::string(trim(buf));
    return {};
}

std::uint64_t cfNumber(CFTypeRef ref) {
    if (!ref || CFGetTypeID(ref) != CFNumberGetTypeID()) return 0;
    std::int64_t v = 0;
    CFNumberGetValue(static_cast<CFNumberRef>(ref), kCFNumberSInt64Type, &v);
    return static_cast<std::uint64_t>(v);
}

bool cfBool(CFTypeRef ref) {
    return ref && CFGetTypeID(ref) == CFBooleanGetTypeID() && CFBooleanGetValue(static_cast<CFBooleanRef>(ref));
}

// Property from the media object or any ancestor (device characteristics live on the driver).
CFTypeRef searchUp(io_object_t media, CFStringRef key) {
    return IORegistryEntrySearchCFProperty(media, kIOServicePlane, key, kCFAllocatorDefault, kIORegistryIterateRecursively | kIORegistryIterateParents);
}

Bus busFromInterconnect(const std::string& s) {
    const std::string l = toLower(s);
    if (l == "sata" || l == "ata" || l == "pata") return Bus::Ata;
    if (l == "sas" || l == "scsi" || l == "scsi parallel interface") return Bus::Scsi;
    if (l == "pci-express" || l == "nvme" || l == "apple fabric") return Bus::Nvme;
    if (l == "usb") return Bus::Usb;
    if (l == "secure digital" || l == "sd") return Bus::Sd;
    if (l == "virtual interface") return Bus::Virtual;
    if (l == "fibre channel interface" || l == "fibre channel") return Bus::Scsi;
    if (l == "thunderbolt") return Bus::Other;
    return Bus::Unknown;
}

Expected<DiskInfo> describeMedia(io_object_t media) {
    DiskInfo d;
    CFTypeRef bsd = IORegistryEntryCreateCFProperty(media, CFSTR(kIOBSDNameKey), kCFAllocatorDefault, 0);
    d.kernelName = cfString(bsd);
    if (bsd) CFRelease(bsd);
    if (d.kernelName.empty()) return fail(ErrorCategory::NotFound, "media has no BSD name");
    d.osPath = "/dev/r" + d.kernelName;
    CFTypeRef v;
    if ((v = IORegistryEntryCreateCFProperty(media, CFSTR(kIOMediaSizeKey), kCFAllocatorDefault, 0))) {
        d.geometry.sizeBytes = cfNumber(v);
        CFRelease(v);
    }
    if ((v = IORegistryEntryCreateCFProperty(media, CFSTR(kIOMediaPreferredBlockSizeKey), kCFAllocatorDefault, 0))) {
        d.geometry.logicalSectorSize = static_cast<std::uint32_t>(cfNumber(v));
        d.geometry.physicalSectorSize = d.geometry.logicalSectorSize;
        CFRelease(v);
    }
    if ((v = IORegistryEntryCreateCFProperty(media, CFSTR(kIOMediaRemovableKey), kCFAllocatorDefault, 0))) {
        d.removable = cfBool(v);
        CFRelease(v);
    }
    if ((v = IORegistryEntryCreateCFProperty(media, CFSTR(kIOMediaWritableKey), kCFAllocatorDefault, 0))) {
        d.readOnly = !cfBool(v);
        CFRelease(v);
    }
    if ((v = searchUp(media, CFSTR(kIOPropertyDeviceCharacteristicsKey)))) {
        if (CFGetTypeID(v) == CFDictionaryGetTypeID()) {
            auto dict = static_cast<CFDictionaryRef>(v);
            d.model = cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyProductNameKey)));
            d.vendor = cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyVendorNameKey)));
            d.serial = cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyProductSerialNumberKey)));
            d.firmware = cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyProductRevisionLevelKey)));
            const std::string medium = cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyMediumTypeKey)));
            d.rotational = medium == kIOPropertyMediumTypeRotationalKey;
        }
        CFRelease(v);
    }
    if ((v = searchUp(media, CFSTR(kIOPropertyProtocolCharacteristicsKey)))) {
        if (CFGetTypeID(v) == CFDictionaryGetTypeID()) {
            auto dict = static_cast<CFDictionaryRef>(v);
            d.bus = busFromInterconnect(cfString(CFDictionaryGetValue(dict, CFSTR(kIOPropertyPhysicalInterconnectTypeKey))));
        }
        CFRelease(v);
    }
    // Disk images: the media sits under an IOHDIXController / disk image driver.
    io_name_t cls{};
    io_object_t parent = IO_OBJECT_NULL;
    io_object_t cur = media;
    IOObjectRetain(cur);
    for (int depth = 0; depth < 8 && IORegistryEntryGetParentEntry(cur, kIOServicePlane, &parent) == KERN_SUCCESS; ++depth) {
        IOObjectRelease(cur);
        cur = parent;
        if (IOObjectGetClass(cur, cls) == KERN_SUCCESS) {
            const std::string c = cls;
            if (c.find("HDIX") != std::string::npos || c.find("DiskImage") != std::string::npos || c.find("AppleDiskImage") != std::string::npos) {
                d.isVirtual = true;
                d.bus = Bus::Loop;
                break;
            }
        }
    }
    IOObjectRelease(cur);
    if (d.bus == Bus::Virtual) d.isVirtual = true;
    return d;
}

class MacDisk final : public AlignedDevice {
public:
    MacDisk(int fd, std::string path, Geometry geo, bool ro) : m_fd(fd), m_path(std::move(path)), m_geometry(geo), m_readOnly(ro) {}
    ~MacDisk() override {
        if (m_fd >= 0) ::close(m_fd);
    }
    std::string name() const override { return m_path; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly; }
    Expected<void> flush() override {
        if (!m_readOnly && ::fsync(m_fd) != 0 && errno != EINVAL && errno != ENOTSUP) return fail(ErrorCategory::Io, "fsync: " + std::string(std::strerror(errno)), errno);
        return {};
    }
    Expected<void> discard(ByteCount offset, ByteCount length) override {
        if (auto r = checkRange(offset, length); !r) return r;
        if (m_readOnly) return fail(ErrorCategory::Permission, "device is opened read-only");
        dk_unmap_t unmap{};
        dk_extent_t extent{offset, length};
        unmap.extents = &extent;
        unmap.extentsCount = 1;
        if (::ioctl(m_fd, DKIOCUNMAP, &unmap) != 0) return BlockDevice::discard(offset, length);
        return {};
    }

protected:
    Expected<void> rawRead(ByteCount offset, std::span<std::byte> dst) override {
        std::size_t done = 0;
        while (done < dst.size()) {
            const ssize_t n = ::pread(m_fd, dst.data() + done, dst.size() - done, static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) continue;
                return fail(ErrorCategory::Io, "read " + m_path + " @" + std::to_string(offset + done) + ": " + std::strerror(errno), errno);
            }
            if (n == 0) return fail(ErrorCategory::OutOfRange, "short read at " + std::to_string(offset + done));
            done += static_cast<std::size_t>(n);
        }
        return {};
    }
    Expected<void> rawWrite(ByteCount offset, std::span<const std::byte> src) override {
        std::size_t done = 0;
        while (done < src.size()) {
            const ssize_t n = ::pwrite(m_fd, src.data() + done, src.size() - done, static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) continue;
                return fail(ErrorCategory::Io, "write " + m_path + " @" + std::to_string(offset + done) + ": " + std::strerror(errno), errno);
            }
            done += static_cast<std::size_t>(n);
        }
        return {};
    }

private:
    int m_fd;
    std::string m_path;
    Geometry m_geometry;
    bool m_readOnly;
};

// "/dev/disk2", "/dev/rdisk2", "disk2" -> "disk2"
std::string bsdName(const std::string& osPath) {
    std::string n = osPath;
    if (n.rfind("/dev/", 0) == 0) n = n.substr(5);
    if (n.rfind("r", 0) == 0 && n.rfind("rdisk", 0) == 0) n = n.substr(1);
    return n;
}

std::string runCommand(const std::string& cmd, int& status) {
    std::string out;
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) {
        status = -1;
        return out;
    }
    char buf[1024];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    status = ::pclose(p);
    return out;
}

std::string shellQuote(const std::string& s) {
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    return q + "'";
}

class MacPlatform final : public Platform {
public:
    std::string_view name() const override { return "macos"; }

    Expected<std::vector<DiskInfo>> enumerate() override {
        CFMutableDictionaryRef match = IOServiceMatching(kIOMediaClass);
        if (!match) return fail(ErrorCategory::Internal, "IOServiceMatching failed");
        CFDictionarySetValue(match, CFSTR(kIOMediaWholeKey), kCFBooleanTrue);
        io_iterator_t it = IO_OBJECT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) != KERN_SUCCESS) return fail(ErrorCategory::Io, "IOServiceGetMatchingServices failed");
        std::vector<DiskInfo> disks;
        for (io_object_t media = IOIteratorNext(it); media != IO_OBJECT_NULL; media = IOIteratorNext(it)) {
            if (auto d = describeMedia(media)) disks.push_back(std::move(*d));
            IOObjectRelease(media);
        }
        IOObjectRelease(it);
        std::sort(disks.begin(), disks.end(), [](const DiskInfo& a, const DiskInfo& b) {
            return std::stoi(a.kernelName.substr(4)) < std::stoi(b.kernelName.substr(4));
        });
        return disks;
    }

    Expected<DiskInfo> describe(const std::string& osPath) override {
        const std::string bsd = bsdName(osPath);
        io_object_t media = IOServiceGetMatchingService(kIOMainPortDefault, IOBSDNameMatching(kIOMainPortDefault, 0, bsd.c_str()));
        if (media == IO_OBJECT_NULL) return fail(ErrorCategory::NotFound, "no such disk: " + osPath);
        auto d = describeMedia(media);
        IOObjectRelease(media);
        return d;
    }

    Expected<std::shared_ptr<BlockDevice>> open(const std::string& osPath, OpenMode mode) override {
        // Always use the raw (character) node: unbuffered, and it is what the
        // partition-table re-read on close is keyed to.
        std::string path = osPath;
        const std::string bsd = bsdName(osPath);
        if (bsd.rfind("disk", 0) == 0) path = "/dev/r" + bsd;
        const bool ro = mode == OpenMode::ReadOnly;
        int flags = (ro ? O_RDONLY : O_RDWR) | O_CLOEXEC;
        if (mode == OpenMode::ReadWriteExclusive) flags |= O_EXLOCK | O_NONBLOCK;
        const int fd = ::open(path.c_str(), flags);
        if (fd < 0) {
            const int e = errno;
            if (e == EACCES || e == EPERM) return fail(ErrorCategory::Permission, "open " + path + ": " + std::strerror(e) + " (run with sudo)", e);
            if (e == EBUSY) return fail(ErrorCategory::Busy, "open " + path + ": device is busy (mounted volumes?)", e);
            if (e == ENOENT) return fail(ErrorCategory::NotFound, "open " + path + ": " + std::strerror(e), e);
            return fail(ErrorCategory::Io, "open " + path + ": " + std::strerror(e), e);
        }
        Geometry geo;
        std::uint32_t bs = 0;
        std::uint64_t count = 0;
        if (::ioctl(fd, DKIOCGETBLOCKSIZE, &bs) == 0 && bs) geo.logicalSectorSize = bs;
        if (::ioctl(fd, DKIOCGETBLOCKCOUNT, &count) == 0) geo.sizeBytes = count * geo.logicalSectorSize;
        std::uint32_t pbs = 0;
        geo.physicalSectorSize = (::ioctl(fd, DKIOCGETPHYSICALBLOCKSIZE, &pbs) == 0 && pbs) ? pbs : geo.logicalSectorSize;
        if (geo.sizeBytes == 0) {
            struct stat st{};
            if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) geo.sizeBytes = static_cast<ByteCount>(st.st_size);
        }
        if (geo.sizeBytes == 0) {
            ::close(fd);
            return fail(ErrorCategory::Io, "cannot determine the size of " + path);
        }
        return std::shared_ptr<BlockDevice>(std::make_shared<MacDisk>(fd, path, geo, ro));
    }

    Expected<std::vector<MountInfo>> mounts(const std::string& prefix) override {
        struct statfs* mnt = nullptr;
        const int n = ::getmntinfo(&mnt, MNT_NOWAIT);
        if (n <= 0) return fail(ErrorCategory::Io, "getmntinfo failed", errno);
        std::vector<MountInfo> out;
        const std::string want = prefix.empty() ? std::string() : "/dev/" + bsdName(prefix);
        for (int i = 0; i < n; ++i) {
            MountInfo m;
            m.source = mnt[i].f_mntfromname;
            m.target = mnt[i].f_mntonname;
            m.fsType = mnt[i].f_fstypename;
            m.readOnly = (mnt[i].f_flags & MNT_RDONLY) != 0;
            m.options = m.readOnly ? "ro" : "rw";
            if (!want.empty() && m.source.rfind(want, 0) != 0) continue;
            out.push_back(std::move(m));
        }
        return out;
    }

    Expected<void> unmount(const MountInfo& m, bool force) override {
        int status = 0;
        const std::string out = runCommand(std::string("diskutil unmount ") + (force ? "force " : "") + shellQuote(m.target) + " 2>&1", status);
        if (status != 0) return fail(ErrorCategory::Busy, "diskutil unmount " + m.target + ": " + std::string(trim(out)));
        return {};
    }

    Expected<void> rereadPartitionTable(const std::string&) override {
        // The kernel re-reads the table when the last writer closes the raw device.
        return {};
    }

    Expected<AttachedImage> attach(const std::filesystem::path& file, const AttachOptions& options) override {
        std::string cmd = "hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount";
        if (options.readOnly) cmd += " -readonly";
        cmd += " " + shellQuote(file.string()) + " 2>&1";
        int status = 0;
        const std::string out = runCommand(cmd, status);
        if (status != 0) return fail(ErrorCategory::Io, "hdiutil attach failed: " + std::string(trim(out)));
        // First line: "/dev/disk4 <tab> <content hint>"
        AttachedImage a;
        a.file = file;
        for (const auto& line : split(out, '\n')) {
            if (line.rfind("/dev/disk", 0) == 0) {
                a.osPath = std::string(trim(line.substr(0, line.find_first_of(" \t"))));
                break;
            }
        }
        if (a.osPath.empty()) return fail(ErrorCategory::Internal, "hdiutil attach gave no device: " + std::string(trim(out)));
        return a;
    }

    Expected<void> detach(const AttachedImage& attached) override {
        int status = 0;
        const std::string out = runCommand("hdiutil detach " + shellQuote(attached.osPath) + " 2>&1", status);
        if (status != 0) return fail(ErrorCategory::Io, "hdiutil detach failed: " + std::string(trim(out)));
        return {};
    }

    bool isElevated() const override { return ::geteuid() == 0; }
};

} // namespace

Platform& current() {
    static MacPlatform instance;
    return instance;
}

} // namespace stein::platform
