// SPDX-License-Identifier: MIT
// Linux: sysfs enumeration, raw block devices via open()/pread()/pwrite() and
// the BLK* ioctls, /proc/self/mountinfo, loop devices via /dev/loop-control.
#include "stein/core/strings.hpp"
#include "stein/platform/platform.hpp"

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>

namespace stein::platform {

namespace {

std::string readSysfs(const std::filesystem::path& p) {
    std::ifstream in(p);
    if (!in) return {};
    std::string s;
    std::getline(in, s);
    return std::string(trim(s));
}

std::uint64_t readSysfsU64(const std::filesystem::path& p, std::uint64_t def = 0) {
    const std::string s = readSysfs(p);
    if (s.empty()) return def;
    return std::strtoull(s.c_str(), nullptr, 10);
}

Bus busFor(const std::string& kernelName, const std::filesystem::path& sys) {
    if (startsWith(kernelName, "loop")) return Bus::Loop;
    if (startsWith(kernelName, "nbd")) return Bus::Nbd;
    if (startsWith(kernelName, "dm-")) return Bus::DeviceMapper;
    if (startsWith(kernelName, "md")) return Bus::Md;
    if (startsWith(kernelName, "zram") || startsWith(kernelName, "ram")) return Bus::Virtual;
    if (startsWith(kernelName, "nvme")) return Bus::Nvme;
    if (startsWith(kernelName, "mmcblk")) return Bus::Mmc;
    if (startsWith(kernelName, "vd") || startsWith(kernelName, "xvd")) return Bus::Virtual;
    // Walk the device link for a transport hint.
    std::error_code ec;
    const auto link = std::filesystem::read_symlink(sys / "device", ec);
    const std::string path = ec ? "" : std::filesystem::weakly_canonical(sys / "device", ec).string();
    if (path.find("/usb") != std::string::npos) return Bus::Usb;
    if (path.find("/ata") != std::string::npos) return Bus::Ata;
    if (path.find("/virtio") != std::string::npos) return Bus::Virtual;
    if (startsWith(kernelName, "sd") || startsWith(kernelName, "sr")) return Bus::Scsi;
    return Bus::Unknown;
}

DiskInfo describeSysfs(const std::string& kernelName) {
    const std::filesystem::path sys = std::filesystem::path("/sys/class/block") / kernelName;
    DiskInfo d;
    d.kernelName = kernelName;
    d.osPath = "/dev/" + kernelName;
    d.geometry.sizeBytes = readSysfsU64(sys / "size") * 512;   // sysfs size is always in 512-byte units
    d.geometry.logicalSectorSize = static_cast<std::uint32_t>(readSysfsU64(sys / "queue/logical_block_size", 512));
    d.geometry.physicalSectorSize = static_cast<std::uint32_t>(readSysfsU64(sys / "queue/physical_block_size", d.geometry.logicalSectorSize));
    d.geometry.optimalIoSize = static_cast<std::uint32_t>(readSysfsU64(sys / "queue/optimal_io_size", 0));
    d.geometry.alignmentOffset = readSysfsU64(sys / "alignment_offset", 0);
    d.removable = readSysfsU64(sys / "removable") == 1;
    d.rotational = readSysfsU64(sys / "queue/rotational") == 1;
    d.readOnly = readSysfsU64(sys / "ro") == 1;
    d.bus = busFor(kernelName, sys);
    d.isVirtual = d.bus == Bus::Loop || d.bus == Bus::Nbd || d.bus == Bus::DeviceMapper || d.bus == Bus::Md || d.bus == Bus::Virtual;
    d.model = readSysfs(sys / "device/model");
    d.vendor = readSysfs(sys / "device/vendor");
    d.serial = readSysfs(sys / "device/serial");
    d.firmware = readSysfs(sys / "device/rev");
    if (d.firmware.empty()) d.firmware = readSysfs(sys / "device/firmware_rev");
    d.wwn = readSysfs(sys / "device/wwid");
    if (d.wwn.empty()) d.wwn = readSysfs(sys / "wwid");
    if (d.bus == Bus::Loop) {
        const std::string backing = readSysfs(sys / "loop/backing_file");
        if (!backing.empty()) d.backingFile = backing;
    }
    // Serial via /dev/disk/by-id when sysfs has none (SATA through libata exposes it only there).
    if (d.serial.empty()) {
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator("/dev/disk/by-id", ec)) {
            std::error_code ec2;
            const auto target = std::filesystem::read_symlink(e.path(), ec2);
            if (ec2 || target.filename() != kernelName) continue;
            const std::string n = e.path().filename().string();
            if (startsWith(n, "wwn-") || n.find("-part") != std::string::npos) continue;
            const auto us = n.rfind('_');
            if (us != std::string::npos) d.serial = n.substr(us + 1);
            break;
        }
    }
    return d;
}

bool isWholeDisk(const std::string& kernelName) {
    const std::filesystem::path sys = std::filesystem::path("/sys/class/block") / kernelName;
    std::error_code ec;
    return !std::filesystem::exists(sys / "partition", ec);
}

class LinuxDisk final : public BlockDevice {
public:
    LinuxDisk(int fd, std::string path, Geometry geo, bool ro) : m_fd(fd), m_path(std::move(path)), m_geometry(geo), m_readOnly(ro) {}
    ~LinuxDisk() override {
        if (m_fd >= 0) ::close(m_fd);
    }
    std::string name() const override { return m_path; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_readOnly; }

    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        std::size_t done = 0;
        while (done < dst.size()) {
            const ssize_t n = ::pread(m_fd, dst.data() + done, dst.size() - done, static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) continue;
                return fail(ErrorCategory::Io, "read failed on " + m_path + " at " + std::to_string(offset + done) + ": " + std::strerror(errno), errno);
            }
            if (n == 0) return fail(ErrorCategory::Io, "short read on " + m_path + " at " + std::to_string(offset + done));
            done += static_cast<std::size_t>(n);
        }
        return {};
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        if (m_readOnly) return fail(ErrorCategory::Permission, m_path + " is opened read-only");
        if (auto r = checkRange(offset, src.size()); !r) return r;
        std::size_t done = 0;
        while (done < src.size()) {
            const ssize_t n = ::pwrite(m_fd, src.data() + done, src.size() - done, static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) continue;
                return fail(ErrorCategory::Io, "write failed on " + m_path + " at " + std::to_string(offset + done) + ": " + std::strerror(errno), errno);
            }
            done += static_cast<std::size_t>(n);
        }
        return {};
    }
    Expected<void> flush() override {
        if (m_readOnly) return {};
        if (::fsync(m_fd) != 0 && errno != EINVAL && errno != EROFS)
            return fail(ErrorCategory::Io, "fsync failed on " + m_path + ": " + std::strerror(errno), errno);
        return {};
    }
    Expected<void> discard(ByteCount offset, ByteCount length) override {
        if (m_readOnly) return fail(ErrorCategory::Permission, m_path + " is opened read-only");
        if (auto r = checkRange(offset, length); !r) return r;
        std::uint64_t range[2] = {offset, length};
        if (::ioctl(m_fd, BLKDISCARD, range) != 0)
            return fail(ErrorCategory::Unsupported, "BLKDISCARD failed on " + m_path + ": " + std::strerror(errno), errno);
        return {};
    }
    int fd() const { return m_fd; }

private:
    int m_fd;
    std::string m_path;
    Geometry m_geometry;
    bool m_readOnly;
};

class LinuxPlatform final : public Platform {
public:
    std::string_view name() const override { return "linux"; }

    Expected<std::vector<DiskInfo>> enumerate() override {
        std::vector<DiskInfo> out;
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator("/sys/class/block", ec)) {
            const std::string n = e.path().filename().string();
            if (!isWholeDisk(n)) continue;
            DiskInfo d = describeSysfs(n);
            if (d.geometry.sizeBytes == 0 && d.bus == Bus::Loop) continue;   // unused loop slots
            if (startsWith(n, "ram")) continue;                               // brd ramdisks are noise
            out.push_back(std::move(d));
        }
        if (ec) return fail(ErrorCategory::Io, "cannot list /sys/class/block: " + ec.message(), ec.value());
        std::sort(out.begin(), out.end(), [](const DiskInfo& a, const DiskInfo& b) { return a.kernelName < b.kernelName; });
        return out;
    }

    Expected<DiskInfo> describe(const std::string& osPath) override {
        struct stat st{};
        if (::stat(osPath.c_str(), &st) != 0) return fail(ErrorCategory::NotFound, "cannot stat " + osPath + ": " + std::strerror(errno), errno);
        if (!S_ISBLK(st.st_mode)) return fail(ErrorCategory::InvalidArgument, osPath + " is not a block device");
        // Resolve major:minor to the sysfs name (handles /dev/disk/by-id/... symlinks and partitions).
        const std::filesystem::path sysDev = "/sys/dev/block/" + std::to_string(major(st.st_rdev)) + ":" + std::to_string(minor(st.st_rdev));
        std::error_code ec;
        const auto canon = std::filesystem::weakly_canonical(sysDev, ec);
        if (ec) return fail(ErrorCategory::NotFound, "no sysfs entry for " + osPath);
        DiskInfo d = describeSysfs(canon.filename().string());
        d.osPath = osPath;
        return d;
    }

    Expected<std::shared_ptr<BlockDevice>> open(const std::string& osPath, OpenMode mode) override {
        int flags = (mode == OpenMode::ReadOnly ? O_RDONLY : O_RDWR) | O_CLOEXEC;
        if (mode == OpenMode::ReadWriteExclusive) flags |= O_EXCL;
        const int fd = ::open(osPath.c_str(), flags);
        if (fd < 0) {
            const int e = errno;
            const ErrorCategory cat = (e == EACCES || e == EPERM) ? ErrorCategory::Permission : (e == EBUSY ? ErrorCategory::Busy : (e == ENOENT ? ErrorCategory::NotFound : ErrorCategory::Io));
            return fail(cat, "cannot open " + osPath + ": " + std::strerror(e), e);
        }
        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            ::close(fd);
            return fail(ErrorCategory::Io, "fstat failed on " + osPath, errno);
        }
        Geometry geo;
        if (S_ISBLK(st.st_mode)) {
            std::uint64_t size = 0;
            int lss = 512, pss = 512, opt = 0, align = 0;
            if (::ioctl(fd, BLKGETSIZE64, &size) != 0) {
                ::close(fd);
                return fail(ErrorCategory::Io, "BLKGETSIZE64 failed on " + osPath, errno);
            }
            ::ioctl(fd, BLKSSZGET, &lss);
            ::ioctl(fd, BLKPBSZGET, &pss);
            ::ioctl(fd, BLKIOOPT, &opt);
            ::ioctl(fd, BLKALIGNOFF, &align);
            geo.sizeBytes = size;
            geo.logicalSectorSize = static_cast<std::uint32_t>(lss > 0 ? lss : 512);
            geo.physicalSectorSize = static_cast<std::uint32_t>(pss > 0 ? pss : geo.logicalSectorSize);
            geo.optimalIoSize = static_cast<std::uint32_t>(opt > 0 ? opt : 0);
            geo.alignmentOffset = align > 0 ? static_cast<ByteCount>(align) : 0;
        } else if (S_ISREG(st.st_mode)) {
            geo.sizeBytes = static_cast<ByteCount>(st.st_size);
        } else {
            ::close(fd);
            return fail(ErrorCategory::InvalidArgument, osPath + " is neither a block device nor a regular file");
        }
        return std::shared_ptr<BlockDevice>(std::make_shared<LinuxDisk>(fd, osPath, geo, mode == OpenMode::ReadOnly));
    }

    Expected<std::vector<MountInfo>> mounts(const std::string& prefix) override {
        std::ifstream in("/proc/self/mountinfo");
        if (!in) return fail(ErrorCategory::Io, "cannot read /proc/self/mountinfo");
        std::vector<MountInfo> out;
        std::string line;
        while (std::getline(in, line)) {
            // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
            auto fields = split(line, ' ', true);
            auto sep = std::find(fields.begin(), fields.end(), std::string("-"));
            if (fields.size() < 7 || sep == fields.end() || std::distance(sep, fields.end()) < 4) continue;
            MountInfo m;
            m.target = fields[4];
            m.options = fields[5];
            m.fsType = *(sep + 1);
            m.source = *(sep + 2);
            m.readOnly = startsWith(m.options, "ro,") || m.options == "ro";
            // mountinfo escapes spaces as \040
            for (std::string* s : {&m.target, &m.source}) {
                std::string::size_type pos;
                while ((pos = s->find("\\040")) != std::string::npos) s->replace(pos, 4, " ");
            }
            if (!prefix.empty() && !startsWith(m.source, prefix)) continue;
            out.push_back(std::move(m));
        }
        return out;
    }

    Expected<void> unmount(const MountInfo& m, bool force) override {
        if (::umount2(m.target.c_str(), force ? (MNT_FORCE | MNT_DETACH) : 0) != 0) {
            const int e = errno;
            const ErrorCategory cat = e == EBUSY ? ErrorCategory::Busy : (e == EPERM || e == EACCES) ? ErrorCategory::Permission : ErrorCategory::Io;
            return fail(cat, "umount " + m.target + ": " + std::strerror(e), e);
        }
        return {};
    }

    Expected<void> rereadPartitionTable(const std::string& osPath) override {
        const int fd = ::open(osPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return fail(ErrorCategory::Io, "cannot open " + osPath, errno);
        const int rc = ::ioctl(fd, BLKRRPART, nullptr);
        const int e = errno;
        ::close(fd);
        if (rc != 0) return fail(e == EBUSY ? ErrorCategory::Busy : ErrorCategory::Io, "BLKRRPART failed on " + osPath + ": " + std::strerror(e), e);
        return {};
    }

    Expected<AttachedImage> attach(const std::filesystem::path& file, const AttachOptions& options) override {
        const int ctl = ::open("/dev/loop-control", O_RDWR | O_CLOEXEC);
        if (ctl < 0) return fail(errno == EACCES || errno == EPERM ? ErrorCategory::Permission : ErrorCategory::Io, "cannot open /dev/loop-control: " + std::string(std::strerror(errno)), errno);
        const int ffd = ::open(file.c_str(), (options.readOnly ? O_RDONLY : O_RDWR) | O_CLOEXEC);
        if (ffd < 0) {
            const int e = errno;
            ::close(ctl);
            return fail(ErrorCategory::Io, "cannot open " + file.string() + ": " + std::strerror(e), e);
        }
        for (int attempt = 0; attempt < 8; ++attempt) {
            const int index = ::ioctl(ctl, LOOP_CTL_GET_FREE);
            if (index < 0) {
                const int e = errno;
                ::close(ffd);
                ::close(ctl);
                return fail(ErrorCategory::Io, "LOOP_CTL_GET_FREE failed: " + std::string(std::strerror(e)), e);
            }
            const std::string path = "/dev/loop" + std::to_string(index);
            const int lfd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
            if (lfd < 0) continue;
            struct loop_config cfg{};
            cfg.fd = static_cast<std::uint32_t>(ffd);
            cfg.block_size = options.sectorSize;
            cfg.info.lo_flags = (options.readOnly ? static_cast<std::uint32_t>(LO_FLAGS_READ_ONLY) : 0u) |
                                (options.partitionScan ? static_cast<std::uint32_t>(LO_FLAGS_PARTSCAN) : 0u);
            std::strncpy(reinterpret_cast<char*>(cfg.info.lo_file_name), file.string().c_str(), LO_NAME_SIZE - 1);
            if (::ioctl(lfd, LOOP_CONFIGURE, &cfg) == 0) {
                ::close(lfd);
                ::close(ffd);
                ::close(ctl);
                return AttachedImage{path, file};
            }
            const int e = errno;
            ::close(lfd);
            if (e == EBUSY) continue;   // raced with someone else; try another slot
            ::close(ffd);
            ::close(ctl);
            return fail(ErrorCategory::Io, "LOOP_CONFIGURE failed on " + path + ": " + std::strerror(e), e);
        }
        ::close(ffd);
        ::close(ctl);
        return fail(ErrorCategory::Busy, "no free loop device after several attempts");
    }

    Expected<void> detach(const AttachedImage& attached) override {
        const int lfd = ::open(attached.osPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (lfd < 0) return fail(ErrorCategory::NotFound, "cannot open " + attached.osPath, errno);
        const int rc = ::ioctl(lfd, LOOP_CLR_FD, 0);
        const int e = errno;
        ::close(lfd);
        if (rc != 0) return fail(e == EBUSY ? ErrorCategory::Busy : ErrorCategory::Io, "LOOP_CLR_FD failed on " + attached.osPath + ": " + std::strerror(e), e);
        return {};
    }

    bool isElevated() const override { return ::geteuid() == 0; }
};

} // namespace

Platform& current() {
    static LinuxPlatform instance;
    return instance;
}

} // namespace stein::platform
