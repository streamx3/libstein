// SPDX-License-Identifier: MIT
#include "stein/block/file_device.hpp"

#include <cerrno>
#include <mutex>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#include <winioctl.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace stein {

Expected<std::shared_ptr<FileDevice>> FileDevice::open(const std::filesystem::path& path, Mode mode,
                                                       std::uint32_t sectorSize) {
    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(path, ec);
    if (ec) return fail(ErrorCategory::NotFound, "cannot stat " + path.string() + ": " + ec.message(), ec.value());
    if (sectorSize == 0 || (sectorSize & (sectorSize - 1)) != 0)
        return fail(ErrorCategory::InvalidArgument, "sector size must be a power of two");

    auto dev = std::shared_ptr<FileDevice>(new FileDevice());
    dev->m_path = path;
    dev->m_mode = mode;
    auto flags = std::ios::binary | std::ios::in;
    if (mode == Mode::ReadWrite) flags |= std::ios::out;
    dev->m_stream.open(path, flags);
    if (!dev->m_stream.is_open())
        return fail(ErrorCategory::Io, "cannot open " + path.string(), errno);
    dev->m_geometry.sizeBytes = fileSize;
    dev->m_geometry.logicalSectorSize = sectorSize;
    dev->m_geometry.physicalSectorSize = sectorSize;
    return dev;
}

Expected<std::shared_ptr<FileDevice>> FileDevice::create(const std::filesystem::path& path, ByteCount size,
                                                         std::uint32_t sectorSize) {
    {
        std::ofstream touch(path, std::ios::binary | std::ios::trunc);
        if (!touch) return fail(ErrorCategory::Io, "cannot create " + path.string(), errno);
    }
    std::error_code ec;
    std::filesystem::resize_file(path, size, ec);   // sparse where the filesystem supports it
    if (ec) return fail(ErrorCategory::Io, "cannot size " + path.string() + ": " + ec.message(), ec.value());
    return open(path, Mode::ReadWrite, sectorSize);
}

Expected<void> FileDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    std::lock_guard lock(m_mutex);
    m_stream.clear();
    m_stream.seekg(static_cast<std::streamoff>(offset));
    m_stream.read(reinterpret_cast<char*>(dst.data()), static_cast<std::streamsize>(dst.size()));
    if (static_cast<std::size_t>(m_stream.gcount()) != dst.size())
        return fail(ErrorCategory::Io, "short read from " + m_path.string() + " at " + std::to_string(offset));
    return {};
}

Expected<void> FileDevice::writeAt(ByteCount offset, std::span<const std::byte> src) {
    if (m_mode == Mode::ReadOnly) return fail(ErrorCategory::Permission, m_path.string() + " is opened read-only");
    if (auto r = checkRange(offset, src.size()); !r) return r;
    std::lock_guard lock(m_mutex);
    m_stream.clear();
    m_stream.seekp(static_cast<std::streamoff>(offset));
    m_stream.write(reinterpret_cast<const char*>(src.data()), static_cast<std::streamsize>(src.size()));
    if (!m_stream) return fail(ErrorCategory::Io, "write failed on " + m_path.string() + " at " + std::to_string(offset));
    return {};
}

bool FileDevice::punchHole(ByteCount offset, ByteCount length) {
#if defined(_WIN32)
    HANDLE h = CreateFileW(m_path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD got = 0;
    DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr);
    FILE_ZERO_DATA_INFORMATION z{};
    z.FileOffset.QuadPart = static_cast<LONGLONG>(offset);
    z.BeyondFinalZero.QuadPart = static_cast<LONGLONG>(offset + length);
    const bool ok = DeviceIoControl(h, FSCTL_SET_ZERO_DATA, &z, sizeof z, nullptr, 0, &got, nullptr) != 0;
    CloseHandle(h);
    return ok;
#elif defined(__APPLE__)
    const int fd = ::open(m_path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    fpunchhole_t hole{};
    hole.fp_offset = static_cast<off_t>(offset);
    hole.fp_length = static_cast<off_t>(length);
    const bool ok = ::fcntl(fd, F_PUNCHHOLE, &hole) == 0;
    ::close(fd);
    return ok;
#elif defined(__linux__)
    const int fd = ::open(m_path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, static_cast<off_t>(offset), static_cast<off_t>(length)) == 0;
    ::close(fd);
    return ok;
#else
    (void)offset;
    (void)length;
    return false;
#endif
}

Expected<void> FileDevice::zeroRange(ByteCount offset, ByteCount length) {
    if (m_mode == Mode::ReadOnly) return fail(ErrorCategory::Permission, m_path.string() + " is opened read-only");
    if (auto r = checkRange(offset, length); !r) return r;
    if (length == 0) return {};
    // Buffered writes must land before the hole, or they would fill it again later.
    {
        std::lock_guard lock(m_mutex);
        m_stream.flush();
        if (!m_stream) return fail(ErrorCategory::Io, "flush failed on " + m_path.string());
    }
    // Holes are block-granular on APFS; the ragged ends are written as zeros.
    return zeroWithFastPath(offset, length, 4096, [this](ByteCount a, ByteCount n) { return punchHole(a, n); });
}

Expected<void> FileDevice::flush() {
    if (m_mode == Mode::ReadOnly) return {};
    std::lock_guard lock(m_mutex);
    m_stream.flush();
    if (!m_stream) return fail(ErrorCategory::Io, "flush failed on " + m_path.string());
    return {};
}

} // namespace stein
