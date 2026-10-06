// SPDX-License-Identifier: MIT
#include "stein/block/file_device.hpp"

#include <cerrno>
#include <system_error>

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

Expected<void> FileDevice::flush() {
    if (m_mode == Mode::ReadOnly) return {};
    std::lock_guard lock(m_mutex);
    m_stream.flush();
    if (!m_stream) return fail(ErrorCategory::Io, "flush failed on " + m_path.string());
    return {};
}

} // namespace stein
