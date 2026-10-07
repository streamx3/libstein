// SPDX-License-Identifier: MIT
#pragma once

#include "stein/block/block_device.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>

namespace stein {

// A block device backed by a regular file (raw images, test fixtures, the
// pieces of a split image). Portable: std::fstream + std::filesystem only.
// Raw OS devices are NOT opened with this class; that is stein_platform's job
// (alignment, exclusive locks, ioctls).
class FileDevice final : public BlockDevice {
public:
    enum class Mode { ReadOnly, ReadWrite };

    static Expected<std::shared_ptr<FileDevice>> open(const std::filesystem::path& path, Mode mode,
                                                      std::uint32_t sectorSize = 512);
    // Create (or truncate) a sparse file of `size` bytes and open it read-write.
    static Expected<std::shared_ptr<FileDevice>> create(const std::filesystem::path& path, ByteCount size,
                                                        std::uint32_t sectorSize = 512);

    std::string name() const override { return m_path.string(); }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_mode == Mode::ReadOnly; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override;
    // Punches a hole (fallocate / F_PUNCHHOLE / FSCTL_SET_ZERO_DATA); zeros are written
    // where the filesystem has no holes.
    Expected<void> zeroRange(ByteCount offset, ByteCount length) override;

    const std::filesystem::path& path() const { return m_path; }

private:
    FileDevice() = default;
    bool punchHole(ByteCount offset, ByteCount length);   // true when the OS made the hole
    std::filesystem::path m_path;
    std::fstream m_stream;
    Geometry m_geometry;
    Mode m_mode = Mode::ReadOnly;
    std::mutex m_mutex;
};

} // namespace stein
