// SPDX-License-Identifier: MIT
#include "stein/platform/platform.hpp"

#include "stein/block/file_device.hpp"

namespace stein::platform {

std::string_view toString(Bus b) {
    switch (b) {
    case Bus::Unknown: return "unknown";
    case Bus::Ata: return "ata";
    case Bus::Scsi: return "scsi";
    case Bus::Nvme: return "nvme";
    case Bus::Usb: return "usb";
    case Bus::Sd: return "sd";
    case Bus::Mmc: return "mmc";
    case Bus::Virtual: return "virtual";
    case Bus::Loop: return "loop";
    case Bus::Nbd: return "nbd";
    case Bus::DeviceMapper: return "dm";
    case Bus::Md: return "md";
    case Bus::Other: return "other";
    }
    return "?";
}

std::string DiskInfo::identity() const {
    std::string id;
    if (!wwn.empty()) id = "wwn:" + wwn;
    else if (!serial.empty()) id = (model.empty() ? std::string("serial") : model) + ":" + serial;
    else if (backingFile) id = "file:" + backingFile->string();
    else id = "path:" + osPath;
    id += "/" + std::to_string(geometry.sizeBytes);
    return id;
}

Expected<std::shared_ptr<BlockDevice>> openAny(const std::string& path, OpenMode mode, std::uint32_t fileSectorSize) {
    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec) return fail(ErrorCategory::NotFound, "cannot stat " + path + ": " + ec.message(), ec.value());
    if (std::filesystem::is_regular_file(status)) {
        auto f = FileDevice::open(path, mode == OpenMode::ReadOnly ? FileDevice::Mode::ReadOnly : FileDevice::Mode::ReadWrite, fileSectorSize);
        if (!f) return fail(f.error());
        return std::shared_ptr<BlockDevice>(*f);
    }
    return current().open(path, mode);
}

} // namespace stein::platform
