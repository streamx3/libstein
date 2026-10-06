// SPDX-License-Identifier: MIT
#include "stein/block/sparse_file.hpp"

#include "stein/core/endian.hpp"

#include <cstring>
#include <fstream>

namespace stein {

Expected<SparseFile::Contents> SparseFile::read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail(ErrorCategory::NotFound, "cannot open " + path.string());
    std::vector<char> chars((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto* data = reinterpret_cast<const std::byte*>(chars.data());
    if (chars.size() < 24 || std::memcmp(chars.data(), kMagic, 12) != 0)
        return fail(ErrorCategory::InvalidFormat, path.string() + " is not a STEINSPARSE1 file");
    Contents c;
    c.totalSize = loadLe64(data + 12);
    c.sectorSize = loadLe32(data + 20);
    std::size_t pos = 24;
    while (pos + 16 <= chars.size()) {
        Run r;
        r.offset = loadLe64(data + pos);
        const std::uint64_t len = loadLe64(data + pos + 8);
        pos += 16;
        if (pos + len > chars.size() || r.offset + len > c.totalSize)
            return fail(ErrorCategory::InvalidFormat, "truncated or out-of-range run in " + path.string());
        r.bytes.assign(data + pos, data + pos + len);
        pos += static_cast<std::size_t>(len);
        c.runs.push_back(std::move(r));
    }
    return c;
}

Expected<void> SparseFile::write(const std::filesystem::path& path, const Contents& c) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return fail(ErrorCategory::Io, "cannot create " + path.string());
    std::byte hdr[24];
    std::memcpy(hdr, kMagic, 12);
    storeLe64(hdr + 12, c.totalSize);
    storeLe32(hdr + 20, c.sectorSize);
    out.write(reinterpret_cast<const char*>(hdr), sizeof hdr);
    for (const auto& r : c.runs) {
        std::byte rh[16];
        storeLe64(rh, r.offset);
        storeLe64(rh + 8, r.bytes.size());
        out.write(reinterpret_cast<const char*>(rh), sizeof rh);
        out.write(reinterpret_cast<const char*>(r.bytes.data()), static_cast<std::streamsize>(r.bytes.size()));
    }
    if (!out) return fail(ErrorCategory::Io, "write failed on " + path.string());
    return {};
}

Expected<std::shared_ptr<MemoryDevice>> SparseFile::loadIntoMemory(const std::filesystem::path& path) {
    auto c = read(path);
    if (!c) return fail(c.error());
    auto dev = std::make_shared<MemoryDevice>(c->totalSize, c->sectorSize);
    if (auto r = apply(*c, *dev); !r) return fail(r.error());
    return dev;
}

Expected<SparseFile::Contents> SparseFile::capture(BlockDevice& device, const std::vector<Region>& regions) {
    Contents c;
    c.totalSize = device.size();
    c.sectorSize = device.sectorSize();
    for (const auto& reg : regions) {
        auto bytes = device.read(reg.offset, reg.length);
        if (!bytes) return fail(bytes.error());
        c.runs.push_back(Run{reg.offset, std::move(*bytes)});
    }
    return c;
}

Expected<void> SparseFile::apply(const Contents& c, BlockDevice& device) {
    for (const auto& r : c.runs)
        if (auto chk = device.checkRange(r.offset, r.bytes.size()); !chk) return chk;
    for (const auto& r : c.runs)
        if (auto w = device.writeAt(r.offset, r.bytes); !w) return w;
    return device.flush();
}

} // namespace stein
