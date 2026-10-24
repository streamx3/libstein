// SPDX-License-Identifier: MIT
#include "stein/block/sparse_file.hpp"

#include "stein/core/crypto.hpp"
#include "stein/core/keys.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace stein {

Expected<SparseFile::Contents> SparseFile::parse(std::span<const std::byte> data, const std::string& what) {
    if (data.size() < 24 || std::memcmp(data.data(), kMagic, 12) != 0) return fail(ErrorCategory::InvalidFormat, what + " is not a STEINSPARSE1 piece");
    Contents c;
    c.totalSize = loadLe64(data.data() + 12);
    c.sectorSize = loadLe32(data.data() + 20);
    std::size_t pos = 24;
    while (pos + 16 <= data.size()) {
        Run r;
        r.offset = loadLe64(data.data() + pos);
        const std::uint64_t len = loadLe64(data.data() + pos + 8);
        pos += 16;
        // Subtractions, not sums: a len near 2^64 wraps "pos + len" and "offset + len" below the
        // limits, and assign() would get a reversed range (std::length_error, caught by nothing).
        if (len > data.size() - pos || r.offset > c.totalSize || len > c.totalSize - r.offset)
            return fail(ErrorCategory::InvalidFormat, "truncated or out-of-range run in " + what);
        r.bytes.assign(data.begin() + static_cast<std::ptrdiff_t>(pos), data.begin() + static_cast<std::ptrdiff_t>(pos + len));
        pos += static_cast<std::size_t>(len);
        c.runs.push_back(std::move(r));
    }
    return c;
}

std::vector<std::byte> SparseFile::serialize(const Contents& c) {
    std::vector<std::byte> out(24);
    std::memcpy(out.data(), kMagic, 12);
    storeLe64(out.data() + 12, c.totalSize);
    storeLe32(out.data() + 20, c.sectorSize);
    for (const auto& r : c.runs) {
        std::byte rh[16];
        storeLe64(rh, r.offset);
        storeLe64(rh + 8, r.bytes.size());
        out.insert(out.end(), rh, rh + 16);
        out.insert(out.end(), r.bytes.begin(), r.bytes.end());
    }
    return out;
}

namespace {
constexpr std::string_view kPieceAad = "stein-piece";
}

bool SparseFile::isEncrypted(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    char m[12];
    return in && in.read(m, 12) && std::memcmp(m, kEncryptedMagic, 12) == 0;
}

Expected<SparseFile::Contents> SparseFile::read(const std::filesystem::path& path, const std::string& passphrase) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail(ErrorCategory::NotFound, "cannot open " + path.string());
    std::vector<char> chars((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto data = std::span<const std::byte>(reinterpret_cast<const std::byte*>(chars.data()), chars.size());
    if (data.size() >= 12 && std::memcmp(data.data(), kEncryptedMagic, 12) == 0) {
        // magic | u32 keysLen | keys JSON | u64 cipherLen | ciphertext+tag
        if (data.size() < 16) return fail(ErrorCategory::InvalidFormat, "truncated encrypted piece " + path.string());
        const std::uint32_t keysLen = loadLe32(data.data() + 12);
        if (16 + keysLen + 8 > data.size()) return fail(ErrorCategory::InvalidFormat, "truncated encrypted piece " + path.string());
        const std::string keysJson(reinterpret_cast<const char*>(data.data() + 16), keysLen);
        const std::uint64_t cipherLen = loadLe64(data.data() + 16 + keysLen);
        const std::size_t cipherPos = 24 + keysLen;
        if (cipherPos + cipherLen != data.size() || cipherLen < crypto::kTagSize) return fail(ErrorCategory::InvalidFormat, "truncated encrypted piece " + path.string());
        if (passphrase.empty()) return fail(ErrorCategory::Permission, path.string() + " is encrypted; a passphrase is required");
        auto keys = Keys::fromJson(keysJson);
        if (!keys) return fail(keys.error());
        auto key = keys->unlock(passphrase);
        if (!key) return fail(key.error());
        std::vector<std::byte> plain(static_cast<std::size_t>(cipherLen - crypto::kTagSize));
        if (auto d = crypto::aeadDecrypt(*key, domainNonce("PIEC", 0), std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPieceAad.data()), kPieceAad.size()),
                                         data.subspan(cipherPos), plain); !d)
            return fail(Error(ErrorCategory::Integrity, path.string() + ": " + d.error().message()));
        return parse(plain, path.string());
    }
    return parse(data, path.string());
}

Expected<void> SparseFile::write(const std::filesystem::path& path, const Contents& c, const std::string& passphrase, const KdfParams& kdf) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return fail(ErrorCategory::Io, "cannot create " + path.string());
    const auto body = serialize(c);
    if (passphrase.empty()) {
        out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
    } else {
        auto keys = Keys::create(passphrase, kdf, "piece");
        if (!keys) return fail(keys.error());
        const std::string keysJson = keys->toJson();
        std::vector<std::byte> cipher(body.size() + crypto::kTagSize);
        crypto::aeadEncrypt(*keys->master(), domainNonce("PIEC", 0), std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPieceAad.data()), kPieceAad.size()), body, cipher);
        std::byte hdr[16];
        std::memcpy(hdr, kEncryptedMagic, 12);
        storeLe32(hdr + 12, static_cast<std::uint32_t>(keysJson.size()));
        std::byte lenBuf[8];
        storeLe64(lenBuf, cipher.size());
        out.write(reinterpret_cast<const char*>(hdr), sizeof hdr);
        out.write(keysJson.data(), static_cast<std::streamsize>(keysJson.size()));
        out.write(reinterpret_cast<const char*>(lenBuf), sizeof lenBuf);
        out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
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

Expected<std::shared_ptr<BlockDevice>> SparseFile::openAsDevice(const std::filesystem::path& path, const std::string& passphrase) {
    auto c = read(path, passphrase);
    if (!c) return fail(c.error());
    auto dev = RunListDevice::create(std::move(*c), path.filename().string());
    if (!dev) return fail(dev.error());
    return std::shared_ptr<BlockDevice>(std::move(*dev));
}

// ---- RunListDevice -----------------------------------------------------------------------------

namespace {

ByteCount runEnd(const SparseFile::Run& r) { return r.offset + r.bytes.size(); }

// Makes the runs disjoint with apply()'s semantics: every run, taken in piece order, overwrites
// the parts of earlier runs it covers. Quadratic, but only reached when a piece overlaps itself,
// which capture() never produces.
std::vector<SparseFile::Run> trimOverlaps(std::vector<SparseFile::Run> runs) {
    std::vector<SparseFile::Run> out;
    for (auto& r : runs) {
        std::vector<SparseFile::Run> kept;
        for (auto& e : out) {
            if (runEnd(e) <= r.offset || runEnd(r) <= e.offset) {
                kept.push_back(std::move(e));
                continue;
            }
            if (e.offset < r.offset)
                kept.push_back(SparseFile::Run{e.offset, {e.bytes.begin(), e.bytes.begin() + static_cast<std::ptrdiff_t>(r.offset - e.offset)}});
            if (runEnd(e) > runEnd(r))
                kept.push_back(SparseFile::Run{runEnd(r), {e.bytes.begin() + static_cast<std::ptrdiff_t>(runEnd(r) - e.offset), e.bytes.end()}});
        }
        kept.push_back(std::move(r));
        out = std::move(kept);
    }
    return out;
}

} // namespace

Expected<std::shared_ptr<RunListDevice>> RunListDevice::create(SparseFile::Contents contents, std::string name) {
    if (contents.sectorSize == 0) return fail(ErrorCategory::InvalidArgument, name + ": piece has a zero sector size");
    auto dev = std::shared_ptr<RunListDevice>(new RunListDevice());
    dev->m_name = std::move(name);
    dev->m_geometry.sizeBytes = contents.totalSize;
    dev->m_geometry.logicalSectorSize = contents.sectorSize;
    dev->m_geometry.physicalSectorSize = contents.sectorSize;
    for (auto& r : contents.runs) {
        if (r.bytes.empty()) continue;
        if (r.offset > contents.totalSize || r.bytes.size() > contents.totalSize - r.offset)
            return fail(ErrorCategory::OutOfRange, dev->m_name + ": run at " + std::to_string(r.offset) + "+" + std::to_string(r.bytes.size()) +
                                                       " reaches past the piece's size " + std::to_string(contents.totalSize));
        dev->m_runs.push_back(std::move(r));
    }
    // Sorted by offset, the runs that touch a read are a contiguous range; that only holds when they
    // are disjoint, so overlaps are trimmed first. stable_sort keeps piece order for equal offsets,
    // which trimOverlaps() relies on.
    bool overlapping = false;
    {
        auto byOffset = dev->m_runs;
        std::stable_sort(byOffset.begin(), byOffset.end(), [](const SparseFile::Run& a, const SparseFile::Run& b) { return a.offset < b.offset; });
        for (std::size_t i = 1; i < byOffset.size() && !overlapping; ++i) overlapping = runEnd(byOffset[i - 1]) > byOffset[i].offset;
        if (!overlapping) dev->m_runs = std::move(byOffset);
    }
    if (overlapping) {
        dev->m_runs = trimOverlaps(std::move(dev->m_runs));
        std::sort(dev->m_runs.begin(), dev->m_runs.end(), [](const SparseFile::Run& a, const SparseFile::Run& b) { return a.offset < b.offset; });
    }
    for (const auto& r : dev->m_runs) dev->m_storedBytes += r.bytes.size();
    return dev;
}

Expected<void> RunListDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    std::fill(dst.begin(), dst.end(), std::byte{0});
    if (dst.empty()) return {};
    const ByteCount end = offset + dst.size();
    // The run starting last at or before `offset` may reach into the read; everything after it up
    // to `end` is a candidate too. Runs are disjoint, so nothing earlier can.
    auto it = std::upper_bound(m_runs.begin(), m_runs.end(), offset, [](ByteCount o, const SparseFile::Run& r) { return o < r.offset; });
    if (it != m_runs.begin()) --it;
    for (; it != m_runs.end() && it->offset < end; ++it) {
        if (runEnd(*it) <= offset) continue;
        const ByteCount from = std::max(offset, it->offset), to = std::min(end, runEnd(*it));
        std::copy_n(it->bytes.begin() + static_cast<std::ptrdiff_t>(from - it->offset), static_cast<std::ptrdiff_t>(to - from),
                    dst.begin() + static_cast<std::ptrdiff_t>(from - offset));
    }
    return {};
}

Expected<void> RunListDevice::writeAt(ByteCount, std::span<const std::byte>) {
    return fail(ErrorCategory::Permission, m_name + " is a sparse piece (byte runs, not a disk) and opens read-only");
}

Expected<void> RunListDevice::discard(ByteCount, ByteCount) {
    return fail(ErrorCategory::Permission, m_name + " is a sparse piece (byte runs, not a disk) and opens read-only");
}

Expected<void> RunListDevice::zeroRange(ByteCount, ByteCount) {
    return fail(ErrorCategory::Permission, m_name + " is a sparse piece (byte runs, not a disk) and opens read-only");
}

} // namespace stein
