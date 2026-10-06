// SPDX-License-Identifier: MIT
#include "stein/block/sparse_file.hpp"

#include "stein/core/crypto.hpp"
#include "stein/core/keys.hpp"

#include "stein/core/endian.hpp"

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
        if (pos + len > data.size() || r.offset + len > c.totalSize) return fail(ErrorCategory::InvalidFormat, "truncated or out-of-range run in " + what);
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

Expected<void> SparseFile::write(const std::filesystem::path& path, const Contents& c, const std::string& passphrase, std::uint32_t kdfIterations) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return fail(ErrorCategory::Io, "cannot create " + path.string());
    const auto body = serialize(c);
    if (passphrase.empty()) {
        out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
    } else {
        auto keys = Keys::create(passphrase, kdfIterations, "piece");
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

} // namespace stein
