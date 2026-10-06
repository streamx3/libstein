// SPDX-License-Identifier: MIT
#include "stein/container/luks.hpp"
#include "xts_device.hpp"

#include "stein/block/slice_device.hpp"
#include "stein/core/aes.hpp"
#include "stein/core/crypto.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/json.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/luks.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace stein::container {

namespace gen = layout::gen;

namespace {

constexpr std::uint32_t kLuks1KeyActive = 0x00AC71F3u;
constexpr std::uint32_t kLuks1KeyDisabled = 0x0000DEADu;

std::span<const std::byte> bytesOf(std::span<const std::uint8_t> s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
std::span<const std::byte> bytesOf(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

std::optional<HashAlgorithm> hashByName(const std::string& name) {
    if (name == "sha256") return HashAlgorithm::Sha256;
    if (name == "sha1") return HashAlgorithm::Sha1;
    if (name == "sha512") return HashAlgorithm::Sha512;
    return std::nullopt;
}

Expected<void> pbkdf2(const std::string& hash, std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out) {
    auto alg = hashByName(hash);
    if (!alg) return fail(ErrorCategory::Unsupported, "unsupported hash " + hash);
    crypto::pbkdf2(*alg, password, salt, iterations, out);
    return {};
}

} // namespace

Expected<std::vector<std::uint8_t>> afMerge(std::span<const std::uint8_t> src, std::size_t blockSize, std::uint32_t stripes, const std::string& hash) {
    auto alg = hashByName(hash);
    if (!alg) return fail(ErrorCategory::Unsupported, "unsupported anti-forensic hash " + hash);
    if (stripes == 0 || src.size() < blockSize * stripes) return fail(ErrorCategory::InvalidFormat, "key material too short for the stripe count");
    const std::size_t ds = Hasher::create(*alg)->digestSize();
    std::vector<std::uint8_t> buf(blockSize, 0);
    auto diffuse = [&]() {
        std::vector<std::uint8_t> out(blockSize);
        for (std::size_t i = 0, pos = 0; pos < blockSize; ++i, pos += ds) {
            auto h = Hasher::create(*alg);
            std::byte iv[4];
            storeBe32(iv, static_cast<std::uint32_t>(i));
            h->update(iv);
            const std::size_t n = std::min(ds, blockSize - pos);
            h->update(bytesOf(std::span<const std::uint8_t>(buf).subspan(pos, n)));
            const auto d = h->finish();
            std::memcpy(out.data() + pos, d.data(), n);
        }
        buf.swap(out);
    };
    for (std::uint32_t i = 0; i + 1 < stripes; ++i) {
        for (std::size_t j = 0; j < blockSize; ++j) buf[j] ^= src[i * blockSize + j];
        diffuse();
    }
    std::vector<std::uint8_t> key(blockSize);
    for (std::size_t j = 0; j < blockSize; ++j) key[j] = buf[j] ^ src[(stripes - 1) * blockSize + j];
    return key;
}

Expected<Luks> Luks::open(std::shared_ptr<BlockDevice> device) {
    if (!device) return fail(ErrorCategory::InvalidArgument, "null device");
    auto hdr = device->read(0, std::min<ByteCount>(device->size(), 4096));
    if (!hdr) return fail(hdr.error());
    if (hdr->size() < 592 || std::memcmp(hdr->data(), "LUKS\xba\xbe", 6) != 0) return fail(ErrorCategory::NotFound, "no LUKS header");
    Luks l;
    l.m_device = std::move(device);
    const std::uint16_t version = loadBe16(hdr->data() + 6);
    if (version == 1) {
        if (auto r = l.parseV1(*hdr); !r) return fail(r.error());
    } else if (version == 2) {
        if (auto r = l.parseV2(*hdr); !r) return fail(r.error());
    } else {
        return fail(ErrorCategory::Unsupported, "LUKS version " + std::to_string(version));
    }
    return l;
}

Expected<void> Luks::parseV1(std::span<const std::byte> hdr) {
    gen::Luks1Phdr h(hdr);
    m_info.version = 1;
    m_info.cipher = h.cipherName();
    m_info.mode = h.cipherMode();
    m_info.hash = h.hashSpec();
    m_info.keyBytes = h.keyBytes();
    m_info.payloadOffset = ByteCount{h.payloadOffset()} * 512;
    m_info.payloadSize = m_device->size() > m_info.payloadOffset ? m_device->size() - m_info.payloadOffset : 0;
    m_info.sectorSize = 512;
    m_info.uuid = h.uuid();
    m_digest.hash = m_info.hash;
    m_digest.iterations = h.mkDigestIter();
    auto ms = h.mkDigestSalt();
    auto md = h.mkDigest();
    m_digest.salt.assign(reinterpret_cast<const std::uint8_t*>(ms.data()), reinterpret_cast<const std::uint8_t*>(ms.data()) + ms.size());
    m_digest.digest.assign(reinterpret_cast<const std::uint8_t*>(md.data()), reinterpret_cast<const std::uint8_t*>(md.data()) + md.size());
    for (int i = 0; i < 8; ++i) {
        gen::Luks1Keyslot ks(hdr.subspan(0xD0 + static_cast<std::size_t>(i) * 48, 48));
        LuksSlotInfo si;
        si.id = i;
        si.active = ks.active() == kLuks1KeyActive;
        if (!si.active && ks.active() != kLuks1KeyDisabled) continue;
        if (!si.active) {
            si.kdf = "disabled";
            m_info.slots.push_back(si);
            continue;
        }
        si.kdf = "pbkdf2";
        si.kdfDetail = m_info.hash + " " + std::to_string(ks.iterations()) + " iterations";
        m_info.slots.push_back(si);
        Slot s;
        s.id = i;
        s.kdf = "pbkdf2";
        s.hash = m_info.hash;
        s.afHash = m_info.hash;
        s.iterations = ks.iterations();
        auto salt = ks.salt();
        s.salt.assign(reinterpret_cast<const std::uint8_t*>(salt.data()), reinterpret_cast<const std::uint8_t*>(salt.data()) + salt.size());
        s.stripes = ks.stripes();
        s.areaOffset = ByteCount{ks.keyMaterialOffset()} * 512;
        s.areaKeySize = m_info.keyBytes;
        s.areaSize = ByteCount{s.stripes} * m_info.keyBytes;
        m_slots.push_back(std::move(s));
    }
    if (m_info.cipher != "aes" || m_info.mode != "xts-plain64") {
        m_info.supported = false;
        m_info.unsupportedWhy = "cipher " + m_info.cipher + "-" + m_info.mode + " (only aes-xts-plain64 is implemented)";
    } else if (!hashByName(m_info.hash)) {
        m_info.supported = false;
        m_info.unsupportedWhy = "hash " + m_info.hash;
    }
    return {};
}

Expected<void> Luks::parseV2(std::span<const std::byte> hdr) {
    gen::Luks2Hdr h(hdr);
    m_info.version = 2;
    m_info.uuid = h.uuid();
    m_info.label = h.label();
    const ByteCount hdrSize = h.hdrSize();
    if (hdrSize < 8192 || hdrSize > 4 * MiB) return fail(ErrorCategory::InvalidFormat, "implausible LUKS2 header size");
    auto area = m_device->read(4096, hdrSize - 4096);
    if (!area) return fail(area.error());
    std::size_t len = 0;
    while (len < area->size() && (*area)[len] != std::byte{0}) ++len;
    auto json = json::Value::parse(std::string_view(reinterpret_cast<const char*>(area->data()), len));
    if (!json) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON metadata: " + json.error().message());
    // Segment 0.
    const auto& seg = json->get("segments").get("0");
    if (seg.get("type").asString() != "crypt") return fail(ErrorCategory::Unsupported, "LUKS2 segment type " + seg.get("type").asString());
    m_info.payloadOffset = std::stoull(seg.get("offset").asString().empty() ? "0" : seg.get("offset").asString());
    m_info.sectorSize = static_cast<std::uint32_t>(seg.get("sector_size").asUInt(512));
    m_info.ivTweak = std::stoull(seg.get("iv_tweak").asString().empty() ? "0" : seg.get("iv_tweak").asString());
    const std::string enc = seg.get("encryption").asString();
    const auto dash = enc.find('-');
    m_info.cipher = enc.substr(0, dash);
    m_info.mode = dash == std::string::npos ? "" : enc.substr(dash + 1);
    const std::string sizeText = seg.get("size").asString();
    if (sizeText == "dynamic" || sizeText.empty()) m_info.payloadSize = m_device->size() > m_info.payloadOffset ? m_device->size() - m_info.payloadOffset : 0;
    else m_info.payloadSize = std::stoull(sizeText);
    m_info.payloadSize -= m_info.payloadSize % m_info.sectorSize;
    // Digest 0 (pbkdf2).
    const auto& dg = json->get("digests").get("0");
    if (dg.get("type").asString() != "pbkdf2") return fail(ErrorCategory::Unsupported, "LUKS2 digest type " + dg.get("type").asString());
    m_digest.hash = dg.get("hash").asString();
    m_digest.iterations = static_cast<std::uint32_t>(dg.get("iterations").asUInt());
    auto dsalt = fromBase64(dg.get("salt").asString());
    auto ddig = fromBase64(dg.get("digest").asString());
    if (!dsalt || !ddig) return fail(ErrorCategory::InvalidFormat, "LUKS2 digest fields are not base64");
    for (auto b : *dsalt) m_digest.salt.push_back(std::to_integer<std::uint8_t>(b));
    for (auto b : *ddig) m_digest.digest.push_back(std::to_integer<std::uint8_t>(b));
    // Key slots.
    for (const auto& [id, ks] : json->get("keyslots").asObject()) {
        LuksSlotInfo si;
        si.id = std::stoi(id);
        if (ks.get("type").asString() != "luks2") {
            si.kdf = ks.get("type").asString();
            si.active = false;
            m_info.slots.push_back(si);
            continue;
        }
        Slot s;
        s.id = si.id;
        const auto& kdf = ks.get("kdf");
        s.kdf = kdf.get("type").asString();
        s.hash = kdf.get("hash").asString();
        s.iterations = static_cast<std::uint32_t>(kdf.get("iterations").asUInt());
        s.time = static_cast<std::uint32_t>(kdf.get("time").asUInt());
        s.memoryKiB = static_cast<std::uint32_t>(kdf.get("memory").asUInt());
        s.cpus = static_cast<std::uint32_t>(kdf.get("cpus").asUInt());
        auto salt = fromBase64(kdf.get("salt").asString());
        if (!salt) return fail(ErrorCategory::InvalidFormat, "LUKS2 keyslot salt is not base64");
        for (auto b : *salt) s.salt.push_back(std::to_integer<std::uint8_t>(b));
        const auto& af = ks.get("af");
        s.stripes = static_cast<std::uint32_t>(af.get("stripes").asUInt(4000));
        s.afHash = af.get("hash").asString();
        const auto& ar = ks.get("area");
        s.areaOffset = std::stoull(ar.get("offset").asString().empty() ? "0" : ar.get("offset").asString());
        s.areaSize = std::stoull(ar.get("size").asString().empty() ? "0" : ar.get("size").asString());
        s.areaKeySize = static_cast<std::uint32_t>(ar.get("key_size").asUInt());
        if (m_info.keyBytes == 0) m_info.keyBytes = static_cast<std::uint32_t>(ks.get("key_size").asUInt());
        si.kdf = s.kdf;
        si.kdfDetail = s.kdf == "pbkdf2" ? s.hash + " " + std::to_string(s.iterations) + " iterations"
                                         : "t=" + std::to_string(s.time) + " m=" + std::to_string(s.memoryKiB) + "KiB p=" + std::to_string(s.cpus);
        if (ar.get("encryption").asString() != "aes-xts-plain64" || af.get("type").asString() != "luks1") {
            si.active = false;
            si.kdfDetail += " (unsupported area encryption or af type)";
            m_info.slots.push_back(si);
            continue;
        }
        m_info.slots.push_back(si);
        m_slots.push_back(std::move(s));
    }
    if (m_info.cipher != "aes" || m_info.mode != "xts-plain64") {
        m_info.supported = false;
        m_info.unsupportedWhy = "segment encryption " + enc + " (only aes-xts-plain64 is implemented)";
    }
    return {};
}

bool Luks::digestMatches(std::span<const std::uint8_t> key) const {
    std::vector<std::uint8_t> d(m_digest.digest.size());
    if (!pbkdf2(m_digest.hash, bytesOf(key), bytesOf(m_digest.salt), m_digest.iterations, d)) return false;
    return crypto::equalConstantTime(d, m_digest.digest);
}

Expected<std::vector<std::uint8_t>> Luks::trySlot(const Slot& slot, const std::string& passphrase) const {
    std::vector<std::uint8_t> areaKey(slot.areaKeySize);
    if (slot.kdf == "pbkdf2") {
        if (auto r = pbkdf2(slot.hash, bytesOf(passphrase), bytesOf(slot.salt), slot.iterations, areaKey); !r) return fail(r.error());
    } else if (slot.kdf == "argon2id" || slot.kdf == "argon2i") {
        const auto type = slot.kdf == "argon2id" ? crypto::Argon2Type::Id : crypto::Argon2Type::I;
        if (auto r = crypto::argon2(type, bytesOf(passphrase), bytesOf(slot.salt), slot.time, slot.memoryKiB, slot.cpus, areaKey); !r) return fail(r.error());
    } else {
        return fail(ErrorCategory::Unsupported, "kdf " + slot.kdf);
    }
    auto xts = crypto::AesXts::create(areaKey);
    if (!xts) return fail(xts.error());
    const ByteCount materialBytes = ByteCount{slot.stripes} * m_info.keyBytes;
    if (slot.areaSize && materialBytes > slot.areaSize) return fail(ErrorCategory::InvalidFormat, "key material larger than its area");
    auto material = m_device->read(slot.areaOffset, materialBytes);
    if (!material) return fail(material.error());
    // The key material area is encrypted with 512-byte sectors from tweak 0.
    const ByteCount padded = (materialBytes + 511) / 512 * 512;
    std::vector<std::byte> cipher(padded), plain(padded);
    std::copy(material->begin(), material->end(), cipher.begin());
    if (padded > materialBytes) {
        auto tail = m_device->read(slot.areaOffset + materialBytes, padded - materialBytes);
        if (tail) std::copy(tail->begin(), tail->end(), cipher.begin() + static_cast<std::ptrdiff_t>(materialBytes));
    }
    if (auto d = xts->decryptSectors(0, 512, cipher, plain); !d) return fail(d.error());
    std::vector<std::uint8_t> split(materialBytes);
    for (ByteCount i = 0; i < materialBytes; ++i) split[i] = std::to_integer<std::uint8_t>(plain[i]);
    auto key = afMerge(split, m_info.keyBytes, slot.stripes, slot.afHash);
    if (!key) return fail(key.error());
    if (!digestMatches(*key)) return fail(ErrorCategory::Integrity, "wrong passphrase for slot " + std::to_string(slot.id));
    return *key;
}

Expected<std::vector<std::uint8_t>> Luks::unlock(const std::string& passphrase) const {
    if (!m_info.supported) return fail(ErrorCategory::Unsupported, m_info.unsupportedWhy);
    if (m_slots.empty()) return fail(ErrorCategory::NotFound, "no usable key slots");
    std::optional<Error> last;
    for (const auto& s : m_slots) {
        auto key = trySlot(s, passphrase);
        if (key) return key;
        if (key.error().category() != ErrorCategory::Integrity) return fail(key.error());
        last = key.error();
    }
    return fail(ErrorCategory::Integrity, "no key slot opens with this passphrase");
}

Expected<std::shared_ptr<BlockDevice>> Luks::openPayload(std::span<const std::uint8_t> masterKey, bool readOnly) const {
    if (!m_info.supported) return fail(ErrorCategory::Unsupported, m_info.unsupportedWhy);
    if (masterKey.size() != m_info.keyBytes) return fail(ErrorCategory::InvalidArgument, "master key must be " + std::to_string(m_info.keyBytes) + " bytes");
    if (!digestMatches(masterKey)) return fail(ErrorCategory::Integrity, "master key does not match the header digest");
    auto xts = crypto::AesXts::create(masterKey);
    if (!xts) return fail(xts.error());
    if (m_info.payloadSize == 0 || m_info.payloadOffset + m_info.payloadSize > m_device->size()) return fail(ErrorCategory::OutOfRange, "payload outside the device");
    return std::shared_ptr<BlockDevice>(std::make_shared<detail::XtsDevice>(m_device, Region{m_info.payloadOffset, m_info.payloadSize}, m_info.sectorSize, m_info.ivTweak, std::move(*xts), readOnly, "luks"));
}

Expected<std::shared_ptr<BlockDevice>> Luks::openPayload(const std::string& passphrase, bool readOnly) const {
    auto key = unlock(passphrase);
    if (!key) return fail(key.error());
    return openPayload(*key, readOnly);
}

} // namespace stein::container
