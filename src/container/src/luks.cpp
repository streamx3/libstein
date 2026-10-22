// SPDX-License-Identifier: MIT
#include "stein/container/luks.hpp"
#include "xts_device.hpp"

#include "stein/block/cached_device.hpp"

#include "stein/core/crypto.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/json.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/luks.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <set>
#include <string_view>

namespace stein::container {

namespace gen = layout::gen;

namespace {

constexpr std::uint32_t kLuks1KeyActive = 0x00AC71F3u;
constexpr std::uint32_t kLuks1KeyDisabled = 0x0000DEADu;
constexpr std::uint32_t kLuks2BinarySize = 4096;
constexpr std::string_view kMagicPrimary("LUKS\xba\xbe", 6);
constexpr std::string_view kMagicSecondary("SKUL\xba\xbe", 6);
// The metadata sizes cryptsetup can write (--luks2-metadata-size); the secondary copy sits at one of them.
constexpr ByteCount kLuks2HeaderSizes[] = {16 * KiB, 32 * KiB, 64 * KiB, 128 * KiB, 256 * KiB, 512 * KiB, 1 * MiB, 2 * MiB, 4 * MiB};
// config.flags that only tune dm-crypt's scheduling and do not change how the data decrypts.
constexpr std::string_view kHarmlessFlags[] = {"allow-discards", "same-cpu-crypt", "submit-from-crypt-cpus", "no-journal", "no-read-workqueue", "no-write-workqueue"};
// 4000 stripes of a 128-byte key is 500 KiB; anything far beyond that is a damaged header, not a slot.
constexpr ByteCount kMaxKeyMaterial = 16 * MiB;

std::span<const std::byte> bytesOf(std::span<const std::uint8_t> s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
std::span<const std::byte> bytesOf(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
std::vector<std::uint8_t> toU8(std::span<const std::byte> b) {
    std::vector<std::uint8_t> out(b.size());
    for (std::size_t i = 0; i < b.size(); ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    return out;
}

Expected<void> pbkdf2(const std::string& hash, std::span<const std::byte> password, std::span<const std::byte> salt, std::uint32_t iterations, std::span<std::uint8_t> out) {
    auto alg = luksHash(hash);
    if (!alg) return fail(ErrorCategory::Unsupported, "unsupported hash " + hash);
    crypto::pbkdf2(*alg, password, salt, iterations, out);
    return {};
}

// LUKS2 stores 64-bit quantities as decimal strings and smaller ones as JSON numbers. A header is
// data, so the conversion must never throw: digits only, no sign, no overflow, InvalidFormat otherwise.
Expected<std::uint64_t> parseU64(std::string_view text, const std::string& what) {
    std::uint64_t out = 0;
    const char* end = text.data() + text.size();
    auto [p, ec] = std::from_chars(text.data(), end, out);
    if (text.empty() || ec != std::errc{} || p != end) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is not a decimal number: \"" + std::string(text) + "\"");
    return out;
}
Expected<std::uint64_t> jsonU64(const json::Value& v, const std::string& what, std::optional<std::uint64_t> def = std::nullopt) {
    if (v.isNull()) {
        if (def) return *def;
        return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is missing");
    }
    if (v.isNumber()) {
        if (v.asDouble() < 0) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is negative");
        return v.asUInt();
    }
    if (!v.isString()) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is neither a number nor a string");
    return parseU64(v.asString(), what);
}
Expected<std::uint32_t> jsonU32(const json::Value& v, const std::string& what, std::optional<std::uint32_t> def = std::nullopt) {
    auto r = jsonU64(v, what, def ? std::optional<std::uint64_t>(*def) : std::nullopt);
    if (!r) return fail(r.error());
    if (*r > 0xFFFFFFFFull) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is out of range");
    return static_cast<std::uint32_t>(*r);
}
Expected<std::vector<std::uint8_t>> jsonBase64(const json::Value& v, const std::string& what) {
    auto b = fromBase64(v.asString());
    if (!b) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: " + what + " is not base64");
    return toU8(*b);
}
std::string mebibytes(std::uint64_t kib) { return std::to_string(kib / 1024) + " MiB"; }

// "aes-xts-plain64" -> ("aes", "xts-plain64"); "capi:xts(aes)-plain64" keeps its prefix in the cipher part.
Expected<crypto::CipherAlgorithm> luksCipherSpec(const std::string& spec) {
    const auto dash = spec.find('-');
    return luksCipher(spec.substr(0, dash), dash == std::string::npos ? std::string() : spec.substr(dash + 1));
}

} // namespace

std::optional<HashAlgorithm> luksHash(const std::string& name) {
    if (name == "sha256") return HashAlgorithm::Sha256;
    if (name == "sha1") return HashAlgorithm::Sha1;
    if (name == "sha512") return HashAlgorithm::Sha512;
    if (name == "ripemd160") return HashAlgorithm::Ripemd160;
    if (name == "whirlpool") return HashAlgorithm::Whirlpool;
    return std::nullopt;
}

Expected<crypto::CipherAlgorithm> luksCipher(const std::string& cipher, const std::string& mode) {
    if (startsWith(cipher, "capi:")) return fail(ErrorCategory::Unsupported, "cipher \"" + cipher + "\" (Linux crypto API notation is not implemented)");
    auto alg = crypto::cipherFromString(cipher);
    if (!alg) return fail(ErrorCategory::Unsupported, "cipher " + cipher + " (aes, serpent, twofish, camellia and kuznyechik are implemented)");
    if (mode == "xts-plain64") return *alg;
    if (mode == "xts-plain64be") return fail(ErrorCategory::Unsupported, "mode xts-plain64be (big-endian sector tweak is not implemented)");
    if (mode == "xts-plain") return fail(ErrorCategory::Unsupported, "mode xts-plain (32-bit sector tweak is not implemented)");
    if (startsWith(mode, "cbc-essiv")) return fail(ErrorCategory::Unsupported, "mode " + mode + " (CBC with ESSIV is not implemented)");
    if (startsWith(mode, "cbc-")) return fail(ErrorCategory::Unsupported, "mode " + mode + " (CBC is not implemented)");
    return fail(ErrorCategory::Unsupported, "mode " + mode + " (only xts-plain64 is implemented)");
}

Expected<std::vector<std::uint8_t>> afMerge(std::span<const std::uint8_t> src, std::size_t blockSize, std::uint32_t stripes, const std::string& hash) {
    auto alg = luksHash(hash);
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

// One of the two LUKS2 header copies as found on the header device.
struct Luks::HeaderCopy {
    ByteCount offset = 0;
    bool present = false;           // a header of the expected kind (LUKS/SKUL magic, version 2) sits there
    bool valid = false;             // ...and its size, position and checksum check out
    std::uint64_t seqid = 0, hdrSize = 0;
    std::vector<std::byte> bytes;   // binary header followed by the JSON area (hdrSize bytes)
    std::string why;                // when !valid
};

Luks::HeaderCopy Luks::readHeaderCopy(BlockDevice& dev, ByteCount at, bool secondary) {
    HeaderCopy c;
    c.offset = at;
    if (at + kLuks2BinarySize > dev.size()) {
        c.why = "beyond the end of the device";
        return c;
    }
    auto bin = dev.read(at, kLuks2BinarySize);
    if (!bin) {
        c.why = bin.error().message();
        return c;
    }
    const auto& magic = secondary ? kMagicSecondary : kMagicPrimary;
    if (std::memcmp(bin->data(), magic.data(), magic.size()) != 0) {
        c.why = secondary ? "no secondary header magic" : "no LUKS magic";
        return c;
    }
    gen::Luks2Hdr h(*bin);
    if (h.version() != 2) {
        c.why = "version " + std::to_string(h.version());
        return c;
    }
    c.present = true;
    c.hdrSize = h.hdrSize();
    c.seqid = h.seqid();
    if (std::find(std::begin(kLuks2HeaderSizes), std::end(kLuks2HeaderSizes), c.hdrSize) == std::end(kLuks2HeaderSizes)) {
        c.why = "implausible header size " + std::to_string(c.hdrSize);
        return c;
    }
    // Each copy records its own position; the secondary sits exactly one header size in.
    if (h.hdrOffset() != at || (secondary && c.hdrSize != at)) {
        c.why = "header offset field " + std::to_string(h.hdrOffset()) + " does not match its position " + std::to_string(at);
        return c;
    }
    if (at + c.hdrSize > dev.size()) {
        c.why = "JSON area beyond the end of the device";
        return c;
    }
    auto area = dev.read(at + kLuks2BinarySize, c.hdrSize - kLuks2BinarySize);
    if (!area) {
        c.why = area.error().message();
        return c;
    }
    const std::string alg = h.csumAlg();
    auto hash = luksHash(alg);
    if (!hash) {
        c.why = "checksum algorithm " + alg + " is not implemented";
        return c;
    }
    // The checksum covers the binary header with its csum field zeroed, then the whole JSON area
    // (padding included); only the digest's own length of the 64-byte field is compared.
    std::vector<std::byte> zeroed(*bin);
    std::fill_n(zeroed.begin() + gen::Luks2Hdr::kCsumOffset, gen::Luks2Hdr::kCsumSize, std::byte{0});
    auto hasher = Hasher::create(*hash);
    hasher->update(zeroed);
    hasher->update(*area);
    const auto digest = hasher->finish();
    const auto stored = h.csum();
    if (digest.size() > stored.size() || std::memcmp(digest.data(), stored.data(), digest.size()) != 0) {
        c.why = alg + " checksum mismatch";
        return c;
    }
    c.valid = true;
    c.bytes = std::move(*bin);
    c.bytes.insert(c.bytes.end(), area->begin(), area->end());
    return c;
}

Expected<Luks> Luks::open(std::shared_ptr<BlockDevice> device) {
    auto data = device;
    return open(std::move(device), std::move(data));
}

Expected<Luks> Luks::open(std::shared_ptr<BlockDevice> header, std::shared_ptr<BlockDevice> data) {
    if (!header || !data) return fail(ErrorCategory::InvalidArgument, "null device");
    Luks l;
    l.m_header = std::move(header);
    l.m_data = std::move(data);
    std::vector<std::byte> hdr;
    if (const ByteCount want = std::min<ByteCount>(l.m_header->size(), kLuks2BinarySize); want > 0) {
        auto r = l.m_header->read(0, want);
        if (!r) return fail(r.error());
        hdr = std::move(*r);
    }
    if (hdr.size() >= 592 && std::memcmp(hdr.data(), kMagicPrimary.data(), kMagicPrimary.size()) == 0) {
        const std::uint16_t version = loadBe16(hdr.data() + 6);
        if (version == 1) {
            if (auto r = l.parseV1(hdr); !r) return fail(r.error());
            return l;
        }
        if (version != 2) return fail(ErrorCategory::Unsupported, "LUKS version " + std::to_string(version));
    }
    // LUKS2, or nothing recognisable at offset 0: a damaged primary may still have a good secondary copy.
    if (auto r = l.loadV2(); !r) return fail(r.error());
    return l;
}

Expected<void> Luks::parseV1(std::span<const std::byte> hdr) {
    gen::Luks1Phdr h(hdr);
    m_info.version = 1;
    m_info.cipher = h.cipherName();
    m_info.mode = h.cipherMode();
    m_info.hash = h.hashSpec();
    m_info.keyBytes = h.keyBytes();
    if (m_info.keyBytes == 0 || m_info.keyBytes > 256) return fail(ErrorCategory::InvalidFormat, "LUKS1 key size " + std::to_string(m_info.keyBytes));
    m_info.payloadOffset = ByteCount{h.payloadOffset()} * 512;
    m_info.payloadSize = m_data->size() > m_info.payloadOffset ? m_data->size() - m_info.payloadOffset : 0;
    m_info.sectorSize = 512;
    m_info.uuid = h.uuid();
    m_digest.hash = m_info.hash;
    m_digest.iterations = h.mkDigestIter();
    m_digest.salt = toU8(h.mkDigestSalt());
    m_digest.digest = toU8(h.mkDigest());
    std::vector<std::string> why;
    auto cipher = luksCipher(m_info.cipher, m_info.mode);
    if (cipher) m_cipher = *cipher;
    else why.push_back(m_info.cipher + "-" + m_info.mode + ": " + cipher.error().message());
    if (!luksHash(m_info.hash)) why.push_back("hash " + m_info.hash);
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
        si.unsupportedWhy = join(why, "; ");   // LUKS1 slots share the header's cipher and hash
        m_info.slots.push_back(si);
        if (!why.empty()) continue;
        Slot s;
        s.id = i;
        s.kdf = "pbkdf2";
        s.hash = m_info.hash;
        s.afHash = m_info.hash;
        s.iterations = ks.iterations();
        s.salt = toU8(ks.salt());
        s.stripes = ks.stripes();
        s.areaOffset = ByteCount{ks.keyMaterialOffset()} * 512;
        s.areaKeySize = m_info.keyBytes;
        s.areaSize = ByteCount{s.stripes} * m_info.keyBytes;
        s.areaCipher = m_cipher;
        m_slots.push_back(std::move(s));
    }
    m_payloadSupported = why.empty();
    if (!why.empty()) {
        m_info.supported = false;
        m_info.unsupportedWhy = join(why, "; ");
    }
    return {};
}

Expected<void> Luks::loadV2() {
    HeaderCopy primary = readHeaderCopy(*m_header, 0, false);
    // The secondary sits at the primary's hdr_size when that can be trusted; otherwise every size
    // cryptsetup writes is tried, so a zeroed or overwritten first 4 KiB still finds the copy.
    std::vector<ByteCount> positions;
    if (primary.valid) positions.push_back(primary.hdrSize);
    else positions.assign(std::begin(kLuks2HeaderSizes), std::end(kLuks2HeaderSizes));
    std::optional<HeaderCopy> secondary;
    for (ByteCount at : positions) {
        HeaderCopy c = readHeaderCopy(*m_header, at, true);
        const bool better = !secondary || (c.valid && !secondary->valid) || (c.present && !secondary->present);
        if (better) secondary = std::move(c);
        if (secondary->valid) break;
    }
    if (!primary.valid && !secondary->valid) {
        if (!primary.present && !secondary->present) return fail(ErrorCategory::NotFound, "no LUKS header");
        return fail(ErrorCategory::InvalidFormat, "LUKS2 header: primary copy " + primary.why + "; secondary copy " + secondary->why);
    }
    // The valid copy with the highest seqid wins, the primary on a tie. Should its JSON not parse
    // (the checksum says it is what was written, not that it is sane), the other valid copy is tried.
    std::vector<const HeaderCopy*> order;
    if (primary.valid) order.push_back(&primary);
    if (secondary->valid) order.push_back(&*secondary);
    std::stable_sort(order.begin(), order.end(), [](const HeaderCopy* a, const HeaderCopy* b) { return a->seqid > b->seqid; });
    // Tracked outside m_info: parseV2 starts from `base` for every copy it tries, and a copy whose
    // checksum passed but whose JSON did not parse is damaged all the same.
    bool primaryValid = primary.valid, secondaryValid = secondary->valid;
    const LuksInfo base = m_info;
    std::optional<Error> firstError;
    for (const HeaderCopy* c : order) {
        m_info = base;
        m_slots.clear();
        m_digest = Digest{};
        std::string_view text(reinterpret_cast<const char*>(c->bytes.data()) + kLuks2BinarySize, c->bytes.size() - kLuks2BinarySize);
        text = text.substr(0, text.find('\0'));   // the JSON is NUL-terminated inside its area
        auto r = parseV2(std::span<const std::byte>(c->bytes).first(kLuks2BinarySize), text);
        if (r) {
            m_info.headerCopyUsed = c == &primary ? 0 : 1;
            m_info.primaryValid = primaryValid;
            m_info.secondaryValid = secondaryValid;
            return {};
        }
        if (!firstError) firstError = r.error();
        (c == &primary ? primaryValid : secondaryValid) = false;
    }
    return fail(*firstError);
}

Expected<void> Luks::parseV2(std::span<const std::byte> binary, std::string_view jsonText) {
    gen::Luks2Hdr h(binary);
    m_info.version = 2;
    m_info.uuid = h.uuid();
    m_info.label = h.label();
    m_info.headerSize = h.hdrSize();
    auto json = json::Value::parse(jsonText);
    if (!json) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON metadata: " + json.error().message());
    std::vector<std::string> why;   // what keeps the payload from decrypting correctly, in reading order

    // config: flags we know to be harmless, requirements we cannot honour.
    const auto& cfg = json->get("config");
    std::vector<std::string> unknownFlags;
    for (const auto& f : cfg.get("flags").asArray()) {
        m_info.flags.push_back(f.asString());
        if (std::find(std::begin(kHarmlessFlags), std::end(kHarmlessFlags), f.asString()) == std::end(kHarmlessFlags)) unknownFlags.push_back(f.asString());
    }
    for (const auto& r : cfg.get("requirements").get("mandatory").asArray()) m_info.requirements.push_back(r.asString());

    // The data segment: exactly one, plain crypt, no integrity tags interleaved with the sectors.
    const auto& segments = json->get("segments").asObject();
    if (segments.empty()) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON has no segments");
    if (segments.size() != 1) why.push_back(std::to_string(segments.size()) + " data segments (reencryption in progress?)");
    const std::string& segId = segments.begin()->first;
    const json::Value& seg = segments.begin()->second;
    const std::string segType = seg.get("type").asString();
    if (segType != "crypt") why.push_back("segment type \"" + segType + "\" (only crypt is implemented)");
    if (seg.has("integrity")) why.push_back("dm-integrity protection (" + seg.get("integrity").get("type").asString() + ") is not implemented");
    auto offset = jsonU64(seg.get("offset"), "segment offset");
    if (!offset) return fail(offset.error());
    m_info.payloadOffset = *offset;
    auto sectorSize = jsonU32(seg.get("sector_size"), "segment sector_size", 512);
    if (!sectorSize) return fail(sectorSize.error());
    if (*sectorSize != 512 && *sectorSize != 1024 && *sectorSize != 2048 && *sectorSize != 4096) return fail(ErrorCategory::InvalidFormat, "LUKS2 segment sector size " + std::to_string(*sectorSize));
    m_info.sectorSize = *sectorSize;
    auto ivTweak = jsonU64(seg.get("iv_tweak"), "segment iv_tweak", 0);
    if (!ivTweak) return fail(ivTweak.error());
    m_info.ivTweak = *ivTweak;
    const std::string enc = seg.get("encryption").asString();
    const auto dash = enc.find('-');
    m_info.cipher = enc.substr(0, dash);
    m_info.mode = dash == std::string::npos ? "" : enc.substr(dash + 1);
    if (segType == "crypt") {
        auto cipher = luksCipherSpec(enc);
        if (cipher) m_cipher = *cipher;
        else why.push_back("segment encryption " + enc + ": " + cipher.error().message());
    }
    // "dynamic" runs to the end of the data device; otherwise a decimal string (a number is taken too).
    const json::Value& sizeValue = seg.get("size");
    if (sizeValue.isNull() || (sizeValue.isString() && sizeValue.asString() == "dynamic")) {
        m_info.payloadSize = m_data->size() > m_info.payloadOffset ? m_data->size() - m_info.payloadOffset : 0;
    } else {
        auto size = jsonU64(sizeValue, "segment size");
        if (!size) return fail(size.error());
        m_info.payloadSize = *size;
    }
    m_info.payloadSize -= m_info.payloadSize % m_info.sectorSize;
    if (!m_info.requirements.empty()) why.push_back("mandatory requirements " + join(m_info.requirements, ", ") + " (not implemented)");
    if (!unknownFlags.empty()) why.push_back("unknown flags " + join(unknownFlags, ", "));

    // The digest covering the segment verifies the volume key and names the slots that hold it.
    const json::Value* dg = nullptr;
    for (const auto& [id, d] : json->get("digests").asObject()) {
        const auto& covered = d.get("segments").asArray();
        if (std::any_of(covered.begin(), covered.end(), [&](const json::Value& s) { return s.asString() == segId; })) {
            dg = &d;
            break;
        }
    }
    if (!dg) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: no digest covers the data segment");
    if (dg->get("type").asString() != "pbkdf2") why.push_back("digest type \"" + dg->get("type").asString() + "\" (only pbkdf2 is implemented)");
    m_digest.hash = dg->get("hash").asString();
    m_info.hash = m_digest.hash;
    if (!luksHash(m_digest.hash)) why.push_back("digest hash " + m_digest.hash);
    auto digestIterations = jsonU32(dg->get("iterations"), "digest iterations");
    if (!digestIterations) return fail(digestIterations.error());
    m_digest.iterations = *digestIterations;
    auto digestSalt = jsonBase64(dg->get("salt"), "digest salt");
    if (!digestSalt) return fail(digestSalt.error());
    m_digest.salt = std::move(*digestSalt);
    auto digestValue = jsonBase64(dg->get("digest"), "digest value");
    if (!digestValue) return fail(digestValue.error());
    m_digest.digest = std::move(*digestValue);
    std::set<std::string> digestSlots;
    for (const auto& k : dg->get("keyslots").asArray()) digestSlots.insert(k.asString());

    // The volume key size is the key_size of the digest's first slot (what cryptsetup takes), so it
    // does not depend on which slot happens to be listed first in the JSON.
    const auto& keyslots = json->get("keyslots").asObject();
    for (const auto& [id, ks] : keyslots) {
        if (!digestSlots.count(id) || ks.get("type").asString() != "luks2") continue;
        auto keySize = jsonU32(ks.get("key_size"), "keyslot " + id + " key_size");
        if (!keySize) return fail(keySize.error());
        m_info.keyBytes = *keySize;
        break;
    }
    if (m_info.keyBytes == 0)   // no slot bound to the digest: show some size, nothing can be tried anyway
        for (const auto& [id, ks] : keyslots)
            if (ks.get("type").asString() == "luks2")
                if (auto keySize = jsonU32(ks.get("key_size"), "keyslot " + id + " key_size")) {
                    m_info.keyBytes = *keySize;
                    break;
                }

    const std::uint64_t argonCapKiB = crypto::argon2MemoryCapKiB();
    std::vector<std::string> slotWhy;
    for (const auto& [id, ks] : keyslots) {
        auto slotId = parseU64(id, "keyslot id");
        if (!slotId) return fail(slotId.error());
        if (*slotId > 0x7FFFFFFFull) return fail(ErrorCategory::InvalidFormat, "LUKS2 JSON: keyslot id " + id + " is out of range");
        LuksSlotInfo si;
        si.id = static_cast<int>(*slotId);
        const std::string type = ks.get("type").asString();
        if (type != "luks2") {
            si.kdf = type;
            si.active = false;
            si.unsupportedWhy = "keyslot type \"" + type + "\"";
            slotWhy.push_back("slot " + std::to_string(si.id) + ": " + si.unsupportedWhy);
            m_info.slots.push_back(si);
            continue;
        }
        Slot s;
        s.id = si.id;
        auto priority = jsonU32(ks.get("priority"), "keyslot " + id + " priority", 1);
        if (!priority) return fail(priority.error());
        s.priority = static_cast<int>(std::min<std::uint32_t>(*priority, 2));
        si.priority = s.priority;
        auto keySize = jsonU32(ks.get("key_size"), "keyslot " + id + " key_size");
        if (!keySize) return fail(keySize.error());
        const auto& kdf = ks.get("kdf");
        s.kdf = kdf.get("type").asString();
        s.hash = kdf.get("hash").asString();
        auto iterations = jsonU32(kdf.get("iterations"), "keyslot " + id + " kdf iterations", 0);
        auto time = jsonU32(kdf.get("time"), "keyslot " + id + " kdf time", 0);
        auto memory = jsonU32(kdf.get("memory"), "keyslot " + id + " kdf memory", 0);
        auto cpus = jsonU32(kdf.get("cpus"), "keyslot " + id + " kdf cpus", 0);
        if (!iterations) return fail(iterations.error());
        if (!time) return fail(time.error());
        if (!memory) return fail(memory.error());
        if (!cpus) return fail(cpus.error());
        s.iterations = *iterations;
        s.time = *time;
        s.memoryKiB = *memory;
        s.cpus = *cpus;
        auto salt = jsonBase64(kdf.get("salt"), "keyslot " + id + " salt");
        if (!salt) return fail(salt.error());
        s.salt = std::move(*salt);
        const auto& af = ks.get("af");
        auto stripes = jsonU32(af.get("stripes"), "keyslot " + id + " af stripes", 4000);
        if (!stripes) return fail(stripes.error());
        s.stripes = *stripes;
        s.afHash = af.get("hash").asString();
        const auto& ar = ks.get("area");
        auto areaOffset = jsonU64(ar.get("offset"), "keyslot " + id + " area offset");
        auto areaSize = jsonU64(ar.get("size"), "keyslot " + id + " area size", 0);
        auto areaKeySize = jsonU32(ar.get("key_size"), "keyslot " + id + " area key_size", 0);
        if (!areaOffset) return fail(areaOffset.error());
        if (!areaSize) return fail(areaSize.error());
        if (!areaKeySize) return fail(areaKeySize.error());
        s.areaOffset = *areaOffset;
        s.areaSize = *areaSize;
        s.areaKeySize = *areaKeySize;
        const std::string areaEnc = ar.get("encryption").asString();
        si.kdf = s.kdf;
        si.kdfDetail = s.kdf == "pbkdf2" ? s.hash + " " + std::to_string(s.iterations) + " iterations"
                                         : "t=" + std::to_string(s.time) + " m=" + std::to_string(s.memoryKiB) + "KiB p=" + std::to_string(s.cpus);
        // Why unlock() has to skip this slot, when it has to.
        const bool argon = s.kdf == "argon2id" || s.kdf == "argon2i";
        std::string skip;
        if (!digestSlots.count(id)) skip = "not bound to the data segment's digest";
        else if (*keySize != m_info.keyBytes) skip = "key size " + std::to_string(*keySize) + " is not the volume key's " + std::to_string(m_info.keyBytes);
        else if (s.kdf != "pbkdf2" && !argon) skip = "kdf " + s.kdf;
        else if (s.kdf == "pbkdf2" && !luksHash(s.hash)) skip = "kdf hash " + s.hash;
        else if (argon && (s.time == 0 || s.cpus == 0 || s.memoryKiB < 8 * s.cpus)) skip = s.kdf + " parameters " + si.kdfDetail + " are invalid";
        else if (argon && s.memoryKiB > argonCapKiB) skip = s.kdf + " needs " + mebibytes(s.memoryKiB) + " of memory, above this machine's cap of " + mebibytes(argonCapKiB);
        else if (af.get("type").asString() != "luks1") skip = "af type \"" + af.get("type").asString() + "\"";
        else if (!luksHash(s.afHash)) skip = "af hash " + s.afHash;
        else if (s.stripes == 0) skip = "af stripes 0";
        else if (ar.get("type").asString() != "raw") skip = "area type \"" + ar.get("type").asString() + "\"";
        else if (s.areaKeySize == 0) skip = "area key_size missing";   // the XTS key for the key material; mandatory for a raw area
        else if (auto areaCipher = luksCipherSpec(areaEnc); !areaCipher) skip = "area encryption " + areaEnc + ": " + areaCipher.error().message();
        else s.areaCipher = *areaCipher;
        si.unsupportedWhy = skip;
        if (!skip.empty()) slotWhy.push_back("slot " + std::to_string(si.id) + ": " + skip);
        m_info.slots.push_back(si);
        if (skip.empty()) m_slots.push_back(std::move(s));
    }

    // Tokens: what unlocks a slot besides a typed passphrase (TPM2, FIDO2, recovery key, clevis...).
    for (const auto& [tokenId, token] : json->get("tokens").asObject()) {
        const std::string type = token.get("type").asString();
        for (const auto& ref : token.get("keyslots").asArray()) {
            auto sid = parseU64(ref.asString(), "token " + tokenId + " keyslot");
            if (!sid || *sid > 0x7FFFFFFFull) continue;   // a token naming no real slot changes nothing
            for (auto& slot : m_info.slots)
                if (slot.id == static_cast<int>(*sid)) slot.tokens.push_back(type);
        }
    }

    m_payloadSupported = why.empty();
    if (!why.empty()) {
        m_info.supported = false;
        m_info.unsupportedWhy = join(why, "; ");
    } else if (m_slots.empty() && !slotWhy.empty()) {
        m_info.supported = false;
        m_info.unsupportedWhy = "no usable key slot (" + join(slotWhy, "; ") + ")";
    }
    return {};
}

bool Luks::digestMatches(std::span<const std::uint8_t> key) const {
    if (m_digest.digest.empty()) return false;
    std::vector<std::uint8_t> d(m_digest.digest.size());
    if (!pbkdf2(m_digest.hash, bytesOf(key), bytesOf(m_digest.salt), m_digest.iterations, d)) return false;
    return crypto::equalConstantTime(d, m_digest.digest);
}

Expected<std::vector<std::uint8_t>> Luks::trySlot(const Slot& slot, const std::string& passphrase, const UnlockOptions& options) const {
    std::vector<std::uint8_t> areaKey(slot.areaKeySize);
    if (slot.kdf == "pbkdf2") {
        if (auto r = pbkdf2(slot.hash, bytesOf(passphrase), bytesOf(slot.salt), slot.iterations, areaKey); !r) return fail(r.error());
    } else if (slot.kdf == "argon2id" || slot.kdf == "argon2i") {
        const auto type = slot.kdf == "argon2id" ? crypto::Argon2Type::Id : crypto::Argon2Type::I;
        crypto::Argon2Options ao;
        ao.cancelled = options.cancelled;
        if (auto r = crypto::argon2(type, bytesOf(passphrase), bytesOf(slot.salt), slot.time, slot.memoryKiB, slot.cpus, areaKey, {}, {}, ao); !r) return fail(r.error());
    } else {
        return fail(ErrorCategory::Unsupported, "kdf " + slot.kdf);
    }
    auto xts = crypto::Xts::create(slot.areaCipher, areaKey);
    if (!xts) return fail(xts.error());
    const ByteCount materialBytes = ByteCount{slot.stripes} * m_info.keyBytes;
    if (materialBytes > kMaxKeyMaterial) return fail(ErrorCategory::InvalidFormat, "implausible key material size for slot " + std::to_string(slot.id));
    if (slot.areaSize && materialBytes > slot.areaSize) return fail(ErrorCategory::InvalidFormat, "key material larger than its area");
    auto material = m_header->read(slot.areaOffset, materialBytes);
    if (!material) return fail(material.error());
    // The key material area is encrypted with 512-byte sectors from tweak 0.
    const ByteCount padded = (materialBytes + 511) / 512 * 512;
    std::vector<std::byte> cipher(padded), plain(padded);
    std::copy(material->begin(), material->end(), cipher.begin());
    if (padded > materialBytes) {
        auto tail = m_header->read(slot.areaOffset + materialBytes, padded - materialBytes);
        if (tail) std::copy(tail->begin(), tail->end(), cipher.begin() + static_cast<std::ptrdiff_t>(materialBytes));
    }
    if (auto d = xts->decryptSectors(0, 512, cipher, plain); !d) return fail(d.error());
    auto key = afMerge(toU8(std::span<const std::byte>(plain).first(materialBytes)), m_info.keyBytes, slot.stripes, slot.afHash);
    if (!key) return fail(key.error());
    if (!digestMatches(*key)) return fail(ErrorCategory::Integrity, "wrong passphrase for slot " + std::to_string(slot.id));
    return *key;
}

Expected<std::vector<std::uint8_t>> Luks::unlock(const std::string& passphrase, const UnlockOptions& options) const {
    if (!m_payloadSupported) return fail(ErrorCategory::Unsupported, m_info.unsupportedWhy);
    if (m_slots.empty()) {
        if (!m_info.supported) return fail(ErrorCategory::Unsupported, m_info.unsupportedWhy);
        return fail(ErrorCategory::NotFound, "no key slots");
    }
    // Preferred slots first, then normal ones, the "ignore" slots last; ids ascending within a class.
    std::vector<const Slot*> order;
    for (const auto& s : m_slots) order.push_back(&s);
    std::stable_sort(order.begin(), order.end(), [](const Slot* a, const Slot* b) { return a->priority > b->priority; });
    bool wrongPassphrase = false;
    std::optional<Error> untried;   // a slot that could not be tried at all: damaged material, I/O
    std::string untriedWhy;
    for (const Slot* s : order) {
        if (options.cancelled && options.cancelled()) return fail(ErrorCategory::Cancelled, "unlock cancelled");
        auto key = trySlot(*s, passphrase, options);
        if (key) return key;
        const auto category = key.error().category();
        if (category == ErrorCategory::Cancelled) return fail(key.error());
        if (category == ErrorCategory::Integrity) {
            wrongPassphrase = true;
            continue;
        }
        if (!untried) untried = key.error();
        untriedWhy += (untriedWhy.empty() ? "" : "; ") + ("slot " + std::to_string(s->id) + ": " + key.error().message());
    }
    if (wrongPassphrase) return fail(ErrorCategory::Integrity, "no key slot opens with this passphrase" + (untriedWhy.empty() ? "" : " (" + untriedWhy + ")"));
    return fail(untried->category(), untriedWhy);
}

Expected<std::shared_ptr<BlockDevice>> Luks::openPayload(std::span<const std::uint8_t> masterKey, bool readOnly) const {
    if (!m_payloadSupported) return fail(ErrorCategory::Unsupported, m_info.unsupportedWhy);
    if (masterKey.size() != m_info.keyBytes) return fail(ErrorCategory::InvalidArgument, "master key must be " + std::to_string(m_info.keyBytes) + " bytes");
    if (!digestMatches(masterKey)) return fail(ErrorCategory::Integrity, "master key does not match the header digest");
    auto xts = crypto::Xts::create(m_cipher, masterKey);
    if (!xts) return fail(xts.error());
    if (m_info.payloadSize == 0 || m_info.payloadOffset + m_info.payloadSize > m_data->size()) return fail(ErrorCategory::OutOfRange, "payload outside the device");
    auto dev = std::make_shared<detail::XtsDevice>(m_data, Region{m_info.payloadOffset, m_info.payloadSize}, m_info.sectorSize, m_info.ivTweak, std::move(*xts), readOnly, "luks");
    // Read-only payloads sit under a directory walk and an NFS server reading the same sectors over
    // and over: a bounded cache above the decryption (256 KiB chunks, 64 MiB) decrypts each once.
    // A writable payload stays uncached so what a writer stores is what the next read decrypts.
    if (readOnly) return std::static_pointer_cast<BlockDevice>(CachedDevice::create(dev));
    return std::static_pointer_cast<BlockDevice>(dev);
}

Expected<std::shared_ptr<BlockDevice>> Luks::openPayload(const std::string& passphrase, bool readOnly, const UnlockOptions& options) const {
    auto key = unlock(passphrase, options);
    if (!key) return fail(key.error());
    return openPayload(*key, readOnly);
}

} // namespace stein::container
