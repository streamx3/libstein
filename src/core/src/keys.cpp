// SPDX-License-Identifier: MIT
#include "stein/core/keys.hpp"

#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"

#include <algorithm>
#include <cstring>

namespace stein {

namespace {

constexpr const char* kCipher = "chacha20-poly1305";
constexpr const char* kKdfPbkdf2 = "pbkdf2-hmac-sha256";
constexpr const char* kKdfArgon2id = "argon2id";
constexpr std::uint32_t kDigestIterations = 1000;   // the master key is random; the digest only has to be deterministic

std::span<const std::byte> bytesOf(std::string_view s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
std::span<const std::byte> bytesOf(std::span<const std::uint8_t> s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

Expected<std::vector<std::uint8_t>> hexField(const json::Value& v, const char* key, std::size_t expect) {
    auto bytes = fromHex(v.get(key).asString());
    if (!bytes || (expect && bytes->size() != expect)) return fail(ErrorCategory::InvalidFormat, std::string("key area: bad field ") + key);
    std::vector<std::uint8_t> out(bytes->size());
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = std::to_integer<std::uint8_t>((*bytes)[i]);
    return out;
}

Expected<void> validate(const KdfParams& k) {
    if (k.kind == KdfParams::Kind::Pbkdf2Sha256) {
        if (k.cost < 1000) return fail(ErrorCategory::InvalidArgument, "PBKDF2 needs at least 1000 iterations");
        return {};
    }
    if (k.cost < 1) return fail(ErrorCategory::InvalidArgument, "Argon2id needs at least one pass");
    if (k.parallelism < 1 || k.parallelism > 64) return fail(ErrorCategory::InvalidArgument, "Argon2id parallelism must be 1..64");
    if (k.memoryKiB < 8 * k.parallelism || k.memoryKiB > 4u * 1024 * 1024) return fail(ErrorCategory::InvalidArgument, "Argon2id memory must be 8 KiB per lane .. 4 GiB");
    return {};
}

Expected<crypto::Key256> deriveKek(const std::string& passphrase, std::span<const std::uint8_t> salt, const KdfParams& k) {
    crypto::Key256 kek{};
    if (k.kind == KdfParams::Kind::Pbkdf2Sha256) {
        crypto::pbkdf2Sha256(bytesOf(passphrase), bytesOf(salt), k.cost, kek);
        return kek;
    }
    if (auto r = crypto::argon2id(bytesOf(passphrase), bytesOf(salt), k.cost, k.memoryKiB, k.parallelism, kek); !r) return fail(r.error());
    return kek;
}

std::array<std::uint8_t, 32> digestOf(const crypto::Key256& master, std::span<const std::uint8_t> salt, std::uint32_t iterations) {
    std::array<std::uint8_t, 32> d{};
    crypto::pbkdf2Sha256(bytesOf(master), bytesOf(salt), iterations, d);
    return d;
}

constexpr std::string_view kSlotAad = "stein-key-slot";

} // namespace

crypto::Nonce96 domainNonce(const char tag[4], std::uint64_t index) {
    crypto::Nonce96 n{};
    storeLe64(reinterpret_cast<std::byte*>(n.data()), index);
    std::memcpy(n.data() + 8, tag, 4);
    return n;
}

std::string KdfParams::describe() const {
    if (kind == Kind::Pbkdf2Sha256) return std::string(kKdfPbkdf2) + " " + std::to_string(cost) + " iterations";
    return std::string(kKdfArgon2id) + " t=" + std::to_string(cost) + " m=" + std::to_string(memoryKiB) + "KiB p=" + std::to_string(parallelism);
}

Expected<Keys> Keys::create(const std::string& passphrase, const KdfParams& kdf, std::string label) {
    if (passphrase.empty()) return fail(ErrorCategory::InvalidArgument, "empty passphrase");
    if (auto v = validate(kdf); !v) return fail(v.error());
    Keys k;
    crypto::Key256 master{};
    if (auto r = crypto::randomBytes(master); !r) return fail(r.error());
    if (auto r = crypto::randomBytes(k.m_digestSalt); !r) return fail(r.error());
    k.m_digestIterations = kDigestIterations;
    k.m_digest = digestOf(master, k.m_digestSalt, kDigestIterations);
    k.m_master = master;
    if (auto s = k.addSlot(master, passphrase, kdf, std::move(label)); !s) return fail(s.error());
    return k;
}

Expected<int> Keys::addSlot(const crypto::Key256& master, const std::string& passphrase, const KdfParams& kdf, std::string label) {
    if (passphrase.empty()) return fail(ErrorCategory::InvalidArgument, "empty passphrase");
    if (auto v = validate(kdf); !v) return fail(v.error());
    if (!verifyMaster(master)) return fail(ErrorCategory::Integrity, "master key does not match this key area");
    if (m_slots.size() >= 8) return fail(ErrorCategory::OutOfRange, "all 8 key slots are in use");
    KeySlot slot;
    slot.id = 0;
    for (const auto& s : m_slots) slot.id = std::max(slot.id, s.id + 1);
    slot.label = std::move(label);
    slot.kdf = kdf;
    if (auto r = crypto::randomBytes(slot.salt); !r) return fail(r.error());
    if (auto r = crypto::randomBytes(slot.nonce); !r) return fail(r.error());
    auto kek = deriveKek(passphrase, slot.salt, kdf);
    if (!kek) return fail(kek.error());
    slot.wrapped.resize(32 + crypto::kTagSize);
    crypto::aeadEncrypt(*kek, slot.nonce, bytesOf(kSlotAad), bytesOf(master), std::span<std::byte>(reinterpret_cast<std::byte*>(slot.wrapped.data()), slot.wrapped.size()));
    m_slots.push_back(std::move(slot));
    return m_slots.back().id;
}

Expected<void> Keys::removeSlot(int id) {
    auto it = std::find_if(m_slots.begin(), m_slots.end(), [&](const KeySlot& s) { return s.id == id; });
    if (it == m_slots.end()) return fail(ErrorCategory::NotFound, "no key slot " + std::to_string(id));
    if (m_slots.size() == 1) return fail(ErrorCategory::InvalidArgument, "refusing to remove the last key slot (the image would become unreadable)");
    m_slots.erase(it);
    return {};
}

bool Keys::verifyMaster(const crypto::Key256& key) const {
    const auto d = digestOf(key, m_digestSalt, m_digestIterations);
    return crypto::equalConstantTime(d, m_digest);
}

Expected<crypto::Key256> Keys::unlock(const std::string& passphrase) const {
    for (const auto& s : m_slots) {
        auto kek = deriveKek(passphrase, s.salt, s.kdf);
        if (!kek) return fail(kek.error());
        crypto::Key256 master{};
        auto r = crypto::aeadDecrypt(*kek, s.nonce, bytesOf(kSlotAad), std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.wrapped.data()), s.wrapped.size()),
                                     std::span<std::byte>(reinterpret_cast<std::byte*>(master.data()), master.size()));
        if (!r) continue;
        if (!verifyMaster(master)) return fail(ErrorCategory::Integrity, "key slot " + std::to_string(s.id) + " opened but its key fails the digest check (corrupted key area)");
        return master;
    }
    return fail(ErrorCategory::Integrity, "no key slot opens with this passphrase");
}

std::string Keys::toJson() const {
    json::Value v = json::Value::object();
    v.set("version", 1);
    v.set("cipher", kCipher);
    json::Value digest = json::Value::object();
    digest.set("salt", toHex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(m_digestSalt.data()), m_digestSalt.size())));
    digest.set("iterations", static_cast<std::uint64_t>(m_digestIterations));
    digest.set("hash", toHex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(m_digest.data()), m_digest.size())));
    v.set("digest", std::move(digest));
    json::Value slots = json::Value::array();
    for (const auto& s : m_slots) {
        json::Value j = json::Value::object();
        j.set("id", s.id);
        if (!s.label.empty()) j.set("label", s.label);
        j.set("type", "passphrase");
        j.set("salt", toHex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.salt.data()), s.salt.size())));
        if (s.kdf.kind == KdfParams::Kind::Pbkdf2Sha256) {
            j.set("kdf", kKdfPbkdf2);
            j.set("iterations", static_cast<std::uint64_t>(s.kdf.cost));
        } else {
            j.set("kdf", kKdfArgon2id);
            j.set("time", static_cast<std::uint64_t>(s.kdf.cost));
            j.set("memory_kib", static_cast<std::uint64_t>(s.kdf.memoryKiB));
            j.set("parallelism", static_cast<std::uint64_t>(s.kdf.parallelism));
        }
        j.set("nonce", toHex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.nonce.data()), s.nonce.size())));
        j.set("wrapped", toHex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.wrapped.data()), s.wrapped.size())));
        slots.push(std::move(j));
    }
    v.set("slots", std::move(slots));
    return v.dump();
}

Expected<Keys> Keys::fromJson(std::string_view text) {
    auto v = json::Value::parse(text);
    if (!v) return fail(ErrorCategory::InvalidFormat, "key area is not valid JSON: " + v.error().message());
    if (v->get("version").asInt() != 1) return fail(ErrorCategory::Unsupported, "key area version not supported");
    if (v->get("cipher").asString() != kCipher) return fail(ErrorCategory::Unsupported, "unsupported cipher: " + v->get("cipher").asString());
    Keys k;
    const auto& d = v->get("digest");
    auto salt = hexField(d, "salt", 16);
    if (!salt) return fail(salt.error());
    std::copy(salt->begin(), salt->end(), k.m_digestSalt.begin());
    k.m_digestIterations = static_cast<std::uint32_t>(d.get("iterations").asUInt());
    auto hash = hexField(d, "hash", 32);
    if (!hash) return fail(hash.error());
    std::copy(hash->begin(), hash->end(), k.m_digest.begin());
    for (const auto& j : v->get("slots").asArray()) {
        KeySlot s;
        s.id = static_cast<int>(j.get("id").asInt());
        s.label = j.get("label").asString();
        // Older key areas carried one top-level "kdf": pbkdf2 with per-slot iterations.
        const std::string kdfName = j.has("kdf") ? j.get("kdf").asString() : v->get("kdf").asString();
        if (kdfName == kKdfArgon2id) {
            s.kdf = KdfParams::argon2id(static_cast<std::uint32_t>(j.get("time").asUInt()), static_cast<std::uint32_t>(j.get("memory_kib").asUInt()),
                                        static_cast<std::uint32_t>(j.get("parallelism").asUInt()));
        } else if (kdfName == kKdfPbkdf2) {
            s.kdf = KdfParams::pbkdf2(static_cast<std::uint32_t>(j.get("iterations").asUInt()));
        } else {
            return fail(ErrorCategory::Unsupported, "unsupported kdf in key slot: " + kdfName);
        }
        if (auto val = validate(s.kdf); !val) return fail(Error(ErrorCategory::InvalidFormat, "key slot " + std::to_string(s.id) + ": " + val.error().message()));
        auto ssalt = hexField(j, "salt", 16);
        auto nonce = hexField(j, "nonce", 12);
        auto wrapped = hexField(j, "wrapped", 48);
        if (!ssalt || !nonce || !wrapped) return fail(ErrorCategory::InvalidFormat, "key area: bad slot " + std::to_string(s.id));
        std::copy(ssalt->begin(), ssalt->end(), s.salt.begin());
        std::copy(nonce->begin(), nonce->end(), s.nonce.begin());
        s.wrapped = *wrapped;
        k.m_slots.push_back(std::move(s));
    }
    if (k.m_slots.empty()) return fail(ErrorCategory::InvalidFormat, "key area has no slots");
    return k;
}

} // namespace stein
