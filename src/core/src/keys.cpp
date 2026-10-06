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
constexpr const char* kKdf = "pbkdf2-hmac-sha256";
constexpr std::uint32_t kMinIterations = 1000;

std::span<const std::byte> bytesOf(std::string_view s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }
std::span<const std::byte> bytesOf(std::span<const std::uint8_t> s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

Expected<std::vector<std::uint8_t>> hexField(const json::Value& v, const char* key, std::size_t expect) {
    auto bytes = fromHex(v.get(key).asString());
    if (!bytes || (expect && bytes->size() != expect)) return fail(ErrorCategory::InvalidFormat, std::string("key area: bad field ") + key);
    std::vector<std::uint8_t> out(bytes->size());
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = std::to_integer<std::uint8_t>((*bytes)[i]);
    return out;
}

crypto::Key256 deriveKek(const std::string& passphrase, std::span<const std::uint8_t> salt, std::uint32_t iterations) {
    crypto::Key256 kek{};
    crypto::pbkdf2Sha256(bytesOf(passphrase), bytesOf(salt), iterations, kek);
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

Expected<Keys> Keys::create(const std::string& passphrase, std::uint32_t iterations, std::string label) {
    if (passphrase.empty()) return fail(ErrorCategory::InvalidArgument, "empty passphrase");
    if (iterations < kMinIterations) return fail(ErrorCategory::InvalidArgument, "KDF iterations too low");
    Keys k;
    crypto::Key256 master{};
    if (auto r = crypto::randomBytes(master); !r) return fail(r.error());
    if (auto r = crypto::randomBytes(k.m_digestSalt); !r) return fail(r.error());
    k.m_digestIterations = iterations;
    k.m_digest = digestOf(master, k.m_digestSalt, iterations);
    k.m_master = master;
    if (auto s = k.addSlot(master, passphrase, iterations, std::move(label)); !s) return fail(s.error());
    return k;
}

Expected<int> Keys::addSlot(const crypto::Key256& master, const std::string& passphrase, std::uint32_t iterations, std::string label) {
    if (passphrase.empty()) return fail(ErrorCategory::InvalidArgument, "empty passphrase");
    if (iterations < kMinIterations) return fail(ErrorCategory::InvalidArgument, "KDF iterations too low");
    if (!verifyMaster(master)) return fail(ErrorCategory::Integrity, "master key does not match this key area");
    if (m_slots.size() >= 8) return fail(ErrorCategory::OutOfRange, "all 8 key slots are in use");
    KeySlot slot;
    slot.id = 0;
    for (const auto& s : m_slots) slot.id = std::max(slot.id, s.id + 1);
    slot.label = std::move(label);
    slot.iterations = iterations;
    if (auto r = crypto::randomBytes(slot.salt); !r) return fail(r.error());
    if (auto r = crypto::randomBytes(slot.nonce); !r) return fail(r.error());
    const auto kek = deriveKek(passphrase, slot.salt, iterations);
    slot.wrapped.resize(32 + crypto::kTagSize);
    crypto::aeadEncrypt(kek, slot.nonce, bytesOf(kSlotAad), bytesOf(master), std::span<std::byte>(reinterpret_cast<std::byte*>(slot.wrapped.data()), slot.wrapped.size()));
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
        const auto kek = deriveKek(passphrase, s.salt, s.iterations);
        crypto::Key256 master{};
        auto r = crypto::aeadDecrypt(kek, s.nonce, bytesOf(kSlotAad), std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.wrapped.data()), s.wrapped.size()),
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
    v.set("kdf", kKdf);
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
        j.set("iterations", static_cast<std::uint64_t>(s.iterations));
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
    if (v->get("kdf").asString() != kKdf) return fail(ErrorCategory::Unsupported, "unsupported kdf: " + v->get("kdf").asString());
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
        s.iterations = static_cast<std::uint32_t>(j.get("iterations").asUInt());
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
