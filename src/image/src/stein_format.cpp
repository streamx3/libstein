// SPDX-License-Identifier: MIT
#include "stein/image/stein_format.hpp"

#include "stein/image/keys.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/lz4.hpp"
#include "stein/core/strings.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <random>

namespace stein::image {

namespace {
constexpr char kMagic[8] = {'S', 'T', 'E', 'I', 'N', 'I', 'M', 'G'};
constexpr char kChunkMagic[4] = {'C', 'H', 'N', 'K'};
constexpr char kTrailerMagic[8] = {'S', 'T', 'E', 'I', 'N', 'I', 'D', 'X'};

// Additional data bound to each chunk's ciphertext: index, flags and raw length.
std::array<std::byte, 16> chunkAad(std::uint64_t index, std::uint32_t flags, std::uint32_t rawLength) {
    std::array<std::byte, 16> aad{};
    storeLe64(aad.data(), index);
    storeLe32(aad.data() + 8, flags);
    storeLe32(aad.data() + 12, rawLength);
    return aad;
}

bool allZero(std::span<const std::byte> b) {
    std::size_t i = 0;
    for (; i + 8 <= b.size(); i += 8)
        if (loadLe64(b.data() + i) != 0) return false;
    for (; i < b.size(); ++i)
        if (b[i] != std::byte{0}) return false;
    return true;
}

Uuid randomUuid() {
    std::random_device rd;
    std::array<std::uint8_t, 16> b{};
    for (auto& x : b) x = static_cast<std::uint8_t>(rd());
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
    return Uuid(b);
}

std::FILE* openFile(const std::filesystem::path& p, const char* mode) {
#ifdef _WIN32
    return _wfopen(p.wstring().c_str(), std::wstring(mode, mode + std::strlen(mode)).c_str());
#else
    return std::fopen(p.c_str(), mode);
#endif
}

bool seekTo(std::FILE* f, ByteCount off) {
#ifdef _WIN32
    return _fseeki64(f, static_cast<long long>(off), SEEK_SET) == 0;
#else
    return fseeko(f, static_cast<off_t>(off), SEEK_SET) == 0;
#endif
}

ByteCount tellAt(std::FILE* f) {
#ifdef _WIN32
    return static_cast<ByteCount>(_ftelli64(f));
#else
    return static_cast<ByteCount>(ftello(f));
#endif
}

Expected<void> readExact(std::FILE* f, ByteCount off, std::span<std::byte> out, const std::string& what) {
    if (!seekTo(f, off) || std::fread(out.data(), 1, out.size(), f) != out.size())
        return fail(ErrorCategory::Io, "cannot read " + what + " at " + std::to_string(off));
    return {};
}

} // namespace

std::string_view toString(Compression c) { return c == Compression::Lz4 ? "lz4" : "none"; }
std::optional<Compression> compressionFromString(std::string_view s) {
    if (s == "none" || s == "0") return Compression::None;
    if (s == "lz4") return Compression::Lz4;
    return std::nullopt;
}

// ----------------------------------------------------------------------------- codecs

void SegmentHeader::encode(std::span<std::byte, kSize> o) const {
    std::fill(o.begin(), o.end(), std::byte{0});
    std::memcpy(o.data(), kMagic, 8);
    storeLe16(o.data() + 8, version);
    storeLe16(o.data() + 10, static_cast<std::uint16_t>(kSize));
    storeLe32(o.data() + 12, flags);
    imageUuid.toRfcBytes(std::span<std::byte, 16>(o.data() + 16, 16));
    storeLe32(o.data() + 32, segmentIndex);
    storeLe32(o.data() + 36, chunkSize);
    storeLe64(o.data() + 40, totalSize);
    storeLe32(o.data() + 48, sectorSize);
    o[52] = std::byte(static_cast<std::uint8_t>(compression));
    o[53] = std::byte(chunkHash);
    o[54] = std::byte(imageHash);
    storeLe64(o.data() + 56, manifestOffset);
    storeLe64(o.data() + 64, manifestLength);
    storeLe64(o.data() + 72, splitSize);
    storeLe64(o.data() + 80, keysOffset);
    storeLe64(o.data() + 88, keysLength);
}

Expected<SegmentHeader> SegmentHeader::decode(std::span<const std::byte> i) {
    if (i.size() < kSize || std::memcmp(i.data(), kMagic, 8) != 0) return fail(ErrorCategory::InvalidFormat, "not a stein image (bad magic)");
    SegmentHeader h;
    h.version = loadLe16(i.data() + 8);
    if (h.version != 1) return fail(ErrorCategory::Unsupported, "stein image version " + std::to_string(h.version) + " is not supported");
    if (loadLe16(i.data() + 10) != kSize) return fail(ErrorCategory::InvalidFormat, "unexpected header size");
    h.flags = loadLe32(i.data() + 12);
    h.imageUuid = Uuid::fromRfcBytes(std::span<const std::byte, 16>(i.data() + 16, 16));
    h.segmentIndex = loadLe32(i.data() + 32);
    h.chunkSize = loadLe32(i.data() + 36);
    h.totalSize = loadLe64(i.data() + 40);
    h.sectorSize = loadLe32(i.data() + 48);
    h.compression = static_cast<Compression>(std::to_integer<std::uint8_t>(i[52]));
    h.chunkHash = std::to_integer<std::uint8_t>(i[53]);
    h.imageHash = std::to_integer<std::uint8_t>(i[54]);
    h.manifestOffset = loadLe64(i.data() + 56);
    h.manifestLength = loadLe64(i.data() + 64);
    h.splitSize = loadLe64(i.data() + 72);
    h.keysOffset = loadLe64(i.data() + 80);
    h.keysLength = loadLe64(i.data() + 88);
    if (h.chunkSize < 4096 || (h.chunkSize & (h.chunkSize - 1)) != 0) return fail(ErrorCategory::InvalidFormat, "bad chunk size");
    if (h.compression != Compression::None && h.compression != Compression::Lz4) return fail(ErrorCategory::Unsupported, "unknown compression");
    if ((h.flags & kFlagEncrypted) && h.segmentIndex == 0 && (h.keysLength == 0 || h.keysLength > 1 * MiB))
        return fail(ErrorCategory::InvalidFormat, "encrypted image without a key area");
    return h;
}

void ChunkRecord::encode(std::span<std::byte, kHeaderSize> o) const {
    std::memcpy(o.data(), kChunkMagic, 4);
    storeLe32(o.data() + 4, flags);
    storeLe64(o.data() + 8, chunkIndex);
    storeLe32(o.data() + 16, rawLength);
    storeLe32(o.data() + 20, storedLength);
    storeLe32(o.data() + 24, rawCrc);
    storeLe32(o.data() + 28, storedCrc);
}

Expected<ChunkRecord> ChunkRecord::decode(std::span<const std::byte> i) {
    if (i.size() < kHeaderSize || std::memcmp(i.data(), kChunkMagic, 4) != 0) return fail(ErrorCategory::InvalidFormat, "bad chunk record magic");
    ChunkRecord r;
    r.flags = loadLe32(i.data() + 4);
    r.chunkIndex = loadLe64(i.data() + 8);
    r.rawLength = loadLe32(i.data() + 16);
    r.storedLength = loadLe32(i.data() + 20);
    r.rawCrc = loadLe32(i.data() + 24);
    r.storedCrc = loadLe32(i.data() + 28);
    return r;
}

void SegmentTrailer::encode(std::span<std::byte, kSize> o) const {
    std::fill(o.begin(), o.end(), std::byte{0});
    std::memcpy(o.data(), kTrailerMagic, 8);
    storeLe64(o.data() + 8, indexOffset);
    storeLe64(o.data() + 16, indexCount);
    storeLe64(o.data() + 24, chunksTotal);
    storeLe64(o.data() + 32, flags);
    for (int k = 0; k < 32; ++k) o[40 + k] = std::byte(imageHash[static_cast<std::size_t>(k)]);
    storeLe32(o.data() + 72, indexCrc);
}

Expected<SegmentTrailer> SegmentTrailer::decode(std::span<const std::byte> i) {
    if (i.size() < kSize || std::memcmp(i.data(), kTrailerMagic, 8) != 0) return fail(ErrorCategory::InvalidFormat, "no segment trailer");
    SegmentTrailer t;
    t.indexOffset = loadLe64(i.data() + 8);
    t.indexCount = loadLe64(i.data() + 16);
    t.chunksTotal = loadLe64(i.data() + 24);
    t.flags = loadLe64(i.data() + 32);
    for (int k = 0; k < 32; ++k) t.imageHash[static_cast<std::size_t>(k)] = std::to_integer<std::uint8_t>(i[40 + k]);
    t.indexCrc = loadLe32(i.data() + 72);
    return t;
}

// ----------------------------------------------------------------------------- writer

std::filesystem::path SteinWriter::segmentPath(const std::filesystem::path& base, std::uint32_t index) {
    if (index == 0) return base;
    char suffix[16];
    std::snprintf(suffix, sizeof suffix, ".%03u", index);
    return std::filesystem::path(base.string() + suffix);
}

Expected<std::unique_ptr<SteinWriter>> SteinWriter::create(const std::filesystem::path& base, ByteCount totalSize,
                                                           std::uint32_t sectorSize, const WriterOptions& options) {
    if (options.chunkSize < 4096 || (options.chunkSize & (options.chunkSize - 1)) != 0)
        return fail(ErrorCategory::InvalidArgument, "chunk size must be a power of two >= 4096");
    if (options.splitSize && options.splitSize < static_cast<ByteCount>(options.chunkSize) * 2 + 1 * MiB)
        return fail(ErrorCategory::InvalidArgument, "split size must hold at least two chunks plus headers");
    auto w = std::unique_ptr<SteinWriter>(new SteinWriter());
    w->m_base = base;
    w->m_options = options;
    w->m_header.flags = SegmentHeader::kFlagHasManifest;
    w->m_header.imageUuid = randomUuid();
    w->m_header.chunkSize = options.chunkSize;
    w->m_header.totalSize = totalSize;
    w->m_header.sectorSize = sectorSize;
    w->m_header.compression = options.compression;
    w->m_header.imageHash = options.computeImageHash ? 1 : 0;
    w->m_header.splitSize = options.splitSize;
    if (options.encryptionKey) {
        if (options.keysJson.empty() || options.keysJson.size() > 1 * MiB) return fail(ErrorCategory::InvalidArgument, "encrypted image needs a key area");
        w->m_key = options.encryptionKey;
        w->m_header.flags |= SegmentHeader::kFlagEncrypted;
    }
    w->m_totalChunks = (totalSize + options.chunkSize - 1) / options.chunkSize;
    if (options.computeImageHash) w->m_imageHasher = Hasher::create(HashAlgorithm::Sha256);
    if (auto r = w->openSegment(0); !r) return fail(r.error());
    return w;
}

SteinWriter::~SteinWriter() {
    if (m_file) std::fclose(m_file);
}

Expected<void> SteinWriter::writeAll(std::span<const std::byte> bytes) {
    if (std::fwrite(bytes.data(), 1, bytes.size(), m_file) != bytes.size())
        return fail(ErrorCategory::Io, "write failed on " + segmentPath(m_base, m_segment).string(), errno);
    m_segmentBytes += bytes.size();
    return {};
}

Expected<void> SteinWriter::openSegment(std::uint32_t index) {
    const auto path = segmentPath(m_base, index);
    m_file = openFile(path, "wb");
    if (!m_file) return fail(ErrorCategory::Io, "cannot create " + path.string(), errno);
    m_segment = index;
    m_segmentBytes = 0;
    m_index.clear();
    m_files.push_back(path);
    SegmentHeader h = m_header;
    h.segmentIndex = index;
    std::string manifest;
    if (index == 0) {
        json::Value m = m_options.manifest;
        m.set("format", "stein-image");
        m.set("version", 1);
        m.set("tool", "libstein 0.1.0");
        {
            const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            char buf[32];
            std::tm tm{};
#ifdef _WIN32
            gmtime_s(&tm, &now);
#else
            gmtime_r(&now, &tm);
#endif
            std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
            m.set("created", buf);
        }
        json::Value layout;
        layout.set("chunk_size", static_cast<std::uint64_t>(m_header.chunkSize));
        layout.set("total_chunks", m_totalChunks);
        layout.set("compression", std::string(toString(m_header.compression)));
        layout.set("split_size", m_header.splitSize);
        layout.set("total_size", m_header.totalSize);
        layout.set("sector_size", static_cast<std::uint64_t>(m_header.sectorSize));
        m.set("layout", std::move(layout));
        manifest = m.dump();
        ByteCount pos = SegmentHeader::kSize;
        if (m_key) {
            // Key area (plaintext JSON) padded to its capacity so slots can be added later in place.
            const ByteCount keysCapacity = std::max<ByteCount>(4096, (m_options.keysJson.size() + 4095) / 4096 * 4096);
            h.keysOffset = pos;
            h.keysLength = m_options.keysJson.size();
            pos += keysCapacity;
            // Manifest: AEAD-encrypted.
            std::vector<std::byte> enc(manifest.size() + crypto::kTagSize);
            const std::string aad = "manifest";
            crypto::aeadEncrypt(*m_key, manifestNonce(), std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad.data()), aad.size()),
                                std::span<const std::byte>(reinterpret_cast<const std::byte*>(manifest.data()), manifest.size()), enc);
            manifest.assign(reinterpret_cast<const char*>(enc.data()), enc.size());
            m_keysPadded.assign(keysCapacity, std::byte{0});
            std::memcpy(m_keysPadded.data(), m_options.keysJson.data(), m_options.keysJson.size());
        }
        h.manifestOffset = pos;
        h.manifestLength = manifest.size();
    } else {
        h.flags &= ~SegmentHeader::kFlagHasManifest;
    }
    std::array<std::byte, SegmentHeader::kSize> hb{};
    h.encode(hb);
    if (auto r = writeAll(hb); !r) return r;
    if (index == 0 && m_key)
        if (auto r = writeAll(m_keysPadded); !r) return r;
    if (!manifest.empty())
        if (auto r = writeAll(std::span<const std::byte>(reinterpret_cast<const std::byte*>(manifest.data()), manifest.size())); !r) return r;
    if (index == 0) {
        m_header.keysOffset = h.keysOffset;
        m_header.keysLength = h.keysLength;
    }
    return {};
}

Expected<void> SteinWriter::closeSegment(bool last) {
    std::sort(m_index.begin(), m_index.end());
    std::vector<std::byte> idx(m_index.size() * 16);
    for (std::size_t i = 0; i < m_index.size(); ++i) {
        storeLe64(idx.data() + i * 16, m_index[i].first);
        storeLe64(idx.data() + i * 16 + 8, m_index[i].second);
    }
    SegmentTrailer t;
    t.indexOffset = m_segmentBytes;
    t.indexCount = m_index.size();
    t.chunksTotal = m_totalChunks;
    t.flags = (last ? SegmentTrailer::kFlagLastSegment : 0) | (m_options.omitZeroChunks ? SegmentTrailer::kFlagZerosOmitted : 0);
    if (last && m_imageHasher) {
        auto d = m_imageHasher->finish();
        std::copy_n(d.begin(), 32, t.imageHash.begin());
        if (m_key) {
            // Hide the plaintext hash from readers without the key.
            std::array<std::byte, 32> in{}, out{};
            for (int k = 0; k < 32; ++k) in[static_cast<std::size_t>(k)] = std::byte(t.imageHash[static_cast<std::size_t>(k)]);
            crypto::chacha20Xor(*m_key, imageHashNonce(), 0, in, out);
            for (int k = 0; k < 32; ++k) t.imageHash[static_cast<std::size_t>(k)] = std::to_integer<std::uint8_t>(out[static_cast<std::size_t>(k)]);
        }
        t.flags |= SegmentTrailer::kFlagImageHash;
    }
    t.indexCrc = Crc32c::compute(idx);
    std::array<std::byte, SegmentTrailer::kSize> tb{};
    t.encode(tb);
    if (auto r = writeAll(idx); !r) return r;
    if (auto r = writeAll(tb); !r) return r;
    if (std::fflush(m_file) != 0) return fail(ErrorCategory::Io, "flush failed", errno);
    std::fclose(m_file);
    m_file = nullptr;
    return {};
}

Expected<void> SteinWriter::writeChunk(std::uint64_t index, std::span<const std::byte> raw) {
    if (m_finished) return fail(ErrorCategory::InvalidArgument, "writer already finished");
    if (index >= m_totalChunks) return fail(ErrorCategory::OutOfRange, "chunk index beyond image");
    const ByteCount expected = std::min<ByteCount>(m_header.chunkSize, m_header.totalSize - index * m_header.chunkSize);
    if (raw.size() != expected) return fail(ErrorCategory::InvalidArgument, "chunk " + std::to_string(index) + " has wrong length");
    if (m_seen.count(index)) return fail(ErrorCategory::InvalidArgument, "chunk " + std::to_string(index) + " written twice");
    m_seen[index] = true;
    if (m_imageHasher) m_imageHasher->update(raw);   // NOTE: requires chunks in order for a meaningful hash; callers write in order
    ++m_chunksWritten;

    ChunkRecord rec;
    rec.chunkIndex = index;
    rec.rawLength = static_cast<std::uint32_t>(raw.size());
    rec.rawCrc = Crc32c::compute(raw);
    if (raw.size() < m_header.chunkSize) rec.flags |= ChunkRecord::kFlagPartial;
    std::vector<std::byte> payload;
    if (allZero(raw)) {
        ++m_zeroChunks;
        if (m_options.omitZeroChunks) return {};
        rec.flags |= ChunkRecord::kFlagZero;
    } else {
        if (m_header.compression == Compression::Lz4) {
            payload = lz4::compress(raw);
            if (payload.size() < raw.size()) rec.flags |= ChunkRecord::kFlagCompressed;
            else payload.assign(raw.begin(), raw.end());
        } else {
            payload.assign(raw.begin(), raw.end());
        }
        if (m_key) {
            std::vector<std::byte> enc(payload.size() + crypto::kTagSize);
            crypto::aeadEncrypt(*m_key, chunkNonce(index), chunkAad(index, rec.flags, rec.rawLength), payload, enc);
            payload.swap(enc);
        }
        rec.storedLength = static_cast<std::uint32_t>(payload.size());
        rec.storedCrc = Crc32c::compute(payload);
    }
    if (m_key) rec.rawCrc = 0;   // a plaintext CRC would leak; the AEAD tag authenticates the chunk
    const ByteCount recordBytes = ChunkRecord::kHeaderSize + payload.size();
    // Split: start a new segment when this record would exceed the limit (leave room for index+trailer).
    const ByteCount reserve = (m_index.size() + 1) * 16 + SegmentTrailer::kSize;
    if (m_options.splitSize && !m_index.empty() && m_segmentBytes + recordBytes + reserve > m_options.splitSize) {
        if (auto r = closeSegment(false); !r) return r;
        if (auto r = openSegment(m_segment + 1); !r) return r;
    }
    m_index.emplace_back(index, m_segmentBytes);
    std::array<std::byte, ChunkRecord::kHeaderSize> rb{};
    rec.encode(rb);
    if (auto r = writeAll(rb); !r) return r;
    if (!payload.empty())
        if (auto r = writeAll(payload); !r) return r;
    m_bytesStored += recordBytes;
    return {};
}

Expected<void> SteinWriter::finish() {
    if (m_finished) return {};
    if (auto r = closeSegment(true); !r) return r;
    m_finished = true;
    // Mark segment 0 complete.
    std::FILE* f = openFile(segmentPath(m_base, 0), "r+b");
    if (!f) return fail(ErrorCategory::Io, "cannot reopen segment 0", errno);
    SegmentHeader h = m_header;
    h.segmentIndex = 0;
    h.flags |= SegmentHeader::kFlagComplete;
    // Re-read manifest offsets from the file we wrote (they live in segment 0's header).
    std::array<std::byte, SegmentHeader::kSize> hb{};
    if (std::fread(hb.data(), 1, hb.size(), f) == hb.size()) {
        if (auto existing = SegmentHeader::decode(hb)) {
            h.manifestOffset = existing->manifestOffset;
            h.manifestLength = existing->manifestLength;
            h.keysOffset = existing->keysOffset;
            h.keysLength = existing->keysLength;
        }
    }
    h.encode(hb);
    const bool ok = seekTo(f, 0) && std::fwrite(hb.data(), 1, hb.size(), f) == hb.size() && std::fflush(f) == 0;
    std::fclose(f);
    if (!ok) return fail(ErrorCategory::Io, "cannot finalize segment 0", errno);
    return {};
}

// ----------------------------------------------------------------------------- reader

SteinReader::~SteinReader() {
    for (auto* f : m_files)
        if (f) std::fclose(f);
}

bool SteinReader::looksLikeStein(const std::filesystem::path& file) {
    std::FILE* f = openFile(file, "rb");
    if (!f) return false;
    char m[8];
    const bool ok = std::fread(m, 1, 8, f) == 8 && std::memcmp(m, kMagic, 8) == 0;
    std::fclose(f);
    return ok;
}

std::uint64_t SteinReader::totalChunks() const {
    if (m_chunksTotal) return m_chunksTotal;
    return (m_header.totalSize + m_header.chunkSize - 1) / m_header.chunkSize;
}

Expected<std::shared_ptr<SteinReader>> SteinReader::open(const std::filesystem::path& base) {
    auto r = std::shared_ptr<SteinReader>(new SteinReader());
    r->m_self = r;
    r->m_base = base;
    if (auto e = r->loadSegment(0, base); !e) return fail(e.error());
    // Further segments: name.NNN while they exist and the previous one was not the last.
    for (std::uint32_t i = 1;; ++i) {
        const auto& prev = r->m_segments.back();
        if (prev.trailer && (prev.trailer->flags & SegmentTrailer::kFlagLastSegment)) break;
        char suffix[16];
        std::snprintf(suffix, sizeof suffix, ".%03u", i);
        const std::filesystem::path p(base.string() + suffix);
        std::error_code ec;
        if (!std::filesystem::exists(p, ec)) break;
        if (auto e = r->loadSegment(i, p); !e) return fail(e.error());
    }
    const auto& last = r->m_segments.back();
    r->m_complete = (r->m_header.flags & SegmentHeader::kFlagComplete) && last.trailer && (last.trailer->flags & SegmentTrailer::kFlagLastSegment);
    if (!r->m_complete) {
        // Degraded but usable: all stored chunks are mapped.
    }
    return r;
}

std::FILE* SteinReader::fileFor(std::uint32_t segment) { return segment < m_files.size() ? m_files[segment] : nullptr; }

Expected<void> SteinReader::loadSegment(std::uint32_t index, const std::filesystem::path& path) {
    std::FILE* f = openFile(path, "rb");
    if (!f) return fail(ErrorCategory::NotFound, "cannot open " + path.string(), errno);
    m_files.push_back(f);
    SegmentInfo seg;
    seg.path = path;
    std::array<std::byte, SegmentHeader::kSize> hb{};
    if (auto e = readExact(f, 0, hb, "segment header"); !e) return e;
    auto h = SegmentHeader::decode(hb);
    if (!h) return fail(h.error());
    if (h->segmentIndex != index) return fail(ErrorCategory::InvalidFormat, path.string() + " is segment " + std::to_string(h->segmentIndex) + ", expected " + std::to_string(index));
    if (index == 0) {
        m_header = *h;
        if (h->encrypted()) {
            std::vector<std::byte> kb(h->keysLength);
            if (auto e = readExact(f, h->keysOffset, kb, "key area"); !e) return e;
            m_keysJson.assign(reinterpret_cast<const char*>(kb.data()), kb.size());
        }
        if (h->manifestLength) {
            if (h->manifestLength > 64 * MiB) return fail(ErrorCategory::InvalidFormat, "manifest too large");
            m_manifestRaw.resize(h->manifestLength);
            if (auto e = readExact(f, h->manifestOffset, m_manifestRaw, "manifest"); !e) return e;
            if (!h->encrypted())
                if (auto e = loadManifest(); !e) return e;
        }
    } else if (h->imageUuid != m_header.imageUuid) {
        return fail(ErrorCategory::InvalidFormat, path.string() + " belongs to a different image");
    }
    seg.header = *h;
    seekTo(f, 0);
    std::fseek(f, 0, SEEK_END);
    seg.fileSize = tellAt(f);
    // Trailer?
    bool haveTrailer = false;
    if (seg.fileSize >= SegmentHeader::kSize + SegmentTrailer::kSize) {
        std::array<std::byte, SegmentTrailer::kSize> tb{};
        if (readExact(f, seg.fileSize - SegmentTrailer::kSize, tb, "trailer")) {
            auto t = SegmentTrailer::decode(tb);
            if (t && t->indexOffset + t->indexCount * 16 + SegmentTrailer::kSize == seg.fileSize) {
                std::vector<std::byte> idx(t->indexCount * 16);
                if (readExact(f, t->indexOffset, idx, "index") && Crc32c::compute(idx) == t->indexCrc) {
                    for (std::uint64_t i = 0; i < t->indexCount; ++i)
                        m_map[loadLe64(idx.data() + i * 16)] = ChunkLocation{index, loadLe64(idx.data() + i * 16 + 8)};
                    seg.records = t->indexCount;
                    seg.trailer = *t;
                    haveTrailer = true;
                    if (t->chunksTotal) m_chunksTotal = t->chunksTotal;
                    if (t->flags & SegmentTrailer::kFlagZerosOmitted) m_zerosOmitted = true;
                    if (t->flags & SegmentTrailer::kFlagImageHash) {
                        m_imageHashStored = t->imageHash;
                        if (!m_header.encrypted()) m_imageHash = t->imageHash;
                    }
                }
            }
        }
    }
    if (!haveTrailer) {
        const ByteCount from = index == 0 ? h->manifestOffset + h->manifestLength : SegmentHeader::kSize;
        if (auto e = scanRecords(seg, f, from); !e) return e;
        m_zerosOmitted = true;   // conservative: unknown chunks read as zero
    }
    m_segments.push_back(std::move(seg));
    return {};
}

Expected<void> SteinReader::loadManifest() {
    std::vector<std::byte> plain;
    std::span<const std::byte> text = m_manifestRaw;
    if (m_header.encrypted()) {
        if (!m_key) return fail(ErrorCategory::Permission, "image is encrypted; unlock it first");
        if (m_manifestRaw.size() < crypto::kTagSize) return fail(ErrorCategory::InvalidFormat, "encrypted manifest too short");
        plain.resize(m_manifestRaw.size() - crypto::kTagSize);
        const std::string aad = "manifest";
        if (auto d = crypto::aeadDecrypt(*m_key, manifestNonce(), std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad.data()), aad.size()), m_manifestRaw, plain); !d)
            return fail(Error(ErrorCategory::Integrity, "manifest: " + d.error().message()));
        text = plain;
    }
    auto mj = json::Value::parse(std::string_view(reinterpret_cast<const char*>(text.data()), text.size()));
    if (!mj) return fail(ErrorCategory::InvalidFormat, "manifest is not valid JSON: " + mj.error().message());
    m_manifest = std::move(*mj);
    return {};
}

Expected<void> SteinReader::unlockWithKey(const crypto::Key256& key) {
    if (!encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    auto keys = Keys::fromJson(m_keysJson);
    if (!keys) return fail(keys.error());
    if (!keys->verifyMaster(key)) return fail(ErrorCategory::Integrity, "key does not match this image");
    m_key = key;
    if (!m_manifestRaw.empty())
        if (auto m = loadManifest(); !m) {
            m_key.reset();
            return m;
        }
    if (m_imageHashStored) {
        std::array<std::byte, 32> in{}, out{};
        for (int k = 0; k < 32; ++k) in[static_cast<std::size_t>(k)] = std::byte((*m_imageHashStored)[static_cast<std::size_t>(k)]);
        crypto::chacha20Xor(key, imageHashNonce(), 0, in, out);
        std::array<std::uint8_t, 32> h{};
        for (int k = 0; k < 32; ++k) h[static_cast<std::size_t>(k)] = std::to_integer<std::uint8_t>(out[static_cast<std::size_t>(k)]);
        m_imageHash = h;
    }
    return {};
}

Expected<void> SteinReader::unlock(const std::string& passphrase) {
    if (!encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    auto keys = Keys::fromJson(m_keysJson);
    if (!keys) return fail(keys.error());
    auto key = keys->unlock(passphrase);
    if (!key) return fail(key.error());
    return unlockWithKey(*key);
}

Expected<void> SteinReader::writeKeys(const std::string& keysJson) {
    if (!encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    const ByteCount capacity = m_header.manifestOffset - m_header.keysOffset;
    if (keysJson.size() > capacity) return fail(ErrorCategory::OutOfRange, "key area too small for the new slots");
    std::FILE* f = openFile(m_base, "r+b");
    if (!f) return fail(ErrorCategory::Io, "cannot open " + m_base.string() + " for writing", errno);
    std::vector<std::byte> padded(capacity, std::byte{0});
    std::memcpy(padded.data(), keysJson.data(), keysJson.size());
    bool ok = seekTo(f, m_header.keysOffset) && std::fwrite(padded.data(), 1, padded.size(), f) == padded.size();
    if (ok) {
        SegmentHeader h = m_header;
        h.keysLength = keysJson.size();
        std::array<std::byte, SegmentHeader::kSize> hb{};
        h.encode(hb);
        ok = seekTo(f, 0) && std::fwrite(hb.data(), 1, hb.size(), f) == hb.size() && std::fflush(f) == 0;
        if (ok) {
            m_header = h;
            m_keysJson = keysJson;
        }
    }
    std::fclose(f);
    if (!ok) return fail(ErrorCategory::Io, "cannot rewrite the key area", errno);
    return {};
}

Expected<void> SteinReader::scanRecords(SegmentInfo& seg, std::FILE* f, ByteCount from) {
    ByteCount pos = from;
    std::array<std::byte, ChunkRecord::kHeaderSize> rb{};
    while (pos + ChunkRecord::kHeaderSize <= seg.fileSize) {
        if (!readExact(f, pos, rb, "record")) break;
        auto rec = ChunkRecord::decode(rb);
        if (!rec) break;
        if (pos + ChunkRecord::kHeaderSize + rec->storedLength > seg.fileSize) break;   // torn
        if (rec->storedLength) {
            std::vector<std::byte> payload(rec->storedLength);
            if (!readExact(f, pos + ChunkRecord::kHeaderSize, payload, "payload") || Crc32c::compute(payload) != rec->storedCrc) break;
        }
        m_map[rec->chunkIndex] = ChunkLocation{seg.header.segmentIndex, pos};
        ++seg.records;
        pos += ChunkRecord::kHeaderSize + rec->storedLength;
    }
    return {};
}

std::vector<std::uint64_t> SteinReader::missingChunks() const {
    std::vector<std::uint64_t> out;
    if (m_complete) return out;
    for (std::uint64_t i = 0; i < totalChunks(); ++i)
        if (!m_map.count(i)) out.push_back(i);
    return out;
}

Expected<ChunkRecord> SteinReader::recordOf(std::uint64_t index) {
    auto it = m_map.find(index);
    if (it == m_map.end()) return fail(ErrorCategory::NotFound, "chunk not stored");
    std::FILE* f = fileFor(it->second.segment);
    std::array<std::byte, ChunkRecord::kHeaderSize> rb{};
    if (auto e = readExact(f, it->second.offset, rb, "chunk record"); !e) return fail(e.error());
    auto rec = ChunkRecord::decode(rb);
    if (!rec) return fail(rec.error());
    if (rec->chunkIndex != index) return fail(ErrorCategory::InvalidFormat, "index points at the wrong chunk");
    return rec;
}

Expected<bool> SteinReader::verifyStored(std::uint64_t index) {
    auto it = m_map.find(index);
    if (it == m_map.end()) return false;
    auto rec = recordOf(index);
    if (!rec) return fail(rec.error());
    if (rec->storedLength == 0) return true;
    std::vector<std::byte> payload(rec->storedLength);
    if (auto e = readExact(fileFor(it->second.segment), it->second.offset + ChunkRecord::kHeaderSize, payload, "payload"); !e) return fail(e.error());
    if (Crc32c::compute(payload) != rec->storedCrc) return fail(ErrorCategory::Integrity, "chunk " + std::to_string(index) + ": stored payload CRC mismatch");
    return true;
}

Expected<void> SteinReader::readChunk(std::uint64_t index, std::span<std::byte> out) {
    const ByteCount expected = std::min<ByteCount>(m_header.chunkSize, m_header.totalSize - index * m_header.chunkSize);
    if (index >= totalChunks() || out.size() != expected) return fail(ErrorCategory::OutOfRange, "bad chunk index or buffer");
    auto it = m_map.find(index);
    if (it == m_map.end()) {
        std::fill(out.begin(), out.end(), std::byte{0});
        return {};
    }
    auto rec = recordOf(index);
    if (!rec) return fail(rec.error());
    if (rec->rawLength != out.size()) return fail(ErrorCategory::InvalidFormat, "chunk raw length mismatch");
    if (rec->flags & ChunkRecord::kFlagZero) {
        std::fill(out.begin(), out.end(), std::byte{0});
        return {};
    }
    std::vector<std::byte> payload(rec->storedLength);
    if (auto e = readExact(fileFor(it->second.segment), it->second.offset + ChunkRecord::kHeaderSize, payload, "payload"); !e) return e;
    if (Crc32c::compute(payload) != rec->storedCrc) return fail(ErrorCategory::Integrity, "chunk " + std::to_string(index) + ": stored payload CRC mismatch");
    if (m_header.encrypted()) {
        if (!m_key) return fail(ErrorCategory::Permission, "image is encrypted; unlock it first");
        if (payload.size() < crypto::kTagSize) return fail(ErrorCategory::InvalidFormat, "encrypted payload too short");
        std::vector<std::byte> plain(payload.size() - crypto::kTagSize);
        if (auto d = crypto::aeadDecrypt(*m_key, chunkNonce(index), chunkAad(index, rec->flags, rec->rawLength), payload, plain); !d)
            return fail(Error(ErrorCategory::Integrity, "chunk " + std::to_string(index) + ": " + d.error().message()));
        payload.swap(plain);
    }
    if (rec->flags & ChunkRecord::kFlagCompressed) {
        if (m_header.compression != Compression::Lz4) return fail(ErrorCategory::Unsupported, "unknown compression");
        if (auto d = lz4::decompress(payload, out); !d) return d;
    } else {
        if (payload.size() != out.size()) return fail(ErrorCategory::InvalidFormat, "uncompressed payload length mismatch");
        std::copy(payload.begin(), payload.end(), out.begin());
    }
    if (!m_header.encrypted() && Crc32c::compute(out) != rec->rawCrc) return fail(ErrorCategory::Integrity, "chunk " + std::to_string(index) + ": raw CRC mismatch after decompression");
    return {};
}

std::shared_ptr<BlockDevice> SteinReader::asDevice() { return std::make_shared<ImageDevice>(m_self.lock()); }

// ----------------------------------------------------------------------------- device

ImageDevice::ImageDevice(std::shared_ptr<SteinReader> reader) : m_reader(std::move(reader)) {
    m_name = m_reader->segments().front().path.string();
    m_geometry.sizeBytes = m_reader->header().totalSize;
    m_geometry.logicalSectorSize = m_reader->header().sectorSize ? m_reader->header().sectorSize : 512;
    m_geometry.physicalSectorSize = m_geometry.logicalSectorSize;
}

Expected<void> ImageDevice::readAt(ByteCount offset, std::span<std::byte> dst) {
    if (auto r = checkRange(offset, dst.size()); !r) return r;
    const ByteCount cs = m_reader->header().chunkSize;
    std::size_t done = 0;
    while (done < dst.size()) {
        const ByteCount pos = offset + done;
        const std::uint64_t idx = pos / cs;
        const ByteCount inChunk = pos % cs;
        if (idx != m_cachedIndex) {
            const ByteCount len = std::min<ByteCount>(cs, m_geometry.sizeBytes - idx * cs);
            m_cache.resize(len);
            if (auto r = m_reader->readChunk(idx, m_cache); !r) return r;
            m_cachedIndex = idx;
        }
        const std::size_t n = static_cast<std::size_t>(std::min<ByteCount>(m_cache.size() - inChunk, dst.size() - done));
        std::copy_n(m_cache.begin() + static_cast<std::ptrdiff_t>(inChunk), n, dst.begin() + static_cast<std::ptrdiff_t>(done));
        done += n;
    }
    return {};
}

} // namespace stein::image
