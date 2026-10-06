// SPDX-License-Identifier: MIT
// The .stein container, version 1. Spec: doc/spec/stein-image-v1.md.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/guid.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/json.hpp"
#include "stein/core/units.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace stein::image {

enum class Compression : std::uint8_t { None = 0, Lz4 = 1 };
std::string_view toString(Compression c);
std::optional<Compression> compressionFromString(std::string_view s);

struct SegmentHeader {
    static constexpr std::size_t kSize = 128;
    static constexpr std::uint32_t kFlagHasManifest = 1u << 0;
    static constexpr std::uint32_t kFlagEncrypted = 1u << 1;
    static constexpr std::uint32_t kFlagComplete = 1u << 2;

    std::uint16_t version = 1;
    std::uint32_t flags = 0;
    Uuid imageUuid;
    std::uint32_t segmentIndex = 0;
    std::uint32_t chunkSize = 4 * MiB;
    ByteCount totalSize = 0;
    std::uint32_t sectorSize = 512;
    Compression compression = Compression::None;
    std::uint8_t chunkHash = 1;     // crc32c
    std::uint8_t imageHash = 1;     // sha256
    ByteCount manifestOffset = 0, manifestLength = 0;
    ByteCount splitSize = 0;

    void encode(std::span<std::byte, kSize> out) const;
    static Expected<SegmentHeader> decode(std::span<const std::byte> in);
};

struct ChunkRecord {
    static constexpr std::size_t kHeaderSize = 32;
    static constexpr std::uint32_t kFlagZero = 1u << 0;
    static constexpr std::uint32_t kFlagCompressed = 1u << 1;
    static constexpr std::uint32_t kFlagPartial = 1u << 2;

    std::uint32_t flags = 0;
    std::uint64_t chunkIndex = 0;
    std::uint32_t rawLength = 0;
    std::uint32_t storedLength = 0;
    std::uint32_t rawCrc = 0;
    std::uint32_t storedCrc = 0;

    void encode(std::span<std::byte, kHeaderSize> out) const;
    static Expected<ChunkRecord> decode(std::span<const std::byte> in);
};

struct SegmentTrailer {
    static constexpr std::size_t kSize = 80;
    static constexpr std::uint64_t kFlagLastSegment = 1u << 0;
    static constexpr std::uint64_t kFlagImageHash = 1u << 1;
    static constexpr std::uint64_t kFlagZerosOmitted = 1u << 2;

    ByteCount indexOffset = 0;
    std::uint64_t indexCount = 0;
    std::uint64_t chunksTotal = 0;
    std::uint64_t flags = 0;
    std::array<std::uint8_t, 32> imageHash{};
    std::uint32_t indexCrc = 0;

    void encode(std::span<std::byte, kSize> out) const;
    static Expected<SegmentTrailer> decode(std::span<const std::byte> in);
};

struct WriterOptions {
    std::uint32_t chunkSize = 4 * MiB;
    Compression compression = Compression::Lz4;
    ByteCount splitSize = 0;              // 0 = single file
    bool omitZeroChunks = true;
    bool computeImageHash = true;
    json::Value manifest;                 // "source", "topology", "notes"... filled by the caller
};

// Sequential writer: writeChunk() in any order, finish() once.
class SteinWriter {
public:
    static Expected<std::unique_ptr<SteinWriter>> create(const std::filesystem::path& base, ByteCount totalSize,
                                                         std::uint32_t sectorSize, const WriterOptions& options);
    ~SteinWriter();
    SteinWriter(const SteinWriter&) = delete;
    SteinWriter& operator=(const SteinWriter&) = delete;

    // `raw` is the chunk's source bytes (chunkSize, or less for the last chunk).
    Expected<void> writeChunk(std::uint64_t index, std::span<const std::byte> raw);
    Expected<void> finish();
    const Uuid& imageUuid() const { return m_header.imageUuid; }
    std::uint64_t chunksWritten() const { return m_chunksWritten; }
    std::uint64_t zeroChunks() const { return m_zeroChunks; }
    ByteCount bytesStored() const { return m_bytesStored; }
    std::vector<std::filesystem::path> files() const { return m_files; }

private:
    SteinWriter() = default;
    Expected<void> openSegment(std::uint32_t index);
    Expected<void> closeSegment(bool last);
    Expected<void> writeAll(std::span<const std::byte> bytes);
    static std::filesystem::path segmentPath(const std::filesystem::path& base, std::uint32_t index);

    std::filesystem::path m_base;
    SegmentHeader m_header;
    WriterOptions m_options;
    std::FILE* m_file = nullptr;
    std::uint32_t m_segment = 0;
    ByteCount m_segmentBytes = 0;
    std::vector<std::pair<std::uint64_t, ByteCount>> m_index;     // current segment
    std::vector<std::filesystem::path> m_files;
    std::uint64_t m_chunksWritten = 0, m_zeroChunks = 0, m_totalChunks = 0;
    ByteCount m_bytesStored = 0;
    std::unique_ptr<stein::Hasher> m_imageHasher;
    std::map<std::uint64_t, bool> m_seen;
    bool m_finished = false;
};

struct ChunkLocation {
    std::uint32_t segment;
    ByteCount offset;
};

struct SegmentInfo {
    std::filesystem::path path;
    SegmentHeader header;
    std::optional<SegmentTrailer> trailer;   // absent = recovered by scanning
    std::uint64_t records = 0;
    ByteCount fileSize = 0;
};

// Opens all segments of an image, builds the chunk map, exposes it as a BlockDevice.
class SteinReader {
public:
    static Expected<std::shared_ptr<SteinReader>> open(const std::filesystem::path& base);
    ~SteinReader();

    const SegmentHeader& header() const { return m_header; }
    const json::Value& manifest() const { return m_manifest; }
    const std::vector<SegmentInfo>& segments() const { return m_segments; }
    std::uint64_t totalChunks() const;
    std::uint64_t storedChunks() const { return m_map.size(); }
    bool complete() const { return m_complete; }
    bool zerosOmitted() const { return m_zerosOmitted; }
    std::optional<std::array<std::uint8_t, 32>> imageHash() const { return m_imageHash; }
    // Chunks that are neither stored nor implicitly zero (incomplete image).
    std::vector<std::uint64_t> missingChunks() const;

    // Read one chunk's raw bytes (zero-filled for omitted chunks). Verifies CRCs.
    Expected<void> readChunk(std::uint64_t index, std::span<std::byte> out);
    // Verify a stored chunk's payload CRC without decompressing. Returns false when not stored.
    Expected<bool> verifyStored(std::uint64_t index);
    Expected<ChunkRecord> recordOf(std::uint64_t index);

    std::shared_ptr<BlockDevice> asDevice();   // read-only ImageDevice over this reader

    static bool looksLikeStein(const std::filesystem::path& file);

private:
    SteinReader() = default;
    Expected<void> loadSegment(std::uint32_t index, const std::filesystem::path& path);
    Expected<void> scanRecords(SegmentInfo& seg, std::FILE* f, ByteCount from);
    std::FILE* fileFor(std::uint32_t segment);

    SegmentHeader m_header;
    json::Value m_manifest;
    std::vector<SegmentInfo> m_segments;
    std::vector<std::FILE*> m_files;
    std::map<std::uint64_t, ChunkLocation> m_map;
    bool m_complete = false, m_zerosOmitted = false;
    std::optional<std::array<std::uint8_t, 32>> m_imageHash;
    std::uint64_t m_chunksTotal = 0;
    std::weak_ptr<SteinReader> m_self;
    friend class ImageDevice;
};

// Read-only BlockDevice over a SteinReader with a small chunk cache.
class ImageDevice final : public BlockDevice {
public:
    explicit ImageDevice(std::shared_ptr<SteinReader> reader);
    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount, std::span<const std::byte>) override {
        return fail(ErrorCategory::Permission, "stein images are read-only in this version");
    }
    Expected<void> flush() override { return {}; }

private:
    std::shared_ptr<SteinReader> m_reader;
    std::string m_name;
    Geometry m_geometry;
    std::uint64_t m_cachedIndex = ~0ull;
    std::vector<std::byte> m_cache;
};

} // namespace stein::image
