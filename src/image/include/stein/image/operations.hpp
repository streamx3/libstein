// SPDX-License-Identifier: MIT
// High-level image operations shared by the CLI, UIs and stein_app:
// create, restore, verify, info, open. Thin compositions of the copy engine,
// the .stein writer/reader and the probe tree.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/json.hpp"
#include "stein/core/progress.hpp"
#include "stein/image/copy.hpp"
#include "stein/image/stein_format.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace stein::image {

struct CreateOptions {
    std::uint32_t chunkSize = 4 * MiB;
    Compression compression = Compression::Lz4;
    ByteCount splitSize = 0;
    BadSectorPolicy badSectors = BadSectorPolicy::SkipZero;
    bool computeImageHash = true;
    bool recordTopology = true;       // probe the source and store the tree in the manifest
    bool usedBlocksOnly = false;      // read allocation bitmaps and store free space as zero chunks
    std::string sourceName;           // defaults to device->name()
    std::string sourceIdentity;       // platform identity when known
    std::string notes;
};

struct CreateResult {
    std::vector<std::filesystem::path> files;
    std::vector<std::string> allocationNotes;   // per filesystem: map used / why not
    Uuid imageUuid;
    CopyStats stats;
    ByteCount storedBytes = 0;
    std::string imageHashHex;
};

struct RestoreOptions {
    bool verifyPayloadFirst = false;   // CRC pass over the image before writing anything
    bool writeZeroChunks = true;       // false only when the target is known to be zeroed
    bool discardZeroChunks = false;
    bool allowSmallerTarget = false;   // write only what fits
};

struct RestoreResult {
    CopyStats stats;
    bool targetLarger = false;
    bool targetSmaller = false;
};

struct VerifyResult {
    bool structureOk = false;
    bool complete = false;
    std::uint64_t chunksTotal = 0, chunksStored = 0, chunksChecked = 0, chunksBad = 0;
    std::vector<std::uint64_t> badChunks;
    bool imageHashChecked = false, imageHashOk = false;
    std::string imageHashHex;
};

struct ImageInfo {
    SegmentHeader header;
    json::Value manifest;
    std::vector<SegmentInfo> segments;
    std::uint64_t chunksTotal = 0, chunksStored = 0;
    bool complete = false;
    std::optional<std::string> imageHashHex;
    ByteCount storedBytes = 0;
};

Expected<CreateResult> createImage(std::shared_ptr<BlockDevice> source, const std::filesystem::path& out, const CreateOptions& options,
                                   Progress& progress);
Expected<RestoreResult> restoreImage(const std::filesystem::path& image, BlockDevice& target, const RestoreOptions& options,
                                     Progress& progress);
// level: 1 structure only, 2 stored CRCs, 3 full content (decompress + raw CRCs + SHA-256).
Expected<VerifyResult> verifyImage(const std::filesystem::path& image, int level, Progress& progress);
Expected<ImageInfo> imageInfo(const std::filesystem::path& image);
// Open a .stein image as a read-only block device (R5d: images are devices).
Expected<std::shared_ptr<BlockDevice>> openImage(const std::filesystem::path& image);

// Split raw images: disk.img.000/.001/..., disk.img.001-based sets, or
// `split -d` style disk.img.00/.01. `path` may be any member or the common
// prefix. The set must be contiguous; files are opened in order and
// concatenated (ConcatDevice).
struct SplitRawSet {
    std::filesystem::path prefix;
    std::vector<std::filesystem::path> members;   // sorted
    ByteCount totalBytes = 0;
};
std::optional<SplitRawSet> findSplitRaw(const std::filesystem::path& path);
Expected<std::shared_ptr<BlockDevice>> openSplitRaw(const std::filesystem::path& path, bool writable, std::uint32_t sectorSize = 512);

} // namespace stein::image
