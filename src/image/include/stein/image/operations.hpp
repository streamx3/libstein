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
    std::string passphrase;           // non-empty: encrypt (ChaCha20-Poly1305, key area with one passphrase slot)
    KdfParams kdf;                    // Argon2id t=3 m=256MiB p=4 by default
    std::string sourceName;           // defaults to device->name()
    std::string sourceIdentity;       // platform identity when known
    json::Value sourceExtra;          // object; its members are merged into manifest "source" (e.g. partition provenance)
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
    bool writeZeroChunks = true;       // deprecated alias: false means zeroPolicy = Skip
    ZeroPolicy zeroPolicy = ZeroPolicy::Write;   // SkipInside: zero only the partition table's free space, see keepRegionsOf()
    bool discardZeroChunks = false;
    bool skipIdentical = true;         // compare before writing, skip chunks the target already holds (see CopyOptions)
    bool allowSmallerTarget = false;   // write only what fits
};

// The ranges a partition-aware restore must not zero: every entry of the image's
// partition table (any type, extended containers included), clipped to the device.
// Without a table, or with one the library does not understand, the whole device
// is kept: what cannot be read as a table is not treated as free space.
struct KeepRegions {
    std::vector<Region> regions;
    std::string reason;                // "GPT, 3 partitions", "no partition table: whole device kept", ...
    bool tableUnderstood = false;
};
Expected<KeepRegions> keepRegionsOf(const std::shared_ptr<BlockDevice>& source);

// What a restore will do with the image's zero chunks under `options.zeroPolicy`,
// computed from the chunk map before anything is written.
struct ZeroPlan {
    ByteCount zeroBytes = 0;           // bytes of the image that are implicit (all-zero) chunks
    ByteCount toWrite = 0;             // of those, bytes that will be written as zeros
    ByteCount toSkip = 0;              // of those, bytes left untouched on the target
    std::uint64_t zeroChunks = 0, totalChunks = 0;
    KeepRegions keep;                  // filled for SkipInside
};
Expected<ZeroPlan> planZeroWrites(const std::filesystem::path& image, const RestoreOptions& options, const std::string& passphrase = {});

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
    bool encrypted = false;
    bool unlocked = false;            // manifest and hash below are only meaningful when !encrypted || unlocked
    std::size_t keySlots = 0;
    json::Value manifest;
    std::vector<SegmentInfo> segments;
    std::uint64_t chunksTotal = 0, chunksStored = 0;
    bool complete = false;
    std::optional<std::string> imageHashHex;
    ByteCount storedBytes = 0;
};

Expected<CreateResult> createImage(std::shared_ptr<BlockDevice> source, const std::filesystem::path& out, const CreateOptions& options,
                                   Progress& progress);
// `passphrase` unlocks encrypted images; empty leaves them locked (restore, level-3 verify
// and openImage then fail with Permission; info and level-2 verify work without the key).
Expected<RestoreResult> restoreImage(const std::filesystem::path& image, BlockDevice& target, const RestoreOptions& options,
                                     Progress& progress, const std::string& passphrase = {});
// level: 1 structure only, 2 stored CRCs, 3 full content (decompress + raw CRCs + SHA-256).
Expected<VerifyResult> verifyImage(const std::filesystem::path& image, int level, Progress& progress, const std::string& passphrase = {});
Expected<ImageInfo> imageInfo(const std::filesystem::path& image, const std::string& passphrase = {});
// Open a .stein image as a read-only block device (R5d: images are devices).
Expected<std::shared_ptr<BlockDevice>> openImage(const std::filesystem::path& image, const std::string& passphrase = {});
// Key slot management on an existing encrypted image (the file is rewritten in place).
Expected<Keys> imageKeys(const std::filesystem::path& image);
Expected<int> addImageKey(const std::filesystem::path& image, const std::string& passphrase, const std::string& newPassphrase, const KdfParams& kdf = {}, std::string label = {});
Expected<void> removeImageKey(const std::filesystem::path& image, const std::string& passphrase, int slotId);

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
