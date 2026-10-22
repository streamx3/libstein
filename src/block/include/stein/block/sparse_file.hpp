// SPDX-License-Identifier: MIT
// The STEINSPARSE1 container: a list of (offset, bytes) runs plus the total
// size and sector size. Used for test fixtures (tools/fixtures/sparsify.py)
// and as the first "piece" format for dumping and restoring partition-table
// metadata (doc/design/14-imaging.md §2a). Not the full .stein image format.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/block/memory_device.hpp"
#include "stein/core/keys.hpp"

#include <filesystem>
#include <memory>
#include <vector>

namespace stein {

class SparseFile {
public:
    struct Run {
        ByteCount offset;
        std::vector<std::byte> bytes;
    };
    struct Contents {
        ByteCount totalSize = 0;
        std::uint32_t sectorSize = 512;
        std::vector<Run> runs;
    };

    static constexpr const char* kMagic = "STEINSPARSE1";
    static constexpr const char* kEncryptedMagic = "STEINPIECE1E";   // key area + AEAD(STEINSPARSE1 body)

    // `passphrase` opens encrypted pieces (Permission error when missing, Integrity when wrong).
    static Expected<Contents> read(const std::filesystem::path& path, const std::string& passphrase = {});
    // Non-empty `passphrase`: write an encrypted piece with one key slot.
    static Expected<void> write(const std::filesystem::path& path, const Contents& contents, const std::string& passphrase = {},
                                const KdfParams& kdf = {});
    static bool isEncrypted(const std::filesystem::path& path);

    std::vector<std::byte> static serialize(const Contents& contents);
    static Expected<Contents> parse(std::span<const std::byte> bytes, const std::string& what);

    // Load into a fresh in-memory device (fixtures).
    static Expected<std::shared_ptr<MemoryDevice>> loadIntoMemory(const std::filesystem::path& path);
    // The piece as a read-only device of its full geometry that holds only the runs (RunListDevice
    // below): what a CLI or viewer opens a dumped table piece as, since loadIntoMemory() would
    // allocate the whole disk the piece was taken from.
    static Expected<std::shared_ptr<BlockDevice>> openAsDevice(const std::filesystem::path& path, const std::string& passphrase = {});
    // Capture the given regions of `device` (e.g. PartitionTable::metadataRegions()).
    static Expected<Contents> capture(BlockDevice& device, const std::vector<Region>& regions);
    // Write every run back onto `device`. Fails before writing anything if a run does not fit.
    static Expected<void> apply(const Contents& contents, BlockDevice& device);
};

// A piece's byte runs as a read-only BlockDevice with the piece's own size and sector size: a
// read inside a run returns the run's bytes, a read anywhere else returns zeros, and writes are
// refused. Nothing is allocated for the gaps, so a table piece dumped from a 2 TB disk (a few
// tens of KiB of runs that describe 2 TiB) costs what it stores, where a MemoryDevice of the
// described size would try to allocate the 2 TiB. Overlapping runs resolve the way
// SparseFile::apply() writes them: the later run in the piece wins.
class RunListDevice final : public BlockDevice {
public:
    // OutOfRange when a run reaches past totalSize; InvalidArgument for a zero sector size.
    static Expected<std::shared_ptr<RunListDevice>> create(SparseFile::Contents contents, std::string name = "piece");

    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return true; }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override;
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override;
    Expected<void> flush() override { return {}; }
    Expected<void> discard(ByteCount offset, ByteCount length) override;
    Expected<void> zeroRange(ByteCount offset, ByteCount length) override;

    // The runs as served: sorted by offset, overlaps trimmed, empty runs dropped.
    const std::vector<SparseFile::Run>& runs() const { return m_runs; }
    // Bytes the runs hold, as opposed to size(): what the piece actually stores.
    ByteCount storedBytes() const { return m_storedBytes; }

private:
    RunListDevice() = default;
    std::vector<SparseFile::Run> m_runs;
    Geometry m_geometry;
    std::string m_name;
    ByteCount m_storedBytes = 0;
};

} // namespace stein
