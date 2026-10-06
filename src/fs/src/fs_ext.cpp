// SPDX-License-Identifier: MIT
#include "detectors.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/ext.hpp"

namespace stein::fs::detail {

namespace gen = layout::gen;
using layout::Validity;

Result detectExt(Dev dev) {
    constexpr ByteCount kSbOffset = 1024;
    auto raw = readOrNotFound(*dev, kSbOffset, gen::ExtSuperblock::kSize);
    if (!raw) return fail(raw.error());
    gen::ExtSuperblock sb(*raw);
    if (sb.magic() != 0xEF53) return notMine("no ext magic");
    if (sb.logBlockSize() > 6 || sb.inodesPerGroup() == 0 || sb.blocksPerGroup() == 0) return notMine("implausible ext superblock");

    auto fs = std::make_unique<SimpleFileSystem>(dev);
    auto& info = fs->mutableInfo();
    const std::uint32_t incompat = sb.featureIncompat(), rocompat = sb.featureRoCompat(), compat = sb.featureCompat();
    constexpr std::uint32_t kIncompatExt4 = (1u << 4) | (1u << 6) | (1u << 7) | (1u << 8) | (1u << 9) | (1u << 10) | (1u << 12) |
                                            (1u << 13) | (1u << 14) | (1u << 15) | (1u << 16) | (1u << 17);
    constexpr std::uint32_t kRoCompatExt4 = (1u << 3) | (1u << 4) | (1u << 5) | (1u << 6) | (1u << 8) | (1u << 9) | (1u << 10) |
                                            (1u << 13) | (1u << 15);
    const bool hasJournal = compat & (1u << 2);
    if ((incompat & kIncompatExt4) || (rocompat & kRoCompatExt4)) info.type = FsType::Ext4;
    else if (hasJournal) info.type = FsType::Ext3;
    else info.type = FsType::Ext2;

    const ByteCount bs = ByteCount{1024} << sb.logBlockSize();
    const bool is64 = incompat & (1u << 7);
    const std::uint64_t blocks = sb.blocksCountLo() | (is64 ? (std::uint64_t{sb.blocksCountHi()} << 32) : 0);
    const std::uint64_t freeBlocks = sb.freeBlocksCountLo() | (is64 ? (std::uint64_t{sb.freeBlocksCountHi()} << 32) : 0);
    info.version = std::to_string(sb.revLevel()) + "." + std::to_string(sb.minorRevLevel());
    info.label = sb.volumeName();
    info.uuid = uuidText(std::span<const std::byte>(*raw).subspan(gen::ExtSuperblock::kUuidOffset, 16));
    info.blockSize = bs;
    info.totalBytes = blocks * bs;
    info.usedBytes = (blocks > freeBlocks ? blocks - freeBlocks : 0) * bs;
    const std::uint16_t state = sb.state();
    info.clean = (state & 1) && !(state & 2);
    if (!(state & 1)) fs->diag(Validity::Warning, "ext.not_clean", "filesystem was not cleanly unmounted");
    if (state & 2) fs->diag(Validity::Warning, "ext.errors", "filesystem has recorded errors");
    if (sb.errorCount()) fs->diag(Validity::Info, "ext.error_count", std::to_string(sb.errorCount()) + " errors recorded");
    if (incompat & (1u << 2)) fs->diag(Validity::Info, "ext.needs_recovery", "journal needs recovery");

    auto tree = sb.describe(kSbOffset);
    if (auto* n = tree.child("feature_incompat")) for (const auto& f : split(n->pretty, '|')) if (f != "none") info.features.push_back("incompat:" + f);
    if (auto* n = tree.child("feature_ro_compat")) for (const auto& f : split(n->pretty, '|')) if (f != "none") info.features.push_back("ro_compat:" + f);
    if (auto* n = tree.child("feature_compat")) for (const auto& f : split(n->pretty, '|')) if (f != "none") info.features.push_back("compat:" + f);
    fs->setTreeName(std::string(displayName(info.type)) + " filesystem");
    fs->addNode(std::move(tree));
    fs->addRegion(Region{kSbOffset, gen::ExtSuperblock::kSize});
    // Group descriptor table follows the superblock's block.
    const ByteCount gdtBlock = bs == 1024 ? 2 : 1;
    const std::uint64_t groups = (blocks + sb.blocksPerGroup() - 1) / sb.blocksPerGroup();
    const std::uint32_t descSize = (incompat & (1u << 7)) && sb.descSize() ? sb.descSize() : 32;
    const ByteCount gdtBytes = alignUp(groups * descSize, bs);
    if (gdtBlock * bs + gdtBytes <= dev->size()) fs->addRegion(Region{gdtBlock * bs, gdtBytes});
    // First backup superblock (group 1) when it exists.
    if (groups > 1) {
        const ByteCount backup = ByteCount{sb.blocksPerGroup()} * bs + (bs == 1024 ? 1024 : 0);
        if (backup + 1024 <= dev->size()) fs->addRegion(Region{backup, 1024});
    }
    return std::unique_ptr<FileSystem>(std::move(fs));
}

} // namespace stein::fs::detail
