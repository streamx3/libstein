// SPDX-License-Identifier: MIT
#include "stein/image/operations.hpp"

#include <algorithm>
#include <cctype>

#include "stein/block/concat_device.hpp"
#include "stein/block/file_device.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/strings.hpp"
#include "stein/probe/topology.hpp"
#include "stein/pt/gpt_table.hpp"

namespace stein::image {

namespace {

json::Value topologyJson(const probe::Node& n) {
    json::Value j;
    j.set("name", n.name);
    j.set("offset", n.region.offset);
    j.set("length", n.region.length);
    if (n.partition) {
        json::Value p;
        p.set("index", static_cast<std::uint64_t>(n.partition->index));
        p.set("first_lba", n.partition->firstLba);
        p.set("last_lba", n.partition->lastLba);
        p.set("type", n.partition->type.code());
        p.set("type_name", pt::types::name(n.partition->type));
        if (!n.partition->name.empty()) p.set("name", n.partition->name);
        if (!n.partition->uuid.isNil()) p.set("uuid", n.partition->uuid.toString());
        if (n.partition->attributes) p.set("attributes", n.partition->attributes);
        j.set("partition", std::move(p));
    }
    if (n.table) {
        json::Value t;
        t.set("type", std::string(pt::toString(n.table->type())));
        t.set("first_usable_lba", n.table->firstUsableLba());
        t.set("last_usable_lba", n.table->lastUsableLba());
        if (auto* gpt = dynamic_cast<const pt::GptTable*>(n.table.get())) t.set("disk_guid", gpt->diskGuid().toString());
        j.set("table", std::move(t));
    }
    if (n.content) {
        const auto& info = n.content->info();
        json::Value c;
        c.set("type", std::string(fs::toString(info.type)));
        if (!info.label.empty()) c.set("label", info.label);
        if (!info.uuid.empty()) c.set("uuid", info.uuid);
        if (!info.version.empty()) c.set("version", info.version);
        if (info.totalBytes) c.set("size", *info.totalBytes);
        if (info.usedBytes) c.set("used", *info.usedBytes);
        j.set("content", std::move(c));
    }
    if (!n.children.empty()) {
        json::Value kids = json::Value::array();
        for (const auto& c : n.children) kids.push(topologyJson(c));
        j.set("children", std::move(kids));
    }
    return j;
}

class WriterSink final : public ChunkSink {
public:
    explicit WriterSink(SteinWriter& w) : m_w(w) {}
    Expected<void> writeChunk(std::uint64_t index, std::span<const std::byte> raw) override { return m_w.writeChunk(index, raw); }

private:
    SteinWriter& m_w;
};

std::string hex32(const std::array<std::uint8_t, 32>& h) { return Hasher::hex(h); }

} // namespace

Expected<CreateResult> createImage(std::shared_ptr<BlockDevice> source, const std::filesystem::path& out, const CreateOptions& options,
                                   Progress& progress) {
    if (!source) return fail(ErrorCategory::InvalidArgument, "null source");
    WriterOptions wo;
    std::optional<Keys> keys;
    if (!options.passphrase.empty()) {
        auto k = Keys::create(options.passphrase, options.kdf, "created with the image");
        if (!k) return fail(k.error());
        keys = std::move(*k);
        wo.encryptionKey = keys->master();
        wo.keysJson = keys->toJson();
    }
    wo.chunkSize = options.chunkSize;
    wo.compression = options.compression;
    wo.splitSize = options.splitSize;
    wo.computeImageHash = options.computeImageHash;
    json::Value src;
    src.set("name", options.sourceName.empty() ? source->name() : options.sourceName);
    if (!options.sourceIdentity.empty()) src.set("identity", options.sourceIdentity);
    src.set("size", source->size());
    src.set("sector_size", static_cast<std::uint64_t>(source->geometry().logicalSectorSize));
    src.set("physical_sector_size", static_cast<std::uint64_t>(source->geometry().physicalSectorSize));
    wo.manifest.set("source", std::move(src));
    if (!options.notes.empty()) wo.manifest.set("notes", options.notes);
    std::vector<std::unique_ptr<fs::AllocationMap>> maps;
    CopyOptions co;
    co.chunkSize = options.chunkSize;
    co.badSectors = options.badSectors;
    CreateResult r;
    if (options.recordTopology || options.usedBlocksOnly) {
        progress.message("Probing source");
        auto tree = probe::probe(source);
        if (tree && options.recordTopology) wo.manifest.set("topology", topologyJson(*tree));
        if (tree && options.usedBlocksOnly) {
            // Every filesystem with a readable allocation bitmap contributes a map; the others are copied whole.
            std::vector<const probe::Node*> stack{&*tree};
            while (!stack.empty()) {
                const probe::Node* n = stack.back();
                stack.pop_back();
                for (const auto& c : n->children) stack.push_back(&c);
                if (!n->content) continue;
                const std::string what = std::string(fs::displayName(n->content->type())) + " at " + std::to_string(n->region.offset);
                if (!fs::has(n->content->capabilities(), fs::Capability::UsedBlocks)) {
                    r.allocationNotes.push_back(what + ": no allocation map support, copied whole");
                    continue;
                }
                auto map = n->content->allocationMap();
                if (!map) {
                    r.allocationNotes.push_back(what + ": " + map.error().message() + "; copied whole");
                    continue;
                }
                maps.push_back(std::make_unique<fs::AllocationMap>(std::move(*map)));
                co.allocations.push_back(MappedAllocation{n->region, maps.back().get()});
                r.allocationNotes.push_back(what + ": " + formatSize(maps.back()->usedBytes()) + " used of " + formatSize(maps.back()->blocks() * maps.back()->blockSize()));
            }
            wo.manifest.set("used_blocks_only", true);
        }
    }
    auto writer = SteinWriter::create(out, source->size(), source->geometry().logicalSectorSize, wo);
    if (!writer) return fail(writer.error());
    WriterSink sink(**writer);
    auto stats = copyToSink(*source, sink, co, progress);
    if (!stats) return fail(stats.error());
    if (auto f = (*writer)->finish(); !f) return fail(f.error());
    r.files = (*writer)->files();
    r.imageUuid = (*writer)->imageUuid();
    r.stats = *stats;
    r.storedBytes = (*writer)->bytesStored();
    if (auto reader = SteinReader::open(out); reader) {
        if (keys) (void)(*reader)->unlockWithKey(*keys->master());
        if ((*reader)->imageHash()) r.imageHashHex = hex32(*(*reader)->imageHash());
    }
    return r;
}

namespace {
// Open and, when encrypted and a passphrase is given, unlock. `needContent` turns a
// still-locked image into a Permission error.
Expected<std::shared_ptr<SteinReader>> openReader(const std::filesystem::path& image, const std::string& passphrase, bool needContent) {
    auto reader = SteinReader::open(image);
    if (!reader) return reader;
    if ((*reader)->encrypted() && !passphrase.empty())
        if (auto u = (*reader)->unlock(passphrase); !u) return fail(u.error());
    if (needContent && (*reader)->locked()) return fail(ErrorCategory::Permission, "image " + image.string() + " is encrypted; a passphrase is required");
    return reader;
}
} // namespace

Expected<RestoreResult> restoreImage(const std::filesystem::path& image, BlockDevice& target, const RestoreOptions& options,
                                     Progress& progress, const std::string& passphrase) {
    auto reader = openReader(image, passphrase, true);
    if (!reader) return fail(reader.error());
    const auto& h = (*reader)->header();
    RestoreResult result;
    if (target.size() < h.totalSize) {
        if (!options.allowSmallerTarget)
            return fail(ErrorCategory::OutOfRange, "target (" + formatSize(target.size()) + ") is smaller than the image (" + formatSize(h.totalSize) + ")");
        result.targetSmaller = true;
    } else if (target.size() > h.totalSize) {
        result.targetLarger = true;
    }
    if (h.sectorSize && target.sectorSize() != h.sectorSize)
        progress.message("note: image sector size " + std::to_string(h.sectorSize) + " differs from target " + std::to_string(target.sectorSize()));
    if (!(*reader)->complete()) progress.message("warning: image is incomplete; missing chunks restore as zeros");
    if (options.verifyPayloadFirst) {
        progress.setPhase("Verifying image", (*reader)->storedChunks(), "chunks");
        for (std::uint64_t i = 0; i < (*reader)->totalChunks(); ++i) {
            if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
            auto ok = (*reader)->verifyStored(i);
            if (!ok) return fail(ok.error());
            if (*ok) progress.advance(1);
        }
        progress.finishPhase();
    }
    auto dev = (*reader)->asDevice();
    CopyOptions co;
    co.chunkSize = h.chunkSize;
    co.skipZeroChunksOnWrite = !options.writeZeroChunks;
    co.discardZeroChunks = options.discardZeroChunks;
    co.limit = std::min(target.size(), h.totalSize);
    auto stats = copyDevice(*dev, target, co, progress);
    if (!stats) return fail(stats.error());
    result.stats = *stats;
    return result;
}

Expected<VerifyResult> verifyImage(const std::filesystem::path& image, int level, Progress& progress, const std::string& passphrase) {
    VerifyResult v;
    auto reader = openReader(image, passphrase, level >= 3);
    if (!reader) return fail(reader.error());
    v.structureOk = true;
    v.complete = (*reader)->complete();
    v.chunksTotal = (*reader)->totalChunks();
    v.chunksStored = (*reader)->storedChunks();
    if ((*reader)->imageHash()) v.imageHashHex = hex32(*(*reader)->imageHash());
    if (level <= 1) return v;
    const auto& h = (*reader)->header();
    std::unique_ptr<Hasher> sha = (level >= 3 && (*reader)->imageHash()) ? Hasher::create(HashAlgorithm::Sha256) : nullptr;
    progress.setPhase(level >= 3 ? "Verifying content" : "Verifying payloads", v.chunksTotal, "chunks");
    std::vector<std::byte> buf(h.chunkSize);
    for (std::uint64_t i = 0; i < v.chunksTotal; ++i) {
        if (progress.isCancelled()) return fail(ErrorCategory::Cancelled, "cancelled");
        if (level >= 3) {
            const ByteCount len = std::min<ByteCount>(h.chunkSize, h.totalSize - i * h.chunkSize);
            auto chunk = std::span<std::byte>(buf).first(static_cast<std::size_t>(len));
            auto r = (*reader)->readChunk(i, chunk);
            if (!r) {
                ++v.chunksBad;
                v.badChunks.push_back(i);
            } else if (sha) {
                sha->update(chunk);
            }
            ++v.chunksChecked;
        } else {
            auto ok = (*reader)->verifyStored(i);
            if (!ok) {
                ++v.chunksBad;
                v.badChunks.push_back(i);
            }
            if (ok && *ok) ++v.chunksChecked;
        }
        progress.advance(1);
    }
    progress.finishPhase();
    if (sha) {
        v.imageHashChecked = true;
        v.imageHashOk = Hasher::hex(sha->finish()) == v.imageHashHex;
    }
    return v;
}

Expected<ImageInfo> imageInfo(const std::filesystem::path& image, const std::string& passphrase) {
    auto reader = openReader(image, passphrase, false);
    if (!reader) return fail(reader.error());
    ImageInfo info;
    info.header = (*reader)->header();
    info.encrypted = (*reader)->encrypted();
    info.unlocked = info.encrypted && !(*reader)->locked();
    if (info.encrypted)
        if (auto k = Keys::fromJson((*reader)->keysJson())) info.keySlots = k->slots().size();
    info.manifest = (*reader)->manifest();
    info.segments = (*reader)->segments();
    info.chunksTotal = (*reader)->totalChunks();
    info.chunksStored = (*reader)->storedChunks();
    info.complete = (*reader)->complete();
    if ((*reader)->imageHash()) info.imageHashHex = hex32(*(*reader)->imageHash());
    for (const auto& s : info.segments) info.storedBytes += s.fileSize;
    return info;
}

Expected<std::shared_ptr<BlockDevice>> openImage(const std::filesystem::path& image, const std::string& passphrase) {
    auto reader = openReader(image, passphrase, true);
    if (!reader) return fail(reader.error());
    return (*reader)->asDevice();
}

Expected<Keys> imageKeys(const std::filesystem::path& image) {
    auto reader = SteinReader::open(image);
    if (!reader) return fail(reader.error());
    if (!(*reader)->encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    return Keys::fromJson((*reader)->keysJson());
}

Expected<int> addImageKey(const std::filesystem::path& image, const std::string& passphrase, const std::string& newPassphrase, const KdfParams& kdf, std::string label) {
    auto reader = SteinReader::open(image);
    if (!reader) return fail(reader.error());
    if (!(*reader)->encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    auto keys = Keys::fromJson((*reader)->keysJson());
    if (!keys) return fail(keys.error());
    auto master = keys->unlock(passphrase);
    if (!master) return fail(master.error());
    auto id = keys->addSlot(*master, newPassphrase, kdf, std::move(label));
    if (!id) return fail(id.error());
    if (auto w = (*reader)->writeKeys(keys->toJson()); !w) return fail(w.error());
    return *id;
}

Expected<void> removeImageKey(const std::filesystem::path& image, const std::string& passphrase, int slotId) {
    auto reader = SteinReader::open(image);
    if (!reader) return fail(reader.error());
    if (!(*reader)->encrypted()) return fail(ErrorCategory::InvalidArgument, "image is not encrypted");
    auto keys = Keys::fromJson((*reader)->keysJson());
    if (!keys) return fail(keys.error());
    if (auto master = keys->unlock(passphrase); !master) return fail(master.error());
    if (auto r = keys->removeSlot(slotId); !r) return r;
    return (*reader)->writeKeys(keys->toJson());
}

namespace {
bool allDigits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}
} // namespace

std::optional<SplitRawSet> findSplitRaw(const std::filesystem::path& path) {
    std::error_code ec;
    // Strip a numeric extension to get the prefix.
    std::filesystem::path prefix = path;
    std::string ext = path.extension().string();
    if (!ext.empty() && ext.front() == '.' && allDigits(ext.substr(1))) prefix = path.parent_path() / path.stem();
    const auto dir = prefix.parent_path().empty() ? std::filesystem::path(".") : prefix.parent_path();
    const std::string stem = prefix.filename().string();
    std::vector<std::pair<unsigned long, std::filesystem::path>> found;
    std::size_t width = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();
        if (name.size() <= stem.size() + 1 || name.compare(0, stem.size(), stem) != 0 || name[stem.size()] != '.') continue;
        const std::string digits = name.substr(stem.size() + 1);
        if (!allDigits(digits) || digits.size() > 6) continue;
        if (width && digits.size() != width) continue;
        width = digits.size();
        found.emplace_back(std::stoul(digits), entry.path());
    }
    if (found.size() < 2) return std::nullopt;
    std::sort(found.begin(), found.end());
    // Contiguous from 0 or 1.
    if (found.front().first > 1) return std::nullopt;
    for (std::size_t i = 1; i < found.size(); ++i)
        if (found[i].first != found[i - 1].first + 1) return std::nullopt;
    SplitRawSet set;
    set.prefix = prefix;
    for (auto& [n, p] : found) {
        set.totalBytes += std::filesystem::file_size(p, ec);
        set.members.push_back(std::move(p));
    }
    return set;
}

Expected<std::shared_ptr<BlockDevice>> openSplitRaw(const std::filesystem::path& path, bool writable, std::uint32_t sectorSize) {
    auto set = findSplitRaw(path);
    if (!set) return fail(ErrorCategory::NotFound, "no split raw image set at " + path.string());
    std::vector<BlockDevicePtr> parts;
    for (const auto& m : set->members) {
        auto f = FileDevice::open(m, writable ? FileDevice::Mode::ReadWrite : FileDevice::Mode::ReadOnly, sectorSize);
        if (!f) return fail(f.error());
        parts.push_back(*f);
    }
    return ConcatDevice::create(std::move(parts), set->prefix.string() + " (" + std::to_string(set->members.size()) + " parts)");
}

} // namespace stein::image
