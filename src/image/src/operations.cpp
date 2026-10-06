// SPDX-License-Identifier: MIT
#include "stein/image/operations.hpp"

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
    if (options.recordTopology) {
        progress.message("Probing source");
        if (auto tree = probe::probe(source)) wo.manifest.set("topology", topologyJson(*tree));
    }
    auto writer = SteinWriter::create(out, source->size(), source->geometry().logicalSectorSize, wo);
    if (!writer) return fail(writer.error());
    WriterSink sink(**writer);
    CopyOptions co;
    co.chunkSize = options.chunkSize;
    co.badSectors = options.badSectors;
    auto stats = copyToSink(*source, sink, co, progress);
    if (!stats) return fail(stats.error());
    if (auto f = (*writer)->finish(); !f) return fail(f.error());
    CreateResult r;
    r.files = (*writer)->files();
    r.imageUuid = (*writer)->imageUuid();
    r.stats = *stats;
    r.storedBytes = (*writer)->bytesStored();
    if (auto reader = SteinReader::open(out); reader && (*reader)->imageHash()) r.imageHashHex = hex32(*(*reader)->imageHash());
    return r;
}

Expected<RestoreResult> restoreImage(const std::filesystem::path& image, BlockDevice& target, const RestoreOptions& options,
                                     Progress& progress) {
    auto reader = SteinReader::open(image);
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

Expected<VerifyResult> verifyImage(const std::filesystem::path& image, int level, Progress& progress) {
    VerifyResult v;
    auto reader = SteinReader::open(image);
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

Expected<ImageInfo> imageInfo(const std::filesystem::path& image) {
    auto reader = SteinReader::open(image);
    if (!reader) return fail(reader.error());
    ImageInfo info;
    info.header = (*reader)->header();
    info.manifest = (*reader)->manifest();
    info.segments = (*reader)->segments();
    info.chunksTotal = (*reader)->totalChunks();
    info.chunksStored = (*reader)->storedChunks();
    info.complete = (*reader)->complete();
    if ((*reader)->imageHash()) info.imageHashHex = hex32(*(*reader)->imageHash());
    for (const auto& s : info.segments) info.storedBytes += s.fileSize;
    return info;
}

Expected<std::shared_ptr<BlockDevice>> openImage(const std::filesystem::path& image) {
    auto reader = SteinReader::open(image);
    if (!reader) return fail(reader.error());
    return (*reader)->asDevice();
}

} // namespace stein::image
