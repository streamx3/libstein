// SPDX-License-Identifier: MIT
#include "stein/ops/operation.hpp"

#include "stein/block/slice_device.hpp"
#include "stein/core/strings.hpp"
#include "stein/pt/gpt_table.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>

namespace stein::ops {

using layout::Validity;

namespace {

std::string partitionLabel(const pt::Partition& p) {
    std::string s = p.index ? "partition " + std::to_string(p.index) : std::string("partition");
    if (!p.name.empty()) s += " \"" + p.name + "\"";
    return s;
}

Expected<std::unique_ptr<pt::PartitionTable>> tableCopy(const probe::Node& topology) {
    if (!topology.table) return fail(ErrorCategory::NotFound, "device has no partition table");
    return topology.table->clone();
}

} // namespace

std::vector<Region> signatureRegions(const probe::Node& node) {
    std::vector<Region> regions;
    const ByteCount head = std::min<ByteCount>(1 * MiB, node.region.length);
    regions.push_back(Region{node.region.offset, head});
    if (node.content)
        for (const auto& r : node.content->metadataRegions())
            if (r.offset + r.length <= node.region.length) regions.push_back(Region{node.region.offset + r.offset, r.length});
    if (node.table)
        for (const auto& r : node.table->metadataRegions())
            if (r.offset + r.length <= node.region.length) regions.push_back(Region{node.region.offset + r.offset, r.length});
    // Common backup locations at the end (GPT backup, nilfs2, md 1.0, btrfs mirrors are inside metadataRegions already).
    if (node.region.length > 2 * MiB) regions.push_back(Region{node.region.offset + node.region.length - 1 * MiB, 1 * MiB});
    std::sort(regions.begin(), regions.end(), [](const Region& a, const Region& b) { return a.offset < b.offset; });
    std::vector<Region> merged;
    for (const auto& r : regions) {
        if (!merged.empty() && merged.back().end() >= r.offset) merged.back().length = std::max(merged.back().end(), r.end()) - merged.back().offset;
        else merged.push_back(r);
    }
    return merged;
}

// ----------------------------------------------------------------------------- jobs

std::string WriteTableJob::title() const {
    return "Write " + std::string(pt::toString(m_table->type())) + " partition table (" + std::to_string(m_table->partitions().size()) + " partitions)";
}

Expected<void> WriteTableJob::run(BlockDevice& device, Progress& progress, Report& report) {
    progress.setPhase("Writing partition table", 1, "tables");
    for (const auto& r : m_table->metadataRegions()) report.addDetail("region", std::to_string(r.offset) + "+" + std::to_string(r.length));
    if (auto w = m_table->write(device); !w) return w;
    progress.finishPhase();
    return {};
}

std::string ZeroRegionJob::title() const { return "Zero " + formatSize(m_region.length) + " at " + std::to_string(m_region.offset) + " (" + m_why + ")"; }

Expected<void> ZeroRegionJob::run(BlockDevice& device, Progress& progress, Report& report) {
    progress.setPhase("Wiping", m_region.length);
    report.addDetail("region", std::to_string(m_region.offset) + "+" + std::to_string(m_region.length));
    if (auto z = device.zero(m_region.offset, m_region.length); !z) return z;
    progress.finishPhase();
    return {};
}

Expected<void> RepairTableJob::run(BlockDevice& device, Progress& progress, Report& report) {
    progress.setPhase("Repairing partition table", 1, "tables");
    auto table = pt::PartitionTable::read(std::shared_ptr<BlockDevice>(&device, [](BlockDevice*) {}));
    if (!table) return fail(table.error());
    for (const auto& d : (*table)->diagnostics())
        if (d.repairable) report.addLine("fixing: " + d.message);
    if (auto r = (*table)->repair(device, m_options); !r) return r;
    progress.finishPhase();
    return {};
}

// ----------------------------------------------------------------------------- operations

std::string CreateTable::description() const { return "Create " + toUpper(std::string(pt::toString(m_type))) + " partition table"; }

Expected<void> CreateTable::validate(const probe::Node& topology) const {
    if (m_type != pt::TableType::Gpt && m_type != pt::TableType::Mbr && m_type != pt::TableType::Apm)
        return fail(ErrorCategory::Unsupported, "cannot create a " + std::string(pt::toString(m_type)) + " table");
    if (topology.device->size() < 2 * MiB) return fail(ErrorCategory::OutOfRange, "device too small for a partition table");
    return {};
}

Expected<std::vector<std::unique_ptr<Job>>> CreateTable::plan(const probe::Node& topology) const {
    std::vector<std::unique_ptr<Job>> jobs;
    // Remove whatever claims the device today (old table copies, whole-device filesystem).
    for (const auto& r : signatureRegions(topology)) jobs.push_back(std::make_unique<ZeroRegionJob>(r, "old signatures"));
    auto table = pt::PartitionTable::createEmpty(m_type, topology.device->geometry());
    if (!table) return fail(table.error());
    if (auto* gpt = dynamic_cast<pt::GptTable*>(table->get())) {
        // Fresh disk GUID.
        std::array<std::uint8_t, 16> b{};
        for (auto& x : b) x = static_cast<std::uint8_t>(std::rand() & 0xFF);
        b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);
        b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
        gpt->setDiskGuid(Uuid(b));
    }
    jobs.push_back(std::make_unique<WriteTableJob>(std::move(*table)));
    return jobs;
}

std::string AddPartition::description() const {
    return "Add " + partitionLabel(m_partition) + ": " + pt::types::name(m_partition.type) + ", sectors " + std::to_string(m_partition.firstLba) + ".." +
           std::to_string(m_partition.lastLba);
}

Expected<void> AddPartition::validate(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    return (*table)->addPartition(m_partition);
}

Expected<std::vector<std::unique_ptr<Job>>> AddPartition::plan(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    if (auto a = (*table)->addPartition(m_partition); !a) return fail(a.error());
    std::vector<std::unique_ptr<Job>> jobs;
    if (m_wipe) {
        const Region r = m_partition.region(topology.device->sectorSize());
        jobs.push_back(std::make_unique<ZeroRegionJob>(Region{topology.region.offset + r.offset, std::min<ByteCount>(1 * MiB, r.length)}, "stale filesystem signatures"));
    }
    jobs.push_back(std::make_unique<WriteTableJob>(std::move(*table)));
    return jobs;
}

std::string DeletePartition::description() const { return "Delete partition " + std::to_string(m_index); }

Expected<void> DeletePartition::validate(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    return (*table)->removePartition(m_index);
}

Expected<std::vector<std::unique_ptr<Job>>> DeletePartition::plan(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    if (auto r = (*table)->removePartition(m_index); !r) return fail(r.error());
    std::vector<std::unique_ptr<Job>> jobs;
    jobs.push_back(std::make_unique<WriteTableJob>(std::move(*table)));
    return jobs;
}

std::string UpdatePartition::description() const { return "Update " + partitionLabel(m_partition); }

Expected<void> UpdatePartition::validate(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    return (*table)->updatePartition(m_partition);
}

Expected<std::vector<std::unique_ptr<Job>>> UpdatePartition::plan(const probe::Node& topology) const {
    auto table = tableCopy(topology);
    if (!table) return fail(table.error());
    if (auto r = (*table)->updatePartition(m_partition); !r) return fail(r.error());
    std::vector<std::unique_ptr<Job>> jobs;
    jobs.push_back(std::make_unique<WriteTableJob>(std::move(*table)));
    return jobs;
}

Expected<void> RepairTable::validate(const probe::Node& topology) const {
    if (!topology.table) return fail(ErrorCategory::NotFound, "device has no partition table");
    bool any = false;
    for (const auto& d : topology.table->diagnostics()) any = any || d.repairable;
    if (!any) return fail(ErrorCategory::InvalidArgument, "nothing repairable on this table");
    return {};
}

Expected<std::vector<std::unique_ptr<Job>>> RepairTable::plan(const probe::Node&) const {
    std::vector<std::unique_ptr<Job>> jobs;
    jobs.push_back(std::make_unique<RepairTableJob>(m_options));
    return jobs;
}

std::string WipeSignatures::description() const { return "Wipe signatures in " + formatSize(m_region.length) + " at " + std::to_string(m_region.offset); }

Expected<void> WipeSignatures::validate(const probe::Node& topology) const {
    if (!topology.region.contains(m_region)) return fail(ErrorCategory::OutOfRange, "region outside the device");
    return {};
}

Expected<std::vector<std::unique_ptr<Job>>> WipeSignatures::plan(const probe::Node& topology) const {
    // Prefer the probe's knowledge of what is there; else the generic head/tail.
    const probe::Node* target = nullptr;
    for (const auto& c : topology.children)
        if (c.region == m_region) target = &c;
    probe::Node synthetic;
    if (!target) {
        synthetic.region = m_region;
        target = &synthetic;
    }
    std::vector<std::unique_ptr<Job>> jobs;
    for (const auto& r : signatureRegions(*target)) jobs.push_back(std::make_unique<ZeroRegionJob>(r, "signatures"));
    return jobs;
}

} // namespace stein::ops
