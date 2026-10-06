// SPDX-License-Identifier: MIT
// Operations and jobs: plan, preview, apply. See doc/design/13-operations.md.
//
// The preview is not computed by a parallel model: an OperationStack runs the
// real jobs against a copy-on-write OverlayDevice over the target and probes
// the result. What you see in the preview is the code path that will run.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/block/overlay_device.hpp"
#include "stein/core/error.hpp"
#include "stein/core/progress.hpp"
#include "stein/core/report.hpp"
#include "stein/probe/topology.hpp"
#include "stein/pt/partition_table.hpp"

#include <memory>
#include <string>
#include <vector>

namespace stein::ops {

// One primitive step. Jobs are small, run against whatever device they are
// given (the overlay during simulation, the real device during apply) and
// never prompt.
class Job {
public:
    virtual ~Job() = default;
    virtual std::string title() const = 0;
    virtual bool isDestructive() const = 0;     // overwrites user data (not just metadata)
    virtual Expected<void> run(BlockDevice& device, Progress& progress, Report& report) = 0;
};

struct Diagnostic {
    layout::Validity severity;
    std::string message;
};

// What the user asked for. validate() against the current topology, plan()
// into jobs. Operations are value-like: they hold their parameters only.
class Operation {
public:
    virtual ~Operation() = default;
    virtual std::string description() const = 0;                       // "Create GPT partition table"
    virtual Expected<void> validate(const probe::Node& topology) const = 0;
    virtual Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const = 0;
    virtual bool isDestructive() const = 0;
};

// ---- jobs ------------------------------------------------------------------

class WriteTableJob final : public Job {
public:
    explicit WriteTableJob(std::unique_ptr<pt::PartitionTable> table) : m_table(std::move(table)) {}
    std::string title() const override;
    bool isDestructive() const override { return false; }
    Expected<void> run(BlockDevice& device, Progress& progress, Report& report) override;

private:
    std::unique_ptr<pt::PartitionTable> m_table;
};

class ZeroRegionJob final : public Job {
public:
    ZeroRegionJob(Region region, std::string why) : m_region(region), m_why(std::move(why)) {}
    std::string title() const override;
    bool isDestructive() const override { return true; }
    Expected<void> run(BlockDevice& device, Progress& progress, Report& report) override;

private:
    Region m_region;
    std::string m_why;
};

class RepairTableJob final : public Job {
public:
    explicit RepairTableJob(pt::RepairOptions options) : m_options(options) {}
    std::string title() const override { return "Repair partition table"; }
    bool isDestructive() const override { return false; }
    Expected<void> run(BlockDevice& device, Progress& progress, Report& report) override;

private:
    pt::RepairOptions m_options;
};

// ---- operations ------------------------------------------------------------

class CreateTable final : public Operation {
public:
    explicit CreateTable(pt::TableType type) : m_type(type) {}
    std::string description() const override;
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return true; }   // existing partitions become unreachable

private:
    pt::TableType m_type;
};

class AddPartition final : public Operation {
public:
    explicit AddPartition(pt::Partition partition, bool wipeSignatures = true) : m_partition(std::move(partition)), m_wipe(wipeSignatures) {}
    std::string description() const override;
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return m_wipe; }

private:
    pt::Partition m_partition;
    bool m_wipe;
};

class DeletePartition final : public Operation {
public:
    explicit DeletePartition(std::uint32_t index) : m_index(index) {}
    std::string description() const override;
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return false; }   // metadata only; data stays until overwritten

private:
    std::uint32_t m_index;
};

// Change type / name / attributes / bounds of an existing partition (matched by index).
class UpdatePartition final : public Operation {
public:
    explicit UpdatePartition(pt::Partition partition) : m_partition(std::move(partition)) {}
    std::string description() const override;
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return false; }

private:
    pt::Partition m_partition;
};

class RepairTable final : public Operation {
public:
    explicit RepairTable(pt::RepairOptions options = {}) : m_options(options) {}
    std::string description() const override { return "Repair partition table (rebuild damaged copies)"; }
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return false; }

private:
    pt::RepairOptions m_options;
};

// Zero the signatures of whatever lives in a region (partition or whole device).
class WipeSignatures final : public Operation {
public:
    explicit WipeSignatures(Region region) : m_region(region) {}
    std::string description() const override;
    Expected<void> validate(const probe::Node& topology) const override;
    Expected<std::vector<std::unique_ptr<Job>>> plan(const probe::Node& topology) const override;
    bool isDestructive() const override { return true; }

private:
    Region m_region;
};

// Regions a wipe must zero for a region's content to stop being recognised:
// the first MiB, plus every metadata region the probe found there.
std::vector<Region> signatureRegions(const probe::Node& node);

} // namespace stein::ops
