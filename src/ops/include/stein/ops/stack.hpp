// SPDX-License-Identifier: MIT
#pragma once

#include "stein/ops/operation.hpp"

namespace stein::ops {

struct PendingEntry {
    std::unique_ptr<Operation> operation;
    std::string description;
    std::vector<std::string> jobTitles;
    bool destructive = false;
};

// Pending operations against one device, each validated and simulated on an
// overlay over the previous state. preview() is the probe of the overlay.
class OperationStack {
public:
    explicit OperationStack(BlockDevicePtr device);

    const probe::Node& base() const { return m_base; }
    const probe::Node& preview() const { return m_preview; }
    const std::vector<PendingEntry>& pending() const { return m_pending; }
    bool empty() const { return m_pending.empty(); }
    bool destructive() const;
    // Bytes the whole stack would change on the device.
    ByteCount changedBytes() const { return m_overlay->dirtyBytes(); }
    std::vector<Region> changedRegions() const { return m_overlay->dirtyRegions(); }

    // Validate against the preview, run the jobs on the overlay, re-probe.
    Expected<void> push(std::unique_ptr<Operation> operation);
    // Remove the last operation (replays the rest on a fresh overlay).
    Expected<void> pop();
    void clear();

    // Apply: writes the overlay's dirty blocks to the device in one pass, then
    // re-probes and compares with the preview. Dry-run = everything up to here.
    struct ApplyResult {
        Report report{"Apply operations"};
        bool postconditionOk = false;
        probe::Node after;
    };
    Expected<ApplyResult> apply(Progress& progress);

    // Re-read the device (after external changes); drops pending operations.
    Expected<void> refresh();

private:
    Expected<void> replay();
    Expected<probe::Node> probeOverlay();

    BlockDevicePtr m_device;
    std::shared_ptr<OverlayDevice> m_overlay;
    probe::Node m_base, m_preview;
    std::vector<PendingEntry> m_pending;
};

// Text rendering of a stack: pending list + preview tree + change summary.
std::string describe(const OperationStack& stack);

} // namespace stein::ops
