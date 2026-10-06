// SPDX-License-Identifier: MIT
#include "stein/ops/stack.hpp"

#include "stein/core/strings.hpp"

namespace stein::ops {

using layout::Validity;

namespace {
// Tree text without the root line: the root names its device, and the
// overlay's name differs from the real device's.
std::string bodyText(const probe::Node& node) {
    auto text = probe::toText(node, false);
    auto nl = text.find('\n');
    return nl == std::string::npos ? std::string() : text.substr(nl + 1);
}
} // namespace

OperationStack::OperationStack(BlockDevicePtr device) : m_device(std::move(device)) {
    m_overlay = OverlayDevice::create(m_device);
    if (auto t = probe::probe(m_device)) m_base = std::move(*t);
    m_base.device = m_device;
    if (auto p = probeOverlay()) m_preview = std::move(*p);
}

Expected<probe::Node> OperationStack::probeOverlay() {
    auto t = probe::probe(m_overlay);
    if (!t) return t;
    t->name = m_device->name();
    return t;
}

bool OperationStack::destructive() const {
    for (const auto& p : m_pending)
        if (p.destructive) return true;
    return false;
}

Expected<void> OperationStack::push(std::unique_ptr<Operation> op) {
    if (auto v = op->validate(m_preview); !v) return v;
    auto jobs = op->plan(m_preview);
    if (!jobs) return fail(jobs.error());
    NullProgressSink sink;
    Progress progress(sink);
    Report report("simulate");
    PendingEntry entry;
    entry.operation = std::move(op);
    entry.description = entry.operation->description();
    entry.destructive = entry.operation->isDestructive();
    // Snapshot the overlay so a failing job leaves the stack consistent.
    auto snapshot = m_overlay->dirtyRegions();
    std::vector<std::vector<std::byte>> saved;
    for (const auto& r : snapshot) saved.push_back(*m_overlay->read(r.offset, r.length));
    for (auto& j : *jobs) {
        entry.jobTitles.push_back(j->title());
        if (auto r = j->run(*m_overlay, progress, report); !r) {
            m_overlay->discardChanges();
            for (std::size_t i = 0; i < snapshot.size(); ++i) (void)m_overlay->writeAt(snapshot[i].offset, saved[i]);
            return fail(Error(r.error().category(), entry.description + ": " + j->title() + ": " + r.error().message(), r.error().osCode()));
        }
    }
    auto preview = probeOverlay();
    if (!preview) return fail(preview.error());
    m_preview = std::move(*preview);
    m_pending.push_back(std::move(entry));
    return {};
}

Expected<void> OperationStack::replay() {
    m_overlay->discardChanges();
    std::vector<std::unique_ptr<Operation>> ops;
    for (auto& p : m_pending) ops.push_back(std::move(p.operation));
    m_pending.clear();
    auto preview = probeOverlay();
    if (!preview) return fail(preview.error());
    m_preview = std::move(*preview);
    for (auto& op : ops)
        if (auto r = push(std::move(op)); !r) return r;
    return {};
}

Expected<void> OperationStack::pop() {
    if (m_pending.empty()) return fail(ErrorCategory::InvalidArgument, "nothing to undo");
    m_pending.pop_back();
    return replay();
}

void OperationStack::clear() {
    m_pending.clear();
    m_overlay->discardChanges();
    if (auto p = probeOverlay()) m_preview = std::move(*p);
}

Expected<OperationStack::ApplyResult> OperationStack::apply(Progress& progress) {
    ApplyResult result;
    result.report.start();
    if (m_pending.empty()) {
        result.report.finish(ReportStatus::Info);
        result.report.addLine("nothing to apply");
        result.postconditionOk = true;
        auto t = probe::probe(m_device);
        if (!t) return fail(t.error());
        result.after = std::move(*t);
        return result;
    }
    if (m_device->isReadOnly()) {
        result.report.finish(ReportStatus::Error);
        return fail(ErrorCategory::Permission, "device is opened read-only");
    }
    // Everything already ran on the overlay; applying is one ordered write of the dirty blocks.
    auto& write = result.report.addChild("Write " + formatSize(m_overlay->dirtyBytes()) + " in " + std::to_string(m_overlay->dirtyRegions().size()) + " region(s)");
    for (const auto& p : m_pending) {
        auto& r = result.report.addChild(p.description);
        for (const auto& t : p.jobTitles) r.addLine(t);
        r.finish(ReportStatus::Success);
    }
    write.start();
    progress.setPhase("Applying", m_overlay->dirtyBytes());
    for (const auto& r : m_overlay->dirtyRegions()) write.addDetail("region", std::to_string(r.offset) + "+" + std::to_string(r.length));
    if (auto c = m_overlay->commit(); !c) {
        write.finish(ReportStatus::Error);
        write.addLine(c.error().toString());
        result.report.finish(ReportStatus::Error);
        return fail(c.error());
    }
    progress.finishPhase();
    write.finish(ReportStatus::Success);
    // Postcondition: the device now probes like the preview.
    auto after = probe::probe(m_device);
    if (!after) {
        result.report.finish(ReportStatus::Warning);
        return fail(after.error());
    }
    result.after = std::move(*after);
    result.postconditionOk = bodyText(result.after) == bodyText(m_preview) && (result.after.table != nullptr) == (m_preview.table != nullptr) &&
                             (result.after.content != nullptr) == (m_preview.content != nullptr);
    auto& post = result.report.addChild("Verify result against preview");
    post.start();
    post.finish(result.postconditionOk ? ReportStatus::Success : ReportStatus::Warning);
    if (!result.postconditionOk) post.addLine("device differs from the preview; re-probe recommended");
    result.report.finish(result.postconditionOk ? ReportStatus::Success : ReportStatus::Warning);
    m_pending.clear();
    // probe::Node is move-only; the device is probed once more for our own state.
    if (auto t = probe::probe(m_device)) m_base = std::move(*t);
    m_base.device = m_device;
    if (auto p = probeOverlay()) m_preview = std::move(*p);
    return result;
}

Expected<void> OperationStack::refresh() {
    clear();
    auto t = probe::probe(m_device);
    if (!t) return fail(t.error());
    m_base = std::move(*t);
    m_base.device = m_device;
    auto p = probeOverlay();
    if (!p) return fail(p.error());
    m_preview = std::move(*p);
    return {};
}

std::string describe(const OperationStack& stack) {
    std::string out;
    if (stack.empty()) {
        out += "no pending operations\n";
    } else {
        out += "pending operations:\n";
        int i = 1;
        for (const auto& p : stack.pending()) {
            out += "  " + std::to_string(i++) + ". " + p.description + (p.destructive ? "  [DESTRUCTIVE]" : "") + "\n";
            for (const auto& t : p.jobTitles) out += "       - " + t + "\n";
        }
        out += "would change " + formatSize(stack.changedBytes()) + " in " + std::to_string(stack.changedRegions().size()) + " region(s)\n";
    }
    // The preview was probed through the overlay; show it under the device's own name.
    auto tree = probe::toText(stack.preview());
    const std::string tag = " (overlay)";
    if (auto pos = tree.find(tag); pos != std::string::npos && pos < tree.find('\n')) tree.erase(pos, tag.size());
    out += "result:\n" + tree;
    return out;
}

} // namespace stein::ops
