// SPDX-License-Identifier: MIT
// Progress reporting and cooperative cancellation, shared by every long job.
// A Progress sink is called from worker threads; implementations must be
// thread-safe. Throttling and ETA are computed here so every UI gets them.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

namespace stein {

class CancelToken {
public:
    void cancel() { m_cancelled.store(true, std::memory_order_relaxed); }
    bool isCancelled() const { return m_cancelled.load(std::memory_order_relaxed); }

private:
    std::atomic<bool> m_cancelled{false};
};

struct ProgressSnapshot {
    std::string phase;          // "Copying", "Verifying"...
    std::uint64_t done = 0;     // in `unit`s
    std::uint64_t total = 0;    // 0 = unknown
    std::string unit = "bytes";
    double rate = 0.0;          // units per second over the recent window
    double etaSeconds = -1.0;   // < 0 = unknown
    double fraction() const { return total ? static_cast<double>(done) / static_cast<double>(total) : 0.0; }
};

// Interface a UI implements. Called at most ~10 times/second per job.
class ProgressSink {
public:
    virtual ~ProgressSink() = default;
    virtual void onProgress(const ProgressSnapshot& snapshot) = 0;
    virtual void onMessage(std::string_view message) = 0;
};

class NullProgressSink final : public ProgressSink {
public:
    void onProgress(const ProgressSnapshot&) override {}
    void onMessage(std::string_view) override {}
};

// What jobs use. Owns throttling and rate/ETA; forwards to the sink.
class Progress {
public:
    explicit Progress(ProgressSink& sink, CancelToken* cancel = nullptr);

    void setPhase(std::string phase, std::uint64_t total, std::string unit = "bytes");
    void advance(std::uint64_t delta);
    void setDone(std::uint64_t done);
    void message(std::string_view text);
    void finishPhase();   // forces a final update with done == total

    bool isCancelled() const { return m_cancel && m_cancel->isCancelled(); }
    const ProgressSnapshot& snapshot() const { return m_snapshot; }

    // Sub-range helper: a child job reports 0..childTotal, mapped into [start, start+span) of this.
    // Children are explicit objects, not implicit stacks, so the mapping is visible in code.
    class SubRange;

private:
    void maybeEmit(bool force);

    ProgressSink& m_sink;
    CancelToken* m_cancel;
    ProgressSnapshot m_snapshot;
    std::chrono::steady_clock::time_point m_lastEmit;
    std::chrono::steady_clock::time_point m_windowStart;
    std::uint64_t m_windowDone = 0;
    std::mutex m_mutex;
};

} // namespace stein
