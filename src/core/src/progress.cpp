// SPDX-License-Identifier: MIT
#include "stein/core/progress.hpp"

namespace stein {

using Clock = std::chrono::steady_clock;

Progress::Progress(ProgressSink& sink, CancelToken* cancel)
    : m_sink(sink), m_cancel(cancel), m_lastEmit(Clock::now()), m_windowStart(m_lastEmit) {}

void Progress::setPhase(std::string phase, std::uint64_t total, std::string unit) {
    std::lock_guard lock(m_mutex);
    m_snapshot.phase = std::move(phase);
    m_snapshot.total = total;
    m_snapshot.unit = std::move(unit);
    m_snapshot.done = 0;
    m_snapshot.rate = 0.0;
    m_snapshot.etaSeconds = -1.0;
    m_windowStart = Clock::now();
    m_windowDone = 0;
    maybeEmit(true);
}

void Progress::advance(std::uint64_t delta) {
    std::lock_guard lock(m_mutex);
    m_snapshot.done += delta;
    m_windowDone += delta;
    maybeEmit(false);
}

void Progress::setDone(std::uint64_t done) {
    std::lock_guard lock(m_mutex);
    if (done > m_snapshot.done) m_windowDone += done - m_snapshot.done;
    m_snapshot.done = done;
    maybeEmit(false);
}

void Progress::message(std::string_view text) { m_sink.onMessage(text); }

void Progress::finishPhase() {
    std::lock_guard lock(m_mutex);
    if (m_snapshot.total) m_snapshot.done = m_snapshot.total;
    m_snapshot.etaSeconds = 0.0;
    maybeEmit(true);
}

void Progress::maybeEmit(bool force) {
    const auto now = Clock::now();
    const auto sinceEmit = std::chrono::duration<double>(now - m_lastEmit).count();
    if (!force && sinceEmit < 0.1) return;   // ≤ 10 updates per second

    // Rate over a sliding ~2 s window; ETA from that rate, not from the start.
    const auto window = std::chrono::duration<double>(now - m_windowStart).count();
    if (window > 0.0) {
        const double rate = static_cast<double>(m_windowDone) / window;
        // Exponential smoothing so the number does not jitter.
        m_snapshot.rate = m_snapshot.rate > 0.0 ? 0.7 * m_snapshot.rate + 0.3 * rate : rate;
        if (m_snapshot.total && m_snapshot.rate > 0.0 && m_snapshot.done <= m_snapshot.total)
            m_snapshot.etaSeconds = static_cast<double>(m_snapshot.total - m_snapshot.done) / m_snapshot.rate;
        if (window >= 2.0) {
            m_windowStart = now;
            m_windowDone = 0;
        }
    }
    m_lastEmit = now;
    m_sink.onProgress(m_snapshot);
}

} // namespace stein
