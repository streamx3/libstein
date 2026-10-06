// SPDX-License-Identifier: MIT
#include "stein/core/report.hpp"

namespace stein {

std::string_view toString(ReportStatus s) {
    switch (s) {
    case ReportStatus::Pending: return "..";
    case ReportStatus::Running: return ">>";
    case ReportStatus::Success: return "OK";
    case ReportStatus::Warning: return "WARN";
    case ReportStatus::Error: return "FAIL";
    case ReportStatus::Info: return "INFO";
    }
    return "?";
}

Report::Report(std::string title) : m_title(std::move(title)) {}

std::chrono::milliseconds Report::duration() const {
    if (!m_started) return std::chrono::milliseconds(0);
    auto end = m_finished ? m_end : std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start);
}

void Report::start() {
    m_status = ReportStatus::Running;
    m_start = std::chrono::steady_clock::now();
    m_started = true;
}

void Report::finish(ReportStatus s) {
    m_status = s;
    m_end = std::chrono::steady_clock::now();
    m_finished = true;
    if (!m_started) {
        m_start = m_end;
        m_started = true;
    }
}

void Report::addDetail(std::string key, std::string value) {
    m_details.emplace_back(std::move(key), std::move(value));
}

void Report::addLine(std::string line) { m_lines.push_back(std::move(line)); }

Report& Report::addChild(std::string title) {
    m_children.push_back(std::make_unique<Report>(std::move(title)));
    return *m_children.back();
}

std::string Report::toText(int indent) const {
    std::string pad(static_cast<std::size_t>(indent) * 2, ' ');
    std::string out = pad + "[" + std::string(stein::toString(m_status)) + "] " + m_title;
    if (m_started) out += " (" + std::to_string(duration().count()) + " ms)";
    out += "\n";
    for (const auto& [k, v] : m_details) out += pad + "    " + k + ": " + v + "\n";
    for (const auto& l : m_lines) out += pad + "    | " + l + "\n";
    for (const auto& c : m_children) out += c->toText(indent + 1);
    return out;
}

} // namespace stein
