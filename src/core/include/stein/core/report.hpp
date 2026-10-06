// SPDX-License-Identifier: MIT
// Report: the tree of what a job did. Rendered by UIs, printed by the CLI,
// asserted on by tests, kept as the audit log of an operation.
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace stein {

enum class ReportStatus : std::uint8_t { Pending, Running, Success, Warning, Error, Info };

std::string_view toString(ReportStatus s);

class Report {
public:
    explicit Report(std::string title);

    const std::string& title() const { return m_title; }
    ReportStatus status() const { return m_status; }
    const std::vector<std::pair<std::string, std::string>>& details() const { return m_details; }
    const std::vector<std::string>& lines() const { return m_lines; }
    const std::vector<std::unique_ptr<Report>>& children() const { return m_children; }
    std::chrono::milliseconds duration() const;

    // Mutation, used by jobs.
    void start();                              // status Running, records start time
    void finish(ReportStatus s);               // Success/Warning/Error, records end time
    void setStatus(ReportStatus s) { m_status = s; }
    void addDetail(std::string key, std::string value);
    void addLine(std::string line);
    Report& addChild(std::string title);

    // Plain-text rendering, indented; "[OK] Write GPT (12 ms)" style.
    std::string toText(int indent = 0) const;

private:
    std::string m_title;
    ReportStatus m_status = ReportStatus::Pending;
    std::vector<std::pair<std::string, std::string>> m_details;
    std::vector<std::string> m_lines;
    std::vector<std::unique_ptr<Report>> m_children;
    std::chrono::steady_clock::time_point m_start{};
    std::chrono::steady_clock::time_point m_end{};
    bool m_started = false, m_finished = false;
};

} // namespace stein
