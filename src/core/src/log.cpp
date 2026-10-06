// SPDX-License-Identifier: MIT
#include "stein/core/log.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>

namespace stein {

std::string_view toString(LogLevel l) {
    switch (l) {
    case LogLevel::Trace: return "trace";
    case LogLevel::Debug: return "debug";
    case LogLevel::Info: return "info";
    case LogLevel::Warning: return "warning";
    case LogLevel::Error: return "error";
    }
    return "?";
}

namespace {
StderrLogSink g_stderrSink;
std::atomic<LogSink*> g_sink{&g_stderrSink};
std::atomic<LogLevel> g_level{LogLevel::Info};
std::mutex g_stderrMutex;
} // namespace

void StderrLogSink::write(LogLevel level, std::string_view module, std::string_view message) {
    std::lock_guard lock(g_stderrMutex);
    std::fprintf(stderr, "[%.*s] %.*s: %.*s\n", static_cast<int>(toString(level).size()), toString(level).data(),
                 static_cast<int>(module.size()), module.data(), static_cast<int>(message.size()), message.data());
}

void setLogSink(LogSink* sink) { g_sink.store(sink ? sink : &g_stderrSink); }
void setLogLevel(LogLevel minimum) { g_level.store(minimum); }
LogLevel logLevel() { return g_level.load(); }

void log(LogLevel level, std::string_view module, std::string_view message) {
    if (level < g_level.load()) return;
    g_sink.load()->write(level, module, message);
}

} // namespace stein
