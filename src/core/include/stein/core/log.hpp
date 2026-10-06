// SPDX-License-Identifier: MIT
// Minimal logging: a process-wide sink pointer, no formatting library, no
// macros beyond the obvious. Front-ends install their own sink.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace stein {

enum class LogLevel : std::uint8_t { Trace, Debug, Info, Warning, Error };

std::string_view toString(LogLevel l);

class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(LogLevel level, std::string_view module, std::string_view message) = 0;
};

// Writes "[level] module: message" to stderr. Installed by default.
class StderrLogSink final : public LogSink {
public:
    void write(LogLevel level, std::string_view module, std::string_view message) override;
};

void setLogSink(LogSink* sink);     // nullptr restores the stderr sink
void setLogLevel(LogLevel minimum); // default Info
LogLevel logLevel();
void log(LogLevel level, std::string_view module, std::string_view message);

inline void logDebug(std::string_view module, std::string_view msg) { log(LogLevel::Debug, module, msg); }
inline void logInfo(std::string_view module, std::string_view msg) { log(LogLevel::Info, module, msg); }
inline void logWarning(std::string_view module, std::string_view msg) { log(LogLevel::Warning, module, msg); }
inline void logError(std::string_view module, std::string_view msg) { log(LogLevel::Error, module, msg); }

} // namespace stein
