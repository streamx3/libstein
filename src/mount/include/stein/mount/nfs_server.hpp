// SPDX-License-Identifier: MIT
// A read-only NFSv3 server (RFC 1813, MOUNT v3, SunRPC over TCP with record
// marking) that exports any fs::Reader. No portmapper: clients mount with an
// explicit port. It is the kext-free macOS mount backend (mount_nfs against
// 127.0.0.1) and works as a plain loopback server on every platform.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/fs/reader.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace stein::mount {

struct NfsServerOptions {
    std::string bindAddress = "127.0.0.1";
    std::uint16_t port = 0;   // 0 = any free port; see port()
};

class NfsServer {
public:
    // Bind, listen and start serving on a background thread. The reader is used from that
    // thread only; the caller keeps the device stack alive.
    static Expected<std::unique_ptr<NfsServer>> start(std::unique_ptr<fs::Reader> reader, const NfsServerOptions& options = {});
    ~NfsServer();
    NfsServer(const NfsServer&) = delete;
    NfsServer& operator=(const NfsServer&) = delete;

    std::uint16_t port() const;
    // Stop accepting, close every connection and join the thread. Idempotent.
    void stop();
    // Requests served so far (for tests and diagnostics).
    std::uint64_t requests() const;

private:
    NfsServer() = default;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// An fs::Reader that shows one block device as a single file in an empty root directory:
// served over NFS it lets the host OS attach a decoded or decrypted disk with its own drivers
// (hdiutil attach on macOS) when it has one for the filesystem inside.
std::unique_ptr<fs::Reader> makeSingleFileReader(std::shared_ptr<BlockDevice> device, std::string name);

} // namespace stein::mount
