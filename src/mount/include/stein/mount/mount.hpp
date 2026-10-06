// SPDX-License-Identifier: MIT
// Mount any fs::Reader as a read-only filesystem the OS can browse. Linux
// backend: libfuse3 (LGPL, linked dynamically, see DECISIONS D9). The
// reader is driven from the mount thread only; callers keep the device
// stack (image -> partition -> LUKS -> LVM -> filesystem) alive.
#pragma once

#include "stein/core/error.hpp"
#include "stein/fs/reader.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace stein::mount {

struct MountOptions {
    bool allowOther = false;    // let other users see the mount (needs user_allow_other in /etc/fuse.conf)
    bool debug = false;
    std::string fsName = "stein";
};

class Mount {
public:
    // Mount `reader` at `mountpoint`. Returns once the kernel accepted the mount; run() serves requests.
    static Expected<std::unique_ptr<Mount>> create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options = {});
    ~Mount();
    Mount(const Mount&) = delete;
    Mount& operator=(const Mount&) = delete;

    // Serve requests until unmounted (fusermount3 -u, umount, or stop()). Blocking.
    Expected<void> run();
    // Ask the running loop to finish and unmount. Safe from another thread.
    void stop();
    // True while run() is serving requests (false before run() and after the loop ended).
    bool running() const;
    const std::filesystem::path& mountpoint() const { return m_mountpoint; }

    static bool available();   // compiled with a backend and the system has what it needs

private:
    Mount() = default;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    std::filesystem::path m_mountpoint;
};

} // namespace stein::mount
