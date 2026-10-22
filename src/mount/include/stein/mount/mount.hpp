// SPDX-License-Identifier: MIT
// Mount any fs::Reader as a read-only filesystem the OS can browse.
//
// Backends: libfuse3 on Linux (LGPL, linked dynamically, see DECISIONS D9),
// WinFsp's fuse3 layer on Windows, and on macOS the library's own NFSv3
// server on 127.0.0.1 mounted through the system's mount_nfs (no kext, no
// root). What every backend guarantees:
//
// - Read-only. Writes are refused by the mount itself (FUSE: ro; NFS: each
//   modifying procedure answers NFS3ERR_ROFS and no attribute carries a write
//   bit), so nothing reaches the reader or the devices under it.
// - run() returns when the mount ends, whichever side ended it: stop(), or
//   the user's umount / fusermount3 -u / Finder eject. FUSE: the kernel
//   connection closes and the loop exits. macOS: run() looks at the mount
//   table once a second (getfsstat, no RPC) and sooner when the kernel
//   client's UMNT reaches the server; it then stops serving and returns {}.
//   running() is false afterwards, so a caller can drop its bookkeeping.
// - Thread model. The reader is driven from the backend's threads, never the
//   caller's. FUSE runs a single-threaded loop. The NFS server has one thread
//   per client connection but serialises every call into the reader with one
//   mutex, so the reader sees one request at a time and need not be
//   thread-safe. The device chain under the reader (image -> partition ->
//   LUKS -> LVM -> filesystem) is shared with whoever else holds it, such as
//   the app's browser on the UI thread, so every device in the chain must
//   tolerate readAt() from several threads: FileDevice, ImageDevice and the
//   vdisk/container mapped devices lock their stream or chunk cache; the XTS,
//   slice, concat and memory devices keep no per-read state.
// - Lifetime. Callers keep the device stack alive while the Mount exists.
//   The destructor unmounts and stops serving when run() has not done so.
#pragma once

#include "stein/core/error.hpp"
#include "stein/fs/reader.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace stein::mount {

struct MountOptions {
    // FUSE: allow_other, so other users see the mount (needs user_allow_other in /etc/fuse.conf).
    // macOS: no effect; a loopback NFS mount is reachable by every local user and the server
    // does not look at the caller's uid.
    bool allowOther = false;
    bool debug = false;
    // Volume name. FUSE: fsname (Linux) / volname (WinFsp). macOS: the NFS export path,
    // "127.0.0.1:/<fsName>", which is what Finder shows; "/" and ":" in it become "_".
    std::string fsName = "stein";
};

class Mount {
public:
    // Mount `reader` at `mountpoint`. Returns once the kernel accepted the mount; run() serves requests.
    static Expected<std::unique_ptr<Mount>> create(std::unique_ptr<fs::Reader> reader, const std::filesystem::path& mountpoint, const MountOptions& options = {});
    ~Mount();
    Mount(const Mount&) = delete;
    Mount& operator=(const Mount&) = delete;

    // Serve requests until the mount ends: stop(), or an unmount from outside (umount,
    // fusermount3 -u, Finder eject). Blocking. Returns {} either way; an error only when the
    // serving loop itself failed.
    Expected<void> run();
    // Ask the running loop to finish and unmount. Safe from another thread; before run() it
    // unmounts right away.
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
