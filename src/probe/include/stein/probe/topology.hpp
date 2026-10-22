// SPDX-License-Identifier: MIT
// Topology: the tree of what is on a device. Disk -> partition table ->
// partitions -> content (filesystem / container marker / nested table).
// Read-only, bounded reads; this is what UIs render and operations validate
// against. See doc/design/10-architecture.md §3.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/layout/node.hpp"
#include "stein/pt/partition_table.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace stein::probe {

enum class NodeKind : std::uint8_t {
    Device,      // the root device (disk or image)
    Partition,   // a partition entry of the parent's table
    Free,        // unallocated space inside a table's usable range
    Metadata,    // table metadata region (shown on request)
    Decrypted,   // the plaintext payload of an unlocked container (LUKS)
    Volume,      // a logical volume assembled from a volume manager (LVM2)
};

// Notes carry a stable `code` for callers that act on them and a `message` for people. Besides the
// codes the partition table and filesystem probes forward from their diagnostics, the probe adds:
//   probe.io, probe.partition_bounds, probe.fs_larger_than_region  (Warning/Error: the walk itself)
//   luks.header       Warning  the LUKS header cannot be read or parsed (both LUKS2 copies damaged, ...)
//   luks.unsupported  Info     the container cannot be opened in-process; the message is
//                              "cannot open in-process: " + LuksInfo::unsupportedWhy (dm-integrity,
//                              reencryption in progress, a cipher or KDF we lack, no usable slot...).
//                              Emitted on every probe, passphrases or not, so a UI can hide its Unlock
//                              action up front: the node is NOT unlockable and gets no Decrypted child.
//   luks.unlock       Warning  a passphrase attempt failed for a reason other than being wrong
//                              (I/O, damaged key material); a wrong passphrase leaves no note.
//   luks.locked       Info     passphrases were supplied and none opens the container (the cached
//                              master key, if any, did not match either). Absent when nothing was
//                              tried or the probe was cancelled.
//   tcrypt.unlock, tcrypt.payload, lvm.metadata, lvm.segment, lvm.missing_pv, lvm.open
// Notes never carry key material or passphrases.
struct Note {
    layout::Validity severity;
    std::string code;
    std::string message;
};

struct Node {
    NodeKind kind = NodeKind::Device;
    std::string name;                               // "disk", "partition 2", "free"
    std::shared_ptr<BlockDevice> device;            // this node's byte range as a device
    Region region;                                  // where it lies on the root device
    std::optional<pt::Partition> partition;         // for Partition nodes
    std::unique_ptr<pt::PartitionTable> table;      // when this range carries a partition table
    std::unique_ptr<fs::FileSystem> content;        // when this range carries a filesystem/container
    std::vector<Node> children;
    std::vector<Note> notes;

    layout::Validity health() const;                // worst over the subtree
    // A compact one-line summary, e.g. "ext4 \"root\" 20.00 GiB clean".
    std::string summary() const;
};

struct Options {
    bool nestedTables = true;    // look for a partition table inside partitions with no filesystem
    bool includeFree = true;
    ByteCount minFreeBytes = 1 * MiB;   // alignment gaps smaller than this are not shown
    int maxDepth = 3;
    // Passphrases tried on every LUKS container found; an unlocked one gets a
    // Decrypted child holding whatever the plaintext carries. Argon2 slots make
    // each attempt cost real time, so pass only what the user typed.
    std::vector<std::string> passphrases;
    // Master keys of containers unlocked earlier in the session, by LUKS UUID (LuksInfo::uuid,
    // the one `blkid` prints). Tried before any passphrase, so a re-probe (hot-plug, Refresh, a
    // repair, a Hex write) reuses the key instead of paying the KDF again. A key that does not
    // match the header digest is skipped silently and the passphrases are tried.
    std::map<std::string, std::vector<std::uint8_t>> masterKeys;
    // Called once for every container a *passphrase* opened (not a cached key), with its UUID and
    // master key, so the caller can put it in masterKeys for the next probe. Runs on the probing
    // thread, before the plaintext is descended into. The probe keeps no copy; the receiver owns
    // the key and its zeroing. Never written to Notes or logs.
    std::function<void(const std::string& uuid, const std::vector<std::uint8_t>& masterKey)> onUnlocked;
    // Polled between Argon2 slices, between key slots and between passphrases: once it returns
    // true the container is left as found (no Decrypted child, no luks.locked note, since nothing
    // was refuted) and probe() still returns the tree it has. Cheap work (headers, filesystems)
    // is not interrupted; only the key derivations and the VeraCrypt trials are.
    std::function<bool()> cancelled;
    // VeraCrypt/TrueCrypt volumes have no signature: with passphrases given, a region
    // nothing else claims is tried by header decryption (costly: up to 500k PBKDF2
    // iterations per passphrase and header location). pim: VeraCrypt iterations multiplier.
    bool tcrypt = true;
    std::uint32_t pim = 0;
    bool volumes = true;         // assemble LVM logical volumes whose extents all lie on this device
};

Expected<Node> probe(std::shared_ptr<BlockDevice> root, const Options& options = {});

// Tree rendering for terminals: one line per node with "├─" connectors.
std::string toText(const Node& root, bool withNotes = true);

} // namespace stein::probe
