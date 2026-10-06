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
