// SPDX-License-Identifier: MIT
#include "stein/probe/topology.hpp"

#include "stein/container/luks.hpp"
#include "stein/container/tcrypt.hpp"
#include "stein/volume/lvm.hpp"

#include "stein/block/slice_device.hpp"
#include "stein/core/strings.hpp"
#include "stein/pt/gpt_table.hpp"

#include <algorithm>

namespace stein::probe {

using layout::Validity;

namespace {

void probeInto(Node& node, const Options& options, int depth);

void addNotesFromTable(Node& node) {
    for (const auto& d : node.table->diagnostics()) node.notes.push_back(Note{d.severity, d.code, d.message});
}

void addNotesFromContent(Node& node) {
    for (const auto& d : node.content->diagnostics()) node.notes.push_back(Note{d.severity, d.code, d.message});
}

void probeContent(Node& node) {
    auto r = fs::probe(node.device);
    if (!r) {
        node.notes.push_back(Note{Validity::Warning, "probe.io", "cannot probe contents: " + r.error().message()});
        return;
    }
    if (*r) {
        node.content = std::move(*r);
        addNotesFromContent(node);
        // Sanity: a filesystem that believes it is larger than its container.
        const auto& info = node.content->info();
        if (info.totalBytes && *info.totalBytes > node.device->size() + node.device->sectorSize())
            node.notes.push_back(Note{Validity::Warning, "probe.fs_larger_than_region",
                                      "filesystem claims " + formatSize(*info.totalBytes) + " but the region is " + formatSize(node.device->size())});
    }
}

void probeTable(Node& node, const Options& options, int depth) {
    auto t = pt::PartitionTable::read(node.device);
    if (!t) {
        node.notes.push_back(Note{Validity::Warning, "probe.io", "cannot read partition table: " + t.error().message()});
        return;
    }
    if ((*t)->type() == pt::TableType::None) return;
    node.table = std::move(*t);
    addNotesFromTable(node);
    const auto& geo = node.table->geometry();
    const std::uint32_t ss = geo.logicalSectorSize;
    std::vector<pt::Partition> parts(node.table->partitions().begin(), node.table->partitions().end());
    std::sort(parts.begin(), parts.end(), [](const pt::Partition& a, const pt::Partition& b) { return a.firstLba < b.firstLba; });
    for (const auto& p : parts) {
        Node child;
        child.kind = NodeKind::Partition;
        child.name = "partition " + std::to_string(p.index);
        child.partition = p;
        Region local = p.region(ss);
        child.region = Region{node.region.offset + local.offset, local.length};
        auto slice = SliceDevice::create(node.device, local, child.name);
        if (!slice) {
            child.notes.push_back(Note{Validity::Error, "probe.partition_bounds", "partition lies outside the device: " + slice.error().message()});
            node.children.push_back(std::move(child));
            continue;
        }
        child.device = *slice;
        if (!p.isExtended) probeInto(child, options, depth + 1);
        node.children.push_back(std::move(child));
    }
    if (options.includeFree) {
        for (const auto& f : node.table->freeRegions(std::max<SectorCount>(1, options.minFreeBytes / ss))) {
            Node freeNode;
            freeNode.kind = NodeKind::Free;
            freeNode.name = "free";
            Region local{f.firstLba * ss, f.sectors() * ss};
            freeNode.region = Region{node.region.offset + local.offset, local.length};
            node.children.push_back(std::move(freeNode));
        }
        std::sort(node.children.begin(), node.children.end(), [](const Node& a, const Node& b) { return a.region.offset < b.region.offset; });
    }
}

// A LUKS container with a passphrase that opens it: descend into the plaintext.
void probeLuks(Node& node, const Options& options, int depth) {
    if (!node.content || options.passphrases.empty()) return;
    const auto t = node.content->type();
    if (t != fs::FsType::Luks1 && t != fs::FsType::Luks2) return;
    auto luks = container::Luks::open(node.device);
    if (!luks) {
        node.notes.push_back(Note{Validity::Warning, "luks.header", luks.error().message()});
        return;
    }
    if (!luks->info().supported) {
        node.notes.push_back(Note{Validity::Info, "luks.unsupported", "cannot open in-process: " + luks->info().unsupportedWhy});
        return;
    }
    for (const auto& pass : options.passphrases) {
        auto payload = luks->openPayload(pass, true);
        if (!payload) {
            if (payload.error().category() != ErrorCategory::Integrity) node.notes.push_back(Note{Validity::Warning, "luks.unlock", payload.error().message()});
            continue;
        }
        Node child;
        child.kind = NodeKind::Decrypted;
        child.name = "decrypted";
        child.device = *payload;
        child.region = Region{node.region.offset + luks->info().payloadOffset, (*payload)->size()};
        // The plaintext may carry a table or a filesystem: probe it like a device.
        Node tmp;
        tmp.kind = NodeKind::Device;
        tmp.device = child.device;
        tmp.region = child.region;
        probeInto(tmp, options, depth + 1);
        child.table = std::move(tmp.table);
        child.content = std::move(tmp.content);
        child.children = std::move(tmp.children);
        child.notes = std::move(tmp.notes);
        node.children.push_back(std::move(child));
        return;
    }
    node.notes.push_back(Note{Validity::Info, "luks.locked", "no supplied passphrase opens this container"});
}

// Unclaimed bytes plus a passphrase: try VeraCrypt/TrueCrypt headers.
void probeTcrypt(Node& node, const Options& options, int depth) {
    if (!options.tcrypt || options.passphrases.empty() || node.content || node.table || !node.children.empty()) return;
    if (node.device->size() < 256 * KiB) return;
    container::TcryptOptions to;
    to.pim = options.pim;
    for (const auto& pass : options.passphrases) {
        auto t = container::Tcrypt::unlock(node.device, pass, to);
        if (!t) {
            if (t.error().category() != ErrorCategory::Integrity) node.notes.push_back(Note{Validity::Info, "tcrypt.unlock", t.error().message()});
            continue;
        }
        auto payload = t->openPayload(true);
        if (!payload) {
            node.notes.push_back(Note{Validity::Warning, "tcrypt.payload", payload.error().message()});
            return;
        }
        Node child;
        child.kind = NodeKind::Decrypted;
        child.name = t->info().variant + (t->info().hidden ? " hidden volume" : " volume") + " (" + t->info().prf + (t->info().backupHeader ? ", backup header)" : ")");
        child.device = *payload;
        child.region = Region{node.region.offset + t->info().payloadOffset, (*payload)->size()};
        Node tmp;
        tmp.kind = NodeKind::Device;
        tmp.device = child.device;
        tmp.region = child.region;
        probeInto(tmp, options, depth + 1);
        child.table = std::move(tmp.table);
        child.content = std::move(tmp.content);
        child.children = std::move(tmp.children);
        child.notes = std::move(tmp.notes);
        node.children.push_back(std::move(child));
        return;
    }
}

// An LVM2 physical volume: list the group's logical volumes; map those this device alone can serve.
void probeLvm(Node& node, const Options& options, int depth) {
    if (!options.volumes || !node.content || node.content->type() != fs::FsType::Lvm2Pv) return;
    auto vg = volume::VolumeGroup::fromPv(node.device);
    if (!vg) {
        node.notes.push_back(Note{Validity::Info, "lvm.metadata", vg.error().message()});
        return;
    }
    for (const auto& lv : vg->lvs()) {
        if (!lv.visible()) continue;
        Node child;
        child.kind = NodeKind::Volume;
        child.name = vg->name() + "/" + lv.name;
        child.region = Region{node.region.offset, lv.extents() * vg->extentBytes()};   // logical size; extents are scattered
        auto missing = vg->missingPvs(lv);
        auto unsupported = vg->unsupportedSegments(lv);
        if (!unsupported.empty()) {
            child.notes.push_back(Note{Validity::Info, "lvm.segment", "segment type " + unsupported.front() + " is not mapped in-process yet"});
        } else if (!missing.empty()) {
            std::string list;
            for (const auto& m : missing) list += (list.empty() ? "" : ", ") + m;
            child.notes.push_back(Note{Validity::Info, "lvm.missing_pv", "needs other physical volume(s): " + list});
        } else if (auto dev = vg->openLv(lv.name)) {
            child.device = *dev;
            Node tmp;
            tmp.kind = NodeKind::Device;
            tmp.device = child.device;
            tmp.region = child.region;
            probeInto(tmp, options, depth + 1);
            child.table = std::move(tmp.table);
            child.content = std::move(tmp.content);
            child.children = std::move(tmp.children);
            for (auto& n : tmp.notes) child.notes.push_back(std::move(n));
        } else {
            child.notes.push_back(Note{Validity::Warning, "lvm.open", dev.error().message()});
        }
        node.children.push_back(std::move(child));
    }
}

void probeInto(Node& node, const Options& options, int depth) {
    if (depth > options.maxDepth) return;
    if (node.kind == NodeKind::Device) {
        probeTable(node, options, depth);
        if (!node.table) {
            probeContent(node);
            probeLuks(node, options, depth);
            probeLvm(node, options, depth);
            probeTcrypt(node, options, depth);
        }
        return;
    }
    // Partition: content first; a nested table only when nothing else claims the bytes.
    probeContent(node);
    probeLuks(node, options, depth);
    probeLvm(node, options, depth);
    probeTcrypt(node, options, depth);
    if (!node.content && node.children.empty() && options.nestedTables && node.device->size() >= 1 * MiB) {
        auto t = pt::PartitionTable::read(node.device);
        if (t && (*t)->type() != pt::TableType::None) {
            node.table = std::move(*t);
            addNotesFromTable(node);
            // Reuse the table walk for the nested children.
            Node tmp;
            tmp.kind = NodeKind::Device;
            tmp.device = node.device;
            tmp.region = node.region;
            tmp.table = std::move(node.table);
            probeTable(tmp, options, depth);   // re-reads; cheap
            node.table = std::move(tmp.table);
            node.children = std::move(tmp.children);
        }
    }
}

std::string sizeOf(const Region& r) { return formatSize(r.length); }

void render(const Node& n, const std::string& prefix, bool last, bool root, bool withNotes, std::string& out) {
    std::string line = root ? "" : prefix + (last ? "└─ " : "├─ ");
    line += n.summary();
    out += line + "\n";
    const std::string childPrefix = root ? "" : prefix + (last ? "   " : "│  ");
    if (withNotes)
        for (const auto& note : n.notes)
            if (note.severity >= Validity::Warning) out += childPrefix + "   [" + std::string(layout::toString(note.severity)) + "] " + note.message + "\n";
    if (n.content)
        for (const auto& v : n.content->subvolumes()) {
            out += childPrefix + "   " + v.kind + " \"" + v.name + "\"";
            if (!v.parent.empty()) out += " of \"" + v.parent + "\"";
            if (!v.note.empty()) out += "  (" + v.note + ")";
            out += "\n";
        }
    for (std::size_t i = 0; i < n.children.size(); ++i) render(n.children[i], childPrefix, i + 1 == n.children.size(), false, withNotes, out);
}

} // namespace

Validity Node::health() const {
    Validity worst = Validity::Ok;
    for (const auto& n : notes) worst = std::max(worst, n.severity);
    for (const auto& c : children) worst = std::max(worst, c.health());
    return worst;
}

std::string Node::summary() const {
    std::string s;
    if (kind == NodeKind::Free) return "free  " + sizeOf(region);
    if (kind == NodeKind::Partition && partition) {
        s = name + "  " + sizeOf(region) + "  " + pt::types::name(partition->type);
        if (!partition->name.empty()) s += " \"" + partition->name + "\"";
        if (partition->isExtended) s += " [extended]";
        if (partition->isLogical) s += " [logical]";
        if (partition->type.scheme == pt::TableType::Mbr && (partition->attributes & pt::Partition::kMbrBootable)) s += " [boot]";
    } else {
        if (kind == NodeKind::Decrypted) s = "decrypted payload  " + sizeOf(region);
        else if (kind == NodeKind::Volume) s = "volume " + name + "  " + sizeOf(region) + (device ? "" : "  (not mappable here)");
        else s = (device ? device->name() : name) + "  " + sizeOf(region);
    }
    if (table) {
        s += "  " + std::string(pt::toString(table->type())) + " table";
        if (auto* gpt = dynamic_cast<const pt::GptTable*>(table.get())) s += " " + gpt->diskGuid().toString(false);
        s += " (" + std::to_string(table->partitions().size()) + " partitions)";
    }
    if (content) {
        const auto& info = content->info();
        s += "  " + std::string(fs::displayName(info.type));
        if (!info.label.empty()) s += " \"" + info.label + "\"";
        if (!info.uuid.empty()) s += " " + info.uuid;
        if (info.clean && !*info.clean) s += " DIRTY";
        if (!info.extra.empty()) s += " (" + info.extra + ")";
    }
    const Validity h = health();
    if (h >= Validity::Warning) s += "  [" + std::string(layout::toString(h)) + "]";
    return s;
}

Expected<Node> probe(std::shared_ptr<BlockDevice> root, const Options& options) {
    if (!root) return fail(ErrorCategory::InvalidArgument, "null device");
    Node n;
    n.kind = NodeKind::Device;
    n.name = root->name();
    n.device = root;
    n.region = Region{0, root->size()};
    probeInto(n, options, 0);
    return n;
}

std::string toText(const Node& root, bool withNotes) {
    std::string out;
    render(root, "", true, true, withNotes, out);
    return out;
}

} // namespace stein::probe
