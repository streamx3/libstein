// SPDX-License-Identifier: MIT
#include "stein/probe/topology.hpp"

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

void probeInto(Node& node, const Options& options, int depth) {
    if (depth > options.maxDepth) return;
    if (node.kind == NodeKind::Device) {
        probeTable(node, options, depth);
        if (!node.table) probeContent(node);
        return;
    }
    // Partition: content first; a nested table only when nothing else claims the bytes.
    probeContent(node);
    if (!node.content && options.nestedTables && node.device->size() >= 1 * MiB) {
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
        s = (device ? device->name() : name) + "  " + sizeOf(region);
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
