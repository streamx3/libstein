// SPDX-License-Identifier: MIT
// `stein` — the command-line front-end. Deliberately thin: every command is a
// few lines over the libraries, so that what the CLI can do, every UI can do.
//
//   stein probe   <image>                 partition table, partitions, diagnostics
//   stein inspect <image> [--doc]         hexinator-style tree of every metadata structure
//   stein verify  <image>                 exit 0 if healthy, 1 on warnings, 2 on errors
//   stein repair  <image> [--dry-run]     fix repairable problems (GPT: rebuild/relocate copies)
//   stein pt dump <image> <piece.sparse>  save the partition-table metadata alone
//   stein pt restore <piece.sparse> <image>
//   stein types [gpt|mbr]                 list known partition types
//
// Images are regular files for now; raw devices arrive with stein_platform.
#include "stein/block/file_device.hpp"
#include "stein/block/sparse_file.hpp"
#include "stein/core/strings.hpp"
#include "stein/core/units.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/partition_table.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace stein;

namespace {

int usage() {
    std::fputs("usage: stein <probe|inspect|verify|repair|types> ... | stein pt <dump|restore> ...\n"
               "  stein probe   <image> [--sector-size N]\n"
               "  stein inspect <image> [--doc] [--sector-size N]\n"
               "  stein verify  <image>\n"
               "  stein repair  <image> [--dry-run]\n"
               "  stein pt dump <image> <piece.sparse>\n"
               "  stein pt restore <piece.sparse> <image>\n"
               "  stein types [gpt|mbr]\n",
               stderr);
    return 64;
}

int die(const Error& e) {
    std::fprintf(stderr, "stein: %s\n", e.toString().c_str());
    return 1;
}

struct Args {
    std::vector<std::string> positional;
    bool doc = false, dryRun = false;
    std::uint32_t sectorSize = 512;
};

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--doc") a.doc = true;
        else if (s == "--dry-run") a.dryRun = true;
        else if (s == "--sector-size" && i + 1 < argc) a.sectorSize = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else a.positional.push_back(s);
    }
    return a;
}

Expected<std::shared_ptr<FileDevice>> openImage(const std::string& path, bool writable, std::uint32_t ss) {
    return FileDevice::open(path, writable ? FileDevice::Mode::ReadWrite : FileDevice::Mode::ReadOnly, ss);
}

void printTable(const pt::PartitionTable& t) {
    const auto& g = t.geometry();
    std::printf("Table: %s   device: %s (%llu sectors of %u bytes)\n", std::string(pt::toString(t.type())).c_str(),
                formatSize(g.sizeBytes).c_str(), static_cast<unsigned long long>(g.sectors()), g.logicalSectorSize);
    if (auto* gpt = dynamic_cast<const pt::GptTable*>(&t)) {
        std::printf("Disk GUID: %s   entries: %u x %u   primary: %s   backup: %s%s\n", gpt->diskGuid().toString().c_str(),
                    gpt->entryCount(), gpt->entrySize(), gpt->primaryState().valid() ? "OK" : "BAD",
                    gpt->backupState().valid() ? "OK" : "BAD", gpt->isHybridMbr() ? "   hybrid MBR" : "");
    }
    std::printf("Usable LBAs: %llu .. %llu\n\n", static_cast<unsigned long long>(t.firstUsableLba()),
                static_cast<unsigned long long>(t.lastUsableLba()));
    std::printf("%-4s %14s %14s %12s  %-28s %s\n", "#", "Start", "End", "Size", "Type", "Name / flags");
    for (const auto& p : t.partitions()) {
        std::string flags;
        if (p.isExtended) flags += "[extended] ";
        if (p.isLogical) flags += "[logical] ";
        if (t.type() == pt::TableType::Mbr && (p.attributes & pt::Partition::kMbrBootable)) flags += "[boot] ";
        if (t.type() == pt::TableType::Gpt && p.attributes) flags += "attrs=" + toHex(p.attributes) + " ";
        std::printf("%-4u %14llu %14llu %12s  %-28s %s%s\n", p.index, static_cast<unsigned long long>(p.firstLba),
                    static_cast<unsigned long long>(p.lastLba), formatSize(p.sectors() * g.logicalSectorSize).c_str(),
                    pt::types::name(p.type).c_str(), p.name.c_str(), flags.empty() ? "" : (" " + flags).c_str());
    }
    for (const auto& f : t.freeRegions(1))
        std::printf("%-4s %14llu %14llu %12s  %s\n", "-", static_cast<unsigned long long>(f.firstLba),
                    static_cast<unsigned long long>(f.lastLba), formatSize(f.sectors() * g.logicalSectorSize).c_str(), "free");
    if (!t.diagnostics().empty()) {
        std::printf("\nDiagnostics:\n");
        for (const auto& d : t.diagnostics())
            std::printf("  [%s] %s%s  (%s)\n", std::string(layout::toString(d.severity)).c_str(), d.message.c_str(),
                        d.repairable ? "  -- repairable" : "", d.code.c_str());
    }
}

int cmdProbe(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto t = pt::PartitionTable::read(*dev);
    if (!t) return die(t.error());
    printTable(**t);
    return 0;
}

int cmdInspect(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto t = pt::PartitionTable::read(*dev);
    if (!t) return die(t.error());
    std::fputs((*t)->describe().toText(0, a.doc).c_str(), stdout);
    return 0;
}

int cmdVerify(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto t = pt::PartitionTable::read(*dev);
    if (!t) return die(t.error());
    for (const auto& d : (*t)->diagnostics())
        std::printf("[%s] %s%s\n", std::string(layout::toString(d.severity)).c_str(), d.message.c_str(),
                    d.repairable ? "  -- repairable" : "");
    switch ((*t)->health()) {
    case layout::Validity::Ok:
    case layout::Validity::Info: std::puts("OK"); return 0;
    case layout::Validity::Warning: std::puts("WARNINGS"); return 1;
    case layout::Validity::Error: std::puts("ERRORS"); return 2;
    }
    return 2;
}

int cmdRepair(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], !a.dryRun, a.sectorSize);
    if (!dev) return die(dev.error());
    auto t = pt::PartitionTable::read(*dev);
    if (!t) return die(t.error());
    bool any = false;
    for (const auto& d : (*t)->diagnostics())
        if (d.repairable) {
            any = true;
            std::printf("would fix: %s\n", d.message.c_str());
        }
    if (!any) {
        std::puts("nothing to repair");
        return 0;
    }
    if (a.dryRun) return 0;
    if (auto r = (*t)->repair(**dev, pt::RepairOptions{}); !r) return die(r.error());
    std::puts("repaired; new state:");
    printTable(**t);
    return 0;
}

int cmdPt(const Args& a) {
    if (a.positional.size() < 4) return usage();
    const std::string& sub = a.positional[1];
    if (sub == "dump") {
        auto dev = openImage(a.positional[2], false, a.sectorSize);
        if (!dev) return die(dev.error());
        auto t = pt::PartitionTable::read(*dev);
        if (!t) return die(t.error());
        if ((*t)->type() == pt::TableType::None) return die(Error(ErrorCategory::NotFound, "no partition table to dump"));
        auto piece = SparseFile::capture(**dev, (*t)->metadataRegions());
        if (!piece) return die(piece.error());
        if (auto w = SparseFile::write(a.positional[3], *piece); !w) return die(w.error());
        std::printf("saved %zu metadata regions of a %s table to %s\n", piece->runs.size(),
                    std::string(pt::toString((*t)->type())).c_str(), a.positional[3].c_str());
        return 0;
    }
    if (sub == "restore") {
        auto piece = SparseFile::read(a.positional[2]);
        if (!piece) return die(piece.error());
        auto dev = openImage(a.positional[3], true, piece->sectorSize);
        if (!dev) return die(dev.error());
        if ((*dev)->size() != piece->totalSize)
            std::fprintf(stderr, "warning: piece was taken from a %s device, target is %s\n",
                         formatSize(piece->totalSize).c_str(), formatSize((*dev)->size()).c_str());
        if (auto r = SparseFile::apply(*piece, **dev); !r) return die(r.error());
        auto t = pt::PartitionTable::read(*dev);
        if (!t) return die(t.error());
        std::printf("restored %zu regions; table now reads as:\n", piece->runs.size());
        printTable(**t);
        return 0;
    }
    return usage();
}

int cmdTypes(const Args& a) {
    const std::string filter = a.positional.size() > 1 ? a.positional[1] : "";
    for (const auto& info : pt::types::all()) {
        if (!filter.empty() && std::string(pt::toString(info.type.scheme)) != filter) continue;
        std::printf("%-4s %-40s %-5s %-10s %s\n", std::string(pt::toString(info.type.scheme)).c_str(), info.type.code().c_str(),
                    info.sgdiskCode, std::string(pt::toString(info.role)).c_str(), info.name);
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    Args a = parse(argc, argv);
    if (a.positional.empty()) return usage();
    const std::string& cmd = a.positional[0];
    if (cmd == "probe") return cmdProbe(a);
    if (cmd == "inspect") return cmdInspect(a);
    if (cmd == "verify") return cmdVerify(a);
    if (cmd == "repair") return cmdRepair(a);
    if (cmd == "pt") return cmdPt(a);
    if (cmd == "types") return cmdTypes(a);
    return usage();
}
