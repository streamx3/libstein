// SPDX-License-Identifier: MIT
// `stein` — the command-line front-end. Deliberately thin: every command is a
// few lines over the libraries, so that what the CLI can do, every UI can do.
//
//   stein probe   <image>                 topology tree: table, partitions, contents
//   stein table   <image>                 partition table details
//   stein inspect <image> [--doc]         hexinator-style tree of every metadata structure
//   stein verify  <image>                 exit 0 if healthy, 1 on warnings, 2 on errors
//   stein repair  <image> [--dry-run]     fix repairable problems (GPT: rebuild/relocate copies)
//   stein pt dump <image> <piece.sparse>  save the partition-table metadata alone
//   stein pt restore <piece.sparse> <image>
//   stein pt create|add|rm|set|wipe ...   edit the table (simulated on an overlay, applied in one pass)
//   stein types [gpt|mbr]                 list known partition types
//
// <image> is a regular file or (on Linux) a raw block device such as /dev/sdb.
#include "stein/block/file_device.hpp"
#include "stein/block/sparse_file.hpp"
#include "stein/core/strings.hpp"
#include "stein/core/units.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/app/scenario.hpp"
#include "stein/image/operations.hpp"
#include "stein/ops/media_test.hpp"
#include "stein/ops/stack.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/partition_table.hpp"
#include "stein/platform/platform.hpp"
#include "stein/probe/topology.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace stein;

namespace {

int usage() {
    std::fputs("usage: stein <probe|inspect|verify|repair|types> ... | stein pt <dump|restore> ...\n"
               "  stein list                                disks the OS knows about\n"
               "  stein probe   <image|device> [--sector-size N]   topology tree: table, partitions, filesystems\n"
               "  stein table   <image>                     partition table details\n"
               "  stein inspect <image> [--doc] [--sector-size N]\n"
               "  stein verify  <image>\n"
               "  stein repair  <image> [--dry-run]\n"
               "  stein pt dump <image> <piece.sparse>\n"
               "  stein pt restore <piece.sparse> <image>\n"
               "      pieces are encrypted when --passphrase (or $STEIN_PASSPHRASE) is given\n"
               "  stein pt create  <image> gpt|mbr|apm [--dry-run] [--force]\n"
               "  stein pt add     <image> [--start LBA|SIZE] [--size SIZE|--end LBA] [--type CODE] [--name NAME] [--index N] [--no-wipe]\n"
               "  stein pt rm      <image> <index>\n"
               "  stein pt set     <image> <index> [--type CODE] [--name NAME] [--start ..] [--size ..|--end ..]\n"
               "  stein pt wipe    <image> [<index>]       zero filesystem/table signatures (whole device or one partition)\n"
               "      every edit prints the pending operations and the resulting layout; --dry-run stops there;\n"
               "      --force is required for destructive edits on a real block device\n"
               "  stein image create  <device|file> <out.stein> [--compress lz4|none] [--chunk 4M] [--split 2G] [--used-only]\n"
               "  stein image restore <in.stein> <device|file> [--no-verify] [--force]\n"
               "  stein image verify  <in.stein> [--level 1|2|3]\n"
               "  stein image info    <in.stein>\n"
               "  stein image keys    <in.stein> list | add [--new-passphrase P] [--name LABEL] | remove <id>\n"
               "      --passphrase P | --passphrase-file F | $STEIN_PASSPHRASE unlock encrypted images (else a prompt);\n"
               "      image create with --passphrase encrypts (chacha20-poly1305, passphrase key slots)\n"
               "  stein fs      <image> [--doc]       filesystem / container signature, label, uuid\n"
               "  stein fs dump <image> <piece.sparse> [--part N]   save the filesystem's metadata regions alone\n"
               "  stein fs restore <piece.sparse> <image>\n"
               "  <image> may be a file, a .stein image, a split raw set (disk.img.000 ...) or a block device\n"
               "  stein media scan <device|file>                      read-only surface scan (unreadable sectors)\n"
               "  stein media test <device|file> [--quick N] [--keep] --force   DESTRUCTIVE capacity/fake-flash test\n"
               "  stein types [gpt|mbr]\n"
               "  stein app init    <profile.json> <device> <image.stein>   write a profile for a disk (identity from the OS)\n"
               "  stein app status  <profile.json> [--unlock]\n"
               "  stein app backup  <profile.json> [--unlock] [--dry-run]\n"
               "  stein app restore <profile.json> [--unlock] [--dry-run]\n"
               "  stein app verify  <profile.json>\n",
               stderr);
    return 64;
}

int die(const Error& e) {
    std::fprintf(stderr, "stein: %s\n", e.toString().c_str());
    return 1;
}

struct Args {
    std::vector<std::string> positional;
    bool doc = false, dryRun = false, noVerify = false, force = false, noWipe = false, unlock = false, usedOnly = false;
    int level = 0;
    std::string compress, split, chunk;
    std::string start, size, end, type, name, index;
    std::string passphrase, passphraseFile, newPassphrase;
    std::uint32_t kdfIterations = 0;
    std::uint32_t quick = 0;
    bool keep = false;
    std::uint32_t sectorSize = 512;
};

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--doc") a.doc = true;
        else if (s == "--dry-run") a.dryRun = true;
        else if (s == "--sector-size" && i + 1 < argc) a.sectorSize = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else if (s == "--no-verify") a.noVerify = true;
        else if (s == "--force") a.force = true;
        else if (s == "--level" && i + 1 < argc) a.level = std::stoi(argv[++i]);
        else if (s == "--compress" && i + 1 < argc) a.compress = argv[++i];
        else if (s == "--split" && i + 1 < argc) a.split = argv[++i];
        else if (s == "--chunk" && i + 1 < argc) a.chunk = argv[++i];
        else if (s == "--start" && i + 1 < argc) a.start = argv[++i];
        else if (s == "--size" && i + 1 < argc) a.size = argv[++i];
        else if (s == "--end" && i + 1 < argc) a.end = argv[++i];
        else if (s == "--type" && i + 1 < argc) a.type = argv[++i];
        else if (s == "--name" && i + 1 < argc) a.name = argv[++i];
        else if ((s == "--index" || s == "--part") && i + 1 < argc) a.index = argv[++i];
        else if (s == "--no-wipe") a.noWipe = true;
        else if (s == "--unlock") a.unlock = true;
        else if (s == "--used-only") a.usedOnly = true;
        else if (s == "--quick" && i + 1 < argc) a.quick = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else if (s == "--keep") a.keep = true;
        else if (s == "--passphrase" && i + 1 < argc) a.passphrase = argv[++i];
        else if (s == "--passphrase-file" && i + 1 < argc) a.passphraseFile = argv[++i];
        else if (s == "--new-passphrase" && i + 1 < argc) a.newPassphrase = argv[++i];
        else if (s == "--kdf-iterations" && i + 1 < argc) a.kdfIterations = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else a.positional.push_back(s);
    }
    return a;
}

#if !defined(_WIN32)
#include <termios.h>
#include <unistd.h>
#else
#include <io.h>
#include <windows.h>
#endif

// Passphrase: --passphrase, --passphrase-file, $STEIN_PASSPHRASE, else a no-echo prompt on a terminal.
std::string readPassphrase(const Args& a, const char* prompt) {
    if (!a.passphrase.empty()) return a.passphrase;
    if (!a.passphraseFile.empty()) {
        std::ifstream in(a.passphraseFile, std::ios::binary);
        std::string line;
        std::getline(in, line);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        return line;
    }
    if (const char* e = std::getenv("STEIN_PASSPHRASE"); e && *e) return e;
    std::string line;
#if !defined(_WIN32)
    if (!isatty(STDIN_FILENO)) {
        std::getline(std::cin, line);
        return line;
    }
    std::fprintf(stderr, "%s", prompt);
    termios old{};
    tcgetattr(STDIN_FILENO, &old);
    termios noecho = old;
    noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    std::getline(std::cin, line);
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::fputc('\n', stderr);
#else
    if (!_isatty(_fileno(stdin))) {
        std::getline(std::cin, line);
        return line;
    }
    std::fprintf(stderr, "%s", prompt);
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    std::getline(std::cin, line);
    SetConsoleMode(h, mode);
    std::fputc('\n', stderr);
#endif
    return line;
}

std::string g_passphrase;   // set from the arguments once; used when an encrypted image is opened as a device

Expected<std::shared_ptr<BlockDevice>> openImage(const std::string& path, bool writable, std::uint32_t ss) {
    // A .stein image opens as a (read-only) device like any disk.
    std::error_code ec;
    if (platform::isDevicePath(path)) return platform::openAny(path, writable ? platform::OpenMode::ReadWrite : platform::OpenMode::ReadOnly, ss);
    if (!writable && std::filesystem::is_regular_file(path, ec) && image::SteinReader::looksLikeStein(path)) return image::openImage(path, g_passphrase);
    // Split raw sets (disk.img.000, .001, ...) open as one device, by any member or the prefix.
    if (!std::filesystem::is_block_file(path, ec) && image::findSplitRaw(path)) return image::openSplitRaw(path, writable, ss);
    return platform::openAny(path, writable ? platform::OpenMode::ReadWrite : platform::OpenMode::ReadOnly, ss);
}

// Terminal progress: one updating line.
struct TtyProgress final : ProgressSink {
    void onProgress(const ProgressSnapshot& s) override {
        if (s.total)
            std::fprintf(stderr, "\r%-12s %5.1f%%  %s / %s  %s/s  ETA %s   ", s.phase.c_str(), 100.0 * s.fraction(),
                         s.unit == "bytes" ? formatSize(s.done).c_str() : std::to_string(s.done).c_str(),
                         s.unit == "bytes" ? formatSize(s.total).c_str() : std::to_string(s.total).c_str(),
                         s.unit == "bytes" ? formatSize(static_cast<ByteCount>(s.rate)).c_str() : std::to_string(static_cast<long>(s.rate)).c_str(),
                         s.etaSeconds < 0 ? "?" : (std::to_string(static_cast<long>(s.etaSeconds)) + "s").c_str());
        if (s.total && s.done >= s.total) std::fputc('\n', stderr);
    }
    void onMessage(std::string_view m) override { std::fprintf(stderr, "%.*s\n", static_cast<int>(m.size()), m.data()); }
};

ByteCount parseSize(const std::string& s) {
    char* end = nullptr;
    const double v = std::strtod(s.c_str(), &end);
    std::string unit = end ? toLower(std::string(end)) : "";
    ByteCount mult = 1;
    if (unit == "k" || unit == "kib") mult = KiB;
    else if (unit == "m" || unit == "mib") mult = MiB;
    else if (unit == "g" || unit == "gib") mult = GiB;
    else if (unit == "t" || unit == "tib") mult = TiB;
    return static_cast<ByteCount>(v * static_cast<double>(mult));
}

int cmdImage(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    TtyProgress tty;
    Progress progress(tty);
    if (sub == "create") {
        if (a.positional.size() < 4) return usage();
        auto dev = openImage(a.positional[2], false, a.sectorSize);
        if (!dev) return die(dev.error());
        image::CreateOptions co;
        if (!a.compress.empty()) {
            auto c = image::compressionFromString(a.compress);
            if (!c) return die(Error(ErrorCategory::InvalidArgument, "unknown compression " + a.compress));
            co.compression = *c;
        }
        if (!a.split.empty()) co.splitSize = parseSize(a.split);
        if (!a.chunk.empty()) co.chunkSize = static_cast<std::uint32_t>(parseSize(a.chunk));
        co.sourceName = a.positional[2];
        co.usedBlocksOnly = a.usedOnly;
        if (!a.passphrase.empty() || !a.passphraseFile.empty() || a.kdfIterations) {
            co.passphrase = readPassphrase(a, "Passphrase for the new image: ");
            if (co.passphrase.empty()) return die(Error(ErrorCategory::InvalidArgument, "empty passphrase"));
            if (a.kdfIterations) co.kdfIterations = a.kdfIterations;
        }
        if (auto d = platform::current().describe(a.positional[2])) co.sourceIdentity = d->identity();
        auto r = image::createImage(*dev, a.positional[3], co, progress);
        if (!r) return die(r.error());
        std::printf("image %s: %llu chunks (%llu all-zero), %s read, %s stored in %zu file(s)\n", r->imageUuid.toString(false).c_str(),
                    static_cast<unsigned long long>(r->stats.chunks), static_cast<unsigned long long>(r->stats.zeroChunks),
                    formatSize(r->stats.bytesRead).c_str(), formatSize(r->storedBytes).c_str(), r->files.size());
        for (const auto& n : r->allocationNotes) std::printf("  allocation: %s\n", n.c_str());
        if (r->stats.freeBytesSkipped) std::printf("  free space skipped: %s\n", formatSize(r->stats.freeBytesSkipped).c_str());
        if (r->stats.unreadableSectors) std::printf("WARNING: %llu unreadable sectors were zero-filled\n", static_cast<unsigned long long>(r->stats.unreadableSectors));
        if (!r->imageHashHex.empty()) std::printf("sha256 %s\n", r->imageHashHex.c_str());
        return r->stats.unreadableSectors ? 1 : 0;
    }
    if (sub == "restore") {
        if (a.positional.size() < 4) return usage();
        {
            // A missing regular-file target is created at the image's size (restore into a new raw file).
            std::error_code ec;
            if (!platform::isDevicePath(a.positional[3]) && !std::filesystem::exists(a.positional[3], ec)) {
                auto info = image::imageInfo(a.positional[2]);
                if (!info) return die(info.error());
                auto created = FileDevice::create(a.positional[3], info->header.totalSize);
                if (!created) return die(created.error());
            }
        }
        auto dev = openImage(a.positional[3], true, a.sectorSize);
        if (!dev) return die(dev.error());
        image::RestoreOptions ro;
        ro.verifyPayloadFirst = !a.noVerify;
        ro.allowSmallerTarget = a.force;
        auto r = image::restoreImage(a.positional[2], **dev, ro, progress, g_passphrase);
        if (!r) return die(r.error());
        std::printf("restored %s (%llu chunks)%s%s\n", formatSize(r->stats.bytesRead).c_str(), static_cast<unsigned long long>(r->stats.chunks),
                    r->targetLarger ? "; target is larger than the image" : "", r->targetSmaller ? "; target was SMALLER, image truncated" : "");
        return 0;
    }
    if (sub == "verify") {
        const int level = a.level ? a.level : 3;
        auto v = image::verifyImage(a.positional[2], level, progress, g_passphrase);
        if (!v) return die(v.error());
        std::printf("structure %s, %s, %llu/%llu chunks stored, %llu checked, %llu bad", v->structureOk ? "ok" : "BAD", v->complete ? "complete" : "INCOMPLETE",
                    static_cast<unsigned long long>(v->chunksStored), static_cast<unsigned long long>(v->chunksTotal),
                    static_cast<unsigned long long>(v->chunksChecked), static_cast<unsigned long long>(v->chunksBad));
        if (v->imageHashChecked) std::printf(", sha256 %s", v->imageHashOk ? "ok" : "MISMATCH");
        std::printf("\n");
        for (auto c : v->badChunks) std::printf("  bad chunk %llu\n", static_cast<unsigned long long>(c));
        return (v->chunksBad || (v->imageHashChecked && !v->imageHashOk)) ? 2 : (v->complete ? 0 : 1);
    }
    if (sub == "info") {
        auto i = image::imageInfo(a.positional[2], g_passphrase);
        if (!i) return die(i.error());
        std::printf("stein image v%u  uuid %s  %s\n", i->header.version, i->header.imageUuid.toString(false).c_str(), i->complete ? "complete" : "INCOMPLETE");
        std::printf("source size %s, sector %u, chunk %s, compression %s, %llu/%llu chunks stored, %s on disk in %zu segment(s)\n",
                    formatSizeExact(i->header.totalSize).c_str(), i->header.sectorSize, formatSize(i->header.chunkSize).c_str(),
                    std::string(image::toString(i->header.compression)).c_str(), static_cast<unsigned long long>(i->chunksStored),
                    static_cast<unsigned long long>(i->chunksTotal), formatSize(i->storedBytes).c_str(), i->segments.size());
        if (i->encrypted) std::printf("encrypted (chacha20-poly1305), %zu key slot(s), %s\n", i->keySlots, i->unlocked ? "unlocked" : "LOCKED - pass --passphrase for manifest and hash");
        if (i->imageHashHex) std::printf("sha256 %s\n", i->imageHashHex->c_str());
        for (const auto& s : i->segments)
            std::printf("  segment %u: %s (%s, %llu records%s)\n", s.header.segmentIndex, s.path.string().c_str(), formatSize(s.fileSize).c_str(),
                        static_cast<unsigned long long>(s.records), s.trailer ? "" : ", NO TRAILER - recovered by scanning");
        if (!i->encrypted || i->unlocked) std::printf("manifest:\n%s\n", i->manifest.dump(2).c_str());
        return 0;
    }
    if (sub == "keys") {
        // stein image keys <in.stein> list | add | remove <id>
        if (a.positional.size() < 4) return usage();
        const std::string& op = a.positional[3];
        if (op == "list") {
            auto k = image::imageKeys(a.positional[2]);
            if (!k) return die(k.error());
            for (const auto& slot : k->slots())
                std::printf("slot %d: passphrase, pbkdf2-hmac-sha256 %u iterations%s\n", slot.id, slot.iterations, slot.label.empty() ? "" : (" \"" + slot.label + "\"").c_str());
            return 0;
        }
        const std::string current = readPassphrase(a, "Current passphrase: ");
        if (op == "add") {
            std::string fresh = a.newPassphrase;
            if (fresh.empty()) {
                Args b = a;
                b.passphrase.clear();
                b.passphraseFile.clear();
                fresh = readPassphrase(b, "New passphrase: ");
            }
            if (fresh.empty()) return die(Error(ErrorCategory::InvalidArgument, "empty new passphrase"));
            auto id = image::addImageKey(a.positional[2], current, fresh, a.kdfIterations ? a.kdfIterations : image::Keys::kDefaultIterations, a.name);
            if (!id) return die(id.error());
            std::printf("added key slot %d\n", *id);
            return 0;
        }
        if (op == "remove") {
            if (a.positional.size() < 5) return usage();
            if (auto r = image::removeImageKey(a.positional[2], current, std::stoi(a.positional[4])); !r) return die(r.error());
            std::printf("removed key slot %s\n", a.positional[4].c_str());
            return 0;
        }
        return usage();
    }
    return usage();
}

int cmdList(const Args&) {
    auto& p = platform::current();
    auto disks = p.enumerate();
    if (!disks) return die(disks.error());
    if (!p.isElevated()) std::fprintf(stderr, "note: not elevated; opening devices will likely fail\n");
    std::printf("%-14s %12s %6s %-8s %-6s %-24s %s\n", "Device", "Size", "Sector", "Bus", "Flags", "Model", "Serial / backing file");
    for (const auto& d : *disks) {
        std::string flags;
        if (d.removable) flags += "R";
        if (d.rotational) flags += "H";
        if (d.readOnly) flags += "ro";
        if (d.isVirtual) flags += "V";
        std::string id = d.serial;
        if (d.backingFile) id = d.backingFile->string();
        std::printf("%-14s %12s %6u %-8s %-6s %-24s %s\n", d.osPath.c_str(), formatSize(d.geometry.sizeBytes).c_str(),
                    d.geometry.logicalSectorSize, std::string(platform::toString(d.bus)).c_str(), flags.c_str(), d.model.c_str(), id.c_str());
    }
    return 0;
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

int cmdTable(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto t = pt::PartitionTable::read(*dev);
    if (!t) return die(t.error());
    printTable(**t);
    return 0;
}

int cmdProbe(const Args& a) {
    if (a.positional.size() < 2) return usage();
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto tree = probe::probe(*dev);
    if (!tree) return die(tree.error());
    std::fputs(probe::toText(*tree).c_str(), stdout);
    return tree->health() >= layout::Validity::Error ? 2 : 0;
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

int cmdPtEdit(const Args& a);

int cmdPt(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    if (sub == "create" || sub == "add" || sub == "rm" || sub == "set" || sub == "wipe") return cmdPtEdit(a);
    if (a.positional.size() < 4) return usage();
    if (sub == "dump") {
        auto dev = openImage(a.positional[2], false, a.sectorSize);
        if (!dev) return die(dev.error());
        auto t = pt::PartitionTable::read(*dev);
        if (!t) return die(t.error());
        if ((*t)->type() == pt::TableType::None) return die(Error(ErrorCategory::NotFound, "no partition table to dump"));
        auto piece = SparseFile::capture(**dev, (*t)->metadataRegions());
        if (!piece) return die(piece.error());
        if (auto w = SparseFile::write(a.positional[3], *piece, g_passphrase, a.kdfIterations ? a.kdfIterations : 600000); !w) return die(w.error());
        std::printf("saved %zu metadata regions of a %s table to %s\n", piece->runs.size(),
                    std::string(pt::toString((*t)->type())).c_str(), a.positional[3].c_str());
        return 0;
    }
    if (sub == "restore") {
        auto piece = SparseFile::read(a.positional[2], g_passphrase);
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

// ---- partition table editing (stein_ops) -----------------------------------

// "2048s" = sectors; otherwise a byte size with units, converted to sectors.
Expected<Lba> parseLba(const std::string& text, std::uint32_t sectorSize) {
    if (text.empty()) return fail(ErrorCategory::InvalidArgument, "empty value");
    if (text.back() == 's' || text.back() == 'S') {
        char* end = nullptr;
        const auto v = std::strtoull(text.c_str(), &end, 10);
        if (end != text.c_str() + text.size() - 1) return fail(ErrorCategory::InvalidArgument, "bad sector value: " + text);
        return Lba{v};
    }
    const ByteCount bytes = parseSize(text);
    if (bytes % sectorSize) return fail(ErrorCategory::InvalidArgument, text + " is not a multiple of the sector size");
    return Lba{bytes / sectorSize};
}

Expected<pt::PartitionType> parseType(pt::TableType scheme, const std::string& text) {
    if (text.empty()) {
        if (auto t = pt::types::forRole(pt::Role::LinuxFilesystem, scheme)) return *t;
        return fail(ErrorCategory::InvalidArgument, "--type is required for this table scheme");
    }
    switch (scheme) {
    case pt::TableType::Gpt:
        if (auto t = pt::types::fromSgdiskCode(text)) return *t;
        if (auto g = Uuid::parse(text)) return pt::PartitionType::gpt(*g);
        return fail(ErrorCategory::InvalidArgument, "unknown GPT type (use an sgdisk code like 8300 or a GUID): " + text);
    case pt::TableType::Mbr: {
        char* end = nullptr;
        const auto v = std::strtoul(text.c_str(), &end, 16);
        if (*end || v > 0xFF) return fail(ErrorCategory::InvalidArgument, "MBR type must be a hex id like 83 or 0x07: " + text);
        return pt::PartitionType::mbr(static_cast<std::uint8_t>(v));
    }
    case pt::TableType::Apm:
        return pt::PartitionType::apm(text);
    default:
        return fail(ErrorCategory::Unsupported, "no editable table");
    }
}

bool isRealDevice(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !std::filesystem::is_regular_file(path, ec);
}

// Show the stack, then apply unless --dry-run. Shared by every edit command.
int finishEdit(ops::OperationStack& stack, const Args& a, const std::string& path) {
    std::fputs(ops::describe(stack).c_str(), stdout);
    if (a.dryRun) {
        std::puts("(dry run: nothing written)");
        return 0;
    }
    if (stack.destructive() && isRealDevice(path) && !a.force)
        return die(Error(ErrorCategory::Permission, "destructive edit on a block device; re-run with --force"));
    std::fflush(stdout);
    TtyProgress tty;
    Progress progress(tty);
    auto r = stack.apply(progress);
    if (!r) return die(r.error());
    std::printf("%s\n", r->postconditionOk ? "applied; device matches the preview" : "applied, but the device does not match the preview (re-probe!)");
    return r->postconditionOk ? 0 : 1;
}

int cmdPtEdit(const Args& a) {
    const std::string& sub = a.positional[1];
    const std::string& path = a.positional[2];
    auto dev = openImage(path, !a.dryRun, a.sectorSize);
    if (!dev) return die(dev.error());
    ops::OperationStack stack(*dev);
    const auto& base = stack.base();
    const std::uint32_t ss = (*dev)->sectorSize();

    if (sub == "create") {
        if (a.positional.size() < 4) return usage();
        pt::TableType type = pt::TableType::Unknown;
        const std::string want = toLower(a.positional[3]);
        if (want == "gpt") type = pt::TableType::Gpt;
        else if (want == "mbr" || want == "dos" || want == "msdos") type = pt::TableType::Mbr;
        else if (want == "apm" || want == "mac") type = pt::TableType::Apm;
        else return die(Error(ErrorCategory::InvalidArgument, "unknown table scheme: " + a.positional[3]));
        if (auto r = stack.push(std::make_unique<ops::CreateTable>(type)); !r) return die(r.error());
        return finishEdit(stack, a, path);
    }
    if (!base.table) return die(Error(ErrorCategory::NotFound, "no partition table on " + path + " (use `stein pt create`)"));
    const auto& table = *base.table;

    if (sub == "add") {
        pt::Partition p;
        p.index = a.index.empty() ? 0 : static_cast<std::uint32_t>(std::stoul(a.index));
        p.name = a.name;
        auto type = parseType(table.type(), a.type);
        if (!type) return die(type.error());
        p.type = *type;
        // Default placement: the largest free region, start aligned to 1 MiB.
        const SectorCount align = std::max<SectorCount>(1, (1 * MiB) / ss);
        auto free = table.freeRegions(align);
        if (free.empty() && a.start.empty()) return die(Error(ErrorCategory::OutOfRange, "no free space in the table"));
        pt::FreeRegion target;
        for (const auto& f : free)
            if (f.sectors() > target.sectors()) target = f;
        if (!a.start.empty()) {
            auto s = parseLba(a.start, ss);
            if (!s) return die(s.error());
            p.firstLba = *s;
            // Pick the free region containing the start, if any.
            for (const auto& f : free)
                if (*s >= f.firstLba && *s <= f.lastLba) target = f;
        } else {
            p.firstLba = ((target.firstLba + align - 1) / align) * align;
        }
        if (!a.end.empty()) {
            auto e = parseLba(a.end, ss);
            if (!e) return die(e.error());
            p.lastLba = *e;
        } else if (!a.size.empty()) {
            auto n = parseLba(a.size, ss);
            if (!n) return die(n.error());
            if (*n == 0) return die(Error(ErrorCategory::InvalidArgument, "size must be positive"));
            p.lastLba = p.firstLba + *n - 1;
        } else {
            p.lastLba = target.lastLba >= p.firstLba ? target.lastLba : p.firstLba;
            // Leave the end aligned too, unless that would make the partition empty.
            const Lba alignedEnd = ((p.lastLba + 1) / align) * align - 1;
            if (alignedEnd > p.firstLba) p.lastLba = alignedEnd;
        }
        if (auto r = stack.push(std::make_unique<ops::AddPartition>(p, !a.noWipe)); !r) return die(r.error());
        return finishEdit(stack, a, path);
    }
    if (sub == "rm") {
        if (a.positional.size() < 4) return usage();
        const auto index = static_cast<std::uint32_t>(std::stoul(a.positional[3]));
        if (auto r = stack.push(std::make_unique<ops::DeletePartition>(index)); !r) return die(r.error());
        return finishEdit(stack, a, path);
    }
    if (sub == "set") {
        if (a.positional.size() < 4) return usage();
        const auto index = static_cast<std::uint32_t>(std::stoul(a.positional[3]));
        const auto* existing = table.find(index);
        if (!existing) return die(Error(ErrorCategory::NotFound, "no partition " + a.positional[3]));
        pt::Partition p = *existing;
        if (!a.type.empty()) {
            auto type = parseType(table.type(), a.type);
            if (!type) return die(type.error());
            p.type = *type;
        }
        if (!a.name.empty()) p.name = a.name;
        if (!a.start.empty()) {
            auto s = parseLba(a.start, ss);
            if (!s) return die(s.error());
            p.firstLba = *s;
        }
        if (!a.end.empty()) {
            auto e = parseLba(a.end, ss);
            if (!e) return die(e.error());
            p.lastLba = *e;
        } else if (!a.size.empty()) {
            auto n = parseLba(a.size, ss);
            if (!n) return die(n.error());
            p.lastLba = p.firstLba + *n - 1;
        }
        if (auto r = stack.push(std::make_unique<ops::UpdatePartition>(p)); !r) return die(r.error());
        return finishEdit(stack, a, path);
    }
    if (sub == "wipe") {
        Region region{0, (*dev)->size()};
        if (a.positional.size() >= 4) {
            const auto index = static_cast<std::uint32_t>(std::stoul(a.positional[3]));
            const auto* existing = table.find(index);
            if (!existing) return die(Error(ErrorCategory::NotFound, "no partition " + a.positional[3]));
            region = existing->region(ss);
        }
        if (auto r = stack.push(std::make_unique<ops::WipeSignatures>(region)); !r) return die(r.error());
        return finishEdit(stack, a, path);
    }
    return usage();
}

int cmdFsPiece(const Args& a) {
    const std::string& sub = a.positional[1];
    if (a.positional.size() < 4) return usage();
    if (sub == "dump") {
        auto dev = openImage(a.positional[2], false, a.sectorSize);
        if (!dev) return die(dev.error());
        // Whole device, or one partition's content located through the probe tree.
        ByteCount base = 0;
        std::shared_ptr<BlockDevice> target = *dev;
        if (!a.index.empty()) {
            auto tree = probe::probe(*dev);
            if (!tree) return die(tree.error());
            const auto want = static_cast<std::uint32_t>(std::stoul(a.index));
            const probe::Node* node = nullptr;
            for (const auto& c : tree->children)
                if (c.partition && c.partition->index == want) node = &c;
            if (!node) return die(Error(ErrorCategory::NotFound, "no partition " + a.index));
            base = node->region.offset;
            target = node->device;
        }
        auto fsr = fs::probe(target);
        if (!fsr) return die(fsr.error());
        if (!*fsr) return die(Error(ErrorCategory::NotFound, "no known filesystem or container signature"));
        std::vector<Region> regions;
        for (const auto& r : (*fsr)->metadataRegions()) regions.push_back(Region{base + r.offset, r.length});
        auto piece = SparseFile::capture(**dev, regions);
        if (!piece) return die(piece.error());
        if (auto w = SparseFile::write(a.positional[3], *piece, g_passphrase, a.kdfIterations ? a.kdfIterations : 600000); !w) return die(w.error());
        ByteCount bytes = 0;
        for (const auto& r : regions) bytes += r.length;
        std::printf("saved %zu metadata regions (%s) of %s to %s\n", regions.size(), formatSize(bytes).c_str(),
                    std::string(fs::displayName((*fsr)->type())).c_str(), a.positional[3].c_str());
        std::puts("note: this is the identification header (superblock/boot sector, descriptor tables, backups),\n"
                  "      not the allocation bitmaps or inode/MFT tables; it brings a wiped signature back, not lost data");
        return 0;
    }
    if (sub == "restore") {
        auto piece = SparseFile::read(a.positional[2], g_passphrase);
        if (!piece) return die(piece.error());
        auto dev = openImage(a.positional[3], true, piece->sectorSize);
        if (!dev) return die(dev.error());
        if ((*dev)->size() != piece->totalSize)
            std::fprintf(stderr, "warning: piece was taken from a %s device, target is %s\n",
                         formatSize(piece->totalSize).c_str(), formatSize((*dev)->size()).c_str());
        if (auto r = SparseFile::apply(*piece, **dev); !r) return die(r.error());
        std::printf("restored %zu regions; device now probes as:\n", piece->runs.size());
        auto tree = probe::probe(*dev);
        if (!tree) return die(tree.error());
        std::fputs(probe::toText(*tree).c_str(), stdout);
        return 0;
    }
    return usage();
}

int cmdFs(const Args& a) {
    if (a.positional.size() < 2) return usage();
    if (a.positional[1] == "dump" || a.positional[1] == "restore") return cmdFsPiece(a);
    auto dev = openImage(a.positional[1], false, a.sectorSize);
    if (!dev) return die(dev.error());
    auto r = fs::probe(*dev);
    if (!r) return die(r.error());
    if (!*r) {
        std::puts("no known filesystem or container signature");
        return 1;
    }
    const auto& info = (*r)->info();
    std::printf("Type:     %s (%s)\n", std::string(fs::displayName(info.type)).c_str(), std::string(fs::toString(info.type)).c_str());
    if (!info.version.empty()) std::printf("Version:  %s\n", info.version.c_str());
    if (!info.label.empty()) std::printf("Label:    %s\n", info.label.c_str());
    if (!info.uuid.empty()) std::printf("UUID:     %s\n", info.uuid.c_str());
    if (info.blockSize) std::printf("Block:    %s\n", formatSize(*info.blockSize).c_str());
    if (info.totalBytes) std::printf("Size:     %s\n", formatSizeExact(*info.totalBytes).c_str());
    if (info.usedBytes) std::printf("Used:     %s\n", formatSizeExact(*info.usedBytes).c_str());
    if (info.clean) std::printf("State:    %s\n", *info.clean ? "clean" : "DIRTY");
    if (!info.extra.empty()) std::printf("Info:     %s\n", info.extra.c_str());
    for (const auto& f : info.features) std::printf("Feature:  %s\n", f.c_str());
    for (const auto& d : (*r)->diagnostics())
        std::printf("[%s] %s (%s)\n", std::string(layout::toString(d.severity)).c_str(), d.message.c_str(), d.code.c_str());
    if (a.doc) std::fputs((*r)->describe().toText(0, true).c_str(), stdout);
    return 0;
}

// ---- profiles (stein_app) ---------------------------------------------------

int cmdApp(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    const std::string& profilePath = a.positional[2];
    if (sub == "init") {
        if (a.positional.size() < 5) return usage();
        app::Profile p;
        p.name = std::filesystem::path(profilePath).stem().string();
        p.image.path = a.positional[4];
        const std::string& dev = a.positional[3];
        std::error_code ec;
        if (std::filesystem::is_regular_file(dev, ec)) {
            p.target.osPath = dev;
            p.target.allowVirtual = true;
            p.description = "regular file target (testing)";
        } else {
            auto d = platform::current().describe(dev);
            if (!d) return die(d.error());
            p.target.serial = d->serial;
            p.target.wwn = d->wwn;
            p.target.model = d->model;
            p.target.sizeBytes = d->geometry.sizeBytes;
            p.target.sizeTolerance = 0.02;
            p.target.osPath = d->osPath;
            p.target.allowRemovable = d->removable;
            p.target.allowVirtual = d->isVirtual;
            p.policy.requireElevated = true;
            p.description = d->model + (d->serial.empty() ? "" : " sn:" + d->serial) + ", " + formatSize(d->geometry.sizeBytes) + " at " + d->osPath;
        }
        if (auto v = p.validate(); !v) return die(v.error());
        if (auto w = p.save(profilePath); !w) return die(w.error());
        std::printf("wrote %s\n%s", profilePath.c_str(), p.toJson().dump(2).c_str());
        std::puts("");
        return 0;
    }
    auto profile = app::Profile::load(profilePath);
    if (!profile) return die(profile.error());
    app::RunOptions o;
    o.unlock = a.unlock;
    o.dryRun = a.dryRun;
    o.passphrase = g_passphrase;
    if (o.passphrase.empty() && profile->image.encrypt && (sub == "backup" || sub == "restore" || sub == "verify")) o.passphrase = readPassphrase(a, "Passphrase: ");
    if (sub == "status") {
        auto st = app::status(*profile, o);
        std::fputs(app::describe(*profile, st).c_str(), stdout);
        return st.target ? 0 : 1;
    }
    TtyProgress tty;
    Progress progress(tty);
    Expected<app::ScenarioResult> r = fail(ErrorCategory::InvalidArgument, "unknown app command: " + sub);
    if (sub == "backup") r = app::backup(*profile, o, progress);
    else if (sub == "restore") r = app::restore(*profile, o, progress);
    else if (sub == "verify") r = app::verify(*profile, o, progress);
    else return usage();
    if (!r) return die(r.error());
    std::fputs(r->report.toText().c_str(), stdout);
    return r->ok ? 0 : 1;
}

int cmdMedia(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    const std::string& path = a.positional[2];
    TtyProgress tty;
    Progress progress(tty);
    if (sub == "scan") {
        auto dev = openImage(path, false, a.sectorSize);
        if (!dev) return die(dev.error());
        Report report("Surface scan");
        report.start();
        auto r = ops::surfaceScan(**dev, progress, report);
        if (!r) return die(r.error());
        report.finish(r->healthy() ? ReportStatus::Success : ReportStatus::Error);
        std::fputs(report.toText().c_str(), stdout);
        std::printf("%s: %s read in %.1f s, %llu unreadable sector(s)\n", r->healthy() ? "OK" : "DAMAGED", formatSize(r->bytesRead).c_str(), r->seconds,
                    static_cast<unsigned long long>(r->unreadableSectors));
        return r->healthy() ? 0 : 2;
    }
    if (sub == "test") {
        if (isRealDevice(path) && !a.force) return die(Error(ErrorCategory::Permission, "the capacity test overwrites the whole device; re-run with --force"));
        auto dev = openImage(path, true, a.sectorSize);
        if (!dev) return die(dev.error());
        ops::CapacityTestOptions o;
        o.quickStride = a.quick;
        o.keepPattern = a.keep;
        Report report("Capacity test");
        report.start();
        auto r = ops::capacityTest(**dev, o, progress, report);
        if (!r) return die(r.error());
        report.finish(r->healthy() ? ReportStatus::Success : ReportStatus::Error);
        std::fputs(report.toText().c_str(), stdout);
        if (r->healthy()) std::printf("OK: %s verified, %d MiB/s write, %d MiB/s read\n", formatSize(r->bytesVerified).c_str(), static_cast<int>(r->writeMiBps), static_cast<int>(r->readMiBps));
        else if (r->realCapacityEstimate) std::printf("FAKE OR DAMAGED: claims %s, real capacity about %s\n", formatSize(r->claimedBytes).c_str(), formatSize(*r->realCapacityEstimate).c_str());
        else std::printf("DAMAGED: %llu bad chunk(s)\n", static_cast<unsigned long long>(r->chunksBad));
        return r->healthy() ? 0 : 2;
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
    if (!a.passphrase.empty() || !a.passphraseFile.empty()) g_passphrase = readPassphrase(a, "Passphrase: ");
    else if (const char* e = std::getenv("STEIN_PASSPHRASE"); e && *e) g_passphrase = e;
    const std::string& cmd = a.positional[0];
    if (cmd == "list") return cmdList(a);
    if (cmd == "probe") return cmdProbe(a);
    if (cmd == "table") return cmdTable(a);
    if (cmd == "inspect") return cmdInspect(a);
    if (cmd == "verify") return cmdVerify(a);
    if (cmd == "repair") return cmdRepair(a);
    if (cmd == "pt") return cmdPt(a);
    if (cmd == "image") return cmdImage(a);
    if (cmd == "fs") return cmdFs(a);
    if (cmd == "types") return cmdTypes(a);
    if (cmd == "app") return cmdApp(a);
    if (cmd == "media") return cmdMedia(a);
    return usage();
}
