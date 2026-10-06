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
#include "stein/container/luks.hpp"
#include "stein/container/tcrypt.hpp"
#include "stein/volume/lvm.hpp"
#include "stein/core/strings.hpp"
#include "stein/core/units.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/app/scenario.hpp"
#include "stein/image/operations.hpp"
#include "stein/image/vdisk.hpp"
#include "stein/mount/mount.hpp"
#include "stein/mount/nfs_server.hpp"
#include "stein/ops/media_test.hpp"
#include "stein/ops/stack.hpp"
#include "stein/pt/gpt_table.hpp"
#include "stein/pt/partition_table.hpp"
#include "stein/platform/platform.hpp"
#include "stein/probe/topology.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>
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
               "  stein image create  <device|file> <out.stein|out.img> [--format stein|raw] [--compress lz4|none] [--chunk 4M] [--split 2G] [--used-only]\n"
               "      a .img/.raw/.dd name (or --format raw) writes a plain dd-style image; restore accepts both\n"
               "  stein image restore <in.stein> <device|file> [--no-verify] [--force]\n"
               "  stein image verify  <in.stein> [--level 1|2|3]\n"
               "  stein image info    <in.stein|vm.qcow2|.vhd|.vhdx|.vmdk|.vdi|.E01|.dmg>\n"
               "  stein image keys    <in.stein> list | add [--new-passphrase P] [--name LABEL] | remove <id>\n"
               "      --passphrase P | --passphrase-file F | $STEIN_PASSPHRASE unlock encrypted images (else a prompt);\n"
               "      image create with --passphrase encrypts (chacha20-poly1305, passphrase key slots);\n"
               "      --kdf argon2id|pbkdf2 --kdf-cost N --kdf-memory KiB tune the passphrase stretching\n"
               "  stein fs      <image> [--doc]       filesystem / container signature, label, uuid\n"
               "  stein fs dump <image> <piece.sparse> [--part N]   save the filesystem's metadata regions alone\n"
               "  stein fs restore <piece.sparse> <image>\n"
               "  <image> may be a file, a .stein image, a split raw set (disk.img.000 ...) or a block device\n"
               "  stein media scan <device|file>                      read-only surface scan (unreadable sectors)\n"
               "  stein media test <device|file> [--quick N] [--keep] --force   DESTRUCTIVE capacity/fake-flash test\n"
               "  stein luks info    <image|device> [--part N]        header, cipher, key slots\n"
               "  stein luks unlock  <image|device> [--part N]        check a passphrase and probe the plaintext\n"
               "  stein luks extract <image|device> <out> [--part N]  decrypt the payload into a plain image\n"
               "  stein tcrypt unlock  <image|device> [--part N] [--pim N] [--prf sha512|sha256|blake2s|ripemd160|whirlpool|streebog]\n"
               "                       VeraCrypt/TrueCrypt: find the header by trial decryption (any cipher or cascade), probe the plaintext\n"
               "  stein tcrypt extract <image|device> <out> [--part N] [--pim N] [--prf NAME]\n"
               "      stein probe --passphrase P also descends into LUKS containers it can open\n"
               "  stein lvm list    <image|device> [--part N] [--doc]   volume group, PVs, LVs and how they map\n"
               "  stein lvm extract <image|device> <lv> <out> [--part N] copy a logical volume into a plain image\n"
               "  stein ls  <image|device> [path] [--part N] [--lv NAME] [--passphrase P]   list a directory in-process\n"
               "  stein cat <image|device> <path> ...                                       print a file\n"
               "  stein cp  <image|device> <path> <out> ...                                 copy a file out (ext2/3/4 so far)\n"
               "  stein mount <image|device> <mountpoint> [--part N] [--lv NAME] [--passphrase P] [--allow-other]\n"
               "      read-only mount of a filesystem inside an image / LUKS / LVM (Linux: FUSE, macOS: NFS loopback, Windows: WinFsp)\n"
               "  stein serve <image|device> [--port N] [--raw] [--part N] [--lv NAME] [--passphrase P]\n"
               "      serve the filesystem (or, with --raw, the decoded disk as one file) over NFSv3 on 127.0.0.1 for any NFS client\n"
               "  stein attach <image|device> [--part N] [--lv NAME] [--passphrase P] [--no-mount]\n"
               "      macOS: hand the decoded disk to the system's own filesystem drivers (NFS loopback + hdiutil attach)\n"
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
    bool doc = false, dryRun = false, noVerify = false, force = false, noWipe = false, unlock = false, usedOnly = false, allowOther = false;
    int level = 0;
    std::string compress, split, chunk;
    std::string start, size, end, type, name, index;
    std::string passphrase, passphraseFile, newPassphrase, kdf, lv;
    std::uint32_t pim = 0;
    std::string prf;   // tcrypt: try only this PRF
    std::string port, format;
    bool raw = false, noMount = false;
    std::uint32_t kdfCost = 0, kdfMemoryKiB = 0;
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
        else if (s == "--lv" && i + 1 < argc) a.lv = argv[++i];
        else if (s == "--allow-other") a.allowOther = true;
        else if (s == "--pim" && i + 1 < argc) a.pim = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (s == "--prf" && i + 1 < argc) a.prf = argv[++i];
        else if (s == "--port" && i + 1 < argc) a.port = argv[++i];
        else if (s == "--format" && i + 1 < argc) a.format = argv[++i];
        else if (s == "--raw") a.raw = true;
        else if (s == "--no-mount") a.noMount = true;
        else if (s == "--no-wipe") a.noWipe = true;
        else if (s == "--unlock") a.unlock = true;
        else if (s == "--used-only") a.usedOnly = true;
        else if (s == "--quick" && i + 1 < argc) a.quick = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else if (s == "--keep") a.keep = true;
        else if (s == "--passphrase" && i + 1 < argc) a.passphrase = argv[++i];
        else if (s == "--passphrase-file" && i + 1 < argc) a.passphraseFile = argv[++i];
        else if (s == "--new-passphrase" && i + 1 < argc) a.newPassphrase = argv[++i];
        else if (s == "--kdf" && i + 1 < argc) a.kdf = argv[++i];
        else if (s == "--kdf-cost" && i + 1 < argc) a.kdfCost = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        else if (s == "--kdf-memory" && i + 1 < argc) a.kdfMemoryKiB = static_cast<std::uint32_t>(std::stoul(argv[++i]));
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

// --kdf argon2id|pbkdf2, --kdf-cost (passes or iterations), --kdf-memory KiB
Expected<KdfParams> kdfFromArgs(const Args& a) {
    KdfParams k;
    if (a.kdf == "pbkdf2" || a.kdf == "pbkdf2-hmac-sha256") k = KdfParams::pbkdf2();
    else if (!a.kdf.empty() && a.kdf != "argon2id") return fail(ErrorCategory::InvalidArgument, "unknown --kdf " + a.kdf + " (argon2id or pbkdf2)");
    if (a.kdfCost) k.cost = a.kdfCost;
    if (a.kdfMemoryKiB && k.kind == KdfParams::Kind::Argon2id) k.memoryKiB = a.kdfMemoryKiB;
    return k;
}

Expected<std::shared_ptr<BlockDevice>> openImage(const std::string& path, bool writable, std::uint32_t ss) {
    // A .stein image opens as a (read-only) device like any disk.
    std::error_code ec;
    if (platform::isDevicePath(path)) return platform::openAny(path, writable ? platform::OpenMode::ReadWrite : platform::OpenMode::ReadOnly, ss);
    if (!writable && std::filesystem::is_regular_file(path, ec) && image::SteinReader::looksLikeStein(path)) return image::openImage(path, g_passphrase);
    // qcow2 / VHD / VHDX / VMDK / VDI containers open read-only as the disk they describe.
    if (std::filesystem::is_regular_file(path, ec)) {
        auto fmt = image::detectVdiskFormat(path);
        if (fmt && *fmt != image::VdiskFormat::Raw && *fmt != image::VdiskFormat::Stein) {
            if (writable) return fail(ErrorCategory::Permission, path + " is a " + std::string(image::toString(*fmt)) + " container; stein opens those read-only");
            image::VdiskInfo vi;
            auto dev = image::openVdisk(path, &vi);
            if (!dev) return dev;
            for (const auto& n : vi.notes) std::fprintf(stderr, "note: %s: %s\n", path.c_str(), n.c_str());
            return dev;
        }
    }
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
        {
            // Plain raw image (what dd and GNOME Disks produce): --format raw, or a .img/.raw/.dd name.
            const std::string ext = std::filesystem::path(a.positional[3]).extension().string();
            const bool raw = a.format == "raw" || (a.format.empty() && (ext == ".img" || ext == ".raw" || ext == ".dd"));
            if (raw) {
                if (a.format.empty()) std::fprintf(stderr, "note: writing a raw image because of the %s extension (use --format stein for a .stein image)\n", ext.c_str());
                auto target = FileDevice::create(a.positional[3], (*dev)->size());
                if (!target) return die(target.error());
                image::CopyOptions cpo;
                cpo.badSectors = image::BadSectorPolicy::SkipZero;
                auto r = image::copyDevice(**dev, **target, cpo, progress);
                if (!r) return die(r.error());
                std::printf("raw image %s: %s copied\n", a.positional[3].c_str(), formatSize(r->bytesRead).c_str());
                if (r->unreadableSectors) std::printf("WARNING: %llu unreadable sectors were zero-filled\n", static_cast<unsigned long long>(r->unreadableSectors));
                return r->unreadableSectors ? 1 : 0;
            }
        }
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
        if (!a.passphrase.empty() || !a.passphraseFile.empty() || !a.kdf.empty() || a.kdfCost) {
            co.passphrase = readPassphrase(a, "Passphrase for the new image: ");
            if (co.passphrase.empty()) return die(Error(ErrorCategory::InvalidArgument, "empty passphrase"));
            auto k = kdfFromArgs(a);
            if (!k) return die(k.error());
            co.kdf = *k;
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
        if (auto fmt = image::detectVdiskFormat(a.positional[2]); fmt && *fmt != image::VdiskFormat::Stein) {
            // A raw image (dd, GNOME Disks) or another container: plain device-to-device copy.
            auto src = openImage(a.positional[2], false, a.sectorSize);
            if (!src) return die(src.error());
            std::error_code ec;
            if (!platform::isDevicePath(a.positional[3]) && !std::filesystem::exists(a.positional[3], ec)) {
                auto created = FileDevice::create(a.positional[3], (*src)->size());
                if (!created) return die(created.error());
            }
            auto dst = openImage(a.positional[3], true, a.sectorSize);
            if (!dst) return die(dst.error());
            if ((*dst)->size() < (*src)->size() && !a.force) return die(Error(ErrorCategory::InvalidArgument, "target is smaller than the image (" + formatSize((*dst)->size()) + " < " + formatSize((*src)->size()) + "); --force writes what fits"));
            image::CopyOptions cpo;
            if ((*dst)->size() < (*src)->size()) cpo.limit = (*dst)->size();
            auto r = image::copyDevice(**src, **dst, cpo, progress);
            if (!r) return die(r.error());
            std::printf("restored %s from %s image\n", formatSize(r->bytesRead).c_str(), std::string(image::toString(*fmt)).c_str());
            return 0;
        }
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
        // Other containers (qcow2, VHD, VHDX, VMDK, VDI, E01, DMG): describe what the reader found.
        if (auto fmt = image::detectVdiskFormat(a.positional[2]); fmt && *fmt != image::VdiskFormat::Stein && *fmt != image::VdiskFormat::Raw) {
            image::VdiskInfo vi;
            auto dev = image::openVdisk(a.positional[2], &vi);
            if (!dev) return die(dev.error());
            std::printf("%s container%s%s  virtual size %s", std::string(image::toString(vi.format)).c_str(), vi.variant.empty() ? "" : (" (" + vi.variant + ")").c_str(),
                        vi.compressed ? ", compressed" : "", formatSizeExact(vi.virtualSize).c_str());
            if (vi.clusterSize) std::printf(", %s units", formatSize(vi.clusterSize).c_str());
            std::printf("\n");
            if (!vi.storedMd5.empty()) std::printf("stored md5 %s\n", vi.storedMd5.c_str());
            if (!vi.storedSha1.empty()) std::printf("stored sha1 %s\n", vi.storedSha1.c_str());
            for (const auto& f : vi.files) std::printf("  file %s\n", f.string().c_str());
            for (const auto& n : vi.notes) std::printf("  note: %s\n", n.c_str());
            return 0;
        }
        auto i = image::imageInfo(a.positional[2], g_passphrase);
        if (!i) return die(i.error());
        std::printf("stein image format %u.%u (this libstein reads %u.%u)%s  uuid %s  %s\n", i->header.version, i->header.versionMinor, image::SegmentHeader::kVersionMajor,
                    image::SegmentHeader::kVersionMinor, i->header.writerVersion ? ("  written by libstein " + i->header.writerVersionText()).c_str() : "", i->header.imageUuid.toString(false).c_str(),
                    i->complete ? "complete" : "INCOMPLETE");
        if (i->header.featuresCompat || i->header.featuresIncompat || i->header.featuresRoCompat)
            std::printf("features: compat 0x%x incompat 0x%x ro_compat 0x%x%s\n", i->header.featuresCompat, i->header.featuresIncompat, i->header.featuresRoCompat,
                        i->header.unknownRoCompat() ? " (unknown ro_compat bits: this libstein must not modify the image)" : "");
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
                std::printf("slot %d: passphrase, %s%s\n", slot.id, slot.kdf.describe().c_str(), slot.label.empty() ? "" : (" \"" + slot.label + "\"").c_str());
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
            auto k = kdfFromArgs(a);
            if (!k) return die(k.error());
            auto id = image::addImageKey(a.positional[2], current, fresh, *k, a.name);
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
    probe::Options o;
    if (!g_passphrase.empty()) o.passphrases.push_back(g_passphrase);
    o.pim = a.pim;
    auto tree = probe::probe(*dev, o);
    if (!tree) return die(tree.error());
    std::fputs(probe::toText(*tree).c_str(), stdout);
    return tree->health() >= layout::Validity::Error ? 2 : 0;
}

// ---- LUKS containers (stein_container) --------------------------------------

// Device for `<image> [--part N]`: the whole device or one partition's slice.
Expected<std::shared_ptr<BlockDevice>> deviceOrPartition(const Args& a, const std::string& path) {
    auto dev = openImage(path, false, a.sectorSize);
    if (!dev) return dev;
    if (a.index.empty()) return dev;
    auto tree = probe::probe(*dev);
    if (!tree) return fail(tree.error());
    const auto want = static_cast<std::uint32_t>(std::stoul(a.index));
    for (const auto& c : tree->children)
        if (c.partition && c.partition->index == want) return c.device;
    return fail(ErrorCategory::NotFound, "no partition " + a.index);
}

int cmdLuks(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    auto dev = deviceOrPartition(a, a.positional[2]);
    if (!dev) return die(dev.error());
    auto luks = container::Luks::open(*dev);
    if (!luks) return die(luks.error());
    const auto& info = luks->info();
    if (sub == "info") {
        std::printf("LUKS%d  %s-%s  %u-bit key  payload at %s (%s, %u-byte sectors)%s\n", info.version, info.cipher.c_str(), info.mode.c_str(), info.keyBytes * 8,
                    formatSizeExact(info.payloadOffset).c_str(), formatSize(info.payloadSize).c_str(), info.sectorSize, info.supported ? "" : ("  [cannot open in-process: " + info.unsupportedWhy + "]").c_str());
        if (!info.uuid.empty()) std::printf("UUID %s%s\n", info.uuid.c_str(), info.label.empty() ? "" : ("  label \"" + info.label + "\"").c_str());
        if (!info.hash.empty()) std::printf("hash %s\n", info.hash.c_str());
        for (const auto& sl : info.slots) std::printf("slot %d: %s%s%s\n", sl.id, sl.active ? "" : "inactive, ", sl.kdf.c_str(), sl.kdfDetail.empty() ? "" : (" (" + sl.kdfDetail + ")").c_str());
        return 0;
    }
    const std::string pass = g_passphrase.empty() ? readPassphrase(a, "LUKS passphrase: ") : g_passphrase;
    if (sub == "unlock") {
        // Prove the passphrase opens the container and show what is inside.
        auto payload = luks->openPayload(pass, true);
        if (!payload) return die(payload.error());
        auto tree = probe::probe(*payload);
        if (!tree) return die(tree.error());
        std::puts("unlocked; plaintext payload:");
        std::fputs(probe::toText(*tree).c_str(), stdout);
        return 0;
    }
    if (sub == "extract") {
        // Decrypt the payload into a plain image file (or any writable device).
        if (a.positional.size() < 4) return usage();
        auto payload = luks->openPayload(pass, true);
        if (!payload) return die(payload.error());
        const std::string& outPath = a.positional[3];
        std::error_code ec;
        if (!platform::isDevicePath(outPath) && !std::filesystem::exists(outPath, ec)) {
            auto created = FileDevice::create(outPath, (*payload)->size());
            if (!created) return die(created.error());
        }
        auto target = openImage(outPath, true, a.sectorSize);
        if (!target) return die(target.error());
        if ((*target)->size() < (*payload)->size() && !a.force) return die(Error(ErrorCategory::OutOfRange, "target smaller than the payload (use --force to write what fits)"));
        TtyProgress tty;
        Progress progress(tty);
        image::CopyOptions co;
        co.limit = std::min((*payload)->size(), (*target)->size());
        auto stats = image::copyDevice(**payload, **target, co, progress);
        if (!stats) return die(stats.error());
        std::printf("decrypted %s to %s\n", formatSize(stats->bytesRead).c_str(), outPath.c_str());
        return 0;
    }
    return usage();
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
        if (auto w = SparseFile::write(a.positional[3], *piece, g_passphrase, kdfFromArgs(a).value_or(KdfParams{})); !w) return die(w.error());
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
        if (auto w = SparseFile::write(a.positional[3], *piece, g_passphrase, kdfFromArgs(a).value_or(KdfParams{})); !w) return die(w.error());
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

// ---- LVM (stein_volume) -------------------------------------------------------

int cmdLvm(const Args& a) {
    // stein lvm list <image|device> [--part N] | stein lvm extract <image|device> <lv> <out> [--part N]
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    auto dev = deviceOrPartition(a, a.positional[2]);
    if (!dev) return die(dev.error());
    auto vg = volume::VolumeGroup::fromPv(*dev);
    if (!vg) return die(vg.error());
    if (sub == "list") {
        std::printf("volume group %s  (%s, extent %s, seqno %llu)\n", vg->name().c_str(), vg->id().c_str(), formatSize(vg->extentBytes()).c_str(),
                    static_cast<unsigned long long>(vg->seqno()));
        for (const auto& [name, pv] : vg->pvs())
            std::printf("  pv %-6s %s  %s  pe_start %llu  %llu extents%s\n", name.c_str(), pv.id.c_str(), formatSize(pv.deviceSizeSectors * 512).c_str(),
                        static_cast<unsigned long long>(pv.peStartSectors), static_cast<unsigned long long>(pv.peCount), pv.device ? "  [here]" : "  [elsewhere]");
        for (const auto& lv : vg->lvs()) {
            std::string how;
            for (const auto& seg : lv.segments) how += (how.empty() ? "" : " + ") + seg.type + (seg.stripeCount > 1 ? "x" + std::to_string(seg.stripeCount) : "") + "/" + std::to_string(seg.extentCount);
            auto missing = vg->missingPvs(lv);
            auto unsupported = vg->unsupportedSegments(lv);
            std::string state = !unsupported.empty() ? "unsupported segment " + unsupported.front() : !missing.empty() ? "needs " + missing.front() : "mappable";
            std::printf("  lv %-10s %10s  %-24s %s%s\n", lv.name.c_str(), formatSize(lv.extents() * vg->extentBytes()).c_str(), how.c_str(), state.c_str(), lv.visible() ? "" : "  (hidden)");
        }
        if (a.doc) std::fputs(vg->metadataText().c_str(), stdout);
        return 0;
    }
    if (sub == "extract") {
        if (a.positional.size() < 5) return usage();
        auto lv = vg->openLv(a.positional[3]);
        if (!lv) return die(lv.error());
        const std::string& outPath = a.positional[4];
        std::error_code ec;
        if (!platform::isDevicePath(outPath) && !std::filesystem::exists(outPath, ec)) {
            auto created = FileDevice::create(outPath, (*lv)->size());
            if (!created) return die(created.error());
        }
        auto target = openImage(outPath, true, a.sectorSize);
        if (!target) return die(target.error());
        TtyProgress tty;
        Progress progress(tty);
        image::CopyOptions co;
        co.limit = std::min((*lv)->size(), (*target)->size());
        auto stats = image::copyDevice(**lv, **target, co, progress);
        if (!stats) return die(stats.error());
        std::printf("copied %s of %s to %s\n", formatSize(stats->bytesRead).c_str(), a.positional[3].c_str(), outPath.c_str());
        return 0;
    }
    return usage();
}

// ---- files inside filesystems (stein_fs L3) -----------------------------------

// The block device to read: <image|device> [--part N] [--lv name], through LUKS/VeraCrypt with
// --passphrase and LVM with --lv, down to the layer that holds a filesystem (or nothing known).
Expected<std::shared_ptr<BlockDevice>> resolveDevice(const Args& a, const std::string& path, std::string& where) {
    auto dev = deviceOrPartition(a, path);
    if (!dev) return fail(dev.error());
    std::shared_ptr<BlockDevice> target = *dev;
    where = path + (a.index.empty() ? "" : " partition " + a.index);
    for (int hops = 0; hops < 4; ++hops) {
        auto probed = fs::probe(target);
        if (!probed) return fail(probed.error());
        if (!*probed) {
            // Nothing recognisable: with a passphrase, it may be a VeraCrypt/TrueCrypt volume.
            if (!g_passphrase.empty() && target->size() >= 256 * KiB) {
                container::TcryptOptions to;
                to.pim = a.pim;
                to.prf = a.prf;
                if (auto t = container::Tcrypt::unlock(target, g_passphrase, to)) {
                    auto payload = t->openPayload(true);
                    if (!payload) return fail(payload.error());
                    target = *payload;
                    where += " (" + t->info().variant + ")";
                    continue;
                }
            }
            return target;   // nothing recognised: the caller decides whether that is fine
        }
        const auto t = (*probed)->type();
        if (t == fs::FsType::Luks1 || t == fs::FsType::Luks2) {
            if (g_passphrase.empty()) return fail(ErrorCategory::Permission, where + " is LUKS-encrypted; pass --passphrase");
            auto luks = container::Luks::open(target);
            if (!luks) return fail(luks.error());
            auto payload = luks->openPayload(g_passphrase, true);
            if (!payload) return fail(payload.error());
            target = *payload;
            where += " (decrypted)";
            continue;
        }
        if (t == fs::FsType::Lvm2Pv) {
            auto vg = volume::VolumeGroup::fromPv(target);
            if (!vg) return fail(vg.error());
            std::string lvName = a.lv;
            if (lvName.empty()) {
                std::string names;
                for (const auto& lv : vg->lvs()) names += (names.empty() ? "" : ", ") + lv.name;
                return fail(ErrorCategory::InvalidArgument, where + " is an LVM physical volume; pick a logical volume with --lv (" + names + ")");
            }
            auto lv = vg->openLv(lvName);
            if (!lv) return fail(lv.error());
            target = *lv;
            where += " lv " + lvName;
            continue;
        }
        return target;
    }
    return fail(ErrorCategory::Internal, "too many container layers");
}

// The filesystem reader at the end of that chain.
Expected<std::unique_ptr<fs::Reader>> openReaderFor(const Args& a, const std::string& path, std::string& where) {
    auto target = resolveDevice(a, path, where);
    if (!target) return fail(target.error());
    auto probed = fs::probe(*target);
    if (!probed) return fail(probed.error());
    if (!*probed) return fail(ErrorCategory::NotFound, where + ": no recognised filesystem");
    const auto t = (*probed)->type();
    if (!fs::has((*probed)->capabilities(), fs::Capability::Read))
        return fail(ErrorCategory::Unsupported, where + ": " + std::string(fs::displayName(t)) + " cannot be read in-process yet");
    return (*probed)->openReader();
}

std::string modeText(const fs::Stat& st) {
    std::string m = st.type == fs::FileType::Directory ? "d" : st.type == fs::FileType::Symlink ? "l" : "-";
    const char* bits = "rwxrwxrwx";
    for (int i = 0; i < 9; ++i) m += (st.mode & (0400 >> i)) ? bits[i] : '-';
    return m;
}

int cmdLs(const Args& a) {
    if (a.positional.size() < 2) return usage();
    std::string where;
    auto reader = openReaderFor(a, a.positional[1], where);
    if (!reader) return die(reader.error());
    const std::string path = a.positional.size() > 2 ? a.positional[2] : "/";
    auto inode = fs::resolvePath(**reader, path);
    if (!inode) return die(inode.error());
    auto st = (*reader)->stat(*inode);
    if (!st) return die(st.error());
    if (st->type != fs::FileType::Directory) {
        std::printf("%s %10llu %s\n", modeText(*st).c_str(), static_cast<unsigned long long>(st->size), path.c_str());
        return 0;
    }
    auto entries = (*reader)->readdir(*inode);
    if (!entries) return die(entries.error());
    std::sort(entries->begin(), entries->end(), [](const fs::DirEntry& x, const fs::DirEntry& y) { return x.name < y.name; });
    for (const auto& e : *entries) {
        auto es = (*reader)->stat(e.inode);
        if (!es) continue;
        std::string extra;
        if (es->type == fs::FileType::Symlink)
            if (auto t = (*reader)->readlink(e.inode)) extra = " -> " + *t;
        std::printf("%s %3u %10llu  %s%s\n", modeText(*es).c_str(), es->nlink, static_cast<unsigned long long>(es->size), e.name.c_str(), extra.c_str());
    }
    return 0;
}

int cmdCat(const Args& a, bool toFile) {
    if (a.positional.size() < (toFile ? 4u : 3u)) return usage();
    std::string where;
    auto reader = openReaderFor(a, a.positional[1], where);
    if (!reader) return die(reader.error());
    auto inode = fs::resolvePath(**reader, a.positional[2]);
    if (!inode) return die(inode.error());
    auto st = (*reader)->stat(*inode);
    if (!st) return die(st.error());
    if (st->type == fs::FileType::Directory) {
        if (!toFile) return die(Error(ErrorCategory::InvalidArgument, a.positional[2] + " is a directory"));
        // Whole tree out of the image: the viewer's drag-and-drop primitive.
        TtyProgress tty;
        Progress progress(tty);
        fs::CopyTreeOptions co;
        auto stats = fs::copyTree(**reader, *inode, a.positional[3], co, &progress);
        if (!stats) return die(stats.error());
        std::fprintf(stderr, "copied %llu files, %llu directories, %llu symlinks (%s) from %s:%s to %s\n", static_cast<unsigned long long>(stats->files),
                     static_cast<unsigned long long>(stats->directories), static_cast<unsigned long long>(stats->symlinks), formatSize(stats->bytes).c_str(), where.c_str(),
                     a.positional[2].c_str(), a.positional[3].c_str());
        for (const auto& w : stats->warnings) std::fprintf(stderr, "  skipped %s\n", w.c_str());
        return stats->warnings.empty() ? 0 : 1;
    }
    std::FILE* out = toFile ? std::fopen(a.positional[3].c_str(), "wb") : stdout;
    if (!out) return die(Error(ErrorCategory::Io, "cannot create " + a.positional[3]));
    std::vector<std::byte> buf(4 * MiB);
    std::uint64_t off = 0;
    while (off < st->size) {
        auto n = (*reader)->read(*inode, off, buf);
        if (!n) {
            if (toFile) std::fclose(out);
            return die(n.error());
        }
        if (*n == 0) break;
        std::fwrite(buf.data(), 1, *n, out);
        off += *n;
    }
    if (toFile) {
        std::fclose(out);
        std::fprintf(stderr, "copied %s from %s:%s to %s\n", formatSize(off).c_str(), where.c_str(), a.positional[2].c_str(), a.positional[3].c_str());
    }
    return 0;
}

int cmdMount(const Args& a) {
    // stein mount <image|device> <mountpoint> [--part N] [--lv NAME] [--passphrase P] [--allow-other]
    if (a.positional.size() < 3) return usage();
    std::string where;
    auto reader = openReaderFor(a, a.positional[1], where);
    if (!reader) return die(reader.error());
    mount::MountOptions mo;
    mo.allowOther = a.allowOther;
    mo.fsName = "stein:" + std::filesystem::path(a.positional[1]).filename().string();
    auto m = mount::Mount::create(std::move(*reader), a.positional[2], mo);
    if (!m) return die(m.error());
#if defined(__APPLE__)
    const char* how = "umount";
#elif defined(_WIN32)
    const char* how = "Ctrl-C here, or stein's process exit";
#else
    const char* how = "fusermount3 -u";
#endif
    std::fprintf(stderr, "mounted %s read-only at %s; unmount with: %s %s\n", where.c_str(), a.positional[2].c_str(), how, a.positional[2].c_str());
    if (auto r = (*m)->run(); !r) return die(r.error());
    return 0;
}

std::atomic<bool> g_interrupted{false};
void onInterrupt(int) { g_interrupted.store(true); }

// Block until Ctrl-C / SIGTERM.
void waitForInterrupt() {
    std::signal(SIGINT, onInterrupt);
    std::signal(SIGTERM, onInterrupt);
    while (!g_interrupted.load()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

int cmdServe(const Args& a) {
    // stein serve <image|device> [--port N] [--raw] [--part N] [--lv NAME] [--passphrase P]
    if (a.positional.size() < 2) return usage();
    std::string where;
    std::unique_ptr<fs::Reader> reader;
    if (a.raw) {
        auto dev = resolveDevice(a, a.positional[1], where);
        if (!dev) return die(dev.error());
        reader = mount::makeSingleFileReader(*dev, "disk.img");
        where += " as disk.img";
    } else {
        auto r = openReaderFor(a, a.positional[1], where);
        if (!r) return die(r.error());
        reader = std::move(*r);
    }
    mount::NfsServerOptions so;
    if (!a.port.empty()) so.port = static_cast<std::uint16_t>(std::strtoul(a.port.c_str(), nullptr, 10));
    auto server = mount::NfsServer::start(std::move(reader), so);
    if (!server) return die(server.error());
    const std::string port = std::to_string((*server)->port());
    std::fprintf(stderr, "serving %s read-only over NFSv3 on 127.0.0.1:%s (Ctrl-C to stop)\n", where.c_str(), port.c_str());
    std::fprintf(stderr, "  macOS:   mount_nfs -o vers=3,tcp,port=%s,mountport=%s,locallocks,rdonly,noresvport 127.0.0.1:/ <dir>\n", port.c_str(), port.c_str());
    std::fprintf(stderr, "  Linux:   sudo mount -t nfs -o vers=3,tcp,port=%s,mountport=%s,nolock,ro 127.0.0.1:/ <dir>\n", port.c_str(), port.c_str());
    std::fprintf(stderr, "  Windows: the built-in NFS client needs a portmapper; use stein mount (WinFsp) there\n");
    waitForInterrupt();
    (*server)->stop();
    return 0;
}

int cmdAttach(const Args& a) {
    // stein attach <image|device> [--part N] [--lv NAME] [--passphrase P] [--no-mount]
    if (a.positional.size() < 2) return usage();
#if !defined(__APPLE__)
    std::fprintf(stderr, "stein attach is for macOS (hdiutil); on Linux use stein mount or the platform attach, on Windows stein mount\n");
    return 2;
#else
    std::string where;
    auto dev = resolveDevice(a, a.positional[1], where);
    if (!dev) return die(dev.error());
    const auto dir = std::filesystem::temp_directory_path() / ("stein_attach_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    auto m = mount::Mount::create(mount::makeSingleFileReader(*dev, "disk.img"), dir);
    if (!m) return die(m.error());
    std::thread loop([&] { (*m)->run(); });
    const std::string image = (dir / "disk.img").string();
    const std::string cmd = "hdiutil attach -imagekey diskimage-class=CRawDiskImage -readonly" + std::string(a.noMount ? " -nomount" : "") + " '" + image + "'";
    std::fprintf(stderr, "%s exported at %s; running: %s\n", where.c_str(), image.c_str(), cmd.c_str());
    const int rc = std::system(cmd.c_str());
    if (rc != 0) {
        (*m)->stop();
        loop.join();
        std::filesystem::remove(dir, ec);
        return die(Error(ErrorCategory::Io, "hdiutil attach failed"));
    }
    std::fprintf(stderr, "attached; detach the disk in Finder or with hdiutil detach, then Ctrl-C here\n");
    waitForInterrupt();
    (*m)->stop();
    loop.join();
    std::filesystem::remove(dir, ec);
    return 0;
#endif
}

int cmdTcrypt(const Args& a) {
    if (a.positional.size() < 3) return usage();
    const std::string& sub = a.positional[1];
    auto dev = deviceOrPartition(a, a.positional[2]);
    if (!dev) return die(dev.error());
    const std::string pass = g_passphrase.empty() ? readPassphrase(a, "Volume passphrase: ") : g_passphrase;
    container::TcryptOptions to;
    to.pim = a.pim;
    to.prf = a.prf;
    auto t = container::Tcrypt::unlock(*dev, pass, to);
    if (!t) return die(t.error());
    const auto& info = t->info();
    std::printf("%s%s  %s  PBKDF2-HMAC-%s (%u iterations)  header v%u (min program %u.%u)%s  payload at %s (%s)\n", info.variant.c_str(), info.hidden ? " hidden volume" : "",
                info.cipher.c_str(), info.prf.c_str(), info.iterations, info.headerVersion, info.minProgramVersion >> 8, info.minProgramVersion & 0xFF,
                info.backupHeader ? "  [primary header unusable; opened from the backup header]" : "", formatSizeExact(info.payloadOffset).c_str(), formatSize(info.payloadSize).c_str());
    auto payload = t->openPayload(true);
    if (!payload) return die(payload.error());
    if (sub == "unlock") {
        auto tree = probe::probe(*payload);
        if (!tree) return die(tree.error());
        std::puts("plaintext payload:");
        std::fputs(probe::toText(*tree).c_str(), stdout);
        return 0;
    }
    if (sub == "extract") {
        if (a.positional.size() < 4) return usage();
        const std::string& outPath = a.positional[3];
        std::error_code ec;
        if (!platform::isDevicePath(outPath) && !std::filesystem::exists(outPath, ec)) {
            auto created = FileDevice::create(outPath, (*payload)->size());
            if (!created) return die(created.error());
        }
        auto target = openImage(outPath, true, a.sectorSize);
        if (!target) return die(target.error());
        if ((*target)->size() < (*payload)->size() && !a.force) return die(Error(ErrorCategory::OutOfRange, "target smaller than the payload (use --force to write what fits)"));
        TtyProgress tty;
        Progress progress(tty);
        image::CopyOptions co;
        co.limit = std::min((*payload)->size(), (*target)->size());
        auto stats = image::copyDevice(**payload, **target, co, progress);
        if (!stats) return die(stats.error());
        std::printf("extracted %s to %s\n", formatSize(stats->bytesRead).c_str(), outPath.c_str());
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
    if (cmd == "luks") return cmdLuks(a);
    if (cmd == "tcrypt") return cmdTcrypt(a);
    if (cmd == "lvm") return cmdLvm(a);
    if (cmd == "ls") return cmdLs(a);
    if (cmd == "mount") return cmdMount(a);
    if (cmd == "serve") return cmdServe(a);
    if (cmd == "attach") return cmdAttach(a);
    if (cmd == "cat") return cmdCat(a, false);
    if (cmd == "cp") return cmdCat(a, true);
    return usage();
}
