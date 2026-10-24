// SPDX-License-Identifier: MIT
// The blkid output recorded next to each fixture is the oracle: for every
// fixture we must agree on TYPE, LABEL, UUID and (where we report one) VERSION.
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/block/memory_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/exfat.hpp"
#include "stein/layout/node.hpp"
#include "stein/fs/fat_reader.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/fs/udf_reader.hpp"
// The LUKS-payload case below needs stein::container, which test_fs links only when its
// CMake DEPS name it; until then the case compiles out and the PayloadView case stands in.
#if __has_include("stein/container/luks.hpp")
#include "stein/container/luks.hpp"
#define STEIN_TEST_FS_HAS_LUKS 1
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>
#include <map>

using namespace stein;
using namespace stein::fs;
using stein::test::loadSparseFixture;

namespace {

std::map<std::string, std::string> readOracle(const std::string& name) {
    std::map<std::string, std::string> kv;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/fs/" + name + ".blkid.txt");
    std::string line;
    while (std::getline(in, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string v = line.substr(eq + 1);
        // blkid escapes spaces and backslashes in -o export mode.
        std::string un;
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (v[i] == '\\' && i + 1 < v.size()) un.push_back(v[++i]);
            else un.push_back(v[i]);
        }
        kv[line.substr(0, eq)] = un;
    }
    return kv;
}

struct Fixture {
    const char* name;
    FsType type;
};

const Fixture kFixtures[] = {
    {"ext2", FsType::Ext2},         {"ext3", FsType::Ext3},     {"ext4", FsType::Ext4},      {"ext4_dirty", FsType::Ext4},
    {"fat12", FsType::Fat12},       {"fat16", FsType::Fat16},   {"fat32", FsType::Fat32},    {"exfat", FsType::ExFat},
    {"ntfs", FsType::Ntfs},         {"hfsplus", FsType::HfsPlus}, {"hfsx", FsType::HfsX},    {"hfs", FsType::Hfs},
    {"xfs", FsType::Xfs},           {"btrfs", FsType::Btrfs},   {"f2fs", FsType::F2fs},      {"jfs", FsType::Jfs},
    {"reiserfs", FsType::ReiserFs}, {"nilfs2", FsType::Nilfs2}, {"minix", FsType::Minix},    {"swap", FsType::Swap},
    {"erofs", FsType::Erofs},       {"squashfs", FsType::SquashFs}, {"ocfs2", FsType::Ocfs2}, {"bcachefs", FsType::Bcachefs},
    {"iso9660", FsType::Iso9660},   {"udf", FsType::Udf},       {"luks1", FsType::Luks1},    {"luks2", FsType::Luks2},
    {"lvm_pv", FsType::Lvm2Pv},     {"md_member", FsType::MdRaidMember},
};

} // namespace

TEST_CASE("every fixture matches its blkid oracle") {
    for (const auto& f : kFixtures) {
        const std::string name = f.name;
        CAPTURE(name);
        auto dev = loadSparseFixture(std::string("fs/") + f.name + ".sparse");
        REQUIRE_MESSAGE(dev != nullptr, "fixture missing: ", f.name);
        auto oracle = readOracle(f.name);
        // blkid records nothing for some images we do understand (e.g. an ext4 marked not-clean);
        // then only our own detection is checked.
        const bool haveOracle = oracle.count("TYPE") > 0;
        auto probed = probe(dev);
        REQUIRE_MESSAGE(probed.has_value(), (probed ? std::string() : probed.error().toString()));
        REQUIRE_MESSAGE(*probed != nullptr, "nothing detected on ", f.name);
        const FileSystem& fs = **probed;
        CHECK(fs.type() == f.type);
        if (auto it = oracle.find("TYPE"); it != oracle.end()) CHECK(toString(fs.type()) == it->second);
        if (auto it = oracle.find("LABEL"); it != oracle.end()) CHECK(fs.info().label == it->second);
        else if (haveOracle) CHECK(fs.info().label.empty());
        if (auto it = oracle.find("UUID"); it != oracle.end()) CHECK(toLower(fs.info().uuid) == toLower(it->second));
        if (auto it = oracle.find("VERSION"); it != oracle.end() && !fs.info().version.empty()) CHECK(fs.info().version == it->second);
        // FSSIZE/FSBLOCKSIZE are not compared generically: blkid's definitions differ per prober
        // (xfs subtracts the log, ext subtracts reserved blocks, NTFS FSBLOCKSIZE is the cluster...).
        CHECK(!fs.metadataRegions().empty());
        auto tree = fs.describe();
        CHECK(!tree.name.empty());
    }
}

TEST_CASE("ext4 dirty flag and features") {
    auto dev = loadSparseFixture("fs/ext4_dirty.sparse");
    auto fs = probe(dev);
    REQUIRE((fs && *fs));
    CHECK((*fs)->info().clean == false);
    CHECK((*fs)->health() == layout::Validity::Warning);
    auto clean = probe(loadSparseFixture("fs/ext4.sparse"));
    CHECK((*clean)->info().clean == true);
    CHECK((*clean)->health() == layout::Validity::Ok);
    bool hasExtents = false;
    for (const auto& feat : (*clean)->info().features) hasExtents = hasExtents || feat == "incompat:extents";
    CHECK(hasExtents);
    CHECK((*clean)->info().usedBytes.has_value());
    CHECK(*(*clean)->info().usedBytes < *(*clean)->info().totalBytes);
}

TEST_CASE("FAT: boot label vs root directory label, serial, cluster count typing") {
    auto fs = probe(loadSparseFixture("fs/fat32.sparse"));
    REQUIRE((fs && *fs));
    CHECK((*fs)->info().uuid == "DEAD-BEEF");
    CHECK((*fs)->info().version == "FAT32");
    CHECK((*fs)->info().clean == true);
    const auto tree = (*fs)->describe();   // held: child() pointers into a temporary tree dangle
    REQUIRE(tree.child("boot sector") != nullptr);
    CHECK(tree.child("boot sector")->child("BPB") != nullptr);
    CHECK(tree.child("boot sector")->child("FAT32 extended BPB") != nullptr);
    CHECK(tree.child("FSInfo sector") != nullptr);
    REQUIRE(tree.child("backup boot sector") != nullptr);
    CHECK(tree.child("backup boot sector")->child("BPB") != nullptr);
    CHECK(tree.child("backup boot sector")->child("FAT32 extended BPB") != nullptr);
    const auto* entry = tree.child("root directory volume label entry");
    REQUIRE(entry != nullptr);
    CHECK(entry->child("name")->value == "STEIN_FAT32");
    CHECK((*fs)->info().label == "STEIN_FAT32");
    // A label edited in the boot sector only: the OS keeps showing the root directory's, and the
    // backup boot sector now disagrees with the live one. Both are said.
    {
        auto edited = loadSparseFixture("fs/fat32.sparse");
        const std::string label = "TEST_APM   ";
        REQUIRE(edited->writeAt(36 + 0x23, std::as_bytes(std::span(label.data(), 11))));
        auto fs2 = probe(edited);
        REQUIRE((fs2 && *fs2));
        CHECK((*fs2)->info().label == "STEIN_FAT32");
        CHECK((*fs2)->info().extra == "boot-sector label: TEST_APM");
        bool mismatch = false, backup = false;
        for (const auto& d : (*fs2)->diagnostics()) {
            if (d.code == "fat.label_mismatch") mismatch = true;
            if (d.code == "fat.backup_boot_mismatch") backup = true;
        }
        CHECK(mismatch);
        CHECK(backup);
    }
    auto f12 = probe(loadSparseFixture("fs/fat12.sparse"));
    CHECK((*f12)->info().uuid == "1234-5678");
    CHECK((*f12)->info().version == "FAT12");
}

TEST_CASE("NTFS: label from $Volume, version, clean") {
    auto fs = probe(loadSparseFixture("fs/ntfs.sparse"));
    REQUIRE((fs && *fs));
    CHECK((*fs)->info().label == "STEIN_NTFS");
    CHECK((*fs)->info().version == "3.1");
    CHECK((*fs)->info().clean == true);
    CHECK((*fs)->describe().child("$Volume MFT record") != nullptr);
    CHECK((*fs)->metadataRegions().size() >= 3);
}

TEST_CASE("LUKS and LVM details") {
    auto l1 = probe(loadSparseFixture("fs/luks1.sparse"));
    REQUIRE((l1 && *l1));
    CHECK((*l1)->info().usage == Usage::Crypto);
    CHECK((*l1)->info().extra.find("aes-xts-plain64") != std::string::npos);
    CHECK((*l1)->info().features.at(0) == "1 active keyslot(s)");
    auto l2 = probe(loadSparseFixture("fs/luks2.sparse"));
    REQUIRE((l2 && *l2));
    CHECK((*l2)->info().label == "STEIN_LUKS2");
    CHECK((*l2)->describe().child("secondary binary header") != nullptr);
    CHECK((*l2)->describe().child("secondary binary header")->validity <= layout::Validity::Info);
    auto pv = probe(loadSparseFixture("fs/lvm_pv.sparse"));
    REQUIRE((pv && *pv));
    CHECK((*pv)->info().uuid == "1ZaNjo-cfIz-0B2C-xXt1-zZ3j-5555-aaaaaa");
    CHECK((*pv)->info().totalBytes == 64 * MiB);
    CHECK((*pv)->metadataRegions().size() >= 2);
    auto md = probe(loadSparseFixture("fs/md_member.sparse"));
    REQUIRE((md && *md));
    CHECK((*md)->info().extra.find("raid1") != std::string::npos);
}

// A LUKS2 disk whose first 4 KiB were wiped still has its secondary header copy, which the
// container layer opens from; before the fix the probe needed the primary magic and showed such a
// disk as unknown data.
TEST_CASE("LUKS2 with its first 4 KiB wiped is detected from the secondary header copy, with a diagnostic saying where it is") {
    auto dev = loadSparseFixture("fs/luks2.sparse");
    REQUIRE(dev);
    REQUIRE(dev->writeAt(0, std::vector<std::byte>(4096)));
    auto fs = probe(dev);
    REQUIRE((fs && *fs));
    CHECK((*fs)->type() == FsType::Luks2);
    CHECK((*fs)->info().usage == Usage::Crypto);
    CHECK((*fs)->info().label == "STEIN_LUKS2");
    CHECK((*fs)->info().uuid == "f363f151-c64d-49e3-9bf9-c6d14619445d");
    const FsDiagnostic* missing = nullptr;
    for (const auto& d : (*fs)->diagnostics())
        if (d.code == "luks2.primary_missing") missing = &d;
    REQUIRE(missing);
    CHECK(missing->message == "primary header missing; secondary copy at 16384");
    CHECK(missing->severity == layout::Validity::Warning);
    CHECK((*fs)->describe().child("secondary binary header") != nullptr);
    CHECK((*fs)->describe().child("primary binary header") == nullptr);
    REQUIRE((*fs)->metadataRegions().size() == 1);
    CHECK((*fs)->metadataRegions()[0].length == 2 * 16384);
    // The copy must vouch for itself: with its hdr_size field zeroed the SKUL magic alone is not a header.
    REQUIRE(dev->writeAt(16384 + 8, std::vector<std::byte>(8)));
    auto gone = probe(dev);
    CHECK((!gone || !*gone || (*gone)->type() != FsType::Luks2));
}

TEST_CASE("nothing on a blank or random device") {
    auto blank = std::make_shared<MemoryDevice>(8 * MiB, 512);
    auto r = probe(blank);
    REQUIRE(r);
    CHECK(*r == nullptr);
    auto tiny = std::make_shared<MemoryDevice>(100, 512);
    auto t = probe(tiny);
    REQUIRE(t);
    CHECK(*t == nullptr);
}

// ---- L1: allocation maps -------------------------------------------------------

namespace {
struct AllocOracle {
    bool mounted = false;
    std::optional<ByteCount> freeBytes;         // ext: dumpe2fs
    std::optional<std::uint64_t> freeClusters;  // ntfs: ntfsinfo
    std::optional<std::uint64_t> usedClusters, totalClusters;   // fat: fsck.fat "used/total"
};
AllocOracle loadAllocOracle(const std::string& name) {
    AllocOracle o;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/alloc/" + name + ".oracle.txt");
    std::string line;
    while (std::getline(in, line)) {
        if (line == "mounted=yes") o.mounted = true;
        else if (line.rfind("free_bytes=", 0) == 0) o.freeBytes = std::stoull(line.substr(11));
        else if (line.rfind("free_clusters=", 0) == 0) o.freeClusters = std::stoull(line.substr(14));
        else if (line.rfind("clusters=", 0) == 0) {
            const auto slash = line.find('/');
            o.usedClusters = std::stoull(line.substr(9, slash - 9));
            o.totalClusters = std::stoull(line.substr(slash + 1));
        }
    }
    return o;
}
} // namespace

TEST_CASE("allocation maps: every non-zero byte lies in a used block; counts match the native tools") {
    const char* names[] = {"ext4", "ext2", "fat16", "fat32", "exfat", "ntfs", "hfsplus"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("alloc/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        auto& f = **probed;
        REQUIRE(fs::has(f.capabilities(), fs::Capability::UsedBlocks));
        auto map = f.allocationMap();
        REQUIRE_MESSAGE(map, (map ? std::string() : map.error().toString()));
        CHECK(map->blockSize() >= 512);
        CHECK(map->blocks() > 0);
        CHECK(map->coveredEnd() <= dev->size() + map->blockSize());
        // Invariant: anything non-zero on the device is inside a used block (or outside the covered range).
        const auto bytes = dev->bytes();
        std::uint64_t violations = 0;
        for (std::uint64_t b = 0; b < map->blocks(); ++b) {
            if (map->isUsed(b)) continue;
            const ByteCount off = map->origin() + b * map->blockSize();
            if (off >= bytes.size()) break;
            const ByteCount len = std::min<ByteCount>(map->blockSize(), bytes.size() - off);
            for (ByteCount i = 0; i < len; ++i)
                if (bytes[off + i] != std::byte{0}) {
                    ++violations;
                    break;
                }
        }
        CHECK(violations == 0);
        // Some data must be marked used (metadata at least); a mounted fixture with files has more.
        const auto o = loadAllocOracle(name);
        CHECK(map->usedBlocks() < map->blocks());   // an empty FAT has 0 used clusters: metadata lives before the data area
        if (o.freeBytes) CHECK(map->freeBytes() == *o.freeBytes);
        if (o.freeClusters) CHECK(map->blocks() - map->usedBlocks() == *o.freeClusters);
        if (o.usedClusters) {
            CHECK(map->blocks() == *o.totalClusters);
            CHECK(map->usedBlocks() == *o.usedClusters);
        }
        if (f.info().usedBytes && (f.type() == fs::FsType::HfsPlus || f.type() == fs::FsType::HfsX))
            CHECK(map->usedBytes() == *f.info().usedBytes);   // volume header free count agrees with the bitmap
        // zeroFree on a whole-device copy leaves exactly the used bytes.
        std::vector<std::byte> copy(bytes.begin(), bytes.end());
        const ByteCount zeroed = map->zeroFree(0, copy);
        CHECK(zeroed <= map->freeBytes());
        CHECK(zeroed > 0);
        for (std::uint64_t b = 0; b < map->blocks(); ++b) {
            const ByteCount off = map->origin() + b * map->blockSize();
            if (off >= copy.size()) break;
            if (map->isUsed(b)) CHECK(std::equal(copy.begin() + off, copy.begin() + std::min<ByteCount>(off + map->blockSize(), copy.size()), bytes.begin() + off));
            else CHECK(copy[off] == std::byte{0});
        }
    }
}

TEST_CASE("allocation maps: a dirty filesystem refuses to hand out its bitmap") {
    auto dev = loadSparseFixture("fs/ext4_dirty.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    auto map = (*probed)->allocationMap();
    REQUIRE_FALSE(map);
    CHECK(map.error().category() == ErrorCategory::Busy);
}

// ---- L3: ext reader ----------------------------------------------------------

#include "stein/core/hash.hpp"
#include "stein/fs/reader.hpp"

namespace {
struct ExtOracle {
    std::map<std::string, std::pair<char, std::uint64_t>> entries;   // path -> (type, size)
    std::map<std::string, std::string> sha;
    std::map<std::string, std::string> links;
};
ExtOracle loadExtOracle(const std::string& name, const std::string& dir = "extfs") {
    ExtOracle o;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/" + dir + "/" + name + ".oracle.txt");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("sha256 ", 0) == 0) {
            const auto sp = line.find(' ', 7);
            o.sha[line.substr(sp + 1)] = line.substr(7, sp - 7);
        } else if (line.rfind("link ", 0) == 0) {
            const auto arrow = line.find(" -> ");
            o.links[line.substr(5, arrow - 5)] = line.substr(arrow + 4);
        } else if (line.size() > 4 && (line[0] == 'f' || line[0] == 'd' || line[0] == 'l')) {
            const auto sp1 = line.find(' ', 2);
            o.entries[line.substr(sp1 + 1)] = {line[0], std::stoull(line.substr(2, sp1 - 2))};
        }
    }
    return o;
}
void walk(fs::Reader& r, const fs::Inode& dir, const std::string& prefix, std::map<std::string, std::pair<char, std::uint64_t>>& seen, std::map<std::string, std::string>& sha,
          std::map<std::string, std::string>& links) {
    auto entries = r.readdir(dir);
    REQUIRE(entries);
    for (const auto& e : *entries) {
        const std::string path = prefix.empty() ? e.name : prefix + "/" + e.name;
        auto st = r.stat(e.inode);
        REQUIRE(st);
        if (e.type != fs::FileType::Unknown) CHECK(e.type == st->type);
        char t = st->type == fs::FileType::Directory ? 'd' : st->type == fs::FileType::Symlink ? 'l' : 'f';
        seen[path] = {t, st->size};
        if (t == 'd') walk(r, e.inode, path, seen, sha, links);
        else if (t == 'f') {
            auto data = fs::readAll(r, e.inode);
            REQUIRE(data);
            CHECK(data->size() == st->size);
            sha[path] = Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, *data));
        } else {
            auto target = r.readlink(e.inode);
            REQUIRE(target);
            links[path] = *target;
        }
    }
}
} // namespace

TEST_CASE("ext reader: every file, directory and symlink matches the kernel mount (ext4 extents+inline, ext2 1K indirect, ext3 2K)") {
    const char* names[] = {"ext4", "ext2", "ext3"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("extfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture);
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first != 'd') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        CHECK(seen.count("many/file_299.txt"));
        // Path resolution, symlink following, partial reads and holes.
        auto leaf = fs::resolvePath(**reader, "/dir/nested/deep/leaf.txt");
        REQUIRE(leaf);
        auto data = fs::readAll(**reader, *leaf);
        REQUIRE(data);
        CHECK(std::string(reinterpret_cast<const char*>(data->data()), data->size()) == "leaf\n");
        auto viaLink = fs::resolvePath(**reader, "link_short");
        REQUIRE(viaLink);
        CHECK(*viaLink == *fs::resolvePath(**reader, "hello.txt"));
        CHECK(*fs::resolvePath(**reader, "hardlink.txt") == *fs::resolvePath(**reader, "hello.txt"));
        CHECK((*reader)->stat(*viaLink)->nlink == 2);
        auto sparse = fs::resolvePath(**reader, "sparse.bin");
        REQUIRE(sparse);
        std::vector<std::byte> buf(13);
        auto n = (*reader)->read(*sparse, 1024 * 1024, buf);
        REQUIRE(n);
        CHECK(std::string(reinterpret_cast<const char*>(buf.data()), *n) == "after a hole\n");
        std::vector<std::byte> hole(4096);
        REQUIRE((*reader)->read(*sparse, 4096, hole));
        CHECK(std::all_of(hole.begin(), hole.end(), [](std::byte b) { return b == std::byte{0}; }));
        CHECK(fs::resolvePath(**reader, "no/such/file").error().category() == ErrorCategory::NotFound);
        CHECK(*fs::resolvePath(**reader, "dir/nested/../nested/deep/../deep/leaf.txt") == *leaf);
    }
}

TEST_CASE("ntfs reader: every file, directory and link matches the ntfs-3g mount") {
    auto dev = loadSparseFixture("ntfsfs/ntfs.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    CHECK((*probed)->type() == fs::FsType::Ntfs);
    REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
    auto reader = (*probed)->openReader();
    REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
    CHECK_FALSE((*reader)->caseSensitive());
    auto root = (*reader)->root();
    REQUIRE(root);
    std::map<std::string, std::pair<char, std::uint64_t>> seen;
    std::map<std::string, std::string> sha, links;
    walk(**reader, *root, "", seen, sha, links);
    const auto o = loadExtOracle("ntfs", "ntfsfs");
    for (const auto& [path, ts] : o.entries) {
        CAPTURE(path);
        REQUIRE(seen.count(path));
        CHECK(seen[path].first == ts.first);
        if (ts.first == 'f') CHECK(seen[path].second == ts.second);
    }
    // Everything we list must be in the oracle too, except NTFS metafiles the mount hides.
    for (const auto& [path, ts] : seen) {
        CAPTURE(path);
        if (path.rfind("System Volume Information", 0) == 0 || path.rfind("$", 0) == 0) continue;
        CHECK(o.entries.count(path));
    }
    for (const auto& [path, h] : o.sha) {
        CAPTURE(path);
        CHECK(sha[path] == h);
    }
    for (const auto& [path, t] : o.links) {
        CAPTURE(path);
        CHECK(links[path] == t);
    }
    // Case-insensitive lookup, hard link count, holes.
    auto upper = fs::resolvePath(**reader, "dir/upper.txt");
    REQUIRE(upper);
    CHECK(*upper == *fs::resolvePath(**reader, "dir/UPPER.TXT"));
    CHECK((*reader)->stat(*fs::resolvePath(**reader, "hello.txt"))->nlink == 2);
    auto sparse = fs::resolvePath(**reader, "sparse.bin");
    REQUIRE(sparse);
    std::vector<std::byte> buf(13);
    auto n = (*reader)->read(*sparse, 1024 * 1024, buf);
    REQUIRE(n);
    CHECK(std::string(reinterpret_cast<const char*>(buf.data()), *n) == "after a hole\n");
    CHECK(seen.count("many/file_299.txt"));
}

TEST_CASE("fat reader: FAT12/16/32 fixtures written by pyfatfs read back exactly (LFN, Unicode, fragmentation, big directories)") {
    const char* names[] = {"fat12", "fat16", "fat32"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("fatfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "fatfs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        CHECK(*fs::resolvePath(**reader, "dir/upper.txt") == *fs::resolvePath(**reader, "dir/UPPER.TXT"));
        CHECK(*fs::resolvePath(**reader, "dir/nested/deep/../deep/leaf.txt") == *fs::resolvePath(**reader, "dir/nested/deep/leaf.txt"));
        CHECK(*fs::resolvePath(**reader, "dir/..") == *root);
        CHECK((*reader)->readlink(*root).error().category() == ErrorCategory::InvalidArgument);
        auto big = fs::resolvePath(**reader, "big.bin");
        REQUIRE(big);
        CHECK((*reader)->stat(*big)->allocatedBytes >= 150 * 1024);
    }
}

TEST_CASE("exfat reader: exfat-fuse fixtures read back exactly (NoFatChain and fragmented files, Unicode and 255-char names, up-case lookup, timestamps)") {
    const char* names[] = {"exfat", "exfat_32k"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("exfatfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::ExFat);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "exfatfs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        CHECK(*fs::resolvePath(**reader, "dir/upper.txt") == *fs::resolvePath(**reader, "DIR/UPPER.TXT"));
        CHECK(*fs::resolvePath(**reader, "dir/\u00fcn\u00efc\u00f6d\u00e9 \u65e5\u672c\u8a9e.txt") ==
              *fs::resolvePath(**reader, "dir/\u00dcN\u00cfC\u00d6D\u00c9 \u65e5\u672c\u8a9e.txt"));   // up-case table beyond ASCII
        CHECK(*fs::resolvePath(**reader, "dir/nested/deep/../deep/leaf.txt") == *fs::resolvePath(**reader, "dir/nested/deep/leaf.txt"));
        CHECK_FALSE(fs::resolvePath(**reader, "dir/missing.txt"));
        CHECK((*reader)->readlink(*root).error().category() == ErrorCategory::InvalidArgument);
        auto frag = fs::resolvePath(**reader, "frag.bin");
        REQUIRE(frag);
        CHECK((*reader)->stat(*frag)->allocatedBytes >= 200 * 1024);
        auto hello = fs::resolvePath(**reader, "hello.txt");
        REQUIRE(hello);
        CHECK((*reader)->stat(*hello)->mtime == 1704164645);   // 2024-01-02 03:04:05 UTC, stored with the UTC-offset byte
        // A stat without a prior listing of the parent exercises the in-place entry-set read.
        auto fresh = (*probed)->openReader();
        REQUIRE(fresh);
        auto st = (*fresh)->stat(*hello);
        REQUIRE(st);
        CHECK(st->size == 20);
    }
}

TEST_CASE("hfsplus reader: hdiutil fixtures (HFS+, HFSX, journaled) read back exactly (hard links, symlinks, overflow extents, case rules)") {
    struct Case { const char* name; bool caseSensitive; };
    const Case cases[] = {{"hfsplus", false}, {"hfsx", true}, {"hfsplus_j", false}};
    for (const auto& c : cases) {
        const std::string fixture = c.name;
        CAPTURE(fixture);
        if (!std::filesystem::exists(std::string(STEIN_FIXTURE_DIR) + "/hfsfs/" + fixture + ".sparse")) {
            MESSAGE("fixture hfsfs/", fixture, " missing (built by the macOS fixture workflow); skipping");
            continue;
        }
        auto dev = loadSparseFixture("hfsfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == (c.caseSensitive ? fs::FsType::HfsX : fs::FsType::HfsPlus));
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        CHECK((*reader)->caseSensitive() == c.caseSensitive);
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "hfsfs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first != 'd') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        // Hard links: separate names, the same bytes, a link count of three.
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK((*reader)->stat(*hl)->nlink == 3);
        CHECK((*reader)->stat(*hl)->size == 20);
        auto hello = fs::resolvePath(**reader, "hello.txt");
        REQUIRE(hello);
        CHECK((*reader)->stat(*hello)->mtime == 1704164645);
        CHECK(*fs::resolvePath(**reader, "link_short") == *hello);
        CHECK(*fs::resolvePath(**reader, "dir/nested/deep/../deep/leaf.txt") == *fs::resolvePath(**reader, "dir/nested/deep/leaf.txt"));
        if (c.caseSensitive) {
            CHECK_FALSE(fs::resolvePath(**reader, "DIR/UPPER.TXT"));
            CHECK(*fs::resolvePath(**reader, "Case.txt") != *fs::resolvePath(**reader, "case.txt"));
        } else {
            CHECK(*fs::resolvePath(**reader, "dir/upper.txt") == *fs::resolvePath(**reader, "DIR/UPPER.TXT"));
        }
        // A stat without a prior listing goes through the thread record.
        auto fresh = (*probed)->openReader();
        REQUIRE(fresh);
        auto leaf = fs::resolvePath(**reader, "dir/nested/deep/leaf.txt");
        REQUIRE(leaf);
        auto st = (*fresh)->stat(*leaf);
        REQUIRE(st);
        CHECK(st->size == 5);
    }
}

TEST_CASE("iso9660 reader: genisoimage fixtures read back exactly (Rock Ridge names/links/relocation, Joliet, plain 8.3)") {
    const char* names[] = {"iso_rr", "iso_joliet", "iso_plain"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("isofs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Iso9660);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        const bool rr = fixture == "iso_rr";
        CHECK((*reader)->caseSensitive() == rr);
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "isofs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        if (rr) {
            auto hl = fs::resolvePath(**reader, "hardlink.txt");
            REQUIRE(hl);
            CHECK((*reader)->stat(*hl)->nlink == 2);
            CHECK((*reader)->stat(*hl)->mtime == 1704164645);   // Rock Ridge TF
            CHECK(*fs::resolvePath(**reader, "link_short") == *fs::resolvePath(**reader, "hello.txt"));
            CHECK_FALSE(fs::resolvePath(**reader, "DIR/UPPER.TXT"));
            auto deep = fs::resolvePath(**reader, "a/b/c/d/e/f/g/h/i/deep.txt");   // through the CL relocation
            REQUIRE(deep);
            CHECK((*reader)->stat(*deep)->size == 24);
        } else {
            const char* upper = fixture == "iso_plain" ? "dir/upper.txt" : "DIR/UPPER.TXT";
            const char* stored = fixture == "iso_plain" ? "DIR/UPPER.TXT" : "dir/upper.txt";
            CHECK(*fs::resolvePath(**reader, upper) == *fs::resolvePath(**reader, stored));
        }
        CHECK(*fs::resolvePath(**reader, "dir/nested/deep/../deep") == *fs::resolvePath(**reader, "dir/nested/deep"));
        // A stat without a prior listing re-parses the record in place.
        auto fresh = (*probed)->openReader();
        REQUIRE(fresh);
        auto hello = fs::resolvePath(**reader, rr ? "hello.txt" : "HELLO.TXT");
        REQUIRE(hello);
        CHECK((*fresh)->stat(*hello)->size == 20);
    }
}

TEST_CASE("xfs reader: protofile-built v5 fixtures read back exactly (shortform/block/leaf/node directories, inline symlinks, 1 KiB blocks)") {
    const char* names[] = {"xfs", "xfs_1k"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("xfsfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Xfs);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        CHECK((*reader)->caseSensitive());
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "xfsfs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto huge = fs::resolvePath(**reader, "huge");
        REQUIRE(huge);
        CHECK((*reader)->readdir(*huge)->size() == 700);
        CHECK_FALSE(fs::resolvePath(**reader, "HELLO.TXT"));
        auto hello = fs::resolvePath(**reader, "hello.txt");
        REQUIRE(hello);
        auto st = (*reader)->stat(*hello);
        REQUIRE(st);
        CHECK(st->mode == 0644);
        CHECK(st->nlink == 1);
        CHECK(st->mtime > 1700000000);   // bigtime decoded to a sane epoch value
        auto dir = (*reader)->stat(*fs::resolvePath(**reader, "dir"));
        REQUIRE(dir);
        CHECK(dir->type == fs::FileType::Directory);
        CHECK(dir->mode == 0755);
        CHECK(*fs::resolvePath(**reader, "link_short") == *hello);
    }
}

TEST_CASE("btrfs reader: mkfs.btrfs --rootdir fixtures read back exactly (inline and regular extents, holes, hard links, symlinks, mixed block groups, zlib/lzo/zstd compression)") {
    const char* names[] = {"btrfs", "btrfs_mixed", "btrfs_zlib", "btrfs_lzo", "btrfs_zstd"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("btrfsfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Btrfs);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "btrfsfs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK(*hl == *fs::resolvePath(**reader, "hello.txt"));   // same inode
        CHECK((*reader)->stat(*hl)->nlink == 2);
        CHECK((*reader)->stat(*hl)->mtime == 1704164645);
        CHECK((*reader)->stat(*hl)->mode == 0644);
        CHECK_FALSE(fs::resolvePath(**reader, "HELLO.TXT"));
        CHECK((*reader)->readdir(*fs::resolvePath(**reader, "many"))->size() == 400);
        CHECK(*fs::resolvePath(**reader, "link_short") == *hl);
        // Partial reads inside a compressed extent and across extent boundaries.
        auto big = fs::resolvePath(**reader, "compressible.txt");
        REQUIRE(big);
        auto whole = fs::readAll(**reader, *big, 1 << 20);
        REQUIRE(whole);
        std::vector<std::byte> part(5000);
        auto n = (*reader)->read(*big, 131072 - 2500, part);
        REQUIRE(n);
        CHECK(*n == 5000);
        CHECK(std::equal(part.begin(), part.end(), whole->begin() + 131072 - 2500));
    }
}

TEST_CASE("squashfs reader: mksquashfs fixtures with every compressor, uncompressed tables, forced fragments and sparse files read back exactly") {
    // squashfs_bcj was made with -Xbcj x86: mksquashfs keeps the filter only for blocks it shrinks,
    // which never happens for this tree, so it reads like plain xz (a filtered block would be refused).
    const char* names[] = {"squashfs_gzip", "squashfs_lzo", "squashfs_xz", "squashfs_lz4", "squashfs_zstd", "squashfs_lzma", "squashfs_plain", "squashfs_frags", "squashfs_bcj"};
    const auto o = loadExtOracle("squashfs", "squashfs");
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("squashfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::SquashFs);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK((*reader)->stat(*hl)->nlink == 2);
        CHECK((*reader)->stat(*hl)->mtime == 1704164645);
        CHECK((*reader)->stat(*hl)->mode == 0644);
        CHECK((*reader)->stat(*hl)->uid == 0);
        CHECK_FALSE(fs::resolvePath(**reader, "HELLO.TXT"));
        CHECK((*reader)->readdir(*fs::resolvePath(**reader, "many"))->size() == 400);
        CHECK(*fs::resolvePath(**reader, "link_short") == *hl);
        // Partial reads across a block boundary and into the fragment tail.
        auto big = fs::resolvePath(**reader, "big.bin");
        REQUIRE(big);
        auto whole = fs::readAll(**reader, *big, 1 << 20);
        REQUIRE(whole);
        std::vector<std::byte> part(5000);
        auto n = (*reader)->read(*big, 131072 - 2500, part);
        REQUIRE(n);
        CHECK(*n == 5000);
        CHECK(std::equal(part.begin(), part.end(), whole->begin() + 131072 - 2500));
        n = (*reader)->read(*big, 2 * 131072 - 10, part);
        REQUIRE(n);
        CHECK(*n == 133);
        CHECK(std::equal(part.begin(), part.begin() + 133, whole->begin() + 2 * 131072 - 10));
    }
}

TEST_CASE("apfs reader: hdiutil fixtures (case-insensitive and case-sensitive) read back exactly (hard links, symlinks, sparse files, case rules)") {
    struct Case { const char* name; bool caseSensitive; };
    const Case cases[] = {{"apfs", false}, {"apfsx", true}};
    for (const auto& c : cases) {
        const std::string fixture = c.name;
        CAPTURE(fixture);
        if (!std::filesystem::exists(std::string(STEIN_FIXTURE_DIR) + "/apfs/" + fixture + ".sparse")) {
            MESSAGE("fixture apfs/", fixture, " missing (built by the macOS fixture workflow); skipping");
            continue;
        }
        auto dev = loadSparseFixture("apfs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Apfs);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        CHECK((*reader)->caseSensitive() == c.caseSensitive);
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "apfs");
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK(*hl == *fs::resolvePath(**reader, "hello.txt"));
        CHECK((*reader)->stat(*hl)->nlink == 3);
        CHECK((*reader)->stat(*hl)->mtime == 1704164645);
        CHECK(static_cast<bool>(fs::resolvePath(**reader, "HELLO.TXT")) == !c.caseSensitive);
        CHECK((*reader)->readdir(*fs::resolvePath(**reader, "many"))->size() == 300);
        CHECK(*fs::resolvePath(**reader, "link_short") == *hl);
        if (c.caseSensitive) CHECK(seen.count("case.txt") + seen.count("Case.txt") == 2);
    }
}

TEST_CASE("f2fs reader: mkfs.f2fs + sload.f2fs fixtures (default features; extra_attr with inode checksums, crtime and the casefold feature; lz4 and lzo compressed clusters) read back exactly") {
    struct Case { const char* name; bool casefold; };
    const Case cases[] = {{"f2fs_plain", false}, {"f2fs_extra", false}, {"f2fs_lz4", false}, {"f2fs_lzo", false}};   // casefolding is per directory (chattr +F); sload sets it on none
    for (const auto& c : cases) {
        const std::string fixture = c.name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("f2fs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::F2fs);
        CHECK((*probed)->info().label == fixture);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        CHECK((*reader)->caseSensitive() == !c.casefold);
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle("f2fs", "f2fs");
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK(*hl == *fs::resolvePath(**reader, "hello.txt"));
        CHECK((*reader)->stat(*hl)->nlink == 2);
        CHECK((*reader)->stat(*hl)->mtime == 1704164645);
        CHECK((*reader)->readdir(*fs::resolvePath(**reader, "many"))->size() == 400);   // several dentry blocks
        CHECK((*reader)->readdir(*fs::resolvePath(**reader, "few"))->size() == 3);      // inline dentries
        auto tiny = fs::resolvePath(**reader, "tiny.txt");                               // inline data
        REQUIRE(tiny);
        CHECK((*reader)->stat(*tiny)->size == 1);
        // Reads that straddle the inode slots, the direct nodes and the indirect node of the 13 MiB file.
        auto big = fs::resolvePath(**reader, "indirect.bin");
        REQUIRE(big);
        std::vector<std::byte> window(8192);
        for (std::uint64_t off : {873ull * 4096 - 100, 2909ull * 4096 - 100, 3000ull * 4096 + 1})
            CHECK(*(*reader)->read(*big, off, window) == window.size());
        CHECK(static_cast<bool>(fs::resolvePath(**reader, "HELLO.TXT")) == c.casefold);
    }
}

TEST_CASE("apfs reader: a container with two volumes, a snapshot and decmpfs files (volume by name/slot, snapshot by name, zlib/lzvn/lzfse in xattr and resource fork)") {
    const std::string base = std::string(STEIN_FIXTURE_DIR) + "/apfs/apfs_snap";
    if (!std::filesystem::exists(base + ".sparse")) {
        MESSAGE("fixture apfs/apfs_snap missing (built by the macOS fixture workflow); skipping");
        return;
    }
    auto dev = loadSparseFixture("apfs/apfs_snap.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    const auto subs = (*probed)->subvolumes();
    std::size_t volumes = 0, snapshots = 0;
    for (const auto& v : subs) (v.kind == "volume" ? volumes : snapshots)++;
    CHECK(volumes == 2);
    CHECK((*probed)->info().extra.find("rd_snap") != std::string::npos);
    CHECK((*probed)->info().extra.find("rd_second") != std::string::npos);
    auto checkTree = [&](fs::Reader& r, const ExtOracle& o) {
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(r, *r.root(), "", seen, sha, links);
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        return seen;
    };
    // Live tree of the first volume: deletions, rewrites and the compressed files after the snapshot.
    fs::ReaderOptions first;
    first.volume = "rd_snap";
    auto live = (*probed)->openReader(first);
    REQUIRE_MESSAGE(live, (live ? std::string() : live.error().toString()));
    const auto liveSeen = checkTree(**live, loadExtOracle("apfs_snap", "apfs"));
    CHECK(liveSeen.count("after_snapshot.txt"));
    CHECK_FALSE(liveSeen.count("tiny.txt"));
    CHECK(liveSeen.count("zlib_src_large.txt"));   // decmpfs type 4 (resource fork, several 64 KiB blocks)
    CHECK(liveSeen.count("zlib_src_small.txt"));   // decmpfs type 3 (in the xattr)
    // The second volume, by name and by slot.
    fs::ReaderOptions second;
    second.volume = "rd_second";
    auto vol2 = (*probed)->openReader(second);
    REQUIRE_MESSAGE(vol2, (vol2 ? std::string() : vol2.error().toString()));
    checkTree(**vol2, loadExtOracle("apfs_snap.second", "apfs"));
    CHECK(fs::resolvePath(**vol2, "second.txt"));
    CHECK_FALSE(fs::resolvePath(**vol2, "hello.txt"));
    for (const auto& v : subs)
        if (v.kind == "volume" && v.name == "rd_second") {
            fs::ReaderOptions bySlot;
            bySlot.volume = std::to_string(v.id);
            auto r = (*probed)->openReader(bySlot);
            REQUIRE(r);
            CHECK(fs::resolvePath(**r, "second.txt"));
        }
    fs::ReaderOptions bad;
    bad.volume = "no_such_volume";
    CHECK_FALSE((*probed)->openReader(bad));
    // The snapshot, when the machine that built the fixture could create one.
    if (std::filesystem::exists(base + ".snapshot.oracle.txt")) {
        REQUIRE(snapshots >= 1);
        std::string snapName;
        for (const auto& v : subs)
            if (v.kind == "snapshot" && v.parent == "rd_snap") snapName = v.name;
        REQUIRE_FALSE(snapName.empty());
        fs::ReaderOptions snap;
        snap.volume = "rd_snap";
        snap.snapshot = snapName;
        auto old = (*probed)->openReader(snap);
        REQUIRE_MESSAGE(old, (old ? std::string() : old.error().toString()));
        const auto oldSeen = checkTree(**old, loadExtOracle("apfs_snap.snapshot", "apfs"));
        CHECK(oldSeen.count("tiny.txt"));                  // deleted after the snapshot
        CHECK_FALSE(oldSeen.count("after_snapshot.txt"));  // created after the snapshot
        snap.snapshot = "no_such_snapshot";
        CHECK_FALSE((*probed)->openReader(snap));
    } else {
        MESSAGE("apfs_snap has no snapshot oracle (the fixture was built on a machine that cannot create snapshots); snapshot checks skipped");
    }
}

TEST_CASE("erofs reader: mkfs.erofs fixtures (plain, chunk-based, lz4 compact/legacy/big pcluster/ztailpacking/fragments+dedupe, lzma, deflate) read back exactly") {
    const char* names[] = {"erofs_plain", "erofs_chunked", "erofs_lz4", "erofs_lz4_legacy", "erofs_lz4hc_bigpcl", "erofs_lz4_ztail", "erofs_lz4_frag", "erofs_lzma", "erofs_deflate"};
    for (const char* name : names) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("erofs/" + fixture + ".sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Erofs);
        REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
        auto reader = (*probed)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto root = (*reader)->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(**reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture == "erofs_chunked" ? "erofs_chunked" : "erofs", "erofs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hl = fs::resolvePath(**reader, "hardlink.txt");
        REQUIRE(hl);
        CHECK(*hl == *fs::resolvePath(**reader, "hello.txt"));
        CHECK((*reader)->stat(*hl)->nlink == 2);
        CHECK((*reader)->stat(*hl)->mtime == 1704164645);
        CHECK((*reader)->stat(*hl)->mode == 0644);
        CHECK_FALSE(fs::resolvePath(**reader, "HELLO.TXT"));
        CHECK(*fs::resolvePath(**reader, "link_short") == *hl);
        // Partial reads inside and across compressed clusters.
        auto big = fs::resolvePath(**reader, "compressible.txt");
        REQUIRE(big);
        auto whole = fs::readAll(**reader, *big, 1 << 20);
        REQUIRE(whole);
        std::vector<std::byte> part(5000);
        auto n = (*reader)->read(*big, 65536 - 2500, part);
        REQUIRE(n);
        CHECK(*n == 5000);
        CHECK(std::equal(part.begin(), part.end(), whole->begin() + 65536 - 2500));
    }
}

TEST_CASE("copyTree: the ext4 fixture copied out to the host matches the oracle (files, directories, symlinks)") {
    auto dev = loadSparseFixture("extfs/ext4.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    std::filesystem::path dir = std::filesystem::temp_directory_path() / ("stein_copytree_" + std::to_string(std::random_device{}()));
#if defined(_WIN32)
    // 255-character names overflow MAX_PATH; read back through the same extended-length form copyTree writes.
    dir = std::filesystem::path(L"\\\\?\\" + std::filesystem::absolute(dir).lexically_normal().make_preferred().native());
#endif
    auto hostPath = [&](const std::string& rel) {
        std::filesystem::path p = dir / std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(rel.data()), rel.size()));
        p.make_preferred();
        return p;
    };
    auto stats = fs::copyTree(**reader, *(*reader)->root(), dir);
    REQUIRE_MESSAGE(stats, (stats ? std::string() : stats.error().toString()));
    CHECK(stats->files > 300);
    CHECK(stats->directories >= 5);
    const auto o = loadExtOracle("ext4");
    for (const auto& [path, h] : o.sha) {
        CAPTURE(path);
        std::ifstream f(hostPath(path), std::ios::binary);
        REQUIRE(f);
        std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()))) == h);
    }
#if !defined(_WIN32)
    for (const auto& [path, t] : o.links) {
        CAPTURE(path);
        std::error_code ec;
        CHECK(std::filesystem::read_symlink(hostPath(path), ec).generic_string() == t);
    }
    CHECK(stats->symlinks == o.links.size());
#endif
    // A single file to a path, and a directory subtree.
    auto one = fs::resolvePath(**reader, "hello.txt");
    REQUIRE(one);
    auto s1 = fs::copyTree(**reader, *one, dir / "copy_of_hello.txt");
    REQUIRE(s1);
    CHECK(s1->files == 1);
    CHECK(std::filesystem::file_size(dir / "copy_of_hello.txt") == (*reader)->stat(*one)->size);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("udf reader: genisoimage UDF 1.02 (bridge and UDF-only) read back exactly; mkudffs 2.50 metadata partition opens") {
    for (const char* name : {"udf_only", "udf_bridge"}) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("udffs/" + fixture + ".sparse");
        std::unique_ptr<fs::Reader> reader;
        if (fixture == "udf_only") {
            auto probed = fs::probe(dev);
            REQUIRE(probed);
            REQUIRE(*probed);
            CHECK((*probed)->info().type == fs::FsType::Udf);
            REQUIRE(fs::has((*probed)->capabilities(), fs::Capability::Read));
            auto r = (*probed)->openReader();
            REQUIRE_MESSAGE(r, (r ? std::string() : r.error().toString()));
            reader = std::move(*r);
        } else {
            // The bridge disc probes as ISO 9660; open its UDF side explicitly.
            auto r = fs::detail::UdfReader::open(dev);
            REQUIRE_MESSAGE(r, (r ? std::string() : r.error().toString()));
            reader = std::move(*r);
        }
        auto root = reader->root();
        REQUIRE(root);
        std::map<std::string, std::pair<char, std::uint64_t>> seen;
        std::map<std::string, std::string> sha, links;
        walk(*reader, *root, "", seen, sha, links);
        const auto o = loadExtOracle(fixture, "udffs");
        CHECK(seen.size() == o.entries.size());
        for (const auto& [path, ts] : o.entries) {
            CAPTURE(path);
            REQUIRE(seen.count(path));
            CHECK(seen[path].first == ts.first);
            if (ts.first == 'f') CHECK(seen[path].second == ts.second);
        }
        for (const auto& [path, h] : o.sha) {
            CAPTURE(path);
            CHECK(sha[path] == h);
        }
        for (const auto& [path, t] : o.links) {
            CAPTURE(path);
            CHECK(links[path] == t);
        }
        auto hello = fs::resolvePath(*reader, "hello.txt");
        REQUIRE(hello);
        CHECK(reader->stat(*hello)->mtime == 1704164645);
        CHECK_FALSE(fs::resolvePath(*reader, "HELLO.TXT"));
        CHECK(reader->readdir(*fs::resolvePath(*reader, "many"))->size() == 120);
        // genisoimage has no UDF symlink support: the links come out as empty files, so readlink refuses.
        auto link = fs::resolvePath(*reader, "link_short");
        REQUIRE(link);
        CHECK_FALSE(reader->readlink(*link));
    }
    if (std::filesystem::exists(std::string(STEIN_FIXTURE_DIR) + "/udffs/udf_250_empty.sparse")) {
        auto dev = loadSparseFixture("udffs/udf_250_empty.sparse");
        auto probed = fs::probe(dev);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->info().type == fs::FsType::Udf);
        auto r = (*probed)->openReader();
        REQUIRE_MESSAGE(r, (r ? std::string() : r.error().toString()));
        auto entries = (*r)->readdir(*(*r)->root());
        REQUIRE(entries);
        CHECK(entries->empty());
        CHECK((*r)->stat(*(*r)->root())->type == fs::FileType::Directory);
    }
}

namespace {
const stein::layout::Node* descendant(const stein::layout::Node& n, std::initializer_list<const char*> path) {
    const stein::layout::Node* cur = &n;
    for (const char* name : path) {
        cur = cur->child(name);
        if (!cur) return nullptr;
    }
    return cur;
}
std::uint32_t computedFrom(const std::string& message) {
    const auto at = message.find("computed 0x");
    REQUIRE(at != std::string::npos);
    return static_cast<std::uint32_t>(std::stoul(message.substr(at + 11), nullptr, 16));
}
} // namespace

TEST_CASE("exfat: both boot regions are described, their checksums verified, the backup compared") {
    for (const char* fixture : {"fs/exfat.sparse", "exfatfs/exfat.sparse", "exfatfs/exfat_32k.sparse"}) {
        CAPTURE(fixture);
        auto dev = loadSparseFixture(fixture);
        REQUIRE(dev);
        auto fs = probe(dev);
        REQUIRE(fs);
        REQUIRE(*fs);
        auto tree = (*fs)->describe();
        const auto* main = descendant(tree, {"main boot region", "boot checksum", "checksum"});
        const auto* backup = descendant(tree, {"backup boot region", "boot checksum", "checksum"});
        REQUIRE(main);
        REQUIRE(backup);
        CHECK(main->validity == stein::layout::Validity::Ok);
        CHECK(backup->validity == stein::layout::Validity::Ok);
        CHECK(main->type == stein::layout::FieldType::Crc32);
        const auto boot = dev->read(0, 512);
        REQUIRE(boot);
        const std::size_t sectorBytes = std::size_t{1} << stein::layout::gen::ExfatBootSector(*boot).bytesPerSectorShift();
        CHECK(main->size == sectorBytes);
        const auto* sig = descendant(tree, {"main boot region", "boot sector", "boot_signature"});
        REQUIRE(sig);
        CHECK(sig->value == "43605");
        for (const auto& d : (*fs)->diagnostics()) CHECK(d.code.find("exfat.b") == std::string::npos);
        const auto* ext = descendant(tree, {"main boot region", "extended boot sectors"});
        REQUIRE(ext);
        REQUIRE(ext->children.size() == 8);
        for (const auto& sec : ext->children) CHECK(sec.child("extended_boot_signature")->validity == stein::layout::Validity::Ok);
        CHECK(descendant(tree, {"main boot region", "OEM parameters"}) != nullptr);
        CHECK(descendant(tree, {"backup boot region", "extended boot sectors"}) != nullptr);
        // The root directory's own entries: bitmap sized for the heap, up-case table with its checksum.
        const auto* bitmap = descendant(tree, {"root directory", "allocation bitmap entry"});
        const auto* upcase = descendant(tree, {"root directory", "up-case table entry", "table_checksum"});
        REQUIRE(bitmap);
        REQUIRE(upcase);
        CHECK(bitmap->child("data_length")->validity == stein::layout::Validity::Ok);
        // fs/exfat.sparse is trimmed, but its runs keep the root directory, the bitmap and the
        // up-case table (the checksum verifies), so every fixture asserts the same things.
        {
            CHECK(upcase->validity == stein::layout::Validity::Ok);
            const auto* label = descendant(tree, {"root directory", "volume label entry"});
            REQUIRE(label);
            CHECK(label->child("volume_label")->value == (*fs)->info().label);
            CHECK_FALSE((*fs)->info().label.empty());
            // Damage the stored table: the checksum field says what it should be.
            const ByteCount heap = ByteCount{stein::layout::gen::ExfatBootSector(*boot).clusterHeapOffset()} * sectorBytes;
            const ByteCount clusterBytes = *(*fs)->info().blockSize;
            const auto* first = descendant(tree, {"root directory", "up-case table entry", "first_cluster"});
            REQUIRE(first);
            const ByteCount tableAt = heap + (std::stoull(first->value) - 2) * clusterBytes;
            auto orig = dev->read(tableAt, 1);
            REQUIRE(orig);
            std::byte flipped = (*orig)[0] ^ std::byte{0xFF};
            REQUIRE(dev->writeAt(tableAt, std::span<const std::byte>(&flipped, 1)));
            auto damaged = probe(dev);
            REQUIRE(damaged);
            const auto td = (*damaged)->describe();
            const auto* u2 = descendant(td, {"root directory", "up-case table entry", "table_checksum"});
            REQUIRE(u2);
            CHECK(u2->validity == stein::layout::Validity::Error);
            CHECK(u2->message.find("computed 0x") != std::string::npos);
            REQUIRE(dev->writeAt(tableAt, std::span<const std::byte>(&(*orig)[0], 1)));
        }

        // Change one boot-sector byte: the main checksum fails with the right value in its
        // message, the backup copy is reported as drifted.
        const ByteCount bps = main->size;
        const std::uint32_t good = static_cast<std::uint32_t>(std::stoul(main->value, nullptr, 16));
        std::byte one{0x81};
        REQUIRE(dev->writeAt(0x6F, std::span<const std::byte>(&one, 1)));   // drive_select
        auto broken = probe(dev);
        REQUIRE(broken);
        auto t2 = (*broken)->describe();
        const auto* m2 = descendant(t2, {"main boot region", "boot checksum", "checksum"});
        REQUIRE(m2);
        CHECK(m2->validity == stein::layout::Validity::Error);
        const std::uint32_t computed = computedFrom(m2->message);
        CHECK(computed != good);
        bool checksumDiag = false, mismatchDiag = false;
        for (const auto& d : (*broken)->diagnostics()) {
            checksumDiag = checksumDiag || d.code == "exfat.boot_checksum";
            mismatchDiag = mismatchDiag || d.code == "exfat.backup_boot_mismatch";
        }
        CHECK(checksumDiag);
        CHECK(mismatchDiag);

        // Writing the computed value through the sector (what a hex editor's "fix" does) heals it.
        std::vector<std::byte> sector(static_cast<std::size_t>(bps));
        for (std::size_t i = 0; i < sector.size(); i += 4) stein::storeLe32(sector.data() + i, computed);
        REQUIRE(dev->writeAt(11 * bps, sector));
        auto healed = probe(dev);
        REQUIRE(healed);
        const auto t3 = (*healed)->describe();
        const auto* m3 = descendant(t3, {"main boot region", "boot checksum", "checksum"});
        REQUIRE(m3);
        CHECK(m3->validity == stein::layout::Validity::Ok);

        // A checksum sector only partly filled is flagged, with the value to refill it.
        stein::storeLe32(sector.data() + 4, computed ^ 1);
        REQUIRE(dev->writeAt(11 * bps, sector));
        auto partial = probe(dev);
        REQUIRE(partial);
        const auto t4 = (*partial)->describe();
        const auto* m4 = descendant(t4, {"main boot region", "boot checksum", "checksum"});
        REQUIRE(m4);
        CHECK(m4->validity == stein::layout::Validity::Warning);
        CHECK(computedFrom(m4->message) == computed);
    }
}

TEST_CASE("exfat: repair restores the damaged boot region from the sound one") {
    auto dev = loadSparseFixture("exfatfs/exfat.sparse");
    REQUIRE(dev);
    auto pristine = loadSparseFixture("exfatfs/exfat.sparse");
    const ByteCount bps = 512;
    auto sameAsPristine = [&](const char* when) {
        auto a = dev->read(0, 24 * bps), b = pristine->read(0, 24 * bps);
        REQUIRE((a && b));
        for (std::size_t i = 0; i < a->size(); ++i)
            if ((*a)[i] != (*b)[i]) {
                MESSAGE(when << ": first difference at byte " << i);
                return false;
            }
        return true;
    };
    auto repairableCodes = [](const FileSystem& fs) {
        std::vector<std::string> out;
        for (const auto& d : fs.diagnostics())
            if (d.repairable) out.push_back(d.code);
        return out;
    };
    // Main boot sector damaged (checksum fails), backup sound: the main region comes back from the backup.
    std::byte one{0x81};
    REQUIRE(dev->writeAt(0x6F, std::span<const std::byte>(&one, 1)));
    auto broken = probe(dev);
    REQUIRE((broken && *broken));
    CHECK(repairableCodes(**broken).size() >= 2);
    REQUIRE((*broken)->repair(*dev));
    CHECK(sameAsPristine("main restored from backup"));
    auto healed = probe(dev);
    REQUIRE((healed && *healed));
    CHECK(repairableCodes(**healed).empty());
    CHECK((*healed)->health() == layout::Validity::Ok);

    // Backup drifted (checksum still sealed by us): it is overwritten from the main region.
    auto backupSector = dev->read(12 * bps, bps);
    REQUIRE(backupSector);
    (*backupSector)[0x6F] = one;
    REQUIRE(dev->writeAt(12 * bps, *backupSector));
    auto drifted = probe(dev);
    REQUIRE((drifted && *drifted));
    bool mismatch = false;
    for (const auto& d : (*drifted)->diagnostics()) mismatch = mismatch || d.code == "exfat.backup_boot_mismatch";
    CHECK(mismatch);
    REQUIRE((*drifted)->repair(*dev));
    CHECK(sameAsPristine("backup rewritten from main"));

    // Nothing to repair: repair() is a no-op that succeeds.
    auto clean = probe(dev);
    REQUIRE((clean && *clean));
    REQUIRE((*clean)->repair(*dev));
    CHECK(sameAsPristine("no-op repair"));
}


// ---- FAT and exFAT: diagnostics, repair, geometry ------------------------------------------

namespace {
const FsDiagnostic* diagOf(const FileSystem& fs, std::string_view code) {
    for (const auto& d : fs.diagnostics())
        if (d.code == code) return &d;
    return nullptr;
}
std::size_t diagCount(const FileSystem& fs, std::string_view code) {
    std::size_t n = 0;
    for (const auto& d : fs.diagnostics()) n += d.code == code;
    return n;
}
std::string diagCodes(const FileSystem& fs) {
    std::string out;
    for (const auto& d : fs.diagnostics()) out += d.code + " ";
    return out;
}
void patchBytes(BlockDevice& dev, ByteCount off, std::initializer_list<std::uint8_t> bytes) {
    std::vector<std::byte> b;
    for (auto v : bytes) b.push_back(std::byte{v});
    REQUIRE(dev.writeAt(off, b));
}
void patchLe16(BlockDevice& dev, ByteCount off, std::uint16_t v) { patchBytes(dev, off, {std::uint8_t(v & 0xFF), std::uint8_t(v >> 8)}); }
void patchLe32(BlockDevice& dev, ByteCount off, std::uint32_t v) {
    patchBytes(dev, off, {std::uint8_t(v & 0xFF), std::uint8_t((v >> 8) & 0xFF), std::uint8_t((v >> 16) & 0xFF), std::uint8_t(v >> 24)});
}
std::uint32_t readLe32(BlockDevice& dev, ByteCount off) {
    auto b = dev.read(off, 4);
    REQUIRE(b);
    return loadLe32(b->data());
}
// The FAT32 fixtures keep their backup boot sector at sector 6: a BPB patch goes to both copies so
// that only the fact under test shows up, not fat.backup_boot_mismatch.
void patchFat32Boot(BlockDevice& dev, ByteCount off, std::initializer_list<std::uint8_t> bytes) {
    patchBytes(dev, off, bytes);
    patchBytes(dev, 6 * 512 + off, bytes);
}
// exFAT fixtures (512-byte sectors): patch both boot sectors and reseal both checksum sectors
// (specification §3.4, VolumeFlags and PercentInUse excluded) so only the patched fact shows.
void patchExfatBoot(BlockDevice& dev, ByteCount off, std::initializer_list<std::uint8_t> bytes) {
    for (ByteCount region : {ByteCount{0}, ByteCount{12 * 512}}) {
        patchBytes(dev, region + off, bytes);
        auto sectors = dev.read(region, 11 * 512);
        REQUIRE(sectors);
        std::uint32_t c = 0;
        for (std::size_t i = 0; i < sectors->size(); ++i) {
            if (i == 106 || i == 107 || i == 112) continue;
            c = ((c & 1u) ? 0x80000000u : 0u) + (c >> 1) + std::to_integer<std::uint32_t>((*sectors)[i]);
        }
        std::vector<std::byte> seal(512);
        for (std::size_t i = 0; i < seal.size(); i += 4) storeLe32(seal.data() + i, c);
        REQUIRE(dev.writeAt(region + 11 * 512, seal));
    }
}
bool sameBytes(const MemoryDevice& a, const MemoryDevice& b, const char* when) {
    const auto x = a.bytes(), y = b.bytes();
    REQUIRE(x.size() == y.size());
    for (std::size_t i = 0; i < x.size(); ++i)
        if (x[i] != y[i]) {
            MESSAGE(when << ": first difference at byte " << i);
            return false;
        }
    return true;
}
// An Info diagnostic is information, never a fault to fix: it must not show a Repair button or
// make `stein repair` write anything.
void checkNoRepairableInfo(const FileSystem& fs) {
    for (const auto& d : fs.diagnostics()) CHECK_MESSAGE(!(d.severity == layout::Validity::Info && d.repairable), d.code);
}
// The shape of a decrypting view (container::detail::XtsDevice): a window at an offset on its
// parent that is not a SliceDevice, with a sector size of its own. Bytes pass through so the
// volume inside is probed for real.
class PayloadView final : public BlockDevice {
public:
    PayloadView(std::shared_ptr<BlockDevice> parent, Region region, std::uint32_t sectorSize) : m_parent(std::move(parent)), m_region(region) {
        m_geometry = m_parent->geometry();
        m_geometry.sizeBytes = region.length;
        m_geometry.logicalSectorSize = sectorSize;
        if (m_geometry.physicalSectorSize < sectorSize) m_geometry.physicalSectorSize = sectorSize;
    }
    std::string name() const override { return m_parent->name() + " (payload)"; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override { return m_parent->isReadOnly(); }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        if (auto r = checkRange(offset, dst.size()); !r) return r;
        return m_parent->readAt(m_region.offset + offset, dst);
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        if (auto r = checkRange(offset, src.size()); !r) return r;
        return m_parent->writeAt(m_region.offset + offset, src);
    }
    Expected<void> flush() override { return m_parent->flush(); }
    std::shared_ptr<BlockDevice> parent() const override { return m_parent; }
    std::vector<Region> extentsOnParent() const override { return {m_region}; }

private:
    std::shared_ptr<BlockDevice> m_parent;
    Region m_region;
    Geometry m_geometry;
};
} // namespace

TEST_CASE("FAT: the boot sector is described whole on FAT12/16/32 (BPB, extended BPB, boot code, signature); pristine fixtures raise nothing") {
    struct Case {
        const char* fixture;
        const char* version;
        const char* ebpb;
        const char* label;
        std::uint64_t codeBytes;
    };
    const Case cases[] = {
        {"fs/fat12.sparse", "FAT12", "FAT12/16 extended BPB", "STEIN_FAT12", 448},
        {"fs/fat16.sparse", "FAT16", "FAT12/16 extended BPB", "STEIN_FAT16", 448},
        {"fs/fat32.sparse", "FAT32", "FAT32 extended BPB", "STEIN_FAT32", 420},
    };
    for (const auto& c : cases) {
        CAPTURE(c.fixture);
        auto fs = probe(loadSparseFixture(c.fixture));
        REQUIRE((fs && *fs));
        CHECK((*fs)->info().version == c.version);
        CHECK((*fs)->info().label == c.label);
        CHECK((*fs)->info().clean == true);
        CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
        CHECK((*fs)->health() == layout::Validity::Ok);
        const auto tree = (*fs)->describe();
        const auto* boot = tree.child("boot sector");
        REQUIRE(boot);
        CHECK(boot->isStruct);
        CHECK(boot->absOffset == 0);
        CHECK(boot->size == 512);
        const auto* bpb = boot->child("BPB");
        REQUIRE(bpb);
        CHECK(bpb->size == 36);
        CHECK(bpb->child("bytes_per_sector")->value == "512");
        CHECK(bpb->child("media")->pretty == "fixed disk");
        CHECK(bpb->child("media")->validity == layout::Validity::Ok);
        CHECK(bpb->child("num_fats")->value == "2");
        const auto* ebpb = boot->child(c.ebpb);
        REQUIRE(ebpb);
        CHECK(ebpb->absOffset == 36);
        CHECK(ebpb->child("volume_label")->value == c.label);
        CHECK(ebpb->child("fs_type")->value == c.version);
        CHECK(ebpb->child("boot_signature")->pretty == "extended fields present");
        CHECK(ebpb->child("reserved1")->pretty == "none");
        const auto* code = boot->child("boot_code");
        REQUIRE(code);
        CHECK(code->absOffset == 36 + ebpb->size);
        CHECK(code->size == c.codeBytes);
        const auto* sig = boot->child("boot_signature");
        REQUIRE(sig);
        CHECK(sig->absOffset == 510);
        CHECK(sig->size == 2);
        CHECK(sig->value == "43605");   // 0xAA55
        CHECK(sig->validity == layout::Validity::Ok);
        // The children tile the sector with no gap or overlap.
        std::uint64_t end = 0;
        for (const auto& child : boot->children) {
            CHECK(child.absOffset == end);
            end = child.endOffset();
        }
        CHECK(end == 512);
        const auto* entry = tree.child("root directory volume label entry");
        REQUIRE(entry);
        CHECK(entry->child("name")->value == c.label);
        CHECK(entry->child("attr")->pretty == "volume_id");
    }
    // FAT32 adds FSInfo and the two backup copies, all in step on a fresh volume; the free count
    // gives the used space (one cluster: the root directory).
    auto fs = probe(loadSparseFixture("fs/fat32.sparse"));
    REQUIRE((fs && *fs));
    const auto tree = (*fs)->describe();
    REQUIRE(tree.child("FSInfo sector"));
    CHECK(tree.child("FSInfo sector")->child("free_count")->value == "129021");
    CHECK(tree.child("FSInfo sector")->child("lead_signature")->validity == layout::Validity::Ok);
    REQUIRE((*fs)->info().usedBytes.has_value());
    CHECK(*(*fs)->info().usedBytes == 512);
    const auto* backup = tree.child("backup boot sector");
    REQUIRE(backup);
    CHECK(backup->absOffset == 6 * 512);
    CHECK(backup->size == 512);
    REQUIRE(backup->child("FAT32 extended BPB"));
    CHECK(backup->child("FAT32 extended BPB")->child("volume_label")->value == "STEIN_FAT32");
    CHECK(backup->child("boot_signature")->value == "43605");
    REQUIRE(tree.child("backup FSInfo sector"));
    CHECK(tree.child("backup FSInfo sector")->absOffset == 7 * 512);
    CHECK(tree.child("boot sector")->child("FAT32 extended BPB")->child("ext_flags")->pretty == "none");
}

TEST_CASE("FAT: FAT12/16/32 cluster-count thresholds (4085 / 65525) are one function shared by detector and reader") {
    using stein::fs::detail::fatActiveIndex;
    using stein::fs::detail::fatBitsFor;
    CHECK(fatBitsFor(false, 1) == 12);
    CHECK(fatBitsFor(false, 4084) == 12);
    CHECK(fatBitsFor(false, 4085) == 16);
    CHECK(fatBitsFor(false, 65524) == 16);
    CHECK(fatBitsFor(false, 65525) == 16);   // a 16-bit layout cannot turn into FAT32; detectFat reports the overflow
    CHECK(fatBitsFor(true, 100) == 32);
    CHECK(fatBitsFor(true, 65524) == 32);
    CHECK(fatBitsFor(true, 65525) == 32);
    CHECK(fatActiveIndex(0x0000, 2) == 0);
    CHECK(fatActiveIndex(0x0001, 2) == 0);   // mirroring on: the index means nothing
    CHECK(fatActiveIndex(0x0081, 2) == 1);
    CHECK(fatActiveIndex(0x0080, 2) == 0);
    CHECK(fatActiveIndex(0x0085, 2) == 0);   // out of range: FAT 0
    // The fixtures sit on each side: 2036 clusters, 16343 clusters, FAT32 layout with 129022.
    auto f12 = probe(loadSparseFixture("fs/fat12.sparse"));
    auto f16 = probe(loadSparseFixture("fs/fat16.sparse"));
    auto f32 = probe(loadSparseFixture("fs/fat32.sparse"));
    REQUIRE((f12 && *f12 && f16 && *f16 && f32 && *f32));
    CHECK((*f12)->type() == FsType::Fat12);
    CHECK((*f16)->type() == FsType::Fat16);
    CHECK((*f32)->type() == FsType::Fat32);
    CHECK(*(*f12)->info().blockSize == 2048);
    CHECK(*(*f32)->info().blockSize == 512);
    CHECK(diagOf(**f32, "fat.small_fat32") == nullptr);
    // A FAT32 layout with few clusters is still FAT32 (what mkfs.vfat -F 32 makes on small media).
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchFat32Boot(*dev, 32, {0x00, 0x40, 0x00, 0x00});   // total_sectors32 = 16384
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->type() == FsType::Fat32);
        const auto* d = diagOf(**fs, "fat.small_fat32");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Info);
    }
    // A 16-bit layout claiming 65525 or more clusters stays FAT16 and is called out as impossible.
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchLe16(*dev, 19, 0);
        patchLe32(*dev, 32, 164 + 4 * 65600);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->type() == FsType::Fat16);
        const auto* d = diagOf(**fs, "fat.bpb_geometry");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Error);
        CHECK(d->message.find("FAT16 cannot address 65600 clusters") != std::string::npos);
        CHECK(diagOf(**fs, "fat.truncated") != nullptr);
        CHECK(diagOf(**fs, "fat.fat_too_small") != nullptr);
    }
}

TEST_CASE("FAT32: backup boot sector drift and an FSInfo copy with wrong signatures are repaired from the intact copy; a backup FSInfo that merely lags is only reported") {
    auto dev = loadSparseFixture("fs/fat32.sparse");
    auto pristine = loadSparseFixture("fs/fat32.sparse");
    REQUIRE((dev && pristine));
    // A label edited in the backup copy only.
    const std::string label = "DRIFTED    ";
    REQUIRE(dev->writeAt(6 * 512 + 36 + 0x23, std::as_bytes(std::span(label.data(), 11))));
    auto drifted = probe(dev);
    REQUIRE((drifted && *drifted));
    const auto* d = diagOf(**drifted, "fat.backup_boot_mismatch");
    REQUIRE(d);
    CHECK(d->repairable);
    CHECK(d->severity == layout::Validity::Warning);
    CHECK((*drifted)->info().label == "STEIN_FAT32");
    CHECK((*drifted)->describe().child("backup boot sector")->child("FAT32 extended BPB")->child("volume_label")->value == "DRIFTED");
    REQUIRE((*drifted)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "backup boot sector rewritten"));
    auto healed = probe(dev);
    REQUIRE((healed && *healed));
    CHECK_MESSAGE((*healed)->diagnostics().empty(), diagCodes(**healed));

    // A stale free count in the backup FSInfo is how every FAT32 that has been written to looks
    // (the driver updates the live copy and lets the backup lag): information, not a fault, and
    // repair() leaves sector 7 alone.
    patchLe32(*dev, 7 * 512 + 0x1E8, 4242);
    auto stale = probe(dev);
    REQUIRE((stale && *stale));
    d = diagOf(**stale, "fat.backup_fsinfo_mismatch");
    REQUIRE(d);
    CHECK_FALSE(d->repairable);
    CHECK(d->severity == layout::Validity::Info);
    CHECK(*(*stale)->info().usedBytes == 512);
    CHECK((*stale)->describe().child("backup FSInfo sector")->child("free_count")->value == "4242");
    checkNoRepairableInfo(**stale);
    REQUIRE((*stale)->repair(*dev));
    CHECK(readLe32(*dev, 7 * 512 + 0x1E8) == 4242);
    // The same lag from the live side: 21 clusters allocated since the backup was written.
    patchLe32(*dev, 7 * 512 + 0x1E8, 129021);
    patchLe32(*dev, 512 + 0x1E8, 129000);
    auto written = probe(dev);
    REQUIRE((written && *written));
    d = diagOf(**written, "fat.backup_fsinfo_mismatch");
    REQUIRE(d);
    CHECK_FALSE(d->repairable);
    CHECK(*(*written)->info().usedBytes == 22 * 512);
    REQUIRE((*written)->repair(*dev));
    CHECK(readLe32(*dev, 7 * 512 + 0x1E8) == 129021);
    REQUIRE(dev->writeAt(0, pristine->bytes()));

    // A backup FSInfo whose signature is wrong is a broken copy; the live one restores it.
    patchLe32(*dev, 7 * 512, 0);
    auto badBackup = probe(dev);
    REQUIRE((badBackup && *badBackup));
    d = diagOf(**badBackup, "fat.backup_fsinfo_mismatch");
    REQUIRE(d);
    CHECK(d->repairable);
    CHECK(d->severity == layout::Validity::Warning);
    CHECK(d->message.find("lead signature wrong") != std::string::npos);
    CHECK(diagOf(**badBackup, "fat.fsinfo_bad") == nullptr);
    CHECK(*(*badBackup)->info().usedBytes == 512);
    REQUIRE((*badBackup)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "backup FSInfo rewritten"));

    // The other way round: the live FSInfo's signature is wrong and the backup is intact. The
    // hint is not trusted, and the repair restores the sector from its backup.
    patchLe32(*dev, 512 + 0x1E4, 0);
    auto badLive = probe(dev);
    REQUIRE((badLive && *badLive));
    d = diagOf(**badLive, "fat.fsinfo_bad");
    REQUIRE(d);
    CHECK(d->repairable);
    CHECK(d->severity == layout::Validity::Warning);
    CHECK(d->message.find("struct signature wrong") != std::string::npos);
    CHECK(d->message.find("restores it from the backup FSInfo sector (sector 7)") != std::string::npos);
    CHECK(diagOf(**badLive, "fat.backup_fsinfo_mismatch") == nullptr);
    CHECK_FALSE((*badLive)->info().usedBytes.has_value());
    REQUIRE((*badLive)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "FSInfo restored from its backup"));

    // Both copies with wrong signatures: nothing to restore from, nothing written.
    patchLe32(*dev, 512, 0);
    patchLe32(*dev, 7 * 512 + 0x1FC, 0);
    auto bothBad = probe(dev);
    REQUIRE((bothBad && *bothBad));
    d = diagOf(**bothBad, "fat.fsinfo_bad");
    REQUIRE(d);
    CHECK_FALSE(d->repairable);
    CHECK(diagOf(**bothBad, "fat.backup_fsinfo_mismatch") == nullptr);
    checkNoRepairableInfo(**bothBad);
    REQUIRE((*bothBad)->repair(*dev));
    CHECK(readLe32(*dev, 512) == 0);
    CHECK(readLe32(*dev, 7 * 512 + 0x1FC) == 0);
    REQUIRE(dev->writeAt(0, pristine->bytes()));

    // Backup boot sector and backup FSInfo broken at once, then nothing: repair() on a clean
    // volume is a no-op that succeeds.
    patchBytes(*dev, 6 * 512 + 0x1FE, {0x00, 0x00});
    patchLe32(*dev, 7 * 512, 0);
    auto both = probe(dev);
    REQUIRE((both && *both));
    CHECK(diagOf(**both, "fat.backup_boot_mismatch"));
    REQUIRE(diagOf(**both, "fat.backup_fsinfo_mismatch"));
    CHECK(diagOf(**both, "fat.backup_fsinfo_mismatch")->repairable);
    CHECK((*both)->describe().child("backup boot sector")->child("boot_signature")->validity == layout::Validity::Error);
    REQUIRE((*both)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "both copies rewritten"));
    auto clean = probe(dev);
    REQUIRE((clean && *clean));
    REQUIRE((*clean)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "no-op repair"));
}

TEST_CASE("FAT32: mirrored FAT copies are compared; a differing copy is rewritten only when its head is the broken one; ext_flags picks the live FAT when mirroring is off") {
    auto dev = loadSparseFixture("fs/fat32.sparse");
    auto pristine = loadSparseFixture("fs/fat32.sparse");
    REQUIRE((dev && pristine));
    const ByteCount fat0 = 32 * 512, fat1 = (32 + 1009) * 512;
    // One entry of FAT 1 changed: both heads are intact, so nothing says which copy is right.
    patchLe32(*dev, fat1 + 8, 0x0ABCDEF0);
    auto differ = probe(dev);
    REQUIRE((differ && *differ));
    const auto* d = diagOf(**differ, "fat.fat_copies_differ");
    REQUIRE(d);
    CHECK_FALSE(d->repairable);
    CHECK(d->severity == layout::Validity::Warning);
    CHECK(d->message.find("FAT 1 differs from FAT 0") != std::string::npos);
    CHECK(d->message.find("FAT byte 8") != std::string::npos);
    CHECK(d->message.find("neither is rewritten") != std::string::npos);
    checkNoRepairableInfo(**differ);
    REQUIRE((*differ)->repair(*dev));
    CHECK(readLe32(*dev, fat1 + 8) == 0x0ABCDEF0);
    // FAT 1's head wrecked as well: now it is the broken copy and FAT 0 restores it whole.
    patchBytes(*dev, fat1, {0, 0, 0, 0, 0, 0, 0, 0});
    auto broken = probe(dev);
    REQUIRE((broken && *broken));
    d = diagOf(**broken, "fat.fat_copies_differ");
    REQUIRE(d);
    CHECK(d->repairable);
    CHECK(d->message.find("rewrites it from FAT 0") != std::string::npos);
    REQUIRE((*broken)->repair(*dev));
    CHECK(sameBytes(*dev, *pristine, "FAT 1 rewritten from FAT 0"));
    auto healed = probe(dev);
    REQUIRE((healed && *healed));
    CHECK_MESSAGE((*healed)->diagnostics().empty(), diagCodes(**healed));

    // Mirroring off, FAT 0 active: FAT 1 is stale by design, so it is neither compared nor rewritten.
    patchLe32(*dev, fat1 + 8, 0x0ABCDEF0);
    patchFat32Boot(*dev, 36 + 4, {0x80, 0x00});
    auto solo = probe(dev);
    REQUIRE((solo && *solo));
    CHECK(diagOf(**solo, "fat.fat_copies_differ") == nullptr);
    CHECK_MESSAGE((*solo)->diagnostics().empty(), diagCodes(**solo));
    CHECK((*solo)->describe().child("boot sector")->child("FAT32 extended BPB")->child("ext_flags")->pretty == "no_fat_mirroring");
    REQUIRE((*solo)->repair(*dev));
    CHECK(readLe32(*dev, fat1 + 8) == 0x0ABCDEF0);

    // An active index past the last FAT.
    patchFat32Boot(*dev, 36 + 4, {0x85, 0x00});
    auto out = probe(dev);
    REQUIRE((out && *out));
    d = diagOf(**out, "fat.active_fat_out_of_range");
    REQUIRE(d);
    CHECK(d->severity == layout::Validity::Error);
    CHECK(d->message.find("FAT 5") != std::string::npos);
    CHECK((*out)->describe().child("boot sector")->child("FAT32 extended BPB")->child("ext_flags")->pretty == "active_fat_bit0|active_fat_bit2|no_fat_mirroring");

    // A FAT past the 64 MiB comparison window is said to be only partly compared.
    REQUIRE(dev->writeAt(0, pristine->bytes()));
    patchFat32Boot(*dev, 36, {0x08, 0x00, 0x02, 0x00});   // sectors_per_fat32 = 131080 (64 MiB + 4 KiB)
    patchFat32Boot(*dev, 32, {0xFF, 0xFF, 0xFF, 0x7F});   // total_sectors32: enough clusters to need it
    auto huge = probe(dev);
    REQUIRE((huge && *huge));
    d = diagOf(**huge, "fat.fat_copies_not_compared");
    REQUIRE(d);
    CHECK(d->severity == layout::Validity::Info);
    CHECK(diagOf(**huge, "fat.truncated") != nullptr);

    // The reader and the allocation map follow the live FAT: make FAT 1 live and wreck FAT 0.
    auto full = loadSparseFixture("fatfs/fat32.sparse");
    REQUIRE(full);
    const auto oracle = loadExtOracle("fat32", "fatfs");
    patchFat32Boot(*full, 36 + 4, {0x81, 0x00});
    REQUIRE(full->zeroRange(fat0, 4096));
    auto live = probe(full);
    REQUIRE((live && *live));
    CHECK(diagOf(**live, "fat.fat_copies_differ") == nullptr);
    CHECK(diagOf(**live, "fat.media_mismatch") == nullptr);   // FAT[0] is read from the live copy
    auto reader = (*live)->openReader();
    REQUIRE(reader);
    auto big = fs::resolvePath(**reader, "big.bin");
    REQUIRE(big);
    CHECK((*reader)->stat(*big)->allocatedBytes >= 150 * 1024);
    auto data = fs::readAll(**reader, *big);
    REQUIRE(data);
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, *data)) == oracle.sha.at("big.bin"));
    auto map = (*live)->allocationMap();
    REQUIRE(map);
    CHECK(map->usedBlocks() > 300);
    // Through the wrecked FAT 0 the same volume falls apart: FAT[0] no longer repeats the media byte
    // and the chains are gone.
    patchFat32Boot(*full, 36 + 4, {0x80, 0x00});
    auto dead = probe(full);
    REQUIRE((dead && *dead));
    CHECK(diagOf(**dead, "fat.media_mismatch") != nullptr);
    auto reader2 = (*dead)->openReader();
    REQUIRE(reader2);
    auto big2 = fs::resolvePath(**reader2, "big.bin");
    CHECK((!big2 || (*reader2)->stat(*big2)->allocatedBytes < 150 * 1024));
}

TEST_CASE("FAT: a FAT copy whose head is broken is restored from the intact one, whichever is active; two intact heads that differ are reported, not rewritten") {
    struct Case {
        const char* fixture;
        ByteCount fat0, fat1;
    };
    // fs/fat16.sparse: 4 reserved sectors, 64 per FAT. fs/fat32.sparse: 32 reserved, 1009 per FAT.
    const Case cases[] = {{"fs/fat16.sparse", 4 * 512, 68 * 512}, {"fs/fat32.sparse", 32 * 512, (32 + 1009) * 512}};
    for (const auto& c : cases) {
        INFO("fixture ", c.fixture);
        auto pristine = loadSparseFixture(c.fixture);
        REQUIRE(pristine);
        // FAT 0, the active copy, loses its first sector while FAT 1 is intact. The repair used to
        // copy the active FAT over the others and so destroyed the good copy.
        {
            auto dev = loadSparseFixture(c.fixture);
            REQUIRE(dev->zeroRange(c.fat0, 512));
            auto fs = probe(dev);
            REQUIRE((fs && *fs));
            CHECK(diagOf(**fs, "fat.media_mismatch") != nullptr);
            const auto* d = diagOf(**fs, "fat.fat_copies_differ");
            REQUIRE(d);
            CHECK(d->repairable);
            CHECK(d->severity == layout::Validity::Warning);
            CHECK(d->message.find("FAT 1 differs from FAT 0") != std::string::npos);
            CHECK(d->message.find("FAT 0 does not start with the media byte") != std::string::npos);
            CHECK(d->message.find("rewrites it from FAT 1") != std::string::npos);
            checkNoRepairableInfo(**fs);
            REQUIRE((*fs)->repair(*dev));
            CHECK(sameBytes(*dev, *pristine, "FAT 0 restored from FAT 1"));
            auto healed = probe(dev);
            REQUIRE((healed && *healed));
            CHECK_MESSAGE((*healed)->diagnostics().empty(), diagCodes(**healed));
        }
        // FAT 1 loses its first sector: the active copy is the intact one and restores it.
        {
            auto dev = loadSparseFixture(c.fixture);
            REQUIRE(dev->zeroRange(c.fat1, 512));
            auto fs = probe(dev);
            REQUIRE((fs && *fs));
            CHECK(diagOf(**fs, "fat.media_mismatch") == nullptr);
            const auto* d = diagOf(**fs, "fat.fat_copies_differ");
            REQUIRE(d);
            CHECK(d->repairable);
            CHECK(d->message.find("FAT 1 does not start with the media byte") != std::string::npos);
            CHECK(d->message.find("rewrites it from FAT 0") != std::string::npos);
            REQUIRE((*fs)->repair(*dev));
            CHECK(sameBytes(*dev, *pristine, "FAT 1 restored from FAT 0"));
            auto healed = probe(dev);
            REQUIRE((healed && *healed));
            CHECK_MESSAGE((*healed)->diagnostics().empty(), diagCodes(**healed));
        }
        // Both heads intact, an entry further in differs: nothing to decide by, nothing rewritten.
        {
            auto dev = loadSparseFixture(c.fixture);
            patchBytes(*dev, c.fat1 + 64, {0x12, 0x34});
            auto fs = probe(dev);
            REQUIRE((fs && *fs));
            const auto* d = diagOf(**fs, "fat.fat_copies_differ");
            REQUIRE(d);
            CHECK_FALSE(d->repairable);
            CHECK(d->severity == layout::Validity::Warning);
            CHECK(d->message.find("FAT byte 64") != std::string::npos);
            CHECK(d->message.find("neither is rewritten") != std::string::npos);
            checkNoRepairableInfo(**fs);
            const std::vector<std::byte> before(dev->bytes().begin(), dev->bytes().end());
            REQUIRE((*fs)->repair(*dev));
            CHECK(std::equal(before.begin(), before.end(), dev->bytes().begin()));
        }
        // Both heads broken, each in its own way: nothing to restore from, nothing written.
        {
            auto dev = loadSparseFixture(c.fixture);
            REQUIRE(dev->zeroRange(c.fat0, 512));
            patchBytes(*dev, c.fat1, {0x11, 0x22, 0x33, 0x44});
            auto fs = probe(dev);
            REQUIRE((fs && *fs));
            const auto* d = diagOf(**fs, "fat.fat_copies_differ");
            REQUIRE(d);
            CHECK_FALSE(d->repairable);
            CHECK(d->severity == layout::Validity::Error);
            CHECK(d->message.find("nothing to restore from") != std::string::npos);
            checkNoRepairableInfo(**fs);
            const std::vector<std::byte> before(dev->bytes().begin(), dev->bytes().end());
            REQUIRE((*fs)->repair(*dev));
            CHECK(std::equal(before.begin(), before.end(), dev->bytes().begin()));
        }
    }
}

TEST_CASE("FAT: the boot sector state flag exists only with the extended BPB; a DOS 3.x boot sector has boot code there") {
    auto dev = loadSparseFixture("fs/fat12.sparse");
    patchBytes(*dev, 38, {0x00});   // no extended boot signature
    patchBytes(*dev, 37, {0x01});   // the byte that would be the state flag
    auto fs = probe(dev);
    REQUIRE((fs && *fs));
    CHECK((*fs)->type() == FsType::Fat12);
    CHECK((*fs)->info().clean == true);
    CHECK(diagOf(**fs, "fat.dirty") == nullptr);
    CHECK((*fs)->info().label == "STEIN_FAT12");   // the root directory's; the boot sector's label and serial are not read either
    CHECK((*fs)->info().uuid.empty());
    CHECK((*fs)->info().extra.empty());
    CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
    // With the signature back the same bit means dirty.
    patchBytes(*dev, 38, {0x29});
    auto dirty = probe(dev);
    REQUIRE((dirty && *dirty));
    CHECK((*dirty)->info().clean == false);
    REQUIRE(diagOf(**dirty, "fat.dirty"));
    CHECK(diagOf(**dirty, "fat.dirty")->message.find("boot sector state flag") != std::string::npos);
    CHECK_FALSE((*dirty)->info().uuid.empty());   // the serial is read again
}

TEST_CASE("FAT: FAT[0] media byte, FAT[1] clean-shutdown and hard-error bits, boot sector state flag: one clean answer") {
    const ByteCount fat0 = 4 * 512, fat1 = 68 * 512;   // fs/fat16.sparse
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchBytes(*dev, fat0, {0xF0});
        patchBytes(*dev, fat1, {0xF0});
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.media_mismatch");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("0xF0") != std::string::npos);
        CHECK(d->message.find("0xF8") != std::string::npos);
        CHECK((*fs)->info().clean == true);
    }
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchLe16(*dev, fat0 + 2, 0x7FFF);   // clean-shutdown bit cleared
        patchLe16(*dev, fat1 + 2, 0x7FFF);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.dirty");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("FAT[1] clean-shutdown bit") != std::string::npos);
        CHECK(d->message.find("boot sector") == std::string::npos);
        CHECK((*fs)->info().clean == false);
        CHECK(diagOf(**fs, "fat.hard_error") == nullptr);
        auto map = (*fs)->allocationMap();
        REQUIRE_FALSE(map);
        CHECK(map.error().category() == ErrorCategory::Busy);
    }
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchLe16(*dev, fat0 + 2, 0xBFFF);   // hard-error bit cleared
        patchLe16(*dev, fat1 + 2, 0xBFFF);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.hard_error");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(diagOf(**fs, "fat.dirty") == nullptr);
        CHECK((*fs)->info().clean == true);
    }
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchBytes(*dev, 37, {0x01});   // the NT / Linux state flag
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.dirty");
        REQUIRE(d);
        CHECK(d->message.find("boot sector state flag") != std::string::npos);
        CHECK(d->message.find(" and ") == std::string::npos);
        CHECK((*fs)->info().clean == false);
        CHECK((*fs)->describe().child("boot sector")->child("FAT12/16 extended BPB")->child("reserved1")->pretty == "dirty");
        // Both flags: still one diagnostic, naming both.
        patchLe16(*dev, fat0 + 2, 0x7FFF);
        patchLe16(*dev, fat1 + 2, 0x7FFF);
        auto fs2 = probe(dev);
        REQUIRE((fs2 && *fs2));
        CHECK(diagCount(**fs2, "fat.dirty") == 1);
        CHECK(diagOf(**fs2, "fat.dirty")->message.find("boot sector state flag and FAT[1] clean-shutdown bit") != std::string::npos);
    }
    // FAT32: the bits sit in the high nibble of the 28-bit entry; the state flag at byte 65.
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchLe32(*dev, 32 * 512 + 4, 0x07FFFFFF);
        patchLe32(*dev, (32 + 1009) * 512 + 4, 0x07FFFFFF);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        REQUIRE(diagOf(**fs, "fat.dirty"));
        CHECK((*fs)->info().clean == false);
        CHECK(diagOf(**fs, "fat.fat_copies_differ") == nullptr);
        patchLe32(*dev, 32 * 512 + 4, 0x0BFFFFFF);
        patchLe32(*dev, (32 + 1009) * 512 + 4, 0x0BFFFFFF);
        auto fs2 = probe(dev);
        REQUIRE((fs2 && *fs2));
        CHECK(diagOf(**fs2, "fat.dirty") == nullptr);
        REQUIRE(diagOf(**fs2, "fat.hard_error"));
        patchLe32(*dev, 32 * 512 + 4, 0x0FFFFFFF);
        patchLe32(*dev, (32 + 1009) * 512 + 4, 0x0FFFFFFF);
        patchFat32Boot(*dev, 65, {0x01});
        auto fs3 = probe(dev);
        REQUIRE((fs3 && *fs3));
        REQUIRE(diagOf(**fs3, "fat.dirty"));
        CHECK((*fs3)->describe().child("boot sector")->child("FAT32 extended BPB")->child("reserved1")->pretty == "dirty");
    }
    // FAT12 has no such bits in FAT[1]: clearing it means nothing.
    {
        auto dev = loadSparseFixture("fs/fat12.sparse");
        patchBytes(*dev, 512 + 1, {0x0F, 0x00});    // FAT[0] stays 0xFF8, FAT[1] becomes 0
        patchBytes(*dev, 3584 + 1, {0x0F, 0x00});
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->info().clean == true);
        CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
    }
}

TEST_CASE("FAT: BPB and FSInfo sanity become diagnostics, not just field flags") {
    // sectors_per_cluster 3 on a sector that calls itself FAT: kept as a broken FAT, described, not readable.
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchBytes(*dev, 13, {3});
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->info().version == "FAT16");
        const auto* d = diagOf(**fs, "fat.bpb_geometry");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Error);
        CHECK(d->message.find("sectors_per_cluster 3") != std::string::npos);
        CHECK_FALSE(has((*fs)->capabilities(), Capability::Read));
        CHECK_FALSE(has((*fs)->capabilities(), Capability::UsedBlocks));
        CHECK((*fs)->describe().child("boot sector") != nullptr);
        // Without the extended signature and fs_type string the same bytes are not FAT at all.
        patchBytes(*dev, 38, {0x00});
        patchBytes(*dev, 54, {0, 0, 0, 0, 0, 0, 0, 0});
        auto none = probe(dev);
        REQUIRE(none);
        CHECK(*none == nullptr);
    }
    {
        auto dev = loadSparseFixture("fs/fat16.sparse");
        patchLe16(*dev, 11, 1000);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.bpb_geometry");
        REQUIRE(d);
        CHECK(d->message.find("bytes_per_sector 1000") != std::string::npos);
    }
    {
        auto dev = loadSparseFixture("fs/fat12.sparse");
        patchLe16(*dev, 17, 100);   // 100 * 32 = 3200 bytes: not whole sectors
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->type() == FsType::Fat12);
        const auto* d = diagOf(**fs, "fat.root_entries_unaligned");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(diagOf(**fs, "fat.bpb_geometry") == nullptr);
    }
    {
        auto dev = loadSparseFixture("fs/fat12.sparse");
        patchLe16(*dev, 17, 0);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.bpb_geometry");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Error);
        CHECK(d->message.find("root_entries is 0") != std::string::npos);
    }
    {
        auto dev = loadSparseFixture("fs/fat12.sparse");
        patchLe16(*dev, 19, 9000);   // the device holds 8192 sectors
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.truncated");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("9000 sectors") != std::string::npos);
        CHECK(*(*fs)->info().totalBytes == 9000 * 512);
    }
    {
        auto dev = loadSparseFixture("fs/fat12.sparse");
        patchLe16(*dev, 22, 1);   // one sector of FAT for ~2000 clusters
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.fat_too_small");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Error);
        CHECK(d->message.find("each FAT has 512 bytes") != std::string::npos);
    }
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchFat32Boot(*dev, 17, {0x10, 0x00});   // root_entries 16 on FAT32
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK((*fs)->type() == FsType::Fat32);
        const auto* d = diagOf(**fs, "fat.bpb_geometry");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("root_entries must be 0") != std::string::npos);
    }
    // FSInfo: signatures, free count, next-free hint, sector number.
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchLe32(*dev, 512, 0);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.fsinfo_bad");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("lead") != std::string::npos);
        CHECK_FALSE((*fs)->info().usedBytes.has_value());
        CHECK((*fs)->describe().child("FSInfo sector")->child("lead_signature")->validity == layout::Validity::Error);
    }
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchLe32(*dev, 512 + 0x1E8, 200000);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.fsinfo_free_count");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(d->message.find("200000") != std::string::npos);
        CHECK_FALSE((*fs)->info().usedBytes.has_value());
    }
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchLe32(*dev, 512 + 0x1EC, 200000);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.fsinfo_next_free");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Info);
        CHECK(*(*fs)->info().usedBytes == 512);
    }
    {
        auto dev = loadSparseFixture("fs/fat32.sparse");
        patchFat32Boot(*dev, 36 + 0x0C, {40, 0});   // fsinfo_sector 40, past the 32 reserved sectors
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "fat.fsinfo_bad");
        REQUIRE(d);
        CHECK(d->message.find("outside") != std::string::npos);
        CHECK((*fs)->describe().child("FSInfo sector") == nullptr);
        CHECK((*fs)->describe().child("backup boot sector") != nullptr);
        CHECK_FALSE((*fs)->info().usedBytes.has_value());
        // fsinfo_sector 0 is read as 1, the way Linux does.
        patchFat32Boot(*dev, 36 + 0x0C, {0, 0});
        auto fs2 = probe(dev);
        REQUIRE((fs2 && *fs2));
        CHECK(diagOf(**fs2, "fat.fsinfo_bad") == nullptr);
        CHECK(*(*fs2)->info().usedBytes == 512);
    }
}

TEST_CASE("FAT: hidden_sectors is checked against the partition's start LBA when the volume is a slice") {
    auto whole = loadSparseFixture("fs/fat12.sparse");   // 4 MiB, formatted as a whole device: hidden_sectors 0
    REQUIRE(whole);
    auto disk = std::make_shared<MemoryDevice>(5 * MiB, 512);
    REQUIRE(disk->writeAt(1 * MiB, whole->bytes()));
    auto part = SliceDevice::create(disk, Region{1 * MiB, 4 * MiB});
    REQUIRE(part);
    auto fs = probe(*part);
    REQUIRE((fs && *fs));
    CHECK((*fs)->info().label == "STEIN_FAT12");
    const auto* d = diagOf(**fs, "fat.hidden_sectors_mismatch");
    REQUIRE(d);
    CHECK(d->severity == layout::Validity::Info);
    CHECK(d->message.find("hidden_sectors is 0") != std::string::npos);
    CHECK(d->message.find("LBA 2048") != std::string::npos);
    // Seen through a read-only wrapper the slice's offset still counts.
    auto ro = std::make_shared<ReadOnlyDevice>(*part);
    auto viaRo = probe(ro);
    REQUIRE((viaRo && *viaRo));
    CHECK(diagOf(**viaRo, "fat.hidden_sectors_mismatch") != nullptr);
    // The formatter that knew its partition wrote 2048.
    patchLe32(**part, 28, 2048);
    auto fixed = probe(*part);
    REQUIRE((fixed && *fixed));
    CHECK_MESSAGE((*fixed)->diagnostics().empty(), diagCodes(**fixed));
    // A whole device has no partition start to compare with.
    auto plain = probe(whole);
    REQUIRE((plain && *plain));
    CHECK(diagOf(**plain, "fat.hidden_sectors_mismatch") == nullptr);

    // An MBR logical partition: DOS and Windows write the distance from its EBR, Linux the disk
    // LBA. Both pass once the sector that far back proves to be the EBR describing this partition.
    {
        auto disk2 = std::make_shared<MemoryDevice>(8 * MiB, 512);
        REQUIRE(disk2->writeAt(3 * MiB, whole->bytes()));
        // EBR at LBA 4096: entry 1 places a FAT12 partition 2048 sectors on, 8192 sectors long.
        const ByteCount ebr = 2 * MiB;
        patchBytes(*disk2, ebr + 446, {0x00, 0, 0, 0, 0x01, 0, 0, 0});
        patchLe32(*disk2, ebr + 446 + 8, 2048);
        patchLe32(*disk2, ebr + 446 + 12, 8192);
        patchBytes(*disk2, ebr + 510, {0x55, 0xAA});
        auto logical = SliceDevice::create(disk2, Region{3 * MiB, 4 * MiB});
        REQUIRE(logical);
        patchLe32(**logical, 28, 2048);   // EBR-relative
        auto viaEbr = probe(*logical);
        REQUIRE((viaEbr && *viaEbr));
        CHECK_MESSAGE((*viaEbr)->diagnostics().empty(), diagCodes(**viaEbr));
        patchLe32(**logical, 28, 6144);   // disk-relative
        auto viaDisk = probe(*logical);
        REQUIRE((viaDisk && *viaDisk));
        CHECK_MESSAGE((*viaDisk)->diagnostics().empty(), diagCodes(**viaDisk));
        patchLe32(**logical, 28, 63);   // a distance no EBR accounts for
        auto wrong = probe(*logical);
        REQUIRE((wrong && *wrong));
        REQUIRE(diagOf(**wrong, "fat.hidden_sectors_mismatch"));
        CHECK(diagOf(**wrong, "fat.hidden_sectors_mismatch")->message.find("LBA 6144") != std::string::npos);
        // The EBR entry must describe this very partition: another size does not vouch for it.
        patchLe32(**logical, 28, 2048);
        patchLe32(*disk2, ebr + 446 + 12, 4096);
        auto other = probe(*logical);
        REQUIRE((other && *other));
        CHECK(diagOf(**other, "fat.hidden_sectors_mismatch") != nullptr);
        checkNoRepairableInfo(**other);
    }
    // A decrypting view (LUKS, VeraCrypt) also sits at an offset on its parent, but that offset
    // is a payload start the formatter never saw: not a partition window, nothing to compare.
    {
        auto disk3 = std::make_shared<MemoryDevice>(5 * MiB, 512);
        REQUIRE(disk3->writeAt(1 * MiB, whole->bytes()));
        auto payload = std::make_shared<PayloadView>(disk3, Region{1 * MiB, 4 * MiB}, 512);
        auto fs3 = probe(payload);
        REQUIRE((fs3 && *fs3));
        CHECK((*fs3)->info().label == "STEIN_FAT12");
        CHECK_MESSAGE((*fs3)->diagnostics().empty(), diagCodes(**fs3));
        // The same payload with 4096-byte sectors (LUKS2 --sector-size 4096).
        auto fs4k = probe(std::make_shared<PayloadView>(disk3, Region{1 * MiB, 4 * MiB}, 4096));
        REQUIRE((fs4k && *fs4k));
        CHECK_MESSAGE((*fs4k)->diagnostics().empty(), diagCodes(**fs4k));
        // Through a read-only wrapper: a plain decorator, whole view of its parent, same bytes.
        auto fsRo = probe(std::make_shared<ReadOnlyDevice>(payload));
        REQUIRE((fsRo && *fsRo));
        CHECK_MESSAGE((*fsRo)->diagnostics().empty(), diagCodes(**fsRo));
        // A payload that views a partition whole (detached header) but re-sectors it: the sector
        // size change ends the walk before the partition's offset is reached.
        auto partDisk = std::make_shared<MemoryDevice>(5 * MiB, 512);
        REQUIRE(partDisk->writeAt(1 * MiB, whole->bytes()));
        auto part2 = SliceDevice::create(partDisk, Region{1 * MiB, 4 * MiB});
        REQUIRE(part2);
        auto fsWhole4k = probe(std::make_shared<PayloadView>(*part2, Region{0, 4 * MiB}, 4096));
        REQUIRE((fsWhole4k && *fsWhole4k));
        CHECK(diagOf(**fsWhole4k, "fat.hidden_sectors_mismatch") == nullptr);
        // The partition's slice itself still reports: hidden_sectors 0, LBA 2048.
        auto fsPart2 = probe(*part2);
        REQUIRE((fsPart2 && *fsPart2));
        CHECK(diagOf(**fsPart2, "fat.hidden_sectors_mismatch") != nullptr);
    }
}

#ifdef STEIN_TEST_FS_HAS_LUKS
// The real thing: the FAT12 fixture inside a LUKS payload, written through libstein's own
// encrypting view (the way the app's test_luks builds its ext4 case). The fixture's header and
// key slot are reused; its payload is replaced by the volume.
TEST_CASE("FAT: a volume inside a LUKS payload is not measured against the payload offset (LUKS2 argon2id/512 and pbkdf2/4096)") {
    for (const char* fixture : {"luks/luks2.sparse", "luks/luks2_pbkdf2.sparse"}) {
        INFO("fixture ", fixture);
        auto luksFixture = loadSparseFixture(fixture);
        auto fat = loadSparseFixture("fs/fat12.sparse");
        REQUIRE((luksFixture && fat));
        auto header = container::Luks::open(luksFixture);
        REQUIRE(header);
        const ByteCount off = header->info().payloadOffset;
        auto dev = std::make_shared<MemoryDevice>(off + fat->size(), 512);
        std::vector<std::byte> head(static_cast<std::size_t>(off));
        REQUIRE(luksFixture->readAt(0, head));
        REQUIRE(dev->writeAt(0, head));
        auto luks = container::Luks::open(dev);
        REQUIRE(luks);
        REQUIRE(luks->info().payloadSize == fat->size());
        auto payload = luks->openPayload(std::string("luks test passphrase"), false);
        REQUIRE(payload);
        CHECK((*payload)->sectorSize() == luks->info().sectorSize);
        REQUIRE((*payload)->writeAt(0, fat->bytes()));
        REQUIRE((*payload)->flush());
        auto fs = probe(*payload);
        REQUIRE((fs && *fs));
        CHECK((*fs)->type() == FsType::Fat12);
        CHECK((*fs)->info().label == "STEIN_FAT12");
        CHECK(diagOf(**fs, "fat.hidden_sectors_mismatch") == nullptr);
        CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
        // Read-only, as the probe opens payloads.
        auto ro = luks->openPayload(std::string("luks test passphrase"), true);
        REQUIRE(ro);
        auto fsRo = probe(*ro);
        REQUIRE((fsRo && *fsRo));
        CHECK_MESSAGE((*fsRo)->diagnostics().empty(), diagCodes(**fsRo));
    }
}

// A detached header (cryptsetup --header) puts the payload at byte 0 of the data device, here a
// partition: the decrypting view is then a whole view of the partition slice at the same sector
// size, the exact shape of a plain decorator, and only its bytes tell the two apart. The LUKS1
// header's payload_offset is a plain field (no checksum seals the header), so the fixture's is set
// to 0 to make such a header; the data device gets the fixture's key slot and the volume.
TEST_CASE("FAT: a detached-header LUKS payload on a partition is a transforming view, not the partition window") {
    auto header = loadSparseFixture("luks/luks1.sparse");
    auto fat = loadSparseFixture("fs/fat12.sparse");
    REQUIRE((header && fat));
    patchBytes(*header, 0x68, {0, 0, 0, 0});   // payload_offset (big-endian, in sectors) = 0
    auto disk = std::make_shared<MemoryDevice>(6 * MiB, 512);
    auto part = SliceDevice::create(disk, Region{1 * MiB, fat->size()});
    REQUIRE(part);
    auto luks = container::Luks::open(header, *part);
    REQUIRE(luks);
    CHECK(luks->info().payloadOffset == 0);
    REQUIRE(luks->info().payloadSize == fat->size());
    auto payload = luks->openPayload(std::string("luks test passphrase"), false);
    REQUIRE(payload);
    CHECK((*payload)->sectorSize() == (*part)->sectorSize());
    CHECK((*payload)->size() == (*part)->size());
    REQUIRE((*payload)->writeAt(0, fat->bytes()));
    REQUIRE((*payload)->flush());
    auto fs = probe(*payload);
    REQUIRE((fs && *fs));
    CHECK((*fs)->type() == FsType::Fat12);
    CHECK((*fs)->info().label == "STEIN_FAT12");
    CHECK(diagOf(**fs, "fat.hidden_sectors_mismatch") == nullptr);
    CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
    // Read-only (behind the payload's read cache), as the probe opens payloads.
    auto ro = luks->openPayload(std::string("luks test passphrase"), true);
    REQUIRE(ro);
    auto fsRo = probe(*ro);
    REQUIRE((fsRo && *fsRo));
    CHECK_MESSAGE((*fsRo)->diagnostics().empty(), diagCodes(**fsRo));
    // The partition itself is still a window: the same volume written there in the clear reports.
    REQUIRE((*part)->writeAt(0, fat->bytes()));
    auto clear = probe(*part);
    REQUIRE((clear && *clear));
    REQUIRE(diagOf(**clear, "fat.hidden_sectors_mismatch"));
    CHECK(diagOf(**clear, "fat.hidden_sectors_mismatch")->message.find("LBA 2048") != std::string::npos);
}
#endif

TEST_CASE("exfat: geometry sanity, truncation, exact used space from the bitmap, TexFAT's second FAT") {
    // Used space: the bitmap's set bits, not percent_in_use, on every fixture (all under 8 MiB).
    for (const char* fixture : {"fs/exfat.sparse", "exfatfs/exfat.sparse", "exfatfs/exfat_32k.sparse"}) {
        CAPTURE(fixture);
        auto fs = probe(loadSparseFixture(fixture));
        REQUIRE((fs && *fs));
        CHECK_MESSAGE((*fs)->diagnostics().empty(), diagCodes(**fs));
        auto map = (*fs)->allocationMap();
        REQUIRE(map);
        REQUIRE((*fs)->info().usedBytes.has_value());
        CHECK(*(*fs)->info().usedBytes == map->usedBytes());
    }
    {
        auto dev = loadSparseFixture("fs/exfat.sparse");
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK(*(*fs)->info().usedBytes == 4 * 4096);   // percent_in_use says 0 %
        // A bitmap entry claiming more than 8 MiB keeps the percentage (probe time stays bounded).
        const auto tree = (*fs)->describe();
        const auto* bitmap = descendant(tree, {"root directory", "allocation bitmap entry"});
        REQUIRE(bitmap);
        patchLe32(*dev, bitmap->absOffset + 24, 9 * 1024 * 1024);
        patchLe32(*dev, bitmap->absOffset + 28, 0);
        auto pct = probe(dev);
        REQUIRE((pct && *pct));
        CHECK(*(*pct)->info().usedBytes == 0);
    }
    // Geometry: Error where impossible, Warning where merely inconsistent.
    auto geometryWith = [](ByteCount off, std::initializer_list<std::uint8_t> bytes, layout::Validity severity, const char* fragment) {
        CAPTURE(fragment);
        auto dev = loadSparseFixture("fs/exfat.sparse");
        patchExfatBoot(*dev, off, bytes);
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        CHECK(diagOf(**fs, "exfat.boot_checksum") == nullptr);   // the patch was sealed
        bool found = false;
        for (const auto& d : (*fs)->diagnostics())
            if (d.code == "exfat.geometry" && d.severity == severity && d.message.find(fragment) != std::string::npos) found = true;
        CHECK_MESSAGE(found, diagCodes(**fs));
        return std::move(*fs);
    };
    geometryWith(0x50, {10, 0, 0, 0}, layout::Validity::Error, "fat_offset 10");
    geometryWith(0x58, {0x34, 0x08, 0, 0}, layout::Validity::Error, "past the cluster heap at 2100");
    geometryWith(0x54, {10, 0, 0, 0}, layout::Validity::Error, "fat_length 10");
    geometryWith(0x5C, {0x20, 0x4E, 0, 0}, layout::Validity::Error, "beyond volume_length");
    auto slack = geometryWith(0x5C, {0x98, 0x3A, 0, 0}, layout::Validity::Warning, "leaves 6976 sectors");
    for (const auto& d : slack->diagnostics()) CHECK(d.severity <= layout::Validity::Warning);
    geometryWith(0x60, {1, 0, 0, 0}, layout::Validity::Error, "first_cluster_of_root 1");
    {
        auto dev = loadSparseFixture("fs/exfat.sparse");
        patchExfatBoot(*dev, 0x48, {0x01, 0x00, 0x02, 0x00, 0, 0, 0, 0});   // volume_length 131073 on a 131072-sector device
        auto fs = probe(dev);
        REQUIRE((fs && *fs));
        const auto* d = diagOf(**fs, "exfat.truncated");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK(diagOf(**fs, "exfat.geometry") == nullptr);
    }
    // TexFAT: two FATs. The fixture's second FAT area is blank, so the copies differ (not
    // repairable: on a real TexFAT volume the two may be mid-transaction); with the first FAT
    // copied over it they agree, and with volume_flags naming the second as live everything is
    // read through it.
    {
        auto dev = loadSparseFixture("exfatfs/exfat.sparse");
        const ByteCount fat1 = 2048 * 512, fatBytes = 128 * 512;
        patchExfatBoot(*dev, 0x6E, {2});
        auto differ = probe(dev);
        REQUIRE((differ && *differ));
        const auto* d = diagOf(**differ, "exfat.fat_copies_differ");
        REQUIRE(d);
        CHECK(d->severity == layout::Validity::Warning);
        CHECK_FALSE(d->repairable);
        CHECK(diagOf(**differ, "exfat.geometry") == nullptr);
        auto first = dev->read(fat1, fatBytes);
        REQUIRE(first);
        REQUIRE(dev->writeAt(fat1 + fatBytes, *first));
        auto same = probe(dev);
        REQUIRE((same && *same));
        CHECK(diagOf(**same, "exfat.fat_copies_differ") == nullptr);
        auto usedThroughFirst = (*same)->allocationMap();
        REQUIRE(usedThroughFirst);
        patchExfatBoot(*dev, 0x6A, {0x01, 0x00});   // active FAT: the second
        REQUIRE(dev->zeroRange(fat1, fatBytes));      // the first is now stale by design
        auto second = probe(dev);
        REQUIRE((second && *second));
        CHECK(diagOf(**second, "exfat.fat_copies_differ") != nullptr);
        CHECK(*(*second)->info().usedBytes == usedThroughFirst->usedBytes());
        auto map = (*second)->allocationMap();
        REQUIRE(map);
        CHECK(map->usedBlocks() == usedThroughFirst->usedBlocks());
        auto reader = (*second)->openReader();
        REQUIRE_MESSAGE(reader, (reader ? std::string() : reader.error().toString()));
        auto hello = fs::resolvePath(**reader, "hello.txt");
        REQUIRE(hello);
        CHECK((*reader)->stat(*hello)->size == 20);
        auto frag = fs::resolvePath(**reader, "frag.bin");
        REQUIRE(frag);
        auto data = fs::readAll(**reader, *frag);
        REQUIRE(data);
        CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, *data)) == loadExtOracle("exfat", "exfatfs").sha.at("frag.bin"));
    }
}
