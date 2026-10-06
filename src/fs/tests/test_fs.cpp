// SPDX-License-Identifier: MIT
// The blkid output recorded next to each fixture is the oracle: for every
// fixture we must agree on TYPE, LABEL, UUID and (where we report one) VERSION.
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
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
    CHECK((*fs)->describe().child("FAT32 extended BPB") != nullptr);
    CHECK((*fs)->describe().child("FSInfo sector") != nullptr);
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
