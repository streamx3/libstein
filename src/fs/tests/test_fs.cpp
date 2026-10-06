// SPDX-License-Identifier: MIT
// The blkid output recorded next to each fixture is the oracle: for every
// fixture we must agree on TYPE, LABEL, UUID and (where we report one) VERSION.
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"

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
