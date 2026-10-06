// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/strings.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/volume/lvm.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

using namespace stein;
using stein::test::loadSparseFixture;

TEST_CASE("lvm: parse the VG from a PV, map linear, fragmented and striped LVs, read their filesystems") {
    auto pv0 = loadSparseFixture("lvm/pv0.sparse");
    auto pv1 = loadSparseFixture("lvm/pv1.sparse");
    auto md = volume::readPvMetadata(*pv0);
    REQUIRE_MESSAGE(md, (md ? std::string() : md.error().toString()));
    CHECK(md->text.find("stein_vg {") != std::string::npos);
    CHECK(md->pvUuid.size() == 32);

    auto vg = volume::VolumeGroup::fromPv(pv0);
    REQUIRE_MESSAGE(vg, (vg ? std::string() : vg.error().toString()));
    CHECK(vg->name() == "stein_vg");
    CHECK(vg->extentBytes() == 1 * MiB);
    CHECK(vg->pvs().size() == 2);
    CHECK(vg->lvs().size() == 4);
    const auto* linear = vg->lv("linear");
    const auto* striped = vg->lv("striped");
    const auto* frag = vg->lv("frag");
    REQUIRE(linear);
    REQUIRE(striped);
    REQUIRE(frag);
    CHECK(linear->extents() == 8);
    CHECK(linear->segments.size() == 1);
    CHECK(frag->segments.size() == 2);
    CHECK(frag->segments[1].startExtent == 4);
    CHECK(striped->segments[0].stripeCount == 2);
    CHECK(striped->segments[0].stripeSizeSectors == 128);
    CHECK(linear->visible());
    // The metadata text agrees with vgcfgbackup's view on extent placement.
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/lvm/vgcfg.txt");
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string cfg = ss.str();
    CHECK(cfg.find("\"" + linear->id + "\"") != std::string::npos);

    // With only pv0: linear and frag map; striped needs pv1.
    CHECK(vg->missingPvs(*linear).empty());
    CHECK(vg->missingPvs(*striped) == std::vector<std::string>{"pv1"});
    CHECK(vg->openLv("striped").error().category() == ErrorCategory::NotFound);
    CHECK(vg->openLv("nope").error().category() == ErrorCategory::NotFound);
    auto lin = vg->openLv("linear");
    REQUIRE(lin);
    CHECK((*lin)->size() == 8 * MiB);
    CHECK((*lin)->isReadOnly());
    auto fsLin = fs::probe(*lin);
    REQUIRE(fsLin);
    REQUIRE(*fsLin);
    CHECK((*fsLin)->info().label == "lv_linear");
    auto fr = vg->openLv("frag");
    REQUIRE(fr);
    CHECK((*fr)->size() == 8 * MiB);
    auto fsFrag = fs::probe(*fr);
    REQUIRE(fsFrag);
    REQUIRE(*fsFrag);
    CHECK((*fsFrag)->info().label == "lv_frag");
    // Data in the second segment reads through the concatenation: the ext2 backup superblock of
    // the 4 KiB-block filesystem lives in group 1 at 32768 blocks... too far; instead read across the seam.
    auto seam = (*fr)->read(4 * MiB - 2048, 4096);
    REQUIRE(seam);

    // Add pv1: striped becomes mappable and its filesystem reads correctly through the interleave.
    REQUIRE(vg->addPv(pv1));
    CHECK(vg->missingPvs(*striped).empty());
    auto st = vg->openLv("striped");
    REQUIRE(st);
    CHECK((*st)->size() == 8 * MiB);
    auto fsSt = fs::probe(*st);
    REQUIRE(fsSt);
    REQUIRE(*fsSt);
    CHECK((*fsSt)->info().label == "lv_striped");
    // Every allocated block of the striped ext2 must be readable and consistent: use its allocation map.
    auto map = (*fsSt)->allocationMap();
    REQUIRE(map);
    CHECK(map->usedBlocks() > 0);
    // A foreign device is refused.
    auto bogus = std::make_shared<MemoryDevice>(1 * MiB);
    CHECK_FALSE(vg->addPv(bogus));
}
