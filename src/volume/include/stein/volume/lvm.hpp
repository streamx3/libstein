// SPDX-License-Identifier: MIT
// LVM2 in-process: read the text metadata from physical volumes, model the
// volume group, and assemble logical volumes as BlockDevices (linear and
// striped segments; others are reported, not mapped). Several PVs can be
// added one by one; an LV becomes mappable when every PV it touches is known.
#pragma once

#include "stein/block/block_device.hpp"
#include "stein/core/error.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace stein::volume {

struct LvmStripe {
    std::string pv;              // key in VolumeGroup::pvs
    std::uint64_t startExtent = 0;
};

struct LvmSegment {
    std::uint64_t startExtent = 0, extentCount = 0;
    std::string type;            // "striped" (stripe_count 1 = linear), "mirror", "raid1", "thin", ...
    std::uint32_t stripeCount = 1;
    std::uint64_t stripeSizeSectors = 0;
    std::vector<LvmStripe> stripes;
};

struct LogicalVolume {
    std::string name, id;
    std::vector<std::string> status;
    std::vector<LvmSegment> segments;
    std::uint64_t extents() const;
    bool visible() const;
};

struct PhysicalVolume {
    std::string name, id, deviceHint;
    std::uint64_t deviceSizeSectors = 0, peStartSectors = 0, peCount = 0;
    std::shared_ptr<BlockDevice> device;   // set when the PV has been seen
};

class VolumeGroup {
public:
    // Parse the live metadata found on `pv` (a device carrying an LVM2 label) and register the PV.
    static Expected<VolumeGroup> fromPv(std::shared_ptr<BlockDevice> pv);
    // Register another PV of the same VG (must carry the same VG id; the newest seqno wins).
    Expected<void> addPv(std::shared_ptr<BlockDevice> pv);

    const std::string& name() const { return m_name; }
    const std::string& id() const { return m_id; }
    std::uint64_t seqno() const { return m_seqno; }
    std::uint64_t extentSizeSectors() const { return m_extentSize; }
    ByteCount extentBytes() const { return m_extentSize * 512; }
    const std::map<std::string, PhysicalVolume>& pvs() const { return m_pvs; }
    const std::vector<LogicalVolume>& lvs() const { return m_lvs; }
    const LogicalVolume* lv(const std::string& name) const;

    // Which PVs (by key) the LV needs that have not been seen.
    std::vector<std::string> missingPvs(const LogicalVolume& lv) const;
    // Segment types we cannot map yet, if any.
    std::vector<std::string> unsupportedSegments(const LogicalVolume& lv) const;
    // The LV as a device (read-only by default). Fails with NotFound when a PV is missing,
    // Unsupported for segment types other than striped/linear.
    Expected<std::shared_ptr<BlockDevice>> openLv(const std::string& name, bool readOnly = true) const;

    // Raw text metadata as read (for `--doc` output and debugging).
    const std::string& metadataText() const { return m_text; }

private:
    Expected<void> parseText(const std::string& text);
    std::string m_name, m_id, m_text;
    std::uint64_t m_seqno = 0, m_extentSize = 0;
    std::map<std::string, PhysicalVolume> m_pvs;
    std::vector<LogicalVolume> m_lvs;
};

// Read the live metadata text from a PV (label -> pv header -> metadata area -> raw_locn). Also returns the PV uuid.
struct PvMetadata {
    std::string pvUuid;
    std::uint64_t deviceSizeBytes = 0;
    std::string text;
};
Expected<PvMetadata> readPvMetadata(BlockDevice& device);

} // namespace stein::volume
