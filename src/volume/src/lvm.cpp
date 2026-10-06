// SPDX-License-Identifier: MIT
#include "stein/volume/lvm.hpp"

#include "stein/block/concat_device.hpp"
#include "stein/block/slice_device.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/strings.hpp"
#include "stein/layout/gen/lvm.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace stein::volume {

namespace gen = layout::gen;

namespace {
// On-disk PV uuids are 32 characters; the metadata text writes them 6-4-4-4-4-4-6.
std::string hyphenate(std::string_view raw) {
    if (raw.size() != 32) return std::string(raw);
    std::string out;
    const int groups[] = {6, 4, 4, 4, 4, 4, 6};
    std::size_t pos = 0;
    for (int g : groups) {
        if (!out.empty()) out += '-';
        out += std::string(raw.substr(pos, static_cast<std::size_t>(g)));
        pos += static_cast<std::size_t>(g);
    }
    return out;
}
} // namespace

// ----------------------------------------------------------------------------- on-disk

Expected<PvMetadata> readPvMetadata(BlockDevice& dev) {
    auto raw = dev.read(0, 4 * 512);
    if (!raw) return fail(raw.error());
    for (std::size_t sector = 0; sector < 4; ++sector) {
        gen::LvmLabelHeader lh(std::span<const std::byte>(*raw).subspan(sector * 512, 512));
        if (std::string(reinterpret_cast<const char*>(raw->data() + sector * 512), 8) != "LABELONE") continue;
        const std::size_t pvOff = sector * 512 + lh.offset();
        if (pvOff + gen::LvmPvHeader::kSize > raw->size()) return fail(ErrorCategory::InvalidFormat, "LVM PV header outside the label sectors");
        gen::LvmPvHeader pv(std::span<const std::byte>(*raw).subspan(pvOff, gen::LvmPvHeader::kSize));
        PvMetadata out;
        out.pvUuid = pv.pvUuid();
        out.deviceSizeBytes = pv.deviceSize();
        // disk_locn lists: data areas then metadata areas (each zero-terminated).
        std::size_t pos = pvOff + gen::LvmPvHeader::kSize;
        for (int list = 0; list < 2; ++list) {
            while (pos + 16 <= raw->size()) {
                gen::LvmDiskLocn locn(std::span<const std::byte>(*raw).subspan(pos, 16));
                pos += 16;
                if (locn.offset() == 0 && locn.size() == 0) break;
                if (list == 0) continue;   // data area
                // Metadata area header.
                auto mda = dev.read(locn.offset(), 512);
                if (!mda) continue;
                gen::LvmMdaHeader mh(*mda);
                if (std::string(reinterpret_cast<const char*>(mda->data() + 4), 16) != " LVM2 x[5A%r0N*>") continue;
                const std::uint64_t mdaStart = mh.start(), mdaSize = mh.size();
                // raw_locn[0]: live metadata inside the circular area (may wrap around).
                gen::LvmRawLocn rl(std::span<const std::byte>(*mda).subspan(gen::LvmMdaHeader::kSize, 24));
                if (rl.size() == 0 || rl.size() > 16 * MiB) continue;
                std::string text;
                text.resize(static_cast<std::size_t>(rl.size()));
                const std::uint64_t first = std::min<std::uint64_t>(rl.size(), mdaSize - rl.offset());
                auto part1 = dev.read(mdaStart + rl.offset(), first);
                if (!part1) return fail(part1.error());
                std::memcpy(text.data(), part1->data(), static_cast<std::size_t>(first));
                if (first < rl.size()) {   // wrapped: the rest starts right after the mda header (512 bytes)
                    auto part2 = dev.read(mdaStart + 512, rl.size() - first);
                    if (!part2) return fail(part2.error());
                    std::memcpy(text.data() + first, part2->data(), static_cast<std::size_t>(rl.size() - first));
                }
                while (!text.empty() && text.back() == '\0') text.pop_back();
                out.text = std::move(text);
                return out;
            }
        }
        return fail(ErrorCategory::NotFound, "PV has no readable metadata area (metadata may live on another PV)");
    }
    return fail(ErrorCategory::NotFound, "no LVM2 label");
}

// ----------------------------------------------------------------------------- text metadata parser

namespace {

// A minimal parser for LVM's config format: `key = value`, `section { ... }`,
// values are integers, "strings" or [ arrays ]; `#` comments to end of line.
struct Node {
    std::string key;
    std::string str;
    std::uint64_t num = 0;
    bool isStr = false, isNum = false, isArray = false, isSection = false;
    std::vector<Node> items;   // array items or section children

    const Node* child(const std::string& k) const {
        for (const auto& c : items)
            if (c.key == k) return &c;
        return nullptr;
    }
    std::uint64_t numOr(const std::string& k, std::uint64_t def) const {
        const Node* c = child(k);
        return c && c->isNum ? c->num : def;
    }
    std::string strOr(const std::string& k, std::string def = {}) const {
        const Node* c = child(k);
        return c && c->isStr ? c->str : def;
    }
};

class Parser {
public:
    explicit Parser(std::string_view s) : m_s(s) {}
    Expected<Node> parseAll() {
        Node root;
        root.isSection = true;
        while (skipWs(), m_pos < m_s.size()) {
            auto n = parseEntry();
            if (!n) return fail(n.error());
            root.items.push_back(std::move(*n));
        }
        return root;
    }

private:
    void skipWs() {
        while (m_pos < m_s.size()) {
            const char c = m_s[m_pos];
            if (c == '#') {
                while (m_pos < m_s.size() && m_s[m_pos] != '\n') ++m_pos;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                ++m_pos;
            } else {
                break;
            }
        }
    }
    Expected<std::string> ident() {
        skipWs();
        const std::size_t start = m_pos;
        while (m_pos < m_s.size() && (std::isalnum(static_cast<unsigned char>(m_s[m_pos])) || m_s[m_pos] == '_' || m_s[m_pos] == '-' || m_s[m_pos] == '.' || m_s[m_pos] == '+')) ++m_pos;
        if (start == m_pos) return fail(ErrorCategory::InvalidFormat, "LVM metadata: identifier expected at " + std::to_string(m_pos));
        return std::string(m_s.substr(start, m_pos - start));
    }
    Expected<Node> parseValue() {
        skipWs();
        Node v;
        if (m_pos >= m_s.size()) return fail(ErrorCategory::InvalidFormat, "LVM metadata: value expected");
        const char c = m_s[m_pos];
        if (c == '"') {
            ++m_pos;
            const std::size_t start = m_pos;
            while (m_pos < m_s.size() && m_s[m_pos] != '"') ++m_pos;
            if (m_pos >= m_s.size()) return fail(ErrorCategory::InvalidFormat, "LVM metadata: unterminated string");
            v.str = std::string(m_s.substr(start, m_pos - start));
            v.isStr = true;
            ++m_pos;
            return v;
        }
        if (c == '[') {
            ++m_pos;
            v.isArray = true;
            while (skipWs(), m_pos < m_s.size() && m_s[m_pos] != ']') {
                auto item = parseValue();
                if (!item) return item;
                v.items.push_back(std::move(*item));
                skipWs();
                if (m_pos < m_s.size() && m_s[m_pos] == ',') ++m_pos;
            }
            if (m_pos >= m_s.size()) return fail(ErrorCategory::InvalidFormat, "LVM metadata: unterminated array");
            ++m_pos;
            return v;
        }
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '-') {
            const std::size_t start = m_pos;
            if (c == '-') ++m_pos;
            while (m_pos < m_s.size() && std::isdigit(static_cast<unsigned char>(m_s[m_pos]))) ++m_pos;
            v.num = std::strtoull(std::string(m_s.substr(start, m_pos - start)).c_str(), nullptr, 10);
            v.isNum = true;
            return v;
        }
        return fail(ErrorCategory::InvalidFormat, "LVM metadata: unexpected character '" + std::string(1, c) + "'");
    }
    Expected<Node> parseEntry() {
        auto key = ident();
        if (!key) return fail(key.error());
        skipWs();
        if (m_pos < m_s.size() && m_s[m_pos] == '{') {
            ++m_pos;
            Node sec;
            sec.key = *key;
            sec.isSection = true;
            while (skipWs(), m_pos < m_s.size() && m_s[m_pos] != '}') {
                auto child = parseEntry();
                if (!child) return child;
                sec.items.push_back(std::move(*child));
            }
            if (m_pos >= m_s.size()) return fail(ErrorCategory::InvalidFormat, "LVM metadata: unterminated section " + *key);
            ++m_pos;
            return sec;
        }
        if (m_pos >= m_s.size() || m_s[m_pos] != '=') return fail(ErrorCategory::InvalidFormat, "LVM metadata: '=' expected after " + *key);
        ++m_pos;
        auto v = parseValue();
        if (!v) return v;
        v->key = *key;
        return v;
    }
    std::string_view m_s;
    std::size_t m_pos = 0;
};

// Round-robin interleave of equally sized stripe devices.
class StripedDevice final : public BlockDevice {
public:
    StripedDevice(std::vector<BlockDevicePtr> stripes, ByteCount stripeSize, std::string name)
        : m_stripes(std::move(stripes)), m_stripeSize(stripeSize), m_name(std::move(name)) {
        m_geometry = m_stripes.front()->geometry();
        m_geometry.sizeBytes = 0;
        for (const auto& s : m_stripes) m_geometry.sizeBytes += s->size();
    }
    std::string name() const override { return m_name; }
    Geometry geometry() const override { return m_geometry; }
    bool isReadOnly() const override {
        for (const auto& s : m_stripes)
            if (s->isReadOnly()) return true;
        return false;
    }
    Expected<void> flush() override {
        for (auto& s : m_stripes)
            if (auto r = s->flush(); !r) return r;
        return {};
    }
    Expected<void> readAt(ByteCount offset, std::span<std::byte> dst) override {
        return forEach(offset, dst.size(), [&](BlockDevice& s, ByteCount in, ByteCount done, ByteCount n) { return s.readAt(in, dst.subspan(done, n)); });
    }
    Expected<void> writeAt(ByteCount offset, std::span<const std::byte> src) override {
        return forEach(offset, src.size(), [&](BlockDevice& s, ByteCount in, ByteCount done, ByteCount n) { return s.writeAt(in, src.subspan(done, n)); });
    }

private:
    template <class Fn> Expected<void> forEach(ByteCount offset, ByteCount length, Fn fn) {
        if (auto r = checkRange(offset, length); !r) return r;
        const ByteCount n = m_stripes.size();
        ByteCount done = 0;
        while (done < length) {
            const ByteCount pos = offset + done;
            const ByteCount chunk = pos / m_stripeSize;          // global chunk index
            const ByteCount inChunk = pos % m_stripeSize;
            const ByteCount stripe = chunk % n;
            const ByteCount inStripe = (chunk / n) * m_stripeSize + inChunk;
            const ByteCount take = std::min(m_stripeSize - inChunk, length - done);
            if (auto r = fn(*m_stripes[stripe], inStripe, done, take); !r) return r;
            done += take;
        }
        return {};
    }
    std::vector<BlockDevicePtr> m_stripes;
    ByteCount m_stripeSize;
    std::string m_name;
    Geometry m_geometry;
};

} // namespace

// ----------------------------------------------------------------------------- model

std::uint64_t LogicalVolume::extents() const {
    std::uint64_t n = 0;
    for (const auto& s : segments) n = std::max(n, s.startExtent + s.extentCount);
    return n;
}

bool LogicalVolume::visible() const { return std::find(status.begin(), status.end(), "VISIBLE") != status.end(); }

Expected<void> VolumeGroup::parseText(const std::string& text) {
    Parser parser(text);
    auto root = parser.parseAll();
    if (!root) return fail(root.error());
    const Node* vg = nullptr;
    for (const auto& n : root->items)
        if (n.isSection) vg = &n;
    if (!vg) return fail(ErrorCategory::InvalidFormat, "LVM metadata has no volume group section");
    m_name = vg->key;
    m_id = vg->strOr("id");
    m_seqno = vg->numOr("seqno", 0);
    m_extentSize = vg->numOr("extent_size", 0);
    if (m_extentSize == 0) return fail(ErrorCategory::InvalidFormat, "LVM metadata: extent_size missing");
    std::map<std::string, PhysicalVolume> pvs;
    if (const Node* pvsec = vg->child("physical_volumes"))
        for (const auto& p : pvsec->items) {
            if (!p.isSection) continue;
            PhysicalVolume pv;
            pv.name = p.key;
            pv.id = p.strOr("id");
            pv.deviceHint = p.strOr("device");
            pv.deviceSizeSectors = p.numOr("dev_size", 0);
            pv.peStartSectors = p.numOr("pe_start", 0);
            pv.peCount = p.numOr("pe_count", 0);
            // keep already-seen devices
            if (auto it = m_pvs.find(pv.name); it != m_pvs.end() && it->second.id == pv.id) pv.device = it->second.device;
            pvs[pv.name] = std::move(pv);
        }
    std::vector<LogicalVolume> lvs;
    if (const Node* lvsec = vg->child("logical_volumes"))
        for (const auto& l : lvsec->items) {
            if (!l.isSection) continue;
            LogicalVolume lv;
            lv.name = l.key;
            lv.id = l.strOr("id");
            if (const Node* st = l.child("status"))
                for (const auto& s : st->items)
                    if (s.isStr) lv.status.push_back(s.str);
            for (const auto& seg : l.items) {
                if (!seg.isSection || seg.key.rfind("segment", 0) != 0) continue;
                LvmSegment s;
                s.startExtent = seg.numOr("start_extent", 0);
                s.extentCount = seg.numOr("extent_count", 0);
                s.type = seg.strOr("type");
                s.stripeCount = static_cast<std::uint32_t>(seg.numOr("stripe_count", 1));
                s.stripeSizeSectors = seg.numOr("stripe_size", 0);
                if (const Node* st = seg.child("stripes"))
                    for (std::size_t i = 0; i + 1 < st->items.size(); i += 2)
                        if (st->items[i].isStr && st->items[i + 1].isNum) s.stripes.push_back(LvmStripe{st->items[i].str, st->items[i + 1].num});
                lv.segments.push_back(std::move(s));
            }
            std::sort(lv.segments.begin(), lv.segments.end(), [](const LvmSegment& a, const LvmSegment& b) { return a.startExtent < b.startExtent; });
            lvs.push_back(std::move(lv));
        }
    m_pvs = std::move(pvs);
    m_lvs = std::move(lvs);
    m_text = text;
    return {};
}

Expected<VolumeGroup> VolumeGroup::fromPv(std::shared_ptr<BlockDevice> pv) {
    VolumeGroup vg;
    if (auto r = vg.addPv(std::move(pv)); !r) return fail(r.error());
    return vg;
}

Expected<void> VolumeGroup::addPv(std::shared_ptr<BlockDevice> pv) {
    if (!pv) return fail(ErrorCategory::InvalidArgument, "null device");
    auto md = readPvMetadata(*pv);
    if (!md) return fail(md.error());
    // Parse into a scratch group first so a foreign PV cannot clobber this one.
    VolumeGroup fresh;
    fresh.m_pvs = m_pvs;
    if (auto r = fresh.parseText(md->text); !r) return r;
    if (!m_id.empty() && fresh.m_id != m_id) return fail(ErrorCategory::InvalidArgument, "PV belongs to volume group " + fresh.m_name + ", not " + m_name);
    if (m_id.empty() || fresh.m_seqno >= m_seqno) {
        m_name = fresh.m_name;
        m_id = fresh.m_id;
        m_seqno = fresh.m_seqno;
        m_extentSize = fresh.m_extentSize;
        m_lvs = fresh.m_lvs;
        m_text = fresh.m_text;
        m_pvs = fresh.m_pvs;
    }
    // Attach the device to the PV whose id matches (ids are stored without hyphens on disk).
    const std::string hyphenated = hyphenate(md->pvUuid);
    bool found = false;
    for (auto& [name, p] : m_pvs)
        if (p.id == hyphenated || p.id == md->pvUuid) {
            p.device = pv;
            found = true;
        }
    if (!found) return fail(ErrorCategory::InvalidFormat, "PV " + hyphenated + " is not listed in its own volume group metadata");
    return {};
}

const LogicalVolume* VolumeGroup::lv(const std::string& name) const {
    for (const auto& l : m_lvs)
        if (l.name == name) return &l;
    return nullptr;
}

std::vector<std::string> VolumeGroup::missingPvs(const LogicalVolume& lv) const {
    std::vector<std::string> out;
    for (const auto& s : lv.segments)
        for (const auto& st : s.stripes) {
            auto it = m_pvs.find(st.pv);
            if (it == m_pvs.end() || !it->second.device)
                if (std::find(out.begin(), out.end(), st.pv) == out.end()) out.push_back(st.pv);
        }
    return out;
}

std::vector<std::string> VolumeGroup::unsupportedSegments(const LogicalVolume& lv) const {
    std::vector<std::string> out;
    for (const auto& s : lv.segments)
        if (s.type != "striped" && std::find(out.begin(), out.end(), s.type) == out.end()) out.push_back(s.type);
    return out;
}

Expected<std::shared_ptr<BlockDevice>> VolumeGroup::openLv(const std::string& name, bool readOnly) const {
    const LogicalVolume* lv = this->lv(name);
    if (!lv) return fail(ErrorCategory::NotFound, "no logical volume " + name + " in " + m_name);
    if (auto u = unsupportedSegments(*lv); !u.empty()) return fail(ErrorCategory::Unsupported, "segment type " + u.front() + " is not mapped yet");
    if (auto m = missingPvs(*lv); !m.empty()) return fail(ErrorCategory::NotFound, "physical volume " + m.front() + " of " + m_name + " has not been seen");
    std::vector<BlockDevicePtr> parts;
    std::uint64_t expectExtent = 0;
    for (const auto& seg : lv->segments) {
        if (seg.startExtent != expectExtent) return fail(ErrorCategory::InvalidFormat, "LV " + name + " has a gap in its segments");
        expectExtent += seg.extentCount;
        if (seg.stripeCount != seg.stripes.size() || seg.stripes.empty()) return fail(ErrorCategory::InvalidFormat, "LV " + name + ": stripe list does not match stripe_count");
        std::vector<BlockDevicePtr> stripeDevs;
        const std::uint64_t perStripe = seg.extentCount / seg.stripeCount;
        for (const auto& st : seg.stripes) {
            const PhysicalVolume& pv = m_pvs.at(st.pv);
            const ByteCount off = (pv.peStartSectors + st.startExtent * m_extentSize) * 512;
            const ByteCount len = perStripe * extentBytes();
            auto slice = SliceDevice::create(pv.device, Region{off, len}, m_name + "/" + name + "@" + st.pv);
            if (!slice) return fail(slice.error());
            stripeDevs.push_back(*slice);
        }
        if (seg.stripeCount == 1) {
            parts.push_back(stripeDevs.front());
        } else {
            if (seg.stripeSizeSectors == 0) return fail(ErrorCategory::InvalidFormat, "striped segment without stripe_size");
            parts.push_back(std::make_shared<StripedDevice>(std::move(stripeDevs), seg.stripeSizeSectors * 512, m_name + "/" + name + " (striped)"));
        }
    }
    std::shared_ptr<BlockDevice> dev;
    if (parts.size() == 1) {
        dev = parts.front();
    } else {
        auto cat = ConcatDevice::create(std::move(parts), m_name + "/" + name);
        if (!cat) return fail(cat.error());
        dev = *cat;
    }
    if (readOnly) dev = std::make_shared<ReadOnlyDevice>(dev);
    return dev;
}

} // namespace stein::volume
