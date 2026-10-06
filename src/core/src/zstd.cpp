// SPDX-License-Identifier: MIT
#include "stein/core/zstd.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace stein::compress {

// ---------------------------------------------------------------- XXH64

std::uint64_t xxh64(std::span<const std::byte> data, std::uint64_t seed) {
    constexpr std::uint64_t P1 = 0x9E3779B185EBCA87ull, P2 = 0xC2B2AE3D27D4EB4Full, P3 = 0x165667B19E3779F9ull,
                            P4 = 0x85EBCA77C2B2AE63ull, P5 = 0x27D4EB2F165667C5ull;
    auto rotl = [](std::uint64_t v, int r) { return (v << r) | (v >> (64 - r)); };
    auto round = [&](std::uint64_t acc, std::uint64_t in) { return rotl(acc + in * P2, 31) * P1; };
    auto merge = [&](std::uint64_t acc, std::uint64_t v) { return (acc ^ round(0, v)) * P1 + P4; };
    const std::byte* p = data.data();
    const std::byte* end = p + data.size();
    std::uint64_t h;
    if (data.size() >= 32) {
        std::uint64_t v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
        while (p + 32 <= end) {
            v1 = round(v1, loadLe64(p));
            v2 = round(v2, loadLe64(p + 8));
            v3 = round(v3, loadLe64(p + 16));
            v4 = round(v4, loadLe64(p + 24));
            p += 32;
        }
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
        h = merge(h, v1);
        h = merge(h, v2);
        h = merge(h, v3);
        h = merge(h, v4);
    } else {
        h = seed + P5;
    }
    h += data.size();
    while (p + 8 <= end) {
        h ^= round(0, loadLe64(p));
        h = rotl(h, 27) * P1 + P4;
        p += 8;
    }
    if (p + 4 <= end) {
        h ^= std::uint64_t{loadLe32(p)} * P1;
        h = rotl(h, 23) * P2 + P3;
        p += 4;
    }
    while (p < end) {
        h ^= std::to_integer<std::uint64_t>(*p) * P5;
        h = rotl(h, 11) * P1;
        ++p;
    }
    h ^= h >> 33;
    h *= P2;
    h ^= h >> 29;
    h *= P3;
    h ^= h >> 32;
    return h;
}

namespace {

// ---------------------------------------------------------------- bit readers

// Forward reader for FSE table descriptions (bits consumed LSB first).
struct ForwardBits {
    const std::uint8_t* p;
    std::size_t len, pos = 0;   // bit position
    std::uint32_t read(int n) {
        std::uint32_t v = 0;
        for (int i = 0; i < n; ++i) {
            const std::size_t bit = pos + static_cast<std::size_t>(i);
            if (bit / 8 < len) v |= static_cast<std::uint32_t>((p[bit / 8] >> (bit % 8)) & 1) << i;
        }
        pos += static_cast<std::size_t>(n);
        return v;
    }
    std::size_t bytesConsumed() const { return (pos + 7) / 8; }
};

// Backward reader (RFC 8878 §4.1): starts at the last byte, whose highest set bit is padding.
// Bits are consumed from the top of the accumulator; `consumed` counts real bits so that an
// overrun (which the format allows and uses as a terminator in some places) is detectable.
struct BackwardBits {
    const std::uint8_t* base = nullptr;
    std::ptrdiff_t bytePos = -1;   // next byte to load, moving down
    std::uint64_t acc = 0;
    int bits = 0;                  // valid bits in acc
    std::size_t totalBits = 0, consumed = 0;

    static Expected<BackwardBits> open(std::span<const std::uint8_t> s) {
        if (s.empty()) return fail(ErrorCategory::InvalidFormat, "empty zstd bitstream");
        const std::uint8_t last = s.back();
        if (last == 0) return fail(ErrorCategory::InvalidFormat, "zstd bitstream without a sentinel bit");
        BackwardBits b;
        b.base = s.data();
        int pad = 0;
        while (!((last >> (7 - pad)) & 1)) ++pad;
        b.acc = last & ((1u << (7 - pad)) - 1);
        b.bits = 7 - pad;
        b.bytePos = static_cast<std::ptrdiff_t>(s.size()) - 2;
        b.totalBits = s.size() * 8 - static_cast<std::size_t>(pad) - 1;
        return b;
    }
    void refill() {
        while (bits <= 56) {
            const std::uint64_t byte = bytePos >= 0 ? base[bytePos] : 0;
            --bytePos;
            acc = (acc << 8) | byte;
            bits += 8;
        }
    }
    std::uint32_t peek(int n) {
        if (n == 0) return 0;
        if (bits < n) refill();
        return static_cast<std::uint32_t>((acc >> (bits - n)) & ((std::uint64_t{1} << n) - 1));
    }
    void skip(int n) {
        bits -= n;
        consumed += static_cast<std::size_t>(n);
    }
    std::uint32_t read(int n) {
        const std::uint32_t v = peek(n);
        skip(n);
        return v;
    }
    bool overrun() const { return consumed > totalBits; }
    bool finished() const { return consumed == totalBits; }
};

// ---------------------------------------------------------------- FSE

struct FseEntry {
    std::uint8_t symbol = 0, nbBits = 0;
    std::uint16_t baseline = 0;
};

struct FseTable {
    int accuracyLog = 0;
    std::vector<FseEntry> entries;   // 1 << accuracyLog
};

Expected<FseTable> buildFse(std::span<const std::int16_t> probs, int accuracyLog) {
    const std::size_t size = std::size_t{1} << accuracyLog;
    FseTable t;
    t.accuracyLog = accuracyLog;
    t.entries.resize(size);
    std::vector<std::uint8_t> symbols(size, 0);
    std::size_t high = size - 1;
    // Symbols with probability -1 ("less than one") take the top cells.
    for (std::size_t s = 0; s < probs.size(); ++s)
        if (probs[s] == -1) {
            if (high >= size) return fail(ErrorCategory::InvalidFormat, "FSE distribution overflows the table");
            symbols[high--] = static_cast<std::uint8_t>(s);
        }
    const std::size_t step = (size >> 1) + (size >> 3) + 3, mask = size - 1;
    std::size_t pos = 0;
    for (std::size_t s = 0; s < probs.size(); ++s) {
        if (probs[s] <= 0) continue;
        for (int i = 0; i < probs[s]; ++i) {
            symbols[pos] = static_cast<std::uint8_t>(s);
            do pos = (pos + step) & mask;
            while (pos > high);
        }
    }
    if (pos != 0) return fail(ErrorCategory::InvalidFormat, "FSE distribution does not fill the table");
    std::vector<std::uint16_t> next(probs.size());
    for (std::size_t s = 0; s < probs.size(); ++s) next[s] = probs[s] == -1 ? 1 : static_cast<std::uint16_t>(std::max<int>(probs[s], 0));
    for (std::size_t i = 0; i < size; ++i) {
        const std::uint8_t sym = symbols[i];
        const std::uint16_t x = next[sym]++;
        int hb = 0;   // highest set bit of x
        while ((std::uint32_t{2} << hb) <= x) ++hb;
        const int nbBits = accuracyLog - hb;
        t.entries[i].symbol = sym;
        t.entries[i].nbBits = static_cast<std::uint8_t>(nbBits);
        t.entries[i].baseline = static_cast<std::uint16_t>((static_cast<std::uint32_t>(x) << nbBits) - size);
    }
    return t;
}

// Read an FSE table description (RFC 8878 §4.1.1). Returns the table and the bytes used.
Expected<std::pair<FseTable, std::size_t>> readFseDescription(std::span<const std::uint8_t> in, int maxAccuracy, std::size_t maxSymbol) {
    ForwardBits br{in.data(), in.size()};
    const int accuracyLog = 5 + static_cast<int>(br.read(4));
    if (accuracyLog > maxAccuracy) return fail(ErrorCategory::InvalidFormat, "FSE accuracy log " + std::to_string(accuracyLog) + " exceeds the limit");
    std::vector<std::int16_t> probs;
    int remaining = (1 << accuracyLog) + 1;
    while (remaining > 1 && probs.size() <= maxSymbol) {
        int bitsNeeded = 0;
        while ((1 << bitsNeeded) <= remaining) ++bitsNeeded;   // bits to hold remaining+1 values: ceil(log2(remaining+1))
        const std::uint32_t threshold = (std::uint32_t{1} << bitsNeeded) - 1 - static_cast<std::uint32_t>(remaining);
        std::uint32_t value = br.read(bitsNeeded - 1);
        if (value < threshold) {
            // small value: fits in bitsNeeded-1 bits
        } else {
            value = (value | (br.read(1) << (bitsNeeded - 1)));
            if (value >= (std::uint32_t{1} << (bitsNeeded - 1)))   // large value: subtract the threshold
                value -= threshold;
        }
        const int prob = static_cast<int>(value) - 1;
        probs.push_back(static_cast<std::int16_t>(prob));
        remaining -= prob == -1 ? 1 : prob;
        if (prob == 0) {
            for (;;) {
                const std::uint32_t rep = br.read(2);
                for (std::uint32_t i = 0; i < rep && probs.size() <= maxSymbol; ++i) probs.push_back(0);
                if (rep != 3) break;
            }
        }
        if (br.pos > in.size() * 8) return fail(ErrorCategory::InvalidFormat, "FSE description runs past its input");
    }
    if (remaining != 1) return fail(ErrorCategory::InvalidFormat, "FSE distribution does not sum to the table size");
    if (probs.size() > maxSymbol + 1) return fail(ErrorCategory::InvalidFormat, "FSE description has too many symbols");
    auto t = buildFse(probs, accuracyLog);
    if (!t) return fail(t.error());
    return std::pair{std::move(*t), br.bytesConsumed()};
}

struct FseState {
    const FseTable* table = nullptr;
    std::uint32_t state = 0;
    void init(BackwardBits& b) { state = b.read(table->accuracyLog); }
    std::uint8_t symbol() const { return table->entries[state].symbol; }
    void update(BackwardBits& b) {
        const auto& e = table->entries[state];
        state = e.baseline + b.read(e.nbBits);
    }
};

// ---------------------------------------------------------------- Huffman

struct HuffTable {
    int maxBits = 0;
    struct Entry {
        std::uint8_t symbol = 0, nbBits = 0;
    };
    std::vector<Entry> entries;   // indexed by the next maxBits bits
};

Expected<HuffTable> buildHuffman(std::span<const std::uint8_t> weights) {
    // The last weight is implied: the sum of 2^(w-1) must reach a power of two.
    std::uint32_t sum = 0;
    int maxW = 0;
    for (auto w : weights) {
        if (w > 11) return fail(ErrorCategory::InvalidFormat, "Huffman weight above 11");
        if (w) sum += 1u << (w - 1);
        maxW = std::max<int>(maxW, w);
    }
    if (sum == 0) return fail(ErrorCategory::InvalidFormat, "Huffman tree with no symbols");
    int maxBits = 0;
    while ((1u << maxBits) < sum + 1) ++maxBits;   // smallest power of two above the sum
    const std::uint32_t left = (1u << maxBits) - sum;
    int lastW = 0;
    while ((1u << lastW) < left) ++lastW;
    if ((1u << lastW) != left) return fail(ErrorCategory::InvalidFormat, "Huffman weights do not complete a tree");
    ++lastW;
    std::vector<std::uint8_t> all(weights.begin(), weights.end());
    all.push_back(static_cast<std::uint8_t>(lastW));
    maxW = std::max(maxW, lastW);
    if (all.size() > 256) return fail(ErrorCategory::InvalidFormat, "more than 256 Huffman symbols");
    HuffTable t;
    t.maxBits = maxBits;
    t.entries.resize(std::size_t{1} << maxBits);
    std::size_t pos = 0;
    for (int w = 1; w <= maxW; ++w)
        for (std::size_t sym = 0; sym < all.size(); ++sym) {
            if (all[sym] != w) continue;
            const std::size_t n = std::size_t{1} << (w - 1);
            if (pos + n > t.entries.size()) return fail(ErrorCategory::InvalidFormat, "Huffman table overflow");
            for (std::size_t i = 0; i < n; ++i) t.entries[pos + i] = {static_cast<std::uint8_t>(sym), static_cast<std::uint8_t>(maxBits + 1 - w)};
            pos += n;
        }
    if (pos != t.entries.size()) return fail(ErrorCategory::InvalidFormat, "Huffman table underflow");
    return t;
}

// Huffman tree description (RFC 8878 §4.2.1). Returns the table and the bytes used.
Expected<std::pair<HuffTable, std::size_t>> readHuffmanTree(std::span<const std::uint8_t> in) {
    if (in.empty()) return fail(ErrorCategory::InvalidFormat, "missing Huffman tree header");
    const std::uint8_t h = in[0];
    std::vector<std::uint8_t> weights;
    std::size_t used = 1;
    if (h >= 128) {
        const std::size_t n = h - 127, bytes = (n + 1) / 2;
        if (1 + bytes > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated Huffman weights");
        for (std::size_t i = 0; i < n; ++i) weights.push_back(i % 2 == 0 ? in[1 + i / 2] >> 4 : in[1 + i / 2] & 0xF);
        used += bytes;
    } else {
        const std::size_t comp = h;
        if (1 + comp > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated Huffman weight stream");
        auto desc = readFseDescription(in.subspan(1, comp), 6, 255);
        if (!desc) return fail(desc.error());
        const FseTable& table = desc->first;
        if (desc->second >= comp) return fail(ErrorCategory::InvalidFormat, "Huffman weight stream has no bitstream");
        auto br = BackwardBits::open(in.subspan(1 + desc->second, comp - desc->second));
        if (!br) return fail(br.error());
        FseState s1{&table}, s2{&table};
        s1.init(*br);
        s2.init(*br);
        while (weights.size() < 255) {
            weights.push_back(s1.symbol());
            s1.update(*br);
            if (br->overrun()) {
                weights.push_back(s2.symbol());
                break;
            }
            weights.push_back(s2.symbol());
            s2.update(*br);
            if (br->overrun()) {
                weights.push_back(s1.symbol());
                break;
            }
        }
        used += comp;
    }
    auto t = buildHuffman(weights);
    if (!t) return fail(t.error());
    return std::pair{std::move(*t), used};
}

Expected<void> huffmanStream(const HuffTable& t, std::span<const std::uint8_t> in, std::span<std::uint8_t> out) {
    auto br = BackwardBits::open(in);
    if (!br) return fail(br.error());
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto& e = t.entries[br->peek(t.maxBits)];
        br->skip(e.nbBits);
        out[i] = e.symbol;
        if (br->overrun()) return fail(ErrorCategory::InvalidFormat, "Huffman literal stream too short");
    }
    if (!br->finished()) return fail(ErrorCategory::InvalidFormat, "Huffman literal stream has trailing bits");
    return {};
}

// ---------------------------------------------------------------- sequences

constexpr std::uint8_t kLlBits[36] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
constexpr std::uint32_t kLlBase[36] = {0,  1,  2,  3,  4,  5,  6,  7,  8,   9,   10,  11,  12,   13,   14,   15,   16,   18,
                                       20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536};
constexpr std::uint8_t kMlBits[53] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
constexpr std::uint32_t kMlBase[53] = {3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,  21,  22,  23,   24,   25,   26,   27,   28,   29,
                                       30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539};
constexpr std::int16_t kLlDefault[36] = {4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1};
constexpr std::int16_t kMlDefault[53] = {1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1};
constexpr std::int16_t kOfDefault[29] = {1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};

struct FrameState {
    FseTable ll, of, ml;          // current tables (repeatable across blocks)
    bool haveLl = false, haveOf = false, haveMl = false;
    HuffTable huff;
    bool haveHuff = false;
    std::uint32_t rep[3] = {1, 4, 8};
};

// Read one table according to its 2-bit mode; returns bytes used.
Expected<std::size_t> readSeqTable(std::uint32_t mode, std::span<const std::uint8_t> in, FseTable& table, bool& have,
                                   std::span<const std::int16_t> predefined, int predefinedLog, int maxLog, std::size_t maxSymbol, const char* what) {
    switch (mode) {
    case 0: {
        auto t = buildFse(predefined, predefinedLog);
        if (!t) return fail(t.error());
        table = std::move(*t);
        have = true;
        return 0;
    }
    case 1: {
        if (in.empty()) return fail(ErrorCategory::InvalidFormat, std::string("missing RLE symbol for ") + what);
        if (in[0] > maxSymbol) return fail(ErrorCategory::InvalidFormat, std::string("RLE symbol out of range for ") + what);
        table.accuracyLog = 0;
        table.entries.assign(1, FseEntry{in[0], 0, 0});
        have = true;
        return 1;
    }
    case 2: {
        auto d = readFseDescription(in, maxLog, maxSymbol);
        if (!d) return fail(d.error());
        table = std::move(d->first);
        have = true;
        return d->second;
    }
    default:
        if (!have) return fail(ErrorCategory::InvalidFormat, std::string("repeat mode without a previous table for ") + what);
        return 0;
    }
}

struct Output {
    std::byte* data;
    std::size_t cap, pos = 0, frameStart = 0;
};

Expected<void> decodeCompressedBlock(std::span<const std::uint8_t> block, FrameState& fs, Output& out) {
    // ---- literals section
    if (block.empty()) return fail(ErrorCategory::InvalidFormat, "empty compressed block");
    const std::uint8_t b0 = block[0];
    const std::uint32_t litType = b0 & 3, sizeFormat = (b0 >> 2) & 3;
    std::size_t regen = 0, comp = 0, hdr = 0;
    int streams = 1;
    if (litType <= 1) {
        if (sizeFormat == 1) {
            if (block.size() < 2) return fail(ErrorCategory::InvalidFormat, "truncated literals header");
            regen = (b0 >> 4) | (std::size_t{block[1]} << 4);
            hdr = 2;
        } else if (sizeFormat == 3) {
            if (block.size() < 3) return fail(ErrorCategory::InvalidFormat, "truncated literals header");
            regen = (b0 >> 4) | (std::size_t{block[1]} << 4) | (std::size_t{block[2]} << 12);
            hdr = 3;
        } else {
            regen = b0 >> 3;
            hdr = 1;
        }
    } else {
        if (sizeFormat == 0 || sizeFormat == 1) {
            if (block.size() < 3) return fail(ErrorCategory::InvalidFormat, "truncated literals header");
            regen = (b0 >> 4) | (static_cast<std::size_t>(block[1] & 0x3F) << 4);
            comp = (block[1] >> 6) | (std::size_t{block[2]} << 2);
            hdr = 3;
            streams = sizeFormat == 0 ? 1 : 4;
        } else if (sizeFormat == 2) {
            if (block.size() < 4) return fail(ErrorCategory::InvalidFormat, "truncated literals header");
            regen = (b0 >> 4) | (std::size_t{block[1]} << 4) | (static_cast<std::size_t>(block[2] & 3) << 12);
            comp = (block[2] >> 2) | (std::size_t{block[3]} << 6);
            hdr = 4;
            streams = 4;
        } else {
            if (block.size() < 5) return fail(ErrorCategory::InvalidFormat, "truncated literals header");
            regen = (b0 >> 4) | (std::size_t{block[1]} << 4) | (static_cast<std::size_t>(block[2] & 0x3F) << 12);
            comp = (block[2] >> 6) | (std::size_t{block[3]} << 2) | (std::size_t{block[4]} << 10);
            hdr = 5;
            streams = 4;
        }
    }
    if (regen > (1u << 20)) return fail(ErrorCategory::InvalidFormat, "literals size above the block limit");
    std::vector<std::uint8_t> literals(regen);
    std::size_t pos = hdr;
    if (litType == 0) {
        if (pos + regen > block.size()) return fail(ErrorCategory::InvalidFormat, "raw literals run past the block");
        std::memcpy(literals.data(), block.data() + pos, regen);
        pos += regen;
    } else if (litType == 1) {
        if (pos >= block.size()) return fail(ErrorCategory::InvalidFormat, "RLE literals without a byte");
        std::fill(literals.begin(), literals.end(), block[pos++]);
    } else {
        if (pos + comp > block.size()) return fail(ErrorCategory::InvalidFormat, "compressed literals run past the block");
        std::span<const std::uint8_t> lit = block.subspan(pos, comp);
        if (litType == 2) {
            auto tree = readHuffmanTree(lit);
            if (!tree) return fail(tree.error());
            fs.huff = std::move(tree->first);
            fs.haveHuff = true;
            lit = lit.subspan(tree->second);
        } else if (!fs.haveHuff) {
            return fail(ErrorCategory::InvalidFormat, "treeless literals without a previous Huffman tree");
        }
        if (streams == 1) {
            if (auto r = huffmanStream(fs.huff, lit, literals); !r) return fail(r.error());
        } else {
            if (lit.size() < 6) return fail(ErrorCategory::InvalidFormat, "missing Huffman jump table");
            const std::size_t s1 = lit[0] | (std::size_t{lit[1]} << 8), s2 = lit[2] | (std::size_t{lit[3]} << 8), s3 = lit[4] | (std::size_t{lit[5]} << 8);
            if (6 + s1 + s2 + s3 > lit.size()) return fail(ErrorCategory::InvalidFormat, "Huffman streams run past the literals");
            const std::size_t s4 = lit.size() - 6 - s1 - s2 - s3;
            const std::size_t per = (regen + 3) / 4;
            if (per * 3 > regen) return fail(ErrorCategory::InvalidFormat, "literals too short for four streams");
            const std::size_t sizes[4] = {s1, s2, s3, s4};
            std::size_t off = 6, outOff = 0;
            for (int i = 0; i < 4; ++i) {
                const std::size_t n = i < 3 ? per : regen - 3 * per;
                if (auto r = huffmanStream(fs.huff, lit.subspan(off, sizes[i]), std::span<std::uint8_t>(literals).subspan(outOff, n)); !r) return fail(r.error());
                off += sizes[i];
                outOff += n;
            }
        }
        pos += comp;
    }
    // ---- sequences section
    if (pos >= block.size()) return fail(ErrorCategory::InvalidFormat, "block has no sequences section");
    std::size_t nbSeq = block[pos++];
    if (nbSeq == 255) {
        if (pos + 2 > block.size()) return fail(ErrorCategory::InvalidFormat, "truncated sequence count");
        nbSeq = block[pos] + (std::size_t{block[pos + 1]} << 8) + 0x7F00;
        pos += 2;
    } else if (nbSeq >= 128) {
        if (pos >= block.size()) return fail(ErrorCategory::InvalidFormat, "truncated sequence count");
        nbSeq = ((nbSeq - 128) << 8) + block[pos++];
    }
    auto emitLiterals = [&](std::size_t n, std::size_t& litPos) -> Expected<void> {
        if (litPos + n > literals.size()) return fail(ErrorCategory::InvalidFormat, "sequence uses more literals than the block has");
        if (out.pos + n > out.cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the zstd data");
        std::memcpy(out.data + out.pos, literals.data() + litPos, n);
        out.pos += n;
        litPos += n;
        return {};
    };
    std::size_t litPos = 0;
    if (nbSeq == 0) {
        if (auto r = emitLiterals(literals.size(), litPos); !r) return r;
        return {};
    }
    if (pos >= block.size()) return fail(ErrorCategory::InvalidFormat, "truncated sequences header");
    const std::uint8_t modes = block[pos++];
    if (modes & 3) return fail(ErrorCategory::InvalidFormat, "reserved bits set in the sequences header");
    std::span<const std::uint8_t> rest = block.subspan(pos);
    auto used = readSeqTable(modes >> 6, rest, fs.ll, fs.haveLl, kLlDefault, 6, 9, 35, "literal lengths");
    if (!used) return fail(used.error());
    rest = rest.subspan(*used);
    used = readSeqTable((modes >> 4) & 3, rest, fs.of, fs.haveOf, kOfDefault, 5, 8, 31, "offsets");
    if (!used) return fail(used.error());
    rest = rest.subspan(*used);
    used = readSeqTable((modes >> 2) & 3, rest, fs.ml, fs.haveMl, kMlDefault, 6, 9, 52, "match lengths");
    if (!used) return fail(used.error());
    rest = rest.subspan(*used);
    auto br = BackwardBits::open(rest);
    if (!br) return fail(br.error());
    FseState ll{&fs.ll}, of{&fs.of}, ml{&fs.ml};
    ll.init(*br);
    of.init(*br);
    ml.init(*br);
    for (std::size_t i = 0; i < nbSeq; ++i) {
        const std::uint8_t ofCode = of.symbol(), mlCode = ml.symbol(), llCode = ll.symbol();
        if (ofCode > 31 || mlCode > 52 || llCode > 35) return fail(ErrorCategory::InvalidFormat, "sequence code out of range");
        std::uint32_t offsetValue = (std::uint32_t{1} << ofCode) + br->read(ofCode);
        const std::uint32_t matchLength = kMlBase[mlCode] + br->read(kMlBits[mlCode]);
        const std::uint32_t literalLength = kLlBase[llCode] + br->read(kLlBits[llCode]);
        if (br->overrun()) return fail(ErrorCategory::InvalidFormat, "sequence bitstream too short");
        if (i + 1 < nbSeq) {
            ll.update(*br);
            ml.update(*br);
            of.update(*br);
        }
        std::uint32_t offset;
        if (offsetValue > 3) {
            offset = offsetValue - 3;
            fs.rep[2] = fs.rep[1];
            fs.rep[1] = fs.rep[0];
            fs.rep[0] = offset;
        } else {
            std::uint32_t idx = offsetValue - 1;
            if (literalLength == 0) ++idx;
            if (idx == 0) {
                offset = fs.rep[0];
            } else {
                offset = idx < 3 ? fs.rep[idx] : fs.rep[0] - 1;
                if (idx > 1) fs.rep[2] = fs.rep[1];
                fs.rep[1] = fs.rep[0];
                fs.rep[0] = offset;
            }
        }
        if (auto r = emitLiterals(literalLength, litPos); !r) return r;
        if (offset == 0 || offset > out.pos - out.frameStart) return fail(ErrorCategory::InvalidFormat, "match offset reaches before the frame start");
        if (out.pos + matchLength > out.cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the zstd data");
        for (std::uint32_t k = 0; k < matchLength; ++k) out.data[out.pos + k] = out.data[out.pos + k - offset];
        out.pos += matchLength;
    }
    if (!br->finished()) return fail(ErrorCategory::InvalidFormat, "sequence bitstream not fully consumed");
    if (auto r = emitLiterals(literals.size() - litPos, litPos); !r) return r;
    return {};
}

// ---------------------------------------------------------------- frames

constexpr std::uint32_t kMagic = 0xFD2FB528u;

struct FrameHeader {
    std::size_t size = 0;   // header bytes after the magic
    bool singleSegment = false, checksum = false, hasContentSize = false;
    std::uint64_t contentSize = 0;
    std::uint32_t dictId = 0;
};

Expected<FrameHeader> parseFrameHeader(std::span<const std::uint8_t> in) {
    if (in.empty()) return fail(ErrorCategory::InvalidFormat, "truncated zstd frame header");
    FrameHeader h;
    const std::uint8_t fhd = in[0];
    const int fcsFlag = fhd >> 6, dictFlag = fhd & 3;
    h.singleSegment = (fhd >> 5) & 1;
    h.checksum = (fhd >> 2) & 1;
    if ((fhd >> 3) & 1) return fail(ErrorCategory::InvalidFormat, "reserved bit set in the zstd frame header");
    std::size_t pos = 1;
    if (!h.singleSegment) pos += 1;   // window descriptor
    const std::size_t dictBytes = dictFlag == 0 ? 0 : dictFlag == 1 ? 1 : dictFlag == 2 ? 2 : 4;
    const std::size_t fcsBytes = fcsFlag == 0 ? (h.singleSegment ? 1 : 0) : fcsFlag == 1 ? 2 : fcsFlag == 2 ? 4 : 8;
    if (pos + dictBytes + fcsBytes > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated zstd frame header");
    for (std::size_t i = 0; i < dictBytes; ++i) h.dictId |= std::uint32_t{in[pos + i]} << (8 * i);
    pos += dictBytes;
    if (fcsBytes) {
        for (std::size_t i = 0; i < fcsBytes; ++i) h.contentSize |= std::uint64_t{in[pos + i]} << (8 * i);
        if (fcsBytes == 2) h.contentSize += 256;
        h.hasContentSize = true;
    }
    pos += fcsBytes;
    h.size = pos;
    return h;
}

} // namespace

Expected<std::uint64_t> zstdContentSize(std::span<const std::byte> inBytes) {
    std::span<const std::uint8_t> in(reinterpret_cast<const std::uint8_t*>(inBytes.data()), inBytes.size());
    if (in.size() < 4 || loadLe32(inBytes.data()) != kMagic) return fail(ErrorCategory::InvalidFormat, "not a zstd frame");
    auto h = parseFrameHeader(in.subspan(4));
    if (!h) return fail(h.error());
    if (!h->hasContentSize) return fail(ErrorCategory::NotFound, "zstd frame does not announce its content size");
    return h->contentSize;
}

namespace {

Expected<std::size_t> decompressFrames(std::span<const std::byte> inBytes, std::span<std::byte> outBytes, bool firstFrameOnly) {
    std::span<const std::uint8_t> in(reinterpret_cast<const std::uint8_t*>(inBytes.data()), inBytes.size());
    Output out{outBytes.data(), outBytes.size()};
    std::size_t pos = 0;
    bool any = false;
    while (pos + 4 <= in.size()) {
        const std::uint32_t magic = loadLe32(inBytes.data() + pos);
        if ((magic & 0xFFFFFFF0u) == 0x184D2A50u) {   // skippable frame
            if (pos + 8 > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated skippable frame");
            const std::uint32_t len = loadLe32(inBytes.data() + pos + 4);
            if (pos + 8 + len > in.size()) return fail(ErrorCategory::InvalidFormat, "skippable frame runs past the input");
            pos += 8 + len;
            continue;
        }
        if (magic != kMagic) {
            if (any) break;   // trailing bytes after the last frame (sector padding)
            return fail(ErrorCategory::InvalidFormat, "not a zstd frame");
        }
        any = true;
        auto h = parseFrameHeader(in.subspan(pos + 4));
        if (!h) return fail(h.error());
        if (h->dictId != 0) return fail(ErrorCategory::Unsupported, "zstd frames that need a dictionary are not supported");
        pos += 4 + h->size;
        out.frameStart = out.pos;
        FrameState fs;
        for (;;) {
            if (pos + 3 > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated zstd block header");
            const std::uint32_t bh = in[pos] | (std::uint32_t{in[pos + 1]} << 8) | (std::uint32_t{in[pos + 2]} << 16);
            pos += 3;
            const bool last = bh & 1;
            const std::uint32_t type = (bh >> 1) & 3, size = bh >> 3;
            switch (type) {
            case 0:
                if (pos + size > in.size()) return fail(ErrorCategory::InvalidFormat, "raw block runs past the input");
                if (out.pos + size > out.cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the zstd data");
                std::memcpy(out.data + out.pos, in.data() + pos, size);
                out.pos += size;
                pos += size;
                break;
            case 1:
                if (pos >= in.size()) return fail(ErrorCategory::InvalidFormat, "RLE block without a byte");
                if (out.pos + size > out.cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the zstd data");
                std::memset(out.data + out.pos, in[pos], size);
                out.pos += size;
                pos += 1;
                break;
            case 2: {
                if (pos + size > in.size()) return fail(ErrorCategory::InvalidFormat, "compressed block runs past the input");
                if (auto r = decodeCompressedBlock(in.subspan(pos, size), fs, out); !r) return fail(r.error());
                pos += size;
                break;
            }
            default: return fail(ErrorCategory::InvalidFormat, "reserved zstd block type");
            }
            if (last) break;
        }
        if (h->hasContentSize && out.pos - out.frameStart != h->contentSize)
            return fail(ErrorCategory::InvalidFormat, "zstd frame produced " + std::to_string(out.pos - out.frameStart) + " bytes, header announced " + std::to_string(h->contentSize));
        if (h->checksum) {
            if (pos + 4 > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated zstd content checksum");
            const std::uint32_t want = loadLe32(inBytes.data() + pos);
            const std::uint32_t got = static_cast<std::uint32_t>(xxh64(outBytes.subspan(out.frameStart, out.pos - out.frameStart)));
            if (want != got) return fail(ErrorCategory::Integrity, "zstd content checksum mismatch");
            pos += 4;
        }
        if (firstFrameOnly) break;
    }
    if (!any) return fail(ErrorCategory::InvalidFormat, "no zstd frame in the input");
    return out.pos;
}

} // namespace

Expected<std::size_t> zstdDecompress(std::span<const std::byte> in, std::span<std::byte> out) { return decompressFrames(in, out, false); }
Expected<std::size_t> zstdDecompressFrame(std::span<const std::byte> in, std::span<std::byte> out) { return decompressFrames(in, out, true); }

} // namespace stein::compress
