// SPDX-License-Identifier: MIT
#include "stein/core/bzip2.hpp"

#include <array>
#include <cstring>
#include <vector>

namespace stein::compress {

namespace {

constexpr int kMaxGroups = 6, kGroupSize = 50, kMaxSymbols = 258, kMaxCodeLen = 20;

// bzip2 uses the "reflected" CRC-32 bit order's opposite: the MSB-first polynomial 0x04C11DB7.
std::uint32_t crcTable(unsigned i) {
    std::uint32_t c = i << 24;
    for (int k = 0; k < 8; ++k) c = (c & 0x80000000u) ? (c << 1) ^ 0x04C11DB7u : (c << 1);
    return c;
}

struct Bits {
    std::span<const std::byte> in;
    std::size_t pos = 0;
    std::uint64_t buf = 0;   // up to 32 requested bits plus 7 pending ones
    int count = 0;
    bool truncated = false;

    std::uint32_t get(int n) {
        while (count < n) {
            if (pos >= in.size()) {
                truncated = true;
                return 0;
            }
            buf = (buf << 8) | std::to_integer<std::uint8_t>(in[pos++]);
            count += 8;
        }
        const std::uint32_t v = static_cast<std::uint32_t>((buf >> (count - n)) & ((std::uint64_t{1} << n) - 1));
        count -= n;
        buf &= (std::uint64_t{1} << count) - 1;
        return v;
    }
};

struct Huffman {
    std::array<int, kMaxCodeLen + 2> limit{}, base{};
    std::array<std::uint16_t, kMaxSymbols> perm{};
    int minLen = 0, maxLen = 0;
};

// Canonical code construction (as in bzip2's hbCreateDecodeTables).
void buildTable(Huffman& h, const std::uint8_t* lengths, int symbols) {
    h.minLen = 32;
    h.maxLen = 0;
    for (int i = 0; i < symbols; ++i) {
        h.minLen = std::min<int>(h.minLen, lengths[i]);
        h.maxLen = std::max<int>(h.maxLen, lengths[i]);
    }
    int pp = 0;
    for (int len = h.minLen; len <= h.maxLen; ++len)
        for (int s = 0; s < symbols; ++s)
            if (lengths[s] == len) h.perm[pp++] = static_cast<std::uint16_t>(s);
    std::array<int, kMaxCodeLen + 2> count{};
    for (int s = 0; s < symbols; ++s) count[lengths[s] + 1]++;
    for (int i = 1; i < kMaxCodeLen + 2; ++i) count[i] += count[i - 1];   // now count[len] = first index of codes of length len
    int vec = 0;
    for (int len = h.minLen; len <= h.maxLen; ++len) {
        vec += count[len + 1] - count[len];
        h.limit[len] = vec - 1;
        vec <<= 1;
    }
    for (int len = h.minLen + 1; len <= h.maxLen; ++len) h.base[len] = ((h.limit[len - 1] + 1) << 1) - count[len];
    h.base[h.minLen] = -count[h.minLen];   // so that symbol index = code - base[len]... adjusted below
    // Recompute base in the classic form: base[len] = (count of codes shorter than len, cumulative) offset.
    int acc = 0;
    for (int len = h.minLen; len <= h.maxLen; ++len) {
        const int n = count[len + 1] - count[len];
        h.base[len] = acc - ((h.limit[len] + 1) - n);
        acc += n;
    }
}

int decodeSymbol(Bits& b, const Huffman& h) {
    int len = h.minLen;
    int code = static_cast<int>(b.get(len));
    while (len <= h.maxLen) {
        if (code <= h.limit[len]) {
            const int idx = code + h.base[len];
            return (idx >= 0 && idx < kMaxSymbols) ? h.perm[idx] : -1;
        }
        code = (code << 1) | static_cast<int>(b.get(1));
        ++len;
        if (b.truncated) return -1;
    }
    return -1;
}

Expected<std::size_t> decodeBlock(Bits& b, std::uint32_t blockSize100k, std::span<std::byte> out, std::size_t outPos, std::uint32_t& crcOut, const std::uint32_t* crcTab) {
    crcOut = b.get(32);
    const int randomised = static_cast<int>(b.get(1));
    if (randomised) return fail(ErrorCategory::Unsupported, "randomised bzip2 blocks (pre-0.9.5) are not supported");
    const std::uint32_t origPtr = b.get(24);
    // Symbol map: 16 groups of 16 byte values.
    std::uint8_t seqToUnseq[256];
    int nInUse = 0;
    const std::uint32_t used = b.get(16);
    for (int i = 0; i < 16; ++i) {
        if (!(used & (0x8000u >> i))) continue;
        const std::uint32_t bits = b.get(16);
        for (int j = 0; j < 16; ++j)
            if (bits & (0x8000u >> j)) seqToUnseq[nInUse++] = static_cast<std::uint8_t>(i * 16 + j);
    }
    if (nInUse == 0) return fail(ErrorCategory::InvalidFormat, "bzip2 block uses no symbols");
    const int alphaSize = nInUse + 2;
    const int nGroups = static_cast<int>(b.get(3));
    const int nSelectors = static_cast<int>(b.get(15));
    if (nGroups < 2 || nGroups > kMaxGroups || nSelectors < 1) return fail(ErrorCategory::InvalidFormat, "bzip2 block has a bad group/selector count");
    std::vector<std::uint8_t> selectors(static_cast<std::size_t>(nSelectors));
    {
        std::uint8_t mtf[kMaxGroups];
        for (int i = 0; i < nGroups; ++i) mtf[i] = static_cast<std::uint8_t>(i);
        for (int i = 0; i < nSelectors; ++i) {
            int j = 0;
            while (b.get(1)) {
                if (++j >= nGroups || b.truncated) return fail(ErrorCategory::InvalidFormat, "bzip2 selector out of range");
            }
            const std::uint8_t v = mtf[j];
            for (int k = j; k > 0; --k) mtf[k] = mtf[k - 1];
            mtf[0] = v;
            selectors[static_cast<std::size_t>(i)] = v;
        }
    }
    Huffman tables[kMaxGroups];
    for (int g = 0; g < nGroups; ++g) {
        std::uint8_t lengths[kMaxSymbols];
        int cur = static_cast<int>(b.get(5));
        for (int s = 0; s < alphaSize; ++s) {
            for (;;) {
                if (cur < 1 || cur > kMaxCodeLen) return fail(ErrorCategory::InvalidFormat, "bzip2 code length out of range");
                if (!b.get(1)) break;
                cur += b.get(1) ? -1 : 1;
                if (b.truncated) return fail(ErrorCategory::InvalidFormat, "bzip2 stream ends inside the code lengths");
            }
            lengths[s] = static_cast<std::uint8_t>(cur);
        }
        buildTable(tables[g], lengths, alphaSize);
    }
    // MTF/RLE2 decode into the pre-BWT buffer.
    const std::size_t maxBlock = static_cast<std::size_t>(blockSize100k) * 100000;
    std::vector<std::uint32_t> tt(maxBlock);
    std::uint32_t unzftab[256] = {};
    std::uint8_t mtfSymbols[256];
    for (int i = 0; i < nInUse; ++i) mtfSymbols[i] = static_cast<std::uint8_t>(i);
    std::size_t nblock = 0;
    const int eob = nInUse + 1;
    int groupPos = 0, groupNo = -1;
    const Huffman* gsel = nullptr;
    auto nextSymbol = [&]() -> int {
        if (groupPos == 0) {
            if (++groupNo >= nSelectors) return -1;
            groupPos = kGroupSize;
            gsel = &tables[selectors[static_cast<std::size_t>(groupNo)]];
        }
        --groupPos;
        return decodeSymbol(b, *gsel);
    };
    int sym = nextSymbol();
    while (sym != eob) {
        if (sym < 0 || b.truncated) return fail(ErrorCategory::InvalidFormat, "corrupt bzip2 Huffman data");
        if (sym <= 1) {   // RUNA / RUNB: a run of the MTF front symbol
            std::size_t run = 0, weight = 1;
            while (sym <= 1) {
                run += weight << sym;
                weight <<= 1;
                if (weight > maxBlock) return fail(ErrorCategory::InvalidFormat, "bzip2 run length overflow");
                sym = nextSymbol();
                if (sym < 0 || b.truncated) return fail(ErrorCategory::InvalidFormat, "corrupt bzip2 run");
            }
            const std::uint8_t byte = seqToUnseq[mtfSymbols[0]];
            if (nblock + run > maxBlock) return fail(ErrorCategory::InvalidFormat, "bzip2 block larger than its declared size");
            unzftab[byte] += static_cast<std::uint32_t>(run);
            while (run--) tt[nblock++] = byte;
            continue;
        }
        const int idx = sym - 1;
        if (idx >= nInUse) return fail(ErrorCategory::InvalidFormat, "bzip2 MTF index out of range");
        const std::uint8_t v = mtfSymbols[idx];
        std::memmove(mtfSymbols + 1, mtfSymbols, static_cast<std::size_t>(idx));
        mtfSymbols[0] = v;
        const std::uint8_t byte = seqToUnseq[v];
        if (nblock >= maxBlock) return fail(ErrorCategory::InvalidFormat, "bzip2 block larger than its declared size");
        unzftab[byte]++;
        tt[nblock++] = byte;
        sym = nextSymbol();
    }
    if (origPtr >= nblock) return fail(ErrorCategory::InvalidFormat, "bzip2 origPtr outside the block");
    // Inverse BWT: cumulative counts, then the T vector.
    std::uint32_t cftab[257];
    cftab[0] = 0;
    for (int i = 1; i <= 256; ++i) cftab[i] = cftab[i - 1] + unzftab[i - 1];
    for (std::size_t i = 0; i < nblock; ++i) {
        const std::uint8_t c = static_cast<std::uint8_t>(tt[i] & 0xFF);
        tt[cftab[c]] |= static_cast<std::uint32_t>(i) << 8;
        cftab[c]++;
    }
    // Walk the chain, undoing the initial RLE (4 equal bytes + count) on the way out.
    std::uint32_t pos = tt[origPtr] >> 8;
    std::uint32_t crc = 0xFFFFFFFFu;
    int runLen = 0, prev = -1;
    std::size_t produced = 0;
    auto emit = [&](std::uint8_t byte) -> bool {
        if (outPos + produced >= out.size()) return false;
        out[outPos + produced++] = std::byte(byte);
        crc = (crc << 8) ^ crcTab[((crc >> 24) ^ byte) & 0xFF];
        return true;
    };
    for (std::size_t i = 0; i < nblock; ++i) {
        const std::uint32_t entry = tt[pos];
        const std::uint8_t byte = static_cast<std::uint8_t>(entry & 0xFF);
        pos = entry >> 8;
        if (runLen == 4) {   // the byte after four equal ones is a repeat count
            for (int k = 0; k < byte; ++k)
                if (!emit(static_cast<std::uint8_t>(prev))) return fail(ErrorCategory::OutOfRange, "bunzip2: output buffer too small");
            runLen = 0;
            prev = -1;
            continue;
        }
        if (byte == prev) ++runLen;
        else {
            runLen = 1;
            prev = byte;
        }
        if (!emit(byte)) return fail(ErrorCategory::OutOfRange, "bunzip2: output buffer too small");
    }
    if (~crc != crcOut) return fail(ErrorCategory::Integrity, "bzip2 block CRC mismatch");
    return produced;
}

} // namespace

Expected<std::size_t> bunzip2(std::span<const std::byte> in, std::span<std::byte> out) {
    static std::uint32_t crcTab[256];
    static bool tabReady = false;
    if (!tabReady) {
        for (unsigned i = 0; i < 256; ++i) crcTab[i] = crcTable(i);
        tabReady = true;
    }
    if (in.size() < 10 || in[0] != std::byte{'B'} || in[1] != std::byte{'Z'} || in[2] != std::byte{'h'}) return fail(ErrorCategory::InvalidFormat, "not a bzip2 stream");
    const auto level = std::to_integer<std::uint8_t>(in[3]);
    if (level < '1' || level > '9') return fail(ErrorCategory::InvalidFormat, "bad bzip2 block size");
    Bits b;
    b.in = in.subspan(4);
    std::size_t outPos = 0;
    std::uint32_t combined = 0;
    for (;;) {
        const std::uint32_t m1 = b.get(24), m2 = b.get(24);
        if (b.truncated) return fail(ErrorCategory::InvalidFormat, "bzip2 stream ends early");
        if (m1 == 0x314159 && m2 == 0x265359) {   // block magic (pi)
            std::uint32_t blockCrc = 0;
            auto n = decodeBlock(b, static_cast<std::uint32_t>(level - '0'), out, outPos, blockCrc, crcTab);
            if (!n) return n;
            outPos += *n;
            combined = ((combined << 1) | (combined >> 31)) ^ blockCrc;
        } else if (m1 == 0x177245 && m2 == 0x385090) {   // end-of-stream magic (sqrt(pi))
            const std::uint32_t streamCrc = b.get(32);
            if (streamCrc != combined) return fail(ErrorCategory::Integrity, "bzip2 stream CRC mismatch");
            return outPos;
        } else {
            return fail(ErrorCategory::InvalidFormat, "bad bzip2 block magic");
        }
    }
}

} // namespace stein::compress
