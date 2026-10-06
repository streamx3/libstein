// SPDX-License-Identifier: MIT
#include "stein/core/lzma.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/hash.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace stein::compress {

std::uint64_t crc64(std::span<const std::byte> data, std::uint64_t seed) {
    static const auto table = [] {
        std::array<std::uint64_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint64_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ 0xC96C5795D7870F42ull : c >> 1;
            t[i] = c;
        }
        return t;
    }();
    std::uint64_t c = ~seed;
    for (auto b : data) c = table[(c ^ std::to_integer<std::uint64_t>(b)) & 0xFF] ^ (c >> 8);
    return ~c;
}

namespace {

constexpr int kNumBitModelTotalBits = 11, kNumMoveBits = 5;
constexpr std::uint16_t kProbInit = (1 << kNumBitModelTotalBits) / 2;
constexpr int kNumStates = 12, kNumPosBitsMax = 4, kNumLenToPosStates = 4, kNumAlignBits = 4, kEndPosModelIndex = 14, kNumFullDistances = 128;
constexpr int kMatchMinLen = 2;

struct RangeDecoder {
    const std::uint8_t* p;
    std::size_t len, pos = 0;
    std::uint32_t range = 0xFFFFFFFFu, code = 0;
    bool corrupt = false;

    bool init(bool firstByteIsProps = false) {
        if (len < 5 || (!firstByteIsProps && p[0] != 0)) return false;
        for (int i = 1; i < 5; ++i) code = (code << 8) | p[i];
        pos = 5;
        return code != 0xFFFFFFFFu;
    }
    std::uint8_t next() {
        if (pos < len) return p[pos++];
        corrupt = true;
        ++pos;
        return 0;
    }
    void normalize() {
        if (range < (1u << 24)) {
            range <<= 8;
            code = (code << 8) | next();
        }
    }
    unsigned bit(std::uint16_t& prob) {
        const std::uint32_t bound = (range >> kNumBitModelTotalBits) * prob;
        unsigned b;
        if (code < bound) {
            range = bound;
            prob = static_cast<std::uint16_t>(prob + (((1 << kNumBitModelTotalBits) - prob) >> kNumMoveBits));
            b = 0;
        } else {
            range -= bound;
            code -= bound;
            prob = static_cast<std::uint16_t>(prob - (prob >> kNumMoveBits));
            b = 1;
        }
        normalize();
        return b;
    }
    std::uint32_t direct(int n) {
        std::uint32_t v = 0;
        for (int i = 0; i < n; ++i) {
            range >>= 1;
            code -= range;
            const std::uint32_t t = 0u - (code >> 31);   // all ones when code "went negative"
            code += range & t;
            if (code == range) corrupt = true;
            normalize();
            v = (v << 1) + (t + 1);
        }
        return v;
    }
    std::uint32_t bitTree(std::uint16_t* probs, int numBits) {
        std::uint32_t m = 1;
        for (int i = 0; i < numBits; ++i) m = (m << 1) + bit(probs[m]);
        return m - (1u << numBits);
    }
    std::uint32_t bitTreeReverse(std::uint16_t* probs, int numBits) {
        std::uint32_t m = 1, sym = 0;
        for (int i = 0; i < numBits; ++i) {
            const unsigned b = bit(probs[m]);
            m = (m << 1) + b;
            sym |= b << i;
        }
        return sym;
    }
    bool finishedExactly() const { return code == 0; }
};

struct LenDecoder {
    std::uint16_t choice = kProbInit, choice2 = kProbInit;
    std::uint16_t low[1 << kNumPosBitsMax][1 << 3], mid[1 << kNumPosBitsMax][1 << 3], high[1 << 8];
    void reset() {
        choice = choice2 = kProbInit;
        for (auto& r : low) std::fill(std::begin(r), std::end(r), kProbInit);
        for (auto& r : mid) std::fill(std::begin(r), std::end(r), kProbInit);
        std::fill(std::begin(high), std::end(high), kProbInit);
    }
    std::uint32_t decode(RangeDecoder& rc, unsigned posState) {
        if (rc.bit(choice) == 0) return rc.bitTree(low[posState], 3);
        if (rc.bit(choice2) == 0) return 8 + rc.bitTree(mid[posState], 3);
        return 16 + rc.bitTree(high, 8);
    }
};

// LZMA1 decoder state that survives across LZMA2 chunks.
struct LzmaDecoder {
    int lc = 0, lp = 0, pb = 0;
    std::vector<std::uint16_t> literalProbs;
    std::uint16_t isMatch[kNumStates][1 << kNumPosBitsMax], isRep[kNumStates], isRepG0[kNumStates], isRepG1[kNumStates], isRepG2[kNumStates],
        isRep0Long[kNumStates][1 << kNumPosBitsMax];
    std::uint16_t distSlot[kNumLenToPosStates][1 << 6], distSpecial[1 + kNumFullDistances - kEndPosModelIndex], align[1 << kNumAlignBits];
    LenDecoder lenDecoder, repLenDecoder;
    unsigned state = 0;
    std::uint32_t rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;

    bool setProps(std::uint8_t props) {
        if (props >= 9 * 5 * 5) return false;
        lc = props % 9;
        props /= 9;
        lp = props % 5;
        pb = props / 5;
        literalProbs.assign(std::size_t{0x300} << (lc + lp), kProbInit);
        return true;
    }
    void resetState() {
        std::fill(literalProbs.begin(), literalProbs.end(), kProbInit);
        for (auto& r : isMatch) std::fill(std::begin(r), std::end(r), kProbInit);
        std::fill(std::begin(isRep), std::end(isRep), kProbInit);
        std::fill(std::begin(isRepG0), std::end(isRepG0), kProbInit);
        std::fill(std::begin(isRepG1), std::end(isRepG1), kProbInit);
        std::fill(std::begin(isRepG2), std::end(isRepG2), kProbInit);
        for (auto& r : isRep0Long) std::fill(std::begin(r), std::end(r), kProbInit);
        for (auto& r : distSlot) std::fill(std::begin(r), std::end(r), kProbInit);
        std::fill(std::begin(distSpecial), std::end(distSpecial), kProbInit);
        std::fill(std::begin(align), std::end(align), kProbInit);
        lenDecoder.reset();
        repLenDecoder.reset();
        state = 0;
        rep0 = rep1 = rep2 = rep3 = 0;
    }

    // Decode into out[pos..] up to `limit` bytes (or the end marker when allowEnd). `dictStart`
    // is the first byte matches may reference. Returns the new position.
    Expected<std::size_t> decode(RangeDecoder& rc, std::uint8_t* out, std::size_t pos, std::size_t limit, std::size_t dictStart, bool allowEndMarker, bool* sawEnd) {
        const std::size_t end = pos + limit;
        if (sawEnd) *sawEnd = false;
        while (pos < end) {
            if (rc.corrupt) return fail(ErrorCategory::InvalidFormat, "LZMA stream truncated");
            const unsigned posState = static_cast<unsigned>(pos) & ((1u << pb) - 1);
            if (rc.bit(isMatch[state][posState]) == 0) {
                // literal
                const unsigned prevByte = pos > dictStart ? out[pos - 1] : 0;
                const std::size_t litState = ((static_cast<std::size_t>(pos) & ((1u << lp) - 1)) << lc) + (prevByte >> (8 - lc));
                std::uint16_t* probs = literalProbs.data() + litState * 0x300;
                unsigned sym = 1;
                if (state >= 7) {
                    unsigned matchByte = out[pos - rep0 - 1];
                    do {
                        const unsigned matchBit = (matchByte >> 7) & 1;
                        matchByte <<= 1;
                        const unsigned b = rc.bit(probs[((1 + matchBit) << 8) + sym]);
                        sym = (sym << 1) | b;
                        if (matchBit != b) break;
                    } while (sym < 0x100);
                }
                while (sym < 0x100) sym = (sym << 1) | rc.bit(probs[sym]);
                out[pos++] = static_cast<std::uint8_t>(sym);
                state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
                continue;
            }
            std::uint32_t len;
            if (rc.bit(isRep[state]) != 0) {
                if (pos == dictStart) return fail(ErrorCategory::InvalidFormat, "LZMA repeat match before any data");
                if (rc.bit(isRepG0[state]) == 0) {
                    if (rc.bit(isRep0Long[state][posState]) == 0) {
                        // short rep: one byte at rep0
                        state = state < 7 ? 9 : 11;
                        if (pos - dictStart <= rep0) return fail(ErrorCategory::InvalidFormat, "LZMA match distance beyond the dictionary");
                        out[pos] = out[pos - rep0 - 1];
                        ++pos;
                        continue;
                    }
                } else {
                    std::uint32_t dist;
                    if (rc.bit(isRepG1[state]) == 0) {
                        dist = rep1;
                    } else {
                        if (rc.bit(isRepG2[state]) == 0) {
                            dist = rep2;
                        } else {
                            dist = rep3;
                            rep3 = rep2;
                        }
                        rep2 = rep1;
                    }
                    rep1 = rep0;
                    rep0 = dist;
                }
                len = repLenDecoder.decode(rc, posState);
                state = state < 7 ? 8 : 11;
            } else {
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                len = lenDecoder.decode(rc, posState);
                state = state < 7 ? 7 : 10;
                const unsigned lenState = std::min<unsigned>(len, kNumLenToPosStates - 1);
                const std::uint32_t slot = rc.bitTree(distSlot[lenState], 6);
                if (slot < 4) {
                    rep0 = slot;
                } else {
                    const int numDirectBits = static_cast<int>((slot >> 1) - 1);
                    std::uint32_t dist = (2 | (slot & 1)) << numDirectBits;
                    if (slot < kEndPosModelIndex) {
                        dist += rc.bitTreeReverse(distSpecial + dist - slot, numDirectBits);
                    } else {
                        dist += rc.direct(numDirectBits - kNumAlignBits) << kNumAlignBits;
                        dist += rc.bitTreeReverse(align, kNumAlignBits);
                    }
                    rep0 = dist;
                    if (dist == 0xFFFFFFFFu) {
                        if (!allowEndMarker) return fail(ErrorCategory::InvalidFormat, "unexpected LZMA end marker");
                        if (sawEnd) *sawEnd = true;
                        return pos;
                    }
                }
            }
            len += kMatchMinLen;
            if (pos - dictStart <= rep0) return fail(ErrorCategory::InvalidFormat, "LZMA match distance beyond the dictionary");
            const std::size_t n = std::min<std::size_t>(len, end - pos);
            for (std::size_t i = 0; i < n; ++i) out[pos + i] = out[pos + i - rep0 - 1];
            pos += n;
            if (n < len) return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZMA data");
        }
        return pos;
    }
};

// Decode a stream that may end with an end marker. When the buffer fills without one, the next
// symbol decides: an end marker means the output was exactly right, anything else means the
// buffer is too small (checked on a copy, since matches reference the output itself).
Expected<std::size_t> decodeWithMarker(LzmaDecoder& d, RangeDecoder& rc, std::span<std::byte> out, std::size_t limit) {
    bool sawEnd = false;
    auto pos = d.decode(rc, reinterpret_cast<std::uint8_t*>(out.data()), 0, limit, 0, true, &sawEnd);
    if (!pos) return pos;
    if (rc.corrupt) return fail(ErrorCategory::InvalidFormat, "LZMA stream truncated");
    if (sawEnd || *pos < limit) return *pos;
    if (rc.finishedExactly() && rc.pos >= rc.len) return *pos;   // stream ends exactly here without a marker
    std::vector<std::uint8_t> probe(*pos + 300);
    std::memcpy(probe.data(), out.data(), *pos);
    LzmaDecoder d2 = d;
    RangeDecoder rc2 = rc;
    bool end2 = false;
    auto more = d2.decode(rc2, probe.data(), *pos, 1, 0, true, &end2);
    if (more && end2) return *pos;
    if (!more && more.error().category() != ErrorCategory::OutOfRange) return *pos;   // garbage after the data: not ours to judge
    return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZMA data");
}

} // namespace

Expected<std::size_t> lzmaDecompressRaw(std::span<const std::byte> in, std::span<std::byte> out, std::uint8_t props) {
    LzmaDecoder d;
    if (!d.setProps(props)) return fail(ErrorCategory::InvalidFormat, "invalid LZMA properties byte");
    d.resetState();
    RangeDecoder rc{reinterpret_cast<const std::uint8_t*>(in.data()), in.size()};
    if (!rc.init()) return fail(ErrorCategory::InvalidFormat, "bad LZMA range coder header");
    return decodeWithMarker(d, rc, out, out.size());
}

Expected<std::size_t> lzmaMicroDecompress(std::span<const std::byte> in, std::span<std::byte> out, bool partial) {
    if (in.size() < 5) return fail(ErrorCategory::InvalidFormat, "MicroLZMA stream too short");
    LzmaDecoder d;
    // The properties byte is stored inverted (xz: lzma_lzma_lclppb_decode(&options, ~in[0])).
    if (!d.setProps(static_cast<std::uint8_t>(~std::to_integer<std::uint8_t>(in[0])))) return fail(ErrorCategory::InvalidFormat, "invalid MicroLZMA properties byte");
    d.resetState();
    RangeDecoder rc{reinterpret_cast<const std::uint8_t*>(in.data()), in.size()};
    if (!rc.init(true)) return fail(ErrorCategory::InvalidFormat, "bad MicroLZMA range coder header");
    bool sawEnd = false;
    auto pos = d.decode(rc, reinterpret_cast<std::uint8_t*>(out.data()), 0, out.size(), 0, true, &sawEnd);
    if (!pos) {
        // A match that would run past the buffer is the normal end of a partial decode: the
        // decoder copied what fits before reporting it.
        if (partial && pos.error().category() == ErrorCategory::OutOfRange) return out.size();
        return pos;
    }
    if (rc.corrupt) return fail(ErrorCategory::InvalidFormat, "MicroLZMA stream truncated");
    if (!partial && *pos != out.size()) return fail(ErrorCategory::InvalidFormat, "MicroLZMA stream ended before the expected size");
    return *pos;
}

Expected<std::size_t> lzmaDecompress(std::span<const std::byte> in, std::span<std::byte> out) {
    if (in.size() < 13) return fail(ErrorCategory::InvalidFormat, ".lzma header too short");
    const std::uint8_t props = std::to_integer<std::uint8_t>(in[0]);
    const std::uint64_t size = loadLe64(in.data() + 5);
    LzmaDecoder d;
    if (!d.setProps(props)) return fail(ErrorCategory::InvalidFormat, "invalid LZMA properties byte");
    d.resetState();
    RangeDecoder rc{reinterpret_cast<const std::uint8_t*>(in.data()) + 13, in.size() - 13};
    if (!rc.init()) return fail(ErrorCategory::InvalidFormat, "bad LZMA range coder header");
    const bool known = size != ~0ull;
    if (known && size > out.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZMA data");
    auto pos = decodeWithMarker(d, rc, out, known ? static_cast<std::size_t>(size) : out.size());
    if (!pos) return pos;
    if (known && *pos != size) return fail(ErrorCategory::InvalidFormat, ".lzma stream ended before the announced size");
    return *pos;
}

Expected<std::size_t> lzma2Decompress(std::span<const std::byte> inBytes, std::span<std::byte> outBytes, std::size_t* consumed) {
    const std::uint8_t* in = reinterpret_cast<const std::uint8_t*>(inBytes.data());
    std::uint8_t* out = reinterpret_cast<std::uint8_t*>(outBytes.data());
    std::size_t ip = 0, op = 0, dictStart = 0;
    LzmaDecoder d;
    bool haveProps = false, needDictReset = true;
    for (;;) {
        if (ip >= inBytes.size()) return fail(ErrorCategory::InvalidFormat, "LZMA2 stream without an end marker");
        const std::uint8_t control = in[ip++];
        if (control == 0x00) break;
        if (control == 0x01 || control == 0x02) {
            if (control == 0x01) {
                dictStart = op;
                needDictReset = false;
            } else if (needDictReset) {
                return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk before the first dictionary reset");
            }
            if (ip + 2 > inBytes.size()) return fail(ErrorCategory::InvalidFormat, "truncated LZMA2 chunk header");
            const std::size_t n = (std::size_t{in[ip]} << 8 | in[ip + 1]) + 1;
            ip += 2;
            if (ip + n > inBytes.size()) return fail(ErrorCategory::InvalidFormat, "LZMA2 uncompressed chunk runs past the input");
            if (op + n > outBytes.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZMA2 data");
            std::memcpy(out + op, in + ip, n);
            ip += n;
            op += n;
            continue;
        }
        if (control < 0x80) return fail(ErrorCategory::InvalidFormat, "invalid LZMA2 control byte");
        if (ip + 4 > inBytes.size()) return fail(ErrorCategory::InvalidFormat, "truncated LZMA2 chunk header");
        const std::size_t unpacked = ((std::size_t{control} & 0x1F) << 16) + (std::size_t{in[ip]} << 8 | in[ip + 1]) + 1;
        const std::size_t packed = (std::size_t{in[ip + 2]} << 8 | in[ip + 3]) + 1;
        ip += 4;
        const unsigned mode = (control >> 5) & 3;
        if (mode == 3) {
            dictStart = op;
            needDictReset = false;
        } else if (needDictReset) {
            return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk before the first dictionary reset");
        }
        if (mode >= 2) {
            if (ip >= inBytes.size()) return fail(ErrorCategory::InvalidFormat, "truncated LZMA2 properties");
            const std::uint8_t props = in[ip++];
            if (!d.setProps(props) || d.lc + d.lp > 4) return fail(ErrorCategory::InvalidFormat, "invalid LZMA2 properties");
            haveProps = true;
        } else if (!haveProps) {
            return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk before any properties");
        }
        if (mode >= 1) d.resetState();
        if (ip + packed > inBytes.size()) return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk runs past the input");
        if (op + unpacked > outBytes.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZMA2 data");
        RangeDecoder rc{in + ip, packed};
        if (!rc.init()) return fail(ErrorCategory::InvalidFormat, "bad LZMA2 chunk range coder header");
        auto pos = d.decode(rc, out, op, unpacked, dictStart, false, nullptr);
        if (!pos) return pos;
        if (rc.corrupt || *pos != op + unpacked) return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk did not decode to its announced size");
        if (rc.pos != packed || !rc.finishedExactly()) return fail(ErrorCategory::InvalidFormat, "LZMA2 chunk range coder did not end cleanly");
        op = *pos;
        ip += packed;
    }
    if (consumed) *consumed = ip;
    return op;
}

namespace {

bool readVarint(const std::uint8_t* p, std::size_t len, std::size_t& pos, std::uint64_t& value) {
    value = 0;
    for (int i = 0; i < 9; ++i) {
        if (pos >= len) return false;
        const std::uint8_t b = p[pos++];
        value |= static_cast<std::uint64_t>(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) return true;
    }
    return false;
}

} // namespace

Expected<std::size_t> xzDecompress(std::span<const std::byte> inBytes, std::span<std::byte> outBytes) {
    const std::uint8_t* in = reinterpret_cast<const std::uint8_t*>(inBytes.data());
    const std::size_t len = inBytes.size();
    static constexpr std::uint8_t kMagic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
    std::size_t ip = 0, op = 0;
    bool any = false;
    auto crcOf = [&](std::size_t off, std::size_t n) { return Crc32::compute(inBytes.subspan(off, n)); };
    for (;;) {
        // Stream padding (multiples of four zero bytes) between streams.
        while (ip + 4 <= len && in[ip] == 0 && in[ip + 1] == 0 && in[ip + 2] == 0 && in[ip + 3] == 0) ip += 4;
        if (ip >= len) break;
        if (ip + 12 > len || std::memcmp(in + ip, kMagic, 6) != 0) {
            if (any) return fail(ErrorCategory::InvalidFormat, "trailing bytes after the last xz stream");
            return fail(ErrorCategory::InvalidFormat, "not an xz stream");
        }
        any = true;
        if (in[ip + 6] != 0 || loadLe32(inBytes.data() + ip + 8) != crcOf(ip + 6, 2)) return fail(ErrorCategory::InvalidFormat, "bad xz stream header");
        const std::uint8_t checkType = in[ip + 7];
        const std::size_t checkSize = checkType == 0 ? 0 : checkType == 1 ? 4 : checkType == 4 ? 8 : checkType == 10 ? 32 : static_cast<std::size_t>(-1);
        if (checkSize == static_cast<std::size_t>(-1)) return fail(ErrorCategory::Unsupported, "unsupported xz check type " + std::to_string(checkType));
        ip += 12;
        struct Record {
            std::uint64_t unpadded, uncompressed;
        };
        std::vector<Record> records;
        const std::size_t streamStart = ip - 12;
        for (;;) {
            if (ip >= len) return fail(ErrorCategory::InvalidFormat, "truncated xz stream");
            if (in[ip] == 0) break;   // index indicator
            const std::size_t blockStart = ip, headerSize = (std::size_t{in[ip]} + 1) * 4;
            if (ip + headerSize > len) return fail(ErrorCategory::InvalidFormat, "truncated xz block header");
            if (loadLe32(inBytes.data() + ip + headerSize - 4) != crcOf(ip, headerSize - 4)) return fail(ErrorCategory::InvalidFormat, "xz block header CRC mismatch");
            const std::uint8_t flags = in[ip + 1];
            const unsigned numFilters = (flags & 3) + 1;
            if (flags & 0x3C) return fail(ErrorCategory::InvalidFormat, "reserved xz block flags set");
            std::size_t hp = ip + 2;
            std::uint64_t compressedSize = ~0ull, uncompressedSize = ~0ull;
            if ((flags & 0x40) && !readVarint(in, ip + headerSize - 4, hp, compressedSize)) return fail(ErrorCategory::InvalidFormat, "bad xz block header");
            if ((flags & 0x80) && !readVarint(in, ip + headerSize - 4, hp, uncompressedSize)) return fail(ErrorCategory::InvalidFormat, "bad xz block header");
            std::uint8_t dictProp = 0;
            for (unsigned f = 0; f < numFilters; ++f) {
                std::uint64_t id = 0, propSize = 0;
                if (!readVarint(in, ip + headerSize - 4, hp, id) || !readVarint(in, ip + headerSize - 4, hp, propSize)) return fail(ErrorCategory::InvalidFormat, "bad xz filter flags");
                if (hp + propSize > ip + headerSize - 4) return fail(ErrorCategory::InvalidFormat, "bad xz filter flags");
                if (id != 0x21) return fail(ErrorCategory::Unsupported, "xz filter 0x" + std::to_string(id) + " (BCJ/delta chains) is not supported, only LZMA2");
                if (f != numFilters - 1 || propSize != 1) return fail(ErrorCategory::InvalidFormat, "LZMA2 must be the last filter with one property byte");
                dictProp = in[hp];
                hp += propSize;
            }
            if (dictProp > 40) return fail(ErrorCategory::InvalidFormat, "bad LZMA2 dictionary size");
            for (; hp < ip + headerSize - 4; ++hp)
                if (in[hp] != 0) return fail(ErrorCategory::InvalidFormat, "xz block header padding is not zero");
            ip += headerSize;
            std::size_t consumed = 0;
            auto n = lzma2Decompress(inBytes.subspan(ip, compressedSize != ~0ull ? static_cast<std::size_t>(std::min<std::uint64_t>(compressedSize, len - ip)) : len - ip), outBytes.subspan(op), &consumed);
            if (!n) return fail(n.error());
            if (compressedSize != ~0ull && consumed != compressedSize) return fail(ErrorCategory::InvalidFormat, "xz block compressed size mismatch");
            if (uncompressedSize != ~0ull && *n != uncompressedSize) return fail(ErrorCategory::InvalidFormat, "xz block uncompressed size mismatch");
            const auto produced = outBytes.subspan(op, *n);
            op += *n;
            ip += consumed;
            while (ip % 4 != 0) {
                if (ip >= len || in[ip] != 0) return fail(ErrorCategory::InvalidFormat, "xz block padding is not zero");
                ++ip;
            }
            if (ip + checkSize > len) return fail(ErrorCategory::InvalidFormat, "truncated xz block check");
            bool ok = true;
            if (checkType == 1) ok = loadLe32(inBytes.data() + ip) == Crc32::compute(produced);
            else if (checkType == 4) ok = loadLe64(inBytes.data() + ip) == crc64(produced);
            else if (checkType == 10) {
                Sha256 h;
                h.update(produced);
                const auto d = h.finish();
                ok = std::memcmp(d.data(), in + ip, 32) == 0;
            }
            if (!ok) return fail(ErrorCategory::Integrity, "xz block check mismatch");
            ip += checkSize;
            records.push_back({headerSize + consumed + checkSize, *n});
            (void)blockStart;
        }
        // Index.
        const std::size_t indexStart = ip;
        ++ip;
        std::uint64_t count = 0;
        if (!readVarint(in, len, ip, count) || count != records.size()) return fail(ErrorCategory::InvalidFormat, "xz index record count mismatch");
        for (const auto& r : records) {
            std::uint64_t unpadded = 0, uncompressed = 0;
            if (!readVarint(in, len, ip, unpadded) || !readVarint(in, len, ip, uncompressed)) return fail(ErrorCategory::InvalidFormat, "truncated xz index");
            if (unpadded != r.unpadded || uncompressed != r.uncompressed) return fail(ErrorCategory::InvalidFormat, "xz index disagrees with the blocks");
        }
        while (ip % 4 != 0) {
            if (ip >= len || in[ip] != 0) return fail(ErrorCategory::InvalidFormat, "xz index padding is not zero");
            ++ip;
        }
        if (ip + 4 > len || loadLe32(inBytes.data() + ip) != crcOf(indexStart, ip - indexStart)) return fail(ErrorCategory::InvalidFormat, "xz index CRC mismatch");
        ip += 4;
        const std::size_t indexSize = ip - indexStart;
        // Footer.
        if (ip + 12 > len) return fail(ErrorCategory::InvalidFormat, "truncated xz stream footer");
        if (loadLe32(inBytes.data() + ip) != crcOf(ip + 4, 6)) return fail(ErrorCategory::InvalidFormat, "xz stream footer CRC mismatch");
        if ((std::uint64_t{loadLe32(inBytes.data() + ip + 4)} + 1) * 4 != indexSize) return fail(ErrorCategory::InvalidFormat, "xz backward size does not match the index");
        if (in[ip + 8] != 0 || in[ip + 9] != checkType || in[ip + 10] != 'Y' || in[ip + 11] != 'Z') return fail(ErrorCategory::InvalidFormat, "bad xz stream footer");
        ip += 12;
        (void)streamStart;
    }
    if (!any) return fail(ErrorCategory::InvalidFormat, "no xz stream in the input");
    return op;
}

} // namespace stein::compress
