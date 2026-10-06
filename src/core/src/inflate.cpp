// SPDX-License-Identifier: MIT
#include "stein/core/inflate.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/endian.hpp"

#include <array>
#include <cstring>

namespace stein::compress {

namespace {

constexpr int kMaxBits = 15, kMaxLitCodes = 286, kMaxDistCodes = 30, kMaxCodes = kMaxLitCodes + kMaxDistCodes, kFixedLitCodes = 288;

struct Huffman {
    std::array<std::uint16_t, kMaxBits + 1> count{};
    std::array<std::uint16_t, kFixedLitCodes> symbol{};
};

struct State {
    std::span<const std::byte> in;
    std::size_t inPos = 0;
    std::uint32_t bitBuf = 0;
    int bitCount = 0;
    std::span<std::byte> out;
    std::size_t outPos = 0;
    bool overflow = false, corrupt = false, truncated = false;
    bool partial = false;   // a full output buffer ends decoding successfully

    int bits(int need) {
        while (bitCount < need) {
            if (inPos >= in.size()) {
                truncated = true;
                return 0;
            }
            bitBuf |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[inPos++])) << bitCount;
            bitCount += 8;
        }
        const int v = static_cast<int>(bitBuf & ((1u << need) - 1));
        bitBuf >>= need;
        bitCount -= need;
        return v;
    }
    bool failed() const { return overflow || corrupt || truncated; }
};

// Build canonical decoding tables; returns 0 for a complete code, > 0 for an incomplete one
// (allowed when a single code is in use), < 0 when over-subscribed.
int construct(Huffman& h, const std::uint16_t* length, int n) {
    h.count.fill(0);
    for (int s = 0; s < n; ++s) h.count[length[s]]++;
    if (h.count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= kMaxBits; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return left;
    }
    std::array<std::uint16_t, kMaxBits + 1> offs{};
    for (int len = 1; len < kMaxBits; ++len) offs[len + 1] = static_cast<std::uint16_t>(offs[len] + h.count[len]);
    for (int s = 0; s < n; ++s)
        if (length[s] != 0) h.symbol[offs[length[s]]++] = static_cast<std::uint16_t>(s);
    return left;
}

int decode(State& st, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
        code |= st.bits(1);
        if (st.truncated) return -1;
        const int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

constexpr std::uint16_t kLenBase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::uint16_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::uint16_t kDistBase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr std::uint16_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

void codes(State& st, const Huffman& lencode, const Huffman& distcode) {
    for (;;) {
        int symbol = decode(st, lencode);
        if (symbol < 0) {
            st.corrupt = !st.truncated;
            return;
        }
        if (symbol < 256) {
            if (st.outPos >= st.out.size()) {
                st.overflow = true;
                return;
            }
            st.out[st.outPos++] = std::byte(symbol);
        } else if (symbol == 256) {
            return;
        } else {
            symbol -= 257;
            if (symbol >= 29) {
                st.corrupt = true;
                return;
            }
            const std::size_t len = kLenBase[symbol] + static_cast<std::size_t>(st.bits(kLenExtra[symbol]));
            const int ds = decode(st, distcode);
            if (ds < 0 || ds >= 30) {
                st.corrupt = !st.truncated;
                return;
            }
            const std::size_t dist = kDistBase[ds] + static_cast<std::size_t>(st.bits(kDistExtra[ds]));
            if (st.truncated) return;
            if (dist > st.outPos) {
                st.corrupt = true;
                return;
            }
            if (st.outPos + len > st.out.size()) {
                // In partial mode the bytes that fit still belong to the caller's window.
                const std::size_t fit = st.partial ? st.out.size() - st.outPos : 0;
                for (std::size_t i = 0; i < fit; ++i) st.out[st.outPos + i] = st.out[st.outPos - dist + i];
                st.outPos += fit;
                st.overflow = true;
                return;
            }
            for (std::size_t i = 0; i < len; ++i) st.out[st.outPos + i] = st.out[st.outPos - dist + i];
            st.outPos += len;
        }
    }
}

void stored(State& st) {
    st.bitBuf = 0;
    st.bitCount = 0;
    if (st.inPos + 4 > st.in.size()) {
        st.truncated = true;
        return;
    }
    const std::uint16_t len = loadLe16(st.in.data() + st.inPos), nlen = loadLe16(st.in.data() + st.inPos + 2);
    st.inPos += 4;
    if (static_cast<std::uint16_t>(~len) != nlen) {
        st.corrupt = true;
        return;
    }
    if (st.inPos + len > st.in.size()) {
        st.truncated = true;
        return;
    }
    if (st.outPos + len > st.out.size()) {
        if (st.partial) {
            const std::size_t fit = st.out.size() - st.outPos;
            std::memcpy(st.out.data() + st.outPos, st.in.data() + st.inPos, fit);
            st.outPos += fit;
        }
        st.overflow = true;
        return;
    }
    std::memcpy(st.out.data() + st.outPos, st.in.data() + st.inPos, len);
    st.inPos += len;
    st.outPos += len;
}

void fixed(State& st) {
    static Huffman lencode, distcode;
    static bool built = false;
    if (!built) {
        std::uint16_t lengths[kFixedLitCodes];
        int s = 0;
        for (; s < 144; ++s) lengths[s] = 8;
        for (; s < 256; ++s) lengths[s] = 9;
        for (; s < 280; ++s) lengths[s] = 7;
        for (; s < kFixedLitCodes; ++s) lengths[s] = 8;
        construct(lencode, lengths, kFixedLitCodes);
        for (s = 0; s < kMaxDistCodes; ++s) lengths[s] = 5;
        construct(distcode, lengths, kMaxDistCodes);
        built = true;
    }
    codes(st, lencode, distcode);
}

void dynamic(State& st) {
    static constexpr std::uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    const int nlen = st.bits(5) + 257, ndist = st.bits(5) + 1, ncode = st.bits(4) + 4;
    if (st.truncated) return;
    if (nlen > kMaxLitCodes || ndist > kMaxDistCodes) {
        st.corrupt = true;
        return;
    }
    std::uint16_t lengths[kMaxCodes] = {};
    for (int i = 0; i < ncode; ++i) lengths[order[i]] = static_cast<std::uint16_t>(st.bits(3));
    for (int i = ncode; i < 19; ++i) lengths[order[i]] = 0;
    Huffman lencode, distcode;
    if (construct(lencode, lengths, 19) != 0) {
        st.corrupt = true;
        return;
    }
    int index = 0;
    while (index < nlen + ndist) {
        int symbol = decode(st, lencode);
        if (symbol < 0) {
            st.corrupt = !st.truncated;
            return;
        }
        if (symbol < 16) {
            lengths[index++] = static_cast<std::uint16_t>(symbol);
        } else {
            std::uint16_t len = 0;
            int repeat = 0;
            if (symbol == 16) {
                if (index == 0) {
                    st.corrupt = true;
                    return;
                }
                len = lengths[index - 1];
                repeat = 3 + st.bits(2);
            } else if (symbol == 17) {
                repeat = 3 + st.bits(3);
            } else {
                repeat = 11 + st.bits(7);
            }
            if (index + repeat > nlen + ndist) {
                st.corrupt = true;
                return;
            }
            while (repeat--) lengths[index++] = len;
        }
    }
    if (lengths[256] == 0) {
        st.corrupt = true;
        return;
    }
    int err = construct(lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) {
        st.corrupt = true;
        return;
    }
    err = construct(distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) {
        st.corrupt = true;
        return;
    }
    codes(st, lencode, distcode);
}

Expected<std::size_t> finish(const State& st) {
    if (st.overflow) return st.partial ? Expected<std::size_t>{st.outPos} : fail(ErrorCategory::OutOfRange, "inflate: output buffer too small");
    if (st.truncated) return fail(ErrorCategory::InvalidFormat, "inflate: compressed data ends early");
    if (st.corrupt) return fail(ErrorCategory::InvalidFormat, "inflate: corrupt deflate stream");
    return st.outPos;
}

Expected<std::size_t> inflateInto(State& st) {
    int last = 0;
    do {
        last = st.bits(1);
        const int type = st.bits(2);
        if (st.truncated) break;
        if (type == 0) stored(st);
        else if (type == 1) fixed(st);
        else if (type == 2) dynamic(st);
        else st.corrupt = true;
        if (st.failed()) break;
    } while (!last);
    return finish(st);
}

} // namespace

std::uint32_t adler32(std::span<const std::byte> data, std::uint32_t seed) {
    std::uint32_t a = seed & 0xFFFF, b = seed >> 16;
    std::size_t i = 0;
    while (i < data.size()) {
        const std::size_t n = std::min<std::size_t>(5552, data.size() - i);   // largest run before b can overflow
        for (std::size_t k = 0; k < n; ++k) {
            a += std::to_integer<std::uint8_t>(data[i + k]);
            b += a;
        }
        a %= 65521;
        b %= 65521;
        i += n;
    }
    return (b << 16) | a;
}

Expected<std::size_t> inflateRaw(std::span<const std::byte> in, std::span<std::byte> out) {
    State st;
    st.in = in;
    st.out = out;
    return inflateInto(st);
}

Expected<std::size_t> inflateRawPartial(std::span<const std::byte> in, std::span<std::byte> out) {
    State st;
    st.in = in;
    st.out = out;
    st.partial = true;
    return inflateInto(st);
}

Expected<std::size_t> inflateZlib(std::span<const std::byte> in, std::span<std::byte> out) {
    if (in.size() < 6) return fail(ErrorCategory::InvalidFormat, "zlib stream too short");
    const auto cmf = std::to_integer<std::uint8_t>(in[0]), flg = std::to_integer<std::uint8_t>(in[1]);
    if ((cmf & 0x0F) != 8 || ((cmf << 8) | flg) % 31 != 0) return fail(ErrorCategory::InvalidFormat, "not a zlib stream");
    if (flg & 0x20) return fail(ErrorCategory::Unsupported, "zlib preset dictionaries are not supported");
    State st;
    st.in = in.subspan(2);
    st.out = out;
    auto n = inflateInto(st);
    if (!n) return n;
    if (st.inPos + 4 > st.in.size()) return fail(ErrorCategory::InvalidFormat, "zlib stream has no Adler-32 trailer");
    const std::uint32_t want = loadBe32(st.in.data() + st.inPos);
    if (adler32(out.subspan(0, *n)) != want) return fail(ErrorCategory::Integrity, "zlib Adler-32 mismatch");
    return n;
}

Expected<std::size_t> inflateGzip(std::span<const std::byte> in, std::span<std::byte> out) {
    if (in.size() < 18 || in[0] != std::byte{0x1F} || in[1] != std::byte{0x8B} || in[2] != std::byte{8}) return fail(ErrorCategory::InvalidFormat, "not a gzip member");
    const auto flags = std::to_integer<std::uint8_t>(in[3]);
    std::size_t pos = 10;
    if (flags & 0x04) {   // FEXTRA
        if (pos + 2 > in.size()) return fail(ErrorCategory::InvalidFormat, "gzip extra field truncated");
        pos += 2 + loadLe16(in.data() + pos);
    }
    for (int f : {0x08, 0x10}) {   // FNAME, FCOMMENT: zero-terminated
        if (flags & f) {
            while (pos < in.size() && in[pos] != std::byte{0}) ++pos;
            ++pos;
        }
    }
    if (flags & 0x02) pos += 2;   // FHCRC
    if (pos >= in.size()) return fail(ErrorCategory::InvalidFormat, "gzip header truncated");
    State st;
    st.in = in.subspan(pos);
    st.out = out;
    auto n = inflateInto(st);
    if (!n) return n;
    if (st.inPos + 8 > st.in.size()) return fail(ErrorCategory::InvalidFormat, "gzip member has no trailer");
    const std::uint32_t crc = loadLe32(st.in.data() + st.inPos), isize = loadLe32(st.in.data() + st.inPos + 4);
    if (crc != Crc32::compute(out.subspan(0, *n)) || isize != static_cast<std::uint32_t>(*n)) return fail(ErrorCategory::Integrity, "gzip CRC-32 or size mismatch");
    return n;
}

} // namespace stein::compress

namespace stein::compress {

Expected<std::size_t> adcDecompress(std::span<const std::byte> in, std::span<std::byte> out) {
    std::size_t ip = 0, op = 0;
    while (ip < in.size()) {
        const auto b = std::to_integer<std::uint8_t>(in[ip]);
        std::size_t len = 0, dist = 0;
        if (b & 0x80) {
            len = (b & 0x7F) + 1;
            if (ip + 1 + len > in.size() || op + len > out.size()) return fail(ErrorCategory::InvalidFormat, "ADC literal run overruns a buffer");
            std::memcpy(out.data() + op, in.data() + ip + 1, len);
            ip += 1 + len;
            op += len;
            continue;
        }
        if (b & 0x40) {
            if (ip + 3 > in.size()) return fail(ErrorCategory::InvalidFormat, "ADC long reference truncated");
            len = (b & 0x3F) + 4;
            dist = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(in[ip + 1])) << 8 | std::to_integer<std::uint8_t>(in[ip + 2])) + 1;
            ip += 3;
        } else {
            if (ip + 2 > in.size()) return fail(ErrorCategory::InvalidFormat, "ADC short reference truncated");
            len = ((b & 0x3F) >> 2) + 3;
            dist = (static_cast<std::size_t>(b & 0x03) << 8 | std::to_integer<std::uint8_t>(in[ip + 1])) + 1;
            ip += 2;
        }
        if (dist > op) return fail(ErrorCategory::InvalidFormat, "ADC reference before the start of the output");
        if (op + len > out.size()) return fail(ErrorCategory::OutOfRange, "ADC output buffer too small");
        for (std::size_t i = 0; i < len; ++i) out[op + i] = out[op - dist + i];
        op += len;
    }
    return op;
}

} // namespace stein::compress
