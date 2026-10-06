// SPDX-License-Identifier: MIT
#include "stein/core/lzfse.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <vector>

namespace stein::compress {

namespace {

constexpr std::uint32_t kMagicEnd = 0x24787662u, kMagicRaw = 0x2d787662u, kMagicV1 = 0x31787662u, kMagicV2 = 0x32787662u, kMagicLzvn = 0x6e787662u;
constexpr int kLSymbols = 20, kMSymbols = 20, kDSymbols = 64, kLiteralSymbols = 256;
constexpr int kLStates = 64, kMStates = 64, kDStates = 256, kLiteralStates = 1024;
constexpr std::uint8_t kLExtraBits[kLSymbols] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8};
constexpr std::uint8_t kMExtraBits[kMSymbols] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11};
constexpr std::uint8_t kDExtraBits[kDSymbols] = {0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
                                                 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15};

template <int N>
constexpr std::array<std::int32_t, N> baseValues(const std::uint8_t (&bits)[N]) {
    std::array<std::int32_t, N> b{};
    for (int i = 1; i < N; ++i) b[i] = b[i - 1] + (1 << bits[i - 1]);
    return b;
}
constexpr auto kLBase = baseValues(kLExtraBits);
constexpr auto kMBase = baseValues(kMExtraBits);
constexpr auto kDBase = baseValues(kDExtraBits);

// Bit stream read backwards from the end of a payload; bits are taken from the top of the accumulator.
struct InStream {
    const std::uint8_t* buf;     // next byte to load (moving down)
    const std::uint8_t* start;   // lowest valid address
    std::uint64_t accum = 0;
    int nbits = 0;
    bool bad = false;

    std::uint64_t load8(const std::uint8_t* p) {
        if (p < start) {
            bad = true;
            return 0;
        }
        std::uint64_t v = 0;
        std::memcpy(&v, p, 8);
        if constexpr (std::endian::native == std::endian::big) v = std::byteswap(v);
        return v;
    }
    void init(int n) {   // n in [-7, 0]
        if (n) {
            buf -= 8;
            accum = load8(buf);
            nbits = n + 64;
        } else {
            buf -= 7;
            accum = load8(buf - 1) >> 8;
            nbits = n + 56;
        }
        if (buf < start) bad = true;
    }
    void flush() {
        const int n = (63 - nbits) & -8;
        buf -= n >> 3;
        const std::uint64_t incoming = load8(buf);   // flags an overrun below the input start
        accum = (accum << n) | (n == 64 ? incoming : (incoming & ((std::uint64_t{1} << n) - 1)));
        nbits += n;
    }
    std::uint64_t pull(int n) {
        if (n > nbits) {
            bad = true;
            return 0;
        }
        nbits -= n;
        const std::uint64_t r = accum >> nbits;
        accum &= (std::uint64_t{1} << nbits) - 1;
        return r;
    }
};

struct DecoderEntry {   // literal decoder
    std::int8_t k = 0;
    std::uint8_t symbol = 0;
    std::int16_t delta = 0;
};
struct ValueEntry {   // l/m/d decoders
    std::uint8_t totalBits = 0, valueBits = 0;
    std::int16_t delta = 0;
    std::int32_t vbase = 0;
};

template <typename Entry, typename Fill>
Expected<void> initTable(int nstates, int nsymbols, const std::uint16_t* freq, std::vector<Entry>& table, Fill fill) {
    table.assign(static_cast<std::size_t>(nstates), Entry{});
    const int nClz = std::countl_zero(static_cast<std::uint32_t>(nstates));
    int sum = 0;
    std::size_t t = 0;
    for (int i = 0; i < nsymbols; ++i) {
        const int f = freq[i];
        if (f == 0) continue;
        sum += f;
        if (sum > nstates) return fail(ErrorCategory::InvalidFormat, "lzfse frequency table exceeds its state count");
        const int k = std::countl_zero(static_cast<std::uint32_t>(f)) - nClz;
        const int j0 = ((2 * nstates) >> k) - f;
        for (int j = 0; j < f; ++j) {
            Entry e{};
            if (j < j0) fill(e, i, k, static_cast<std::int16_t>(((f + j) << k) - nstates));
            else fill(e, i, k - 1, static_cast<std::int16_t>((j - j0) << (k - 1)));
            table[t++] = e;
        }
    }
    return {};
}

struct BlockHeaderV1 {
    std::uint32_t nRawBytes = 0, nPayloadBytes = 0, nLiterals = 0, nMatches = 0, nLiteralPayloadBytes = 0, nLmdPayloadBytes = 0;
    int literalBits = 0, lmdBits = 0;
    std::uint16_t literalState[4] = {}, lState = 0, mState = 0, dState = 0;
    std::uint16_t lFreq[kLSymbols] = {}, mFreq[kMSymbols] = {}, dFreq[kDSymbols] = {}, literalFreq[kLiteralSymbols] = {};
};

constexpr std::int8_t kFreqNbits[32] = {2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14};
constexpr std::int8_t kFreqValue[32] = {0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1};

// Decode a v2 header (packed fields plus a prefix-coded frequency table) into v1 form.
Expected<std::pair<BlockHeaderV1, std::size_t>> parseHeaderV2(std::span<const std::byte> in) {
    if (in.size() < 32) return fail(ErrorCategory::InvalidFormat, "truncated lzfse v2 block header");
    const std::uint64_t pf0 = loadLe64(in.data() + 8), pf1 = loadLe64(in.data() + 16), pf2 = loadLe64(in.data() + 24);
    auto field = [](std::uint64_t v, int off, int bits) { return static_cast<std::uint32_t>((v >> off) & ((std::uint64_t{1} << bits) - 1)); };
    BlockHeaderV1 h;
    h.nRawBytes = loadLe32(in.data() + 4);
    h.nLiterals = field(pf0, 0, 20);
    h.nLiteralPayloadBytes = field(pf0, 20, 20);
    h.nMatches = field(pf0, 40, 20);
    h.literalBits = static_cast<int>(field(pf0, 60, 3)) - 7;
    for (int i = 0; i < 4; ++i) h.literalState[i] = static_cast<std::uint16_t>(field(pf1, 10 * i, 10));
    h.nLmdPayloadBytes = field(pf1, 40, 20);
    h.lmdBits = static_cast<int>(field(pf1, 60, 3)) - 7;
    const std::uint32_t headerSize = field(pf2, 0, 32);
    h.lState = static_cast<std::uint16_t>(field(pf2, 32, 10));
    h.mState = static_cast<std::uint16_t>(field(pf2, 42, 10));
    h.dState = static_cast<std::uint16_t>(field(pf2, 52, 10));
    h.nPayloadBytes = h.nLiteralPayloadBytes + h.nLmdPayloadBytes;
    if (headerSize < 32 || headerSize > in.size()) return fail(ErrorCategory::InvalidFormat, "bad lzfse v2 header size");
    // Frequency tables: 360 values packed LSB-first.
    std::uint16_t* tables[4] = {h.lFreq, h.mFreq, h.dFreq, h.literalFreq};
    const int counts[4] = {kLSymbols, kMSymbols, kDSymbols, kLiteralSymbols};
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(in.data()) + 32;
    const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(in.data()) + headerSize;
    std::uint32_t accum = 0;
    int accumBits = 0;
    if (headerSize > 32)
        for (int t = 0; t < 4; ++t)
            for (int i = 0; i < counts[t]; ++i) {
                while (accumBits <= 24 && p < end) accum |= std::uint32_t{*p++} << accumBits, accumBits += 8;
                const int b = accum & 31;
                int nbits = kFreqNbits[b];
                std::int32_t value;
                if (nbits == 8) value = 8 + ((accum >> 4) & 0xF);
                else if (nbits == 14) value = 24 + ((accum >> 4) & 0x3FF);
                else value = kFreqValue[b];
                if (nbits > accumBits) return fail(ErrorCategory::InvalidFormat, "lzfse frequency table runs past the header");
                accum >>= nbits;
                accumBits -= nbits;
                tables[t][i] = static_cast<std::uint16_t>(value);
            }
    return std::pair{h, static_cast<std::size_t>(headerSize)};
}

Expected<std::pair<BlockHeaderV1, std::size_t>> parseHeaderV1(std::span<const std::byte> in) {
    constexpr std::size_t kSize = 772;
    if (in.size() < kSize) return fail(ErrorCategory::InvalidFormat, "truncated lzfse v1 block header");
    const std::byte* p = in.data();
    BlockHeaderV1 h;
    h.nRawBytes = loadLe32(p + 4);
    h.nPayloadBytes = loadLe32(p + 8);
    h.nLiterals = loadLe32(p + 12);
    h.nMatches = loadLe32(p + 16);
    h.nLiteralPayloadBytes = loadLe32(p + 20);
    h.nLmdPayloadBytes = loadLe32(p + 24);
    h.literalBits = static_cast<std::int32_t>(loadLe32(p + 28));
    for (int i = 0; i < 4; ++i) h.literalState[i] = loadLe16(p + 32 + 2 * i);
    h.lmdBits = static_cast<std::int32_t>(loadLe32(p + 40));
    h.lState = loadLe16(p + 44);
    h.mState = loadLe16(p + 46);
    h.dState = loadLe16(p + 48);
    std::size_t off = 50;
    for (auto& f : h.lFreq) f = loadLe16(p + off), off += 2;
    for (auto& f : h.mFreq) f = loadLe16(p + off), off += 2;
    for (auto& f : h.dFreq) f = loadLe16(p + off), off += 2;
    for (auto& f : h.literalFreq) f = loadLe16(p + off), off += 2;
    return std::pair{h, kSize};
}

// `all` is the whole input: the backward bit streams start at the end of their payload and may
// legitimately load bytes from before it (the reference bounds them by the input start).
Expected<std::size_t> decodeFseBlock(const BlockHeaderV1& h, std::span<const std::byte> all, std::size_t payloadOff, std::span<std::byte> out, std::size_t outPos) {
    const std::span<const std::byte> payload = all.subspan(payloadOff);
    if (h.nLiterals > (1u << 20) || h.nMatches > (1u << 20)) return fail(ErrorCategory::InvalidFormat, "lzfse block counts out of range");
    if (h.literalBits < -7 || h.literalBits > 0 || h.lmdBits < -7 || h.lmdBits > 0) return fail(ErrorCategory::InvalidFormat, "lzfse block bit counts out of range");
    for (int i = 0; i < 4; ++i)
        if (h.literalState[i] >= kLiteralStates) return fail(ErrorCategory::InvalidFormat, "lzfse literal state out of range");
    if (h.lState >= kLStates || h.mState >= kMStates || h.dState >= kDStates) return fail(ErrorCategory::InvalidFormat, "lzfse lmd state out of range");
    if (std::size_t{h.nLiteralPayloadBytes} + h.nLmdPayloadBytes > payload.size()) return fail(ErrorCategory::InvalidFormat, "lzfse payload runs past the block");
    std::vector<DecoderEntry> literalTable;
    std::vector<ValueEntry> lTable, mTable, dTable;
    if (auto r = initTable(kLiteralStates, kLiteralSymbols, h.literalFreq, literalTable, [](DecoderEntry& e, int sym, int k, std::int16_t delta) {
            e.k = static_cast<std::int8_t>(k);
            e.symbol = static_cast<std::uint8_t>(sym);
            e.delta = delta;
        }); !r) return fail(r.error());
    auto valueFill = [](const std::uint8_t* bits, const std::int32_t* base) {
        return [bits, base](ValueEntry& e, int sym, int k, std::int16_t delta) {
            e.totalBits = static_cast<std::uint8_t>(k + bits[sym]);
            e.valueBits = bits[sym];
            e.delta = delta;
            e.vbase = base[sym];
        };
    };
    if (auto r = initTable(kLStates, kLSymbols, h.lFreq, lTable, valueFill(kLExtraBits, kLBase.data())); !r) return fail(r.error());
    if (auto r = initTable(kMStates, kMSymbols, h.mFreq, mTable, valueFill(kMExtraBits, kMBase.data())); !r) return fail(r.error());
    if (auto r = initTable(kDStates, kDSymbols, h.dFreq, dTable, valueFill(kDExtraBits, kDBase.data())); !r) return fail(r.error());

    // Literals: four interleaved states, read backwards from the end of the literal payload.
    const std::uint8_t* lit = reinterpret_cast<const std::uint8_t*>(payload.data());
    const std::uint8_t* inputStart = reinterpret_cast<const std::uint8_t*>(all.data());
    std::vector<std::uint8_t> literals((h.nLiterals + 3) & ~3u);
    {
        InStream in{lit + h.nLiteralPayloadBytes, inputStart};
        in.init(h.literalBits);
        std::uint32_t state[4] = {h.literalState[0], h.literalState[1], h.literalState[2], h.literalState[3]};
        for (std::uint32_t i = 0; i < h.nLiterals; i += 4) {
            in.flush();
            for (int s = 0; s < 4; ++s) {
                const DecoderEntry& e = literalTable[state[s]];
                state[s] = static_cast<std::uint32_t>(e.delta + static_cast<std::int32_t>(in.pull(e.k)));
                if (state[s] >= static_cast<std::uint32_t>(kLiteralStates)) return fail(ErrorCategory::InvalidFormat, "lzfse literal state out of range");
                literals[i + s] = e.symbol;
            }
            if (in.bad) return fail(ErrorCategory::InvalidFormat, "lzfse literal stream truncated");
        }
    }
    // L/M/D triples, read backwards from the end of the lmd payload.
    const std::uint8_t* lmd = lit + h.nLiteralPayloadBytes;
    InStream in{lmd + h.nLmdPayloadBytes, inputStart};
    in.init(h.lmdBits);
    std::uint32_t lState = h.lState, mState = h.mState, dState = h.dState;
    std::int32_t D = -1;
    std::size_t litPos = 0;
    auto value = [&](std::uint32_t& state, const std::vector<ValueEntry>& table, int nstates) -> std::int32_t {
        const ValueEntry& e = table[state];
        const std::uint64_t bits = in.pull(e.totalBits);
        state = static_cast<std::uint32_t>(e.delta + static_cast<std::int32_t>(bits >> e.valueBits));
        if (state >= static_cast<std::uint32_t>(nstates)) in.bad = true;
        return e.vbase + static_cast<std::int32_t>(bits & ((std::uint64_t{1} << e.valueBits) - 1));
    };
    std::size_t pos = outPos;
    const std::size_t limit = outPos + h.nRawBytes;
    if (limit > out.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the lzfse data");
    for (std::uint32_t i = 0; i < h.nMatches; ++i) {
        in.flush();
        const std::int32_t L = value(lState, lTable, kLStates);
        const std::int32_t M = value(mState, mTable, kMStates);
        const std::int32_t newD = value(dState, dTable, kDStates);
        if (in.bad) return fail(ErrorCategory::InvalidFormat, "lzfse lmd stream corrupt");
        if (newD) D = newD;
        if (L < 0 || M < 0 || litPos + static_cast<std::size_t>(L) > h.nLiterals) return fail(ErrorCategory::InvalidFormat, "lzfse match uses more literals than decoded");
        if (pos + static_cast<std::size_t>(L) + static_cast<std::size_t>(M) > limit) return fail(ErrorCategory::InvalidFormat, "lzfse block decodes past its raw size");
        std::memcpy(out.data() + pos, literals.data() + litPos, static_cast<std::size_t>(L));
        pos += static_cast<std::size_t>(L);
        litPos += static_cast<std::size_t>(L);
        if (M) {
            if (D <= 0 || static_cast<std::size_t>(D) > pos) return fail(ErrorCategory::InvalidFormat, "lzfse match distance before the output start");
            std::byte* dst = out.data() + pos;
            for (std::int32_t k = 0; k < M; ++k) dst[k] = dst[k - D];
            pos += static_cast<std::size_t>(M);
        }
    }
    // Every raw byte comes from an L/M/D triple; the literal count is padded to a multiple of
    // four with bytes no triple uses.
    if (pos != limit) return fail(ErrorCategory::InvalidFormat, "lzfse block raw size does not match its contents");
    return limit;
}

} // namespace

Expected<std::size_t> lzvnDecompress(std::span<const std::byte> inBytes, std::span<std::byte> outBytes) {
    const std::uint8_t* in = reinterpret_cast<const std::uint8_t*>(inBytes.data());
    const std::size_t n = inBytes.size();
    std::byte* out = outBytes.data();
    const std::size_t cap = outBytes.size();
    std::size_t ip = 0, op = 0;
    std::size_t D = 0;
    auto literals = [&](std::size_t L) -> Expected<void> {
        if (ip + L > n) return fail(ErrorCategory::InvalidFormat, "lzvn literals run past the input");
        if (op + L > cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the lzvn data");
        std::memcpy(out + op, in + ip, L);
        ip += L;
        op += L;
        return {};
    };
    auto match = [&](std::size_t M) -> Expected<void> {
        if (D == 0 || D > op) return fail(ErrorCategory::InvalidFormat, "lzvn match distance before the output start");
        if (op + M > cap) return fail(ErrorCategory::OutOfRange, "output buffer too small for the lzvn data");
        for (std::size_t k = 0; k < M; ++k) out[op + k] = out[op + k - D];
        op += M;
        return {};
    };
    while (ip < n) {
        const std::uint8_t opc = in[ip];
        const unsigned row = opc >> 4, low = opc & 7;
        std::size_t L = opc >> 6, M = ((opc >> 3) & 7) + 3;
        if (row == 0xE) {   // literal-only ops
            if (opc == 0xE0) {
                if (ip + 2 > n) return fail(ErrorCategory::InvalidFormat, "truncated lzvn opcode");
                L = std::size_t{in[ip + 1]} + 16;
                ip += 2;
            } else {
                L = opc & 0xF;
                ip += 1;
            }
            if (auto r = literals(L); !r) return fail(r.error());
            continue;
        }
        if (row == 0xF) {   // match-only ops with the previous distance
            if (opc == 0xF0) {
                if (ip + 2 > n) return fail(ErrorCategory::InvalidFormat, "truncated lzvn opcode");
                M = std::size_t{in[ip + 1]} + 16;
                ip += 2;
            } else {
                M = opc & 0xF;
                ip += 1;
            }
            if (auto r = match(M); !r) return fail(r.error());
            continue;
        }
        if (row == 0xA) {   // medium distance
            if (ip + 3 > n) return fail(ErrorCategory::InvalidFormat, "truncated lzvn opcode");
            L = (opc >> 3) & 3;
            M = (((opc & 7) << 2) | (in[ip + 1] & 3)) + 3;
            D = (in[ip + 1] >> 2) | (std::size_t{in[ip + 2]} << 6);
            ip += 3;
        } else if (row == 0x7 || row == 0xD) {
            return fail(ErrorCategory::InvalidFormat, "undefined lzvn opcode");
        } else if (low == 7) {   // large distance: opcode and a 16-bit distance
            if (ip + 3 > n) return fail(ErrorCategory::InvalidFormat, "truncated lzvn opcode");
            D = in[ip + 1] | (std::size_t{in[ip + 2]} << 8);
            ip += 3;
        } else if (low == 6) {
            if (opc == 0x06) return op;   // end of stream
            if (opc == 0x0E || opc == 0x16) {
                ip += 1;
                continue;   // nop
            }
            if (row <= 3) return fail(ErrorCategory::InvalidFormat, "undefined lzvn opcode");
            ip += 1;   // previous distance
        } else {   // small distance
            if (ip + 2 > n) return fail(ErrorCategory::InvalidFormat, "truncated lzvn opcode");
            D = ((opc & 7) << 8) | in[ip + 1];
            ip += 2;
        }
        if (auto r = literals(L); !r) return fail(r.error());
        if (auto r = match(M); !r) return fail(r.error());
    }
    return op;
}

Expected<std::size_t> lzfseDecompress(std::span<const std::byte> in, std::span<std::byte> out) {
    std::size_t ip = 0, op = 0;
    bool any = false;
    while (ip + 4 <= in.size()) {
        const std::uint32_t magic = loadLe32(in.data() + ip);
        any = true;
        if (magic == kMagicEnd) return op;
        if (magic == kMagicRaw) {
            if (ip + 8 > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated lzfse raw block header");
            const std::uint32_t n = loadLe32(in.data() + ip + 4);
            if (ip + 8 + n > in.size()) return fail(ErrorCategory::InvalidFormat, "lzfse raw block runs past the input");
            if (op + n > out.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the lzfse data");
            std::memcpy(out.data() + op, in.data() + ip + 8, n);
            op += n;
            ip += 8 + n;
            continue;
        }
        if (magic == kMagicLzvn) {
            if (ip + 12 > in.size()) return fail(ErrorCategory::InvalidFormat, "truncated lzvn block header");
            const std::uint32_t nRaw = loadLe32(in.data() + ip + 4), nPayload = loadLe32(in.data() + ip + 8);
            if (ip + 12 + nPayload > in.size()) return fail(ErrorCategory::InvalidFormat, "lzvn block runs past the input");
            if (op + nRaw > out.size()) return fail(ErrorCategory::OutOfRange, "output buffer too small for the lzfse data");
            auto n = lzvnDecompress(in.subspan(ip + 12, nPayload), out.subspan(op, nRaw));
            if (!n) return n;
            if (*n != nRaw) return fail(ErrorCategory::InvalidFormat, "lzvn block decoded to the wrong size");
            op += nRaw;
            ip += 12 + nPayload;
            continue;
        }
        if (magic == kMagicV1 || magic == kMagicV2) {
            auto hdr = magic == kMagicV1 ? parseHeaderV1(in.subspan(ip)) : parseHeaderV2(in.subspan(ip));
            if (!hdr) return fail(hdr.error());
            const BlockHeaderV1& h = hdr->first;
            const std::size_t payloadStart = ip + hdr->second;
            if (payloadStart + h.nPayloadBytes > in.size()) return fail(ErrorCategory::InvalidFormat, "lzfse block payload runs past the input");
            auto end = decodeFseBlock(h, in.subspan(0, payloadStart + h.nPayloadBytes), payloadStart, out, op);
            if (!end) return end;
            op = *end;
            ip = payloadStart + h.nPayloadBytes;
            continue;
        }
        return fail(ErrorCategory::InvalidFormat, "unknown lzfse block magic");
    }
    if (!any) return fail(ErrorCategory::InvalidFormat, "no lzfse block in the input");
    return fail(ErrorCategory::InvalidFormat, "lzfse stream without an end-of-stream block");
}

} // namespace stein::compress
