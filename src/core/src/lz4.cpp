// SPDX-License-Identifier: MIT
#include "stein/core/lz4.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>
#include <cstring>

namespace stein::lz4 {

namespace {

constexpr std::size_t kMinMatch = 4;
constexpr std::size_t kLastLiterals = 5;     // the last 5 bytes are always literals
constexpr std::size_t kMfLimit = 12;         // no match may start within the last 12 bytes
constexpr std::size_t kMaxDistance = 65535;
constexpr int kHashLog = 16;

inline std::uint32_t read32(const std::byte* p) { return loadLe32(p); }
inline std::uint32_t hash32(std::uint32_t v) { return (v * 2654435761u) >> (32 - kHashLog); }

std::byte* writeLength(std::byte* op, std::size_t len) {
    while (len >= 255) {
        *op++ = std::byte{255};
        len -= 255;
    }
    *op++ = std::byte(static_cast<unsigned char>(len));
    return op;
}

} // namespace

std::size_t compressBound(std::size_t n) { return n + n / 255 + 16; }

std::size_t compress(std::span<const std::byte> input, std::span<std::byte> output, int acceleration) {
    const std::byte* ip = input.data();
    const std::byte* const iend = ip + input.size();
    const std::byte* anchor = ip;
    std::byte* op = output.data();
    std::byte* const oend = op + output.size();
    if (output.size() < compressBound(input.size())) return 0;
    if (acceleration < 1) acceleration = 1;

    std::vector<std::uint32_t> table(std::size_t{1} << kHashLog, 0);   // position + 1 (0 = empty)

    auto emitSequence = [&](std::size_t literalLen, std::size_t matchLen, std::size_t offset, bool withMatch) {
        // token
        std::byte* token = op++;
        if (literalLen >= 15) {
            *token = std::byte{15 << 4};
            op = writeLength(op, literalLen - 15);
        } else {
            *token = std::byte(static_cast<unsigned char>(literalLen << 4));
        }
        std::memcpy(op, anchor, literalLen);
        op += literalLen;
        if (!withMatch) return;
        storeLe16(op, static_cast<std::uint16_t>(offset));
        op += 2;
        const std::size_t ml = matchLen - kMinMatch;
        if (ml >= 15) {
            *token = std::byte(std::to_integer<unsigned char>(*token) | 15);
            op = writeLength(op, ml - 15);
        } else {
            *token = std::byte(std::to_integer<unsigned char>(*token) | static_cast<unsigned char>(ml));
        }
    };

    if (input.size() >= kMfLimit + 1) {
        const std::byte* const mflimit = iend - kMfLimit;
        ip += 1;
        while (ip < mflimit) {
            // find a match
            const std::byte* match = nullptr;
            std::size_t step = 1;
            std::size_t searchMatchNb = static_cast<std::size_t>(acceleration) << 6;
            while (true) {
                const std::uint32_t h = hash32(read32(ip));
                const std::uint32_t pos = table[h];
                table[h] = static_cast<std::uint32_t>(ip - input.data()) + 1;
                if (pos && static_cast<std::size_t>(ip - input.data()) + 1 - pos <= kMaxDistance) {
                    const std::byte* cand = input.data() + pos - 1;
                    if (read32(cand) == read32(ip)) {
                        match = cand;
                        break;
                    }
                }
                ip += step;
                step = (searchMatchNb++ >> 6);
                if (ip >= mflimit) break;
            }
            if (!match) break;
            // extend backwards
            while (ip > anchor && match > input.data() && ip[-1] == match[-1]) {
                --ip;
                --match;
            }
            // extend forwards
            const std::byte* const matchLimit = iend - kLastLiterals;
            std::size_t matchLen = kMinMatch;
            while (ip + matchLen < matchLimit && ip[matchLen] == match[matchLen]) ++matchLen;
            const std::size_t literalLen = static_cast<std::size_t>(ip - anchor);
            if (op + literalLen + 16 + literalLen / 255 + matchLen / 255 > oend) return 0;
            emitSequence(literalLen, matchLen, static_cast<std::size_t>(ip - match), true);
            ip += matchLen;
            anchor = ip;
            if (ip >= mflimit) break;
            // index the position just written so the next search can use it
            table[hash32(read32(ip - 2))] = static_cast<std::uint32_t>(ip - 2 - input.data()) + 1;
            ip += 1;
        }
    }
    // last literals
    const std::size_t lastLits = static_cast<std::size_t>(iend - anchor);
    if (op + lastLits + 1 + lastLits / 255 > oend) return 0;
    std::byte* token = op++;
    if (lastLits >= 15) {
        *token = std::byte{15 << 4};
        op = writeLength(op, lastLits - 15);
    } else {
        *token = std::byte(static_cast<unsigned char>(lastLits << 4));
    }
    std::memcpy(op, anchor, lastLits);
    op += lastLits;
    return static_cast<std::size_t>(op - output.data());
}

std::vector<std::byte> compress(std::span<const std::byte> input, int acceleration) {
    std::vector<std::byte> out(compressBound(input.size()));
    out.resize(compress(input, out, acceleration));
    return out;
}

static Expected<std::size_t> decompressImpl(std::span<const std::byte> input, std::span<std::byte> output, bool exact) {
    const std::byte* ip = input.data();
    const std::byte* const iend = ip + input.size();
    std::byte* op = output.data();
    std::byte* const oend = op + output.size();
    auto bad = [](const char* why) { return fail(ErrorCategory::InvalidFormat, std::string("lz4: ") + why); };

    if (input.empty()) return (output.empty() || !exact) ? Expected<std::size_t>{0} : Expected<std::size_t>(bad("empty input for non-empty output"));
    while (true) {
        if (ip >= iend) return bad("truncated at token");
        const unsigned token = std::to_integer<unsigned>(*ip++);
        std::size_t literalLen = token >> 4;
        if (literalLen == 15) {
            unsigned b;
            do {
                if (ip >= iend) return bad("truncated literal length");
                b = std::to_integer<unsigned>(*ip++);
                literalLen += b;
            } while (b == 255);
        }
        if (static_cast<std::size_t>(iend - ip) < literalLen) return bad("literals exceed input");
        if (static_cast<std::size_t>(oend - op) < literalLen) return bad("literals exceed output");
        std::memcpy(op, ip, literalLen);
        ip += literalLen;
        op += literalLen;
        if (ip == iend) {
            if (exact && op != oend) return bad("output size mismatch");
            return static_cast<std::size_t>(op - output.data());   // end of block: last sequence has only literals
        }
        if (iend - ip < 2) return bad("truncated offset");
        const std::size_t offset = loadLe16(ip);
        ip += 2;
        if (offset == 0 || offset > static_cast<std::size_t>(op - output.data())) return bad("offset out of range");
        std::size_t matchLen = (token & 0xF) + kMinMatch;
        if ((token & 0xF) == 15) {
            unsigned b;
            do {
                if (ip >= iend) return bad("truncated match length");
                b = std::to_integer<unsigned>(*ip++);
                matchLen += b;
            } while (b == 255);
        }
        if (static_cast<std::size_t>(oend - op) < matchLen) return bad("match exceeds output");
        const std::byte* match = op - offset;
        if (offset >= matchLen) {
            std::memcpy(op, match, matchLen);
        } else {
            for (std::size_t i = 0; i < matchLen; ++i) op[i] = match[i];   // overlapping copy (run-length style)
        }
        op += matchLen;
    }
}

Expected<void> decompress(std::span<const std::byte> input, std::span<std::byte> output) {
    auto n = decompressImpl(input, output, true);
    if (!n) return fail(n.error());
    return {};
}

Expected<std::size_t> decompressUpTo(std::span<const std::byte> input, std::span<std::byte> output) { return decompressImpl(input, output, false); }

Expected<std::vector<std::byte>> decompress(std::span<const std::byte> input, std::size_t originalSize) {
    std::vector<std::byte> out(originalSize);
    if (auto r = decompress(input, out); !r) return fail(r.error());
    return out;
}

} // namespace stein::lz4
