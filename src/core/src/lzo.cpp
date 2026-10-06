// SPDX-License-Identifier: MIT
#include "stein/core/lzo.hpp"

#include <cstring>

namespace stein::compress {

namespace {

// Instruction encoding (lzo1x_d.ch):
//   0..15   after a literal run: M1 three-byte match, distance 1025..3072 (two bytes); otherwise
//           M1 two-byte match, distance 1..1024, or at the very start a literal run of t+3
//   16..31  M4 match, distance 16385..49151, length 2 + (t & 7) [+ extension bytes], two more
//           bytes; distance 16384 with length code 1 is the end-of-block marker
//   32..63  M3 match, distance 1..16384, length 2 + (t & 31) [+ extension bytes], two more bytes
//   64..255 M2 match, distance 1..2048, length (t >> 5) + 1, one more byte
// The two low bits of the last byte of each match instruction hold 0..3 literals that follow it.
struct State {
    const std::uint8_t* in;
    std::size_t inLen, ip = 0;
    std::uint8_t* out;
    std::size_t outLen, op = 0;
    enum class Why { None, Truncated, Small, Corrupt } why = Why::None;
    bool bad = false;

    void flag(Why w) {
        bad = true;
        if (why == Why::None) why = w;
    }

    bool haveIn(std::size_t n) const { return ip + n <= inLen; }
    std::uint8_t byte() {
        if (ip >= inLen) { flag(Why::Truncated); return 0; }
        return in[ip++];
    }
    // Zero bytes extend a length by 255 each; the final non-zero byte is added too.
    std::size_t extend(std::size_t t) {
        while (ip < inLen && in[ip] == 0) { t += 255; ++ip; }
        return t + byte();
    }
    bool literals(std::size_t n) {
        if (!haveIn(n)) { flag(Why::Truncated); return false; }
        if (op + n > outLen) { flag(Why::Small); return false; }
        std::memcpy(out + op, in + ip, n);
        ip += n;
        op += n;
        return true;
    }
    bool match(std::size_t distance, std::size_t length) {
        if (distance == 0 || distance > op) { flag(Why::Corrupt); return false; }
        if (op + length > outLen) { flag(Why::Small); return false; }
        const std::uint8_t* src = out + op - distance;
        std::uint8_t* dst = out + op;
        for (std::size_t i = 0; i < length; ++i) dst[i] = src[i];   // overlapping copies replicate
        op += length;
        return true;
    }
};

} // namespace

Expected<std::size_t> lzo1xDecompress(std::span<const std::byte> inBytes, std::span<std::byte> outBytes) {
    State s{reinterpret_cast<const std::uint8_t*>(inBytes.data()), inBytes.size(), 0,
            reinterpret_cast<std::uint8_t*>(outBytes.data()), outBytes.size(), 0};
    if (s.inLen == 0) return fail(ErrorCategory::InvalidFormat, "empty LZO block");
    auto failure = [&]() -> Expected<std::size_t> {
        switch (s.why) {
        case State::Why::Truncated: return fail(ErrorCategory::InvalidFormat, "truncated LZO1X block");
        case State::Why::Small: return fail(ErrorCategory::OutOfRange, "output buffer too small for the LZO1X block");
        default: return fail(ErrorCategory::InvalidFormat, "corrupt LZO1X block");
        }
    };
    auto le16 = [&](std::size_t& code) {
        if (!s.haveIn(2)) { s.flag(State::Why::Truncated); return false; }
        code = s.in[s.ip] | (static_cast<std::size_t>(s.in[s.ip + 1]) << 8);
        s.ip += 2;
        return true;
    };

    // What the previous instruction was decides how a code below 16 is read.
    enum class Prev { Match, LiteralRun, ShortLiterals } prev = Prev::Match;
    std::size_t t = s.byte();
    if (t > 17) {
        t -= 17;
        if (!s.literals(t)) return failure();
        prev = t < 4 ? Prev::ShortLiterals : Prev::LiteralRun;
        t = s.byte();
    }
    for (;;) {
        if (s.bad) return failure();
        std::size_t distance = 0, length = 0, next = 0;
        if (t < 16) {
            if (prev == Prev::Match) {
                // Literal run of t + 3 bytes (t == 0: extended).
                if (t == 0) t = s.extend(15);
                if (!s.literals(t + 3)) return failure();
                prev = Prev::LiteralRun;
                t = s.byte();
                continue;
            }
            next = t & 3;
            if (prev == Prev::LiteralRun) {
                distance = 0x0801 + (t >> 2) + (static_cast<std::size_t>(s.byte()) << 2);   // M1, 3 bytes
                length = 3;
            } else {
                distance = 1 + (t >> 2) + (static_cast<std::size_t>(s.byte()) << 2);   // M1, 2 bytes
                length = 2;
            }
        } else if (t >= 64) {
            next = t & 3;
            distance = 1 + ((t >> 2) & 7) + (static_cast<std::size_t>(s.byte()) << 3);   // M2
            length = (t >> 5) + 1;
        } else if (t >= 32) {
            length = t & 31;   // M3
            if (length == 0) length = s.extend(31);
            length += 2;
            std::size_t code = 0;
            if (!le16(code)) return failure();
            distance = 1 + (code >> 2);
            next = code & 3;
        } else {
            const std::size_t base = (t & 8) << 11;   // M4
            length = t & 7;
            if (length == 0) length = s.extend(7);
            length += 2;
            std::size_t code = 0;
            if (!le16(code)) return failure();
            distance = base + (code >> 2);
            if (distance == 0) {
                // End of block: "17 0 0" (length code 1, distance 0).
                if (length != 3) return fail(ErrorCategory::InvalidFormat, "bad LZO1X end marker");
                return s.op;
            }
            distance += 0x4000;
            next = code & 3;
        }
        if (s.bad || !s.match(distance, length)) return failure();
        if (next == 0) {
            prev = Prev::Match;
        } else {
            if (!s.literals(next)) return failure();
            prev = Prev::ShortLiterals;
        }
        t = s.byte();
    }
}

} // namespace stein::compress
