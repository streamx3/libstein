#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Zero everything in an image except the given byte ranges (keeps the file size).
usage: trim.py <image> <start:end> [<start:end>...]
       end may be 'end'; a negative start counts from the end; suffixes K/M/G allowed.
Used to keep only the metadata a fixture needs."""
import sys
from pathlib import Path


def num(s: str, size: int) -> int:
    if s == "end":
        return size
    mult = 1
    if s[-1] in "KMG":
        mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[s[-1]]
        s = s[:-1]
    v = int(s) * mult
    return size + v if v < 0 else v


def main() -> int:
    p = Path(sys.argv[1])
    size = p.stat().st_size
    data = p.read_bytes()
    out = bytearray(size)
    for r in sys.argv[2:]:
        a, b = r.split(":")
        a, b = num(a, size), num(b, size)
        out[a:b] = data[a:b]
    p.write_bytes(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
