#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Convert a (mostly zero) disk image into the tiny ".sparse" fixture format and back.

Format (little-endian):
  magic   "STEINSPARSE1" (12 bytes)
  u64     total size in bytes
  u32     sector size
  then records until EOF: u64 offset, u64 length, <length> bytes
Only non-zero 4 KiB chunks are stored, so a partition-table fixture is a few KiB.
Tests load it into a MemoryDevice (tests/include/stein_fixture.hpp).

usage: sparsify.py pack  <image> <out.sparse> [--sector-size N]
       sparsify.py unpack <in.sparse> <image>
"""
import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"STEINSPARSE1"
CHUNK = 4096


def pack(image: Path, out: Path, sector_size: int) -> None:
    size = image.stat().st_size
    with image.open("rb") as f, out.open("wb") as o:
        o.write(MAGIC + struct.pack("<QI", size, sector_size))
        off = 0
        run_start = None
        run = bytearray()
        while off < size:
            data = f.read(CHUNK)
            if not data:
                break
            if any(data):
                if run_start is None:
                    run_start = off
                run += data
            elif run_start is not None:
                o.write(struct.pack("<QQ", run_start, len(run)) + run)
                run_start, run = None, bytearray()
            off += len(data)
        if run_start is not None:
            o.write(struct.pack("<QQ", run_start, len(run)) + run)


def unpack(src: Path, image: Path) -> None:
    data = src.read_bytes()
    if data[:12] != MAGIC:
        sys.exit("not a STEINSPARSE1 file")
    size, sector = struct.unpack_from("<QI", data, 12)
    pos = 24
    with image.open("wb") as f:
        f.truncate(size)
        while pos < len(data):
            off, length = struct.unpack_from("<QQ", data, pos)
            pos += 16
            f.seek(off)
            f.write(data[pos:pos + length])
            pos += length


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack")
    p.add_argument("image", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("--sector-size", type=int, default=512)
    u = sub.add_parser("unpack")
    u.add_argument("src", type=Path)
    u.add_argument("image", type=Path)
    a = ap.parse_args()
    if a.cmd == "pack":
        pack(a.image, a.out, a.sector_size)
    else:
        unpack(a.src, a.image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
