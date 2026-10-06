#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthesises a Linux md RAID superblock version 1.2 (at offset 4096) on an image,
for environments where mdadm cannot create arrays (containers). Layout per the
kernel's struct mdp_superblock_1 (include/uapi/linux/raid/md_p.h), little-endian.
usage: make_md_member.py <image> <set-uuid-hex32> <name>"""
import struct
import sys
from pathlib import Path


def main() -> int:
    img = Path(sys.argv[1])
    set_uuid = bytes.fromhex(sys.argv[2])
    name = sys.argv[3].encode()
    size = img.stat().st_size
    sectors = size // 512
    data_offset = 2048
    sb = bytearray(256)
    # struct mdp_superblock_1 offsets: see include/uapi/linux/raid/md_p.h
    struct.pack_into("<IIII", sb, 0, 0xA92B4EFC, 1, 0, 0)          # magic, major_version, feature_map, pad0
    sb[16:32] = set_uuid                                            # set_uuid
    sb[32:64] = name.ljust(32, b"\0")                               # set_name
    struct.pack_into("<Q", sb, 64, 1_700_000_000)                   # ctime
    struct.pack_into("<IIQ", sb, 72, 1, 0, sectors - data_offset - 8)   # level, layout, size (sectors)
    struct.pack_into("<II", sb, 88, 0, 1)                           # chunksize, raid_disks
    struct.pack_into("<Q", sb, 128, data_offset)                    # data_offset (sectors)
    struct.pack_into("<Q", sb, 136, sectors - data_offset - 8)      # data_size
    struct.pack_into("<Q", sb, 144, 8)                              # super_offset (sectors) = 4096 / 512
    struct.pack_into("<II", sb, 160, 0, 0)                          # dev_number, cnt_corrected_read
    struct.pack_into("<Q", sb, 192, 1_700_000_000)                  # utime
    struct.pack_into("<Q", sb, 200, 7)                              # events
    struct.pack_into("<Q", sb, 208, 0xFFFFFFFFFFFFFFFF)             # resync_offset
    struct.pack_into("<I", sb, 220, 1)                              # max_dev
    roles = struct.pack("<H", 0)
    full = bytes(sb) + roles
    words = full + b"\0" * ((4 - len(full) % 4) % 4)
    total = sum(struct.unpack_from("<I", words, i)[0] for i in range(0, len(words), 4))
    csum = (total & 0xFFFFFFFF) + (total >> 32)
    struct.pack_into("<I", sb, 216, csum & 0xFFFFFFFF)              # sb_csum
    with img.open("r+b") as f:
        f.seek(4096)
        f.write(bytes(sb) + roles)
    return 0


if __name__ == "__main__":
    sys.exit(main())
