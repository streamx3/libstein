#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""FAT12/16/32 fixtures for the in-process reader. mkfs.vfat formats the image;
files are written with the pyfatfs package (no kernel vfat driver needed), so
the oracle is the content we wrote: a listing with sizes, sha256 per file.
Fragmentation is forced by interleaving writes and deletions.

usage: make_fat_fixtures.py <outdir>   (run inside a venv with pyfatfs + mkfs.vfat on PATH)"""
import hashlib, os, subprocess, sys, tempfile
from fs.base import FS
from pyfatfs.PyFatFS import PyFatFS

out = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/fatfs"
os.makedirs(out, exist_ok=True)
here = os.path.dirname(os.path.abspath(__file__))

def prng_bytes(seed, n):
    x = seed
    buf = bytearray()
    while len(buf) < n:
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        buf += x.to_bytes(8, "little")
    return bytes(buf[:n])

def fill(f: FS, oracle):
    def w(path, data):
        d = os.path.dirname(path)
        if d: f.makedirs(d, recreate=True)
        with f.openbin(path, "w") as h: h.write(data)
        oracle.append(("f", len(data), path, hashlib.sha256(data).hexdigest()))
    w("hello.txt", b"hello from libstein\n")
    w("frag_a.bin", prng_bytes(1, 40 * 1024))
    w("frag_b.bin", prng_bytes(2, 40 * 1024))
    f.remove("frag_a.bin"); oracle[:] = [o for o in oracle if o[2] != "frag_a.bin"]
    w("big.bin", prng_bytes(3, 150 * 1024 + 7))          # fills the hole left by frag_a first -> fragmented chain
    w("empty.txt", b"")
    w("dir/nested/deep/leaf.txt", b"leaf\n")
    w("dir/Long File Name With Spaces.txt", b"lfn\n")
    w("dir/" + "n" * 120 + ".txt", b"long name\n")
    w("dir/unicode-éü中文.txt", b"unicode name\n")
    w("dir/UPPER.TXT", b"case\n")
    w("dir/lower.txt", b"lower\n")
    w("SHORT.TXT", b"8.3 name\n")
    f.makedirs("many")
    for i in range(300):
        w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())   # subdirectory spanning several clusters
    for d in ["dir", "dir/nested", "dir/nested/deep", "many"]:
        oracle.append(("d", 0, d, ""))

def make(name, size_mb, fat_type, extra):
    with tempfile.TemporaryDirectory() as work:
        img = os.path.join(work, name + ".img")
        with open(img, "wb") as h: h.truncate(size_mb * 1024 * 1024)
        subprocess.run(["mkfs.vfat", "-F", str(fat_type), "-n", ("FAT%d" % fat_type).encode().decode()] + extra + [img], check=True, capture_output=True)
        oracle = []
        pf = PyFatFS(img)
        fill(pf, oracle)
        pf.close()
        with open(os.path.join(out, name + ".oracle.txt"), "w") as o:
            for t, size, path, sha in sorted(oracle, key=lambda e: e[2]):
                o.write("%s %d %s\n" % (t, size, path))
            for t, size, path, sha in sorted(oracle, key=lambda e: e[2]):
                if t == "f": o.write("sha256 %s %s\n" % (sha, path))
        subprocess.run([sys.executable, os.path.join(here, "sparsify.py"), "pack", img, os.path.join(out, name + ".sparse")], check=True)
        print(name, os.path.getsize(os.path.join(out, name + ".sparse")), "bytes")

make("fat12", 4, 12, ["-s", "4"])
make("fat16", 32, 16, ["-s", "4"])
make("fat32", 64, 32, ["-s", "1"])
