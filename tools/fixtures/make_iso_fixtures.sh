#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ISO 9660 fixtures for the in-process reader, built with genisoimage from a
# deterministic source tree: Rock Ridge + Joliet (POSIX names, symlinks, hard
# link counts), Joliet only (UCS-2 names), and plain level-1 ISO 9660 (8.3
# upper-case names with ";1"). The oracle is isoinfo's listing and extraction
# with the matching name extension, converted to the reader oracle format.
set -eu
OUT=${1:-tests/fixtures/isofs}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
SRC="$WORK/src"
mkdir -p "$SRC"

python3 - "$SRC" <<'PY'
import os, sys
m = sys.argv[1]
def w(path, data):
    p = os.path.join(m, path); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "wb").write(data)
rng = int.from_bytes(b"stein", "big")
def prng(n):
    global rng
    out = bytearray()
    while len(out) < n:
        rng = (rng * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out += rng.to_bytes(8, "little")
    return bytes(out[:n])
w("hello.txt", b"hello from libstein\n")
w("big.bin", prng(150 * 1024 + 123))
w("tiny.txt", b"x")
w("empty.txt", b"")
w("dir/nested/deep/leaf.txt", b"leaf\n")
w("dir/upper.txt", b"case test\n")
w("dir/" + "n" * 200 + ".txt", b"long name\n")
w("dir/ünïcödé 日本語.txt", b"unicode\n")
w("a/b/c/d/e/f/g/h/i/deep.txt", b"relocated by Rock Ridge\n")   # depth 10 > ISO limit 8
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.link(os.path.join(m, "hello.txt"), os.path.join(m, "hardlink.txt"))
os.makedirs(os.path.join(m, "many"))
for i in range(120):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))
PY

oracle() { # image oraclefile isoinfo-flags...
  local img=$1 o=$2; shift 2
  python3 - "$img" "$o" "$@" <<'PY'
import hashlib, re, subprocess, sys
img, out, flags = sys.argv[1], sys.argv[2], sys.argv[3:]
listing = subprocess.run(["isoinfo", "-l", *flags, "-i", img], check=True, capture_output=True).stdout.decode("utf-8")
entries, shas, links = [], [], []
cwd = ""
for line in listing.splitlines():
    m = re.match(r"Directory listing of (.*)$", line)
    if m:
        cwd = m.group(1).strip("/")
        continue
    m = re.match(r"^([-dl])[-rwxsStT]{9}\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\S+\s+\d+\s+\d+\s+\[\s*\d+\s+\d+\]\s+(.*?)\s*$", line)
    if not m:
        continue
    t, size, name = m.group(1), int(m.group(2)), m.group(3)
    target = None
    if t == "l" and " -> " in name:
        name, target = name.split(" -> ", 1)
    raw = name
    name = re.sub(r";1$", "", name)
    if name in (".", ".."):
        continue
    rel = (cwd + "/" + name) if cwd else name
    rawrel = (cwd + "/" + raw) if cwd else raw
    entries.append((t, size, rel))
    if t == "l":
        links.append((rel, target or ""))
    elif t == "f" or t == "-":
        data = subprocess.run(["isoinfo", "-x", "/" + rawrel, *flags, "-i", img], check=True, capture_output=True).stdout
        shas.append((hashlib.sha256(data).hexdigest(), rel))
with open(out, "w", encoding="utf-8") as o:
    for t, size, rel in sorted(entries, key=lambda e: e[2]):
        o.write("%s %d %s\n" % ("f" if t == "-" else t, size, rel))
    for sha, rel in sorted(shas, key=lambda e: e[1]):
        o.write("sha256 %s %s\n" % (sha, rel))
    for rel, target in sorted(links):
        o.write("link %s -> %s\n" % (rel, target))
PY
}

make_one() { # name oracle-flags genisoimage-args...
  local name=$1 oflags=$2; shift 2
  local img="$WORK/$name.iso"
  genisoimage -quiet -input-charset utf-8 -V "RD_${name^^}" "$@" -o "$img" "$SRC" 2>/dev/null
  if [ "$oflags" = "JOLIET" ]; then
    # isoinfo cannot print CJK Joliet names (its charsets stop at Latin code pages), so the
    # oracle is the source tree without symlinks, without the subtree beyond the ISO depth limit
    # (dropped from the Joliet tree) and with names cut to Joliet's 103 units;
    # the path set is cross-checked against isoinfo -f -J for every ASCII path.
    python3 - "$SRC" "$img" "$OUT/$name.oracle.txt" "$HERE/oracle.py" <<'PY'
import subprocess, sys, re
src, img, out, oracle = sys.argv[1:5]
text = subprocess.run([sys.executable, oracle, src], check=True, capture_output=True).stdout.decode("utf-8")
def cut(path):
    return "/".join(c[:103] for c in path.split("/"))
lines = []
for line in text.splitlines():
    if line.startswith("link ") or line.startswith("l "):
        continue
    if line.split(" ", 2)[2].count("/") >= 7:
        continue   # genisoimage drops directories deeper than the ISO limit from the Joliet tree
    if line.startswith("sha256 "):
        sha, rest = line.split(" ", 2)[1], line.split(" ", 2)[2]
        lines.append("sha256 %s %s" % (sha, cut(rest)))
    else:
        t, size, path = line.split(" ", 2)
        lines.append("%s %s %s" % (t, size, cut(path)))
open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
want = set(l.split(" ", 2)[2] for l in lines if not l.startswith("sha256"))
have = set(p.lstrip("/") for p in subprocess.run(["isoinfo", "-f", "-J", "-i", img], check=True, capture_output=True).stdout.decode("latin-1").splitlines() if p.strip())
ascii_want = set(p for p in want if p.isascii())
ascii_have = set(p for p in have if p.isascii())
if ascii_want != ascii_have:
    sys.exit("Joliet oracle mismatch: only in source %r, only in image %r" % (sorted(ascii_want - ascii_have)[:5], sorted(ascii_have - ascii_want)[:5]))
PY
  elif [ "$oflags" = "SOURCE" ]; then
    # Rock Ridge keeps POSIX names, links and deep paths intact (isoinfo does not follow
    # CL/RE relocation, the kernel does); the source tree is the oracle, plus the
    # relocation directory genisoimage leaves behind, which the kernel shows empty.
    python3 "$HERE/oracle.py" "$SRC" > "$OUT/$name.oracle.txt"
    echo "d 2048 rr_moved" >> "$OUT/$name.oracle.txt"
  else
    oracle "$img" "$OUT/$name.oracle.txt"
  fi
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes, $(grep -c . "$OUT/$name.oracle.txt") oracle lines"
}

make_one iso_rr     "SOURCE"      -J -R -joliet-long
make_one iso_joliet "JOLIET" -J -joliet-long
make_one iso_plain  "PLAIN"
