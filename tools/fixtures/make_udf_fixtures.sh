#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# UDF fixtures. genisoimage writes UDF 1.02 next to ISO 9660 (a "bridge"
# disc); the second variant moves the UDF recognition sequence to sector 16 and
# drops the ISO descriptors, so only UDF remains and probing picks the UDF reader. The oracle is
# the source tree.
set -eu
OUT=${1:-tests/fixtures/udffs}
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
os.symlink("hello.txt", os.path.join(m, "link_short"))
os.symlink("dir/nested/deep/" + "p" * 80 + "/target", os.path.join(m, "link_long"))
os.makedirs(os.path.join(m, "many"))
for i in range(120):
    w("many/file_%03d.txt" % i, ("entry %d\n" % i).encode())
for root, dirs, files in os.walk(m):
    for n in dirs + files:
        p = os.path.join(root, n)
        if not os.path.islink(p):
            os.utime(p, (1704164645, 1704164645))
PY

genisoimage -quiet -udf -iso-level 3 -R -input-charset utf-8 -V RD_UDF -o "$WORK/bridge.iso" "$SRC" 2>/dev/null
cp "$WORK/bridge.iso" "$WORK/only.iso"
python3 - "$WORK/only.iso" <<'PY'
import sys
p = sys.argv[1]
# A UDF-only disc starts its volume recognition sequence at sector 16 with BEA01. The bridge
# image puts the ISO 9660 descriptors there first; move BEA01/NSR02/TEA01 down and blank the rest.
with open(p, "r+b") as f:
    sectors = []
    for sector in range(16, 32):
        f.seek(sector * 2048)
        data = f.read(2048)
        if data[1:6] in (b"BEA01", b"NSR02", b"NSR03", b"TEA01"):
            sectors.append(data)
    for i in range(16):
        f.seek((16 + i) * 2048)
        f.write(sectors[i] if i < len(sectors) else b"\0" * 2048)
PY
# UDF 2.50 from mkudffs: a metadata partition (type 2 map) around an empty root directory.
# Only some media types allow revisions above 2.01; skip the fixture when none works here.
if command -v mkudffs >/dev/null; then
  for media in bdr dvdram mo dvdrw; do
    rm -f "$WORK/udf250.img"; truncate -s 8M "$WORK/udf250.img"
    if mkudffs --udfrev=0x250 --media-type=$media --blocksize=2048 --label=rd_udf250 "$WORK/udf250.img" >/dev/null 2>&1; then
      : > "$OUT/udf_250_empty.oracle.txt"
      python3 "$HERE/sparsify.py" pack "$WORK/udf250.img" "$OUT/udf_250_empty.sparse"
      echo "udf_250_empty ($media): $(stat -c %s "$OUT/udf_250_empty.sparse") bytes"
      break
    fi
  done
fi
for name in bridge only; do
  # genisoimage records symlinks on the UDF side as empty regular files; the oracle says so.
  python3 "$HERE/oracle.py" "$SRC" | python3 -c '
import sys, re
for line in sys.stdin:
    if line.startswith("link "): continue
    m = re.match(r"l \d+ (.*)\n", line)
    sys.stdout.write("f 0 %s\n" % m.group(1) if m else line)
' > "$OUT/udf_$name.oracle.txt"
  python3 "$HERE/sparsify.py" pack "$WORK/$name.iso" "$OUT/udf_$name.sparse"
  echo "udf_$name: $(stat -c %s "$OUT/udf_$name.sparse") bytes"
done
