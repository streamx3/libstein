#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# LUKS1 and LUKS2 fixtures with a known passphrase. cryptsetup formats the
# header (no dm-crypt needed); the payload is an ext2 image encrypted with
# AES-XTS-plain64 under the dumped master key by the Python `cryptography`
# package, so unlocking + decrypting end to end has an independent oracle.
set -eu
OUT=${1:-tests/fixtures/luks}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
PASS='luks test passphrase'
printf '%s' "$PASS" > "$WORK/pw.txt"

# A tiny ext2 filesystem as the plaintext payload (256 KiB keeps the fixtures small).
truncate -s 256K "$WORK/plain.img"
mkfs.ext2 -q -b 1024 -L inside_luks "$WORK/plain.img"

make_one() { # name type extra-args...
  local name=$1 type=$2; shift 2
  local img="$WORK/$name.img"
  truncate -s 20M "$img"
  cryptsetup luksFormat --type "$type" --batch-mode --cipher aes-xts-plain64 --key-size 512 --key-file "$WORK/pw.txt" "$@" "$img" >/dev/null 2>&1
  local dump; dump=$(cryptsetup luksDump --dump-master-key --batch-mode --key-file "$WORK/pw.txt" "$img")
  local mk; mk=$(printf '%s' "$dump" | awk '/MK dump/{f=1; sub(/.*MK dump:/, "")} f{gsub(/[ \t]/,""); printf "%s", $0}' )
  local payload; payload=$(printf '%s' "$dump" | awk -F: '/Payload offset|^\toffset:/{gsub(/[ \t]/,"",$2); print $2; exit}')
  # LUKS2 prints the segment offset in bytes (and may use 4096-byte sectors), LUKS1 in 512-byte sectors.
  local sector_size=512
  if [ "$type" = luks2 ]; then
    payload_bytes=$(cryptsetup luksDump --dump-json-metadata "$img" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["segments"]["0"]["offset"]))')
    sector_size=$(cryptsetup luksDump --dump-json-metadata "$img" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["segments"]["0"]["sector_size"]))')
  else
    payload_bytes=$((payload * 512))
  fi
  python3 - "$img" "$WORK/plain.img" "$mk" "$payload_bytes" "$sector_size" <<'PY'
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
img, plain, mk, off, ss = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
data = open(plain, "rb").read()
out = bytearray()
for s in range(0, len(data), ss):
    sector = s // ss
    tweak = sector.to_bytes(8, "little") + bytes(8)
    out += Cipher(algorithms.AES(mk), modes.XTS(tweak)).encryptor().update(data[s:s+ss])
with open(img, "r+b") as f:
    f.seek(off)
    f.write(out)
PY
  if [ "$type" = luks1 ]; then
    # Zero the key material of the seven inactive slots: keeps the fixture small, the header stays valid.
    python3 - "$img" <<'PY'
import sys, struct
p = sys.argv[1]
d = bytearray(open(p, "rb").read())
payload = struct.unpack(">I", d[104:108])[0]
for i in range(8):
    base = 0xD0 + i * 48
    active = struct.unpack(">I", d[base:base+4])[0]
    kmo = struct.unpack(">I", d[base+40:base+44])[0]
    stripes = struct.unpack(">I", d[base+44:base+48])[0]
    if active != 0x00AC71F3:
        nxt = payload if i == 7 else struct.unpack(">I", d[0xD0 + (i+1)*48 + 40:0xD0 + (i+1)*48 + 44])[0]
        d[kmo*512:nxt*512] = bytes((nxt - kmo) * 512)
open(p, "wb").write(d)
PY
  fi
  {
    echo "passphrase=$PASS"
    echo "master_key=$mk"
    echo "payload_offset=$payload_bytes"
    echo "sector_size=$sector_size"
    echo "plain_size=262144"
    echo "label=inside_luks"
  } > "$OUT/$name.oracle.txt"
  cryptsetup luksDump "$img" > "$OUT/$name.dump.txt" 2>/dev/null || true
  python3 "$HERE/sparsify.py" pack "$img" "$OUT/$name.sparse"
  echo "$name: $(stat -c %s "$OUT/$name.sparse") bytes, payload at $payload_bytes"
}

make_one luks1 luks1 --hash sha256 --pbkdf-force-iterations 1000
make_one luks1_sha1 luks1 --hash sha1 --pbkdf-force-iterations 1000
make_one luks2 luks2 --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 64 --pbkdf-parallel 1 --luks2-metadata-size 16k --luks2-keyslots-size 256k --sector-size 512
make_one luks2_pbkdf2 luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --luks2-metadata-size 16k --luks2-keyslots-size 256k --sector-size 4096
