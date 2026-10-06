#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
VeraCrypt / TrueCrypt volume fixtures, written from the format description
with independent implementations (hashlib PBKDF2 over SHA-512/SHA-256/BLAKE2s/RIPEMD-160,
Botan 2 for Whirlpool and Streebog PBKDF2 and for the Serpent/Twofish/Camellia
block ciphers, gostcrypto for Kuznyechik, `cryptography` AES-XTS, zlib CRC-32)
so the C++ reader is checked against something it shares no code with.
Payloads are small ext2 images filled with debugfs. Cascades follow
VeraCrypt: "aes-twofish-serpent" encrypts with Serpent, then Twofish, then
AES, each layer in XTS with its own primary and tweak key; the key material
lists the primary keys of all layers in table order, then the tweak keys.

Layout (VeraCrypt "Volume Format Specification"): 64 KiB header area at the
start (512-byte header: 64-byte salt + 448 bytes encrypted with XTS under
the PBKDF2-derived header key, data unit 0), the hidden-volume header at
64 KiB, the data area at 128 KiB encrypted with the master keys using the
absolute 512-byte data-unit number as tweak, and backup headers in the last
128 KiB (normal at end-128K, hidden at end-64K) under fresh salts.

usage: make_tcrypt_fixtures.py [outdir]
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import botan2
import gostcrypto

OUT = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/tcrypt"
os.makedirs(OUT, exist_ok=True)
HEADER_AREA = 65536
DATA_START = 131072


def prng(label, n):
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"stein-tcrypt:" + label + i.to_bytes(4, "little")).digest()
        i += 1
    return bytes(out[:n])


def ecb(cipher, key, block):
    if cipher == "kuznyechik":
        return bytes(gostcrypto.gostcipher.new("kuznechik", bytearray(key), gostcrypto.gostcipher.MODE_ECB).encrypt(bytearray(block)))
    c = botan2.BlockCipher({"serpent": "Serpent", "twofish": "Twofish", "camellia": "Camellia-256"}[cipher])
    c.set_key(key)
    return bytes(c.encrypt(block))


def gf_mul(t):
    out = bytearray(16)
    carry = 0
    for i in range(16):
        c = t[i] >> 7
        out[i] = ((t[i] << 1) | carry) & 0xFF
        carry = c
    if carry:
        out[0] ^= 0x87
    return bytes(out)


def xts_unit(key64, unit, data, encrypt=True, cipher="aes"):
    tweak = struct.pack("<Q", unit) + b"\0" * 8
    if cipher == "aes":
        c = Cipher(algorithms.AES(key64), modes.XTS(tweak))
        op = c.encryptor() if encrypt else c.decryptor()
        return op.update(data) + op.finalize()
    assert encrypt
    t = ecb(cipher, key64[32:], tweak)
    out = bytearray()
    for off in range(0, len(data), 16):
        x = bytes(a ^ b for a, b in zip(data[off:off + 16], t))
        out += bytes(a ^ b for a, b in zip(ecb(cipher, key64[:32], x), t))
        t = gf_mul(t)
    return bytes(out)


def cascade_unit(ea, keys, unit, data):
    """ea: cipher names in table order; keys: 64*n bytes (primary keys, then tweak keys). Last cipher first."""
    n = len(ea)
    for i in reversed(range(n)):
        data = xts_unit(keys[32 * i:32 * i + 32] + keys[32 * n + 32 * i:32 * n + 32 * i + 32], unit, data, cipher=ea[i])
    return data


def xts_sectors(keys, first_unit, data, ea=("aes",)):
    out = bytearray()
    for i in range(0, len(data), 512):
        out += cascade_unit(ea, keys, first_unit + i // 512, data[i:i + 512])
    return bytes(out)


def pbkdf2(prf, password, salt, iterations, length):
    if prf in ("whirlpool", "streebog512"):
        _, _, dk = botan2.pbkdf("PBKDF2(%s)" % {"whirlpool": "Whirlpool", "streebog512": "Streebog-512"}[prf], password.decode(), length, iterations, salt)
        return dk
    return hashlib.pbkdf2_hmac(prf, password, salt, iterations, length)


def header(magic, prf, password, iterations, salt, master, volume_size, area_start, hidden_size=0, min_version=0x010B, ea=("aes",)):
    plain = bytearray(448)
    plain[0:4] = magic
    struct.pack_into(">H", plain, 4, 5)
    struct.pack_into(">H", plain, 6, min_version)
    keys = bytearray(256)
    keys[0:len(master)] = master
    keys[len(master):] = prng(b"keypad" + salt, 256 - len(master))
    struct.pack_into(">I", plain, 8, zlib.crc32(bytes(keys)))
    struct.pack_into(">Q", plain, 28, hidden_size)
    struct.pack_into(">Q", plain, 36, volume_size)
    struct.pack_into(">Q", plain, 44, area_start)
    struct.pack_into(">Q", plain, 52, volume_size)
    struct.pack_into(">I", plain, 60, 0)
    struct.pack_into(">I", plain, 64, 512)
    struct.pack_into(">I", plain, 188, zlib.crc32(bytes(plain[:188])))
    plain[192:448] = keys
    n = len(ea)
    hk = pbkdf2(prf, password, salt, iterations, 64 * n)
    return salt + cascade_unit(ea, hk, 0, bytes(plain))


def ext2_image(size, label, text):
    d = tempfile.mkdtemp()
    img = os.path.join(d, "fs.img")
    with open(img, "wb") as f:
        f.truncate(size)
    subprocess.run(["mkfs.ext2", "-q", "-b", "1024", "-L", label, img], check=True)
    hello = os.path.join(d, "hello.txt")
    open(hello, "w").write(text)
    subprocess.run(["debugfs", "-w", "-R", "write %s hello.txt" % hello, img], check=True, capture_output=True)
    data = open(img, "rb").read()
    return data


def iterations(variant, prf, pim):
    if variant == b"TRUE":
        return {"sha512": 1000, "ripemd160": 2000, "whirlpool": 1000}[prf]
    if prf == "ripemd160" and pim == 0:
        return 655331
    if pim == 0:
        return 500000
    return 15000 + pim * 1000


def volume(name, password, prf, pim, variant=b"VERA", payload_size=256 * 1024, hidden=None, ea=("aes",)):
    """hidden = (password, prf, pim, size) places a hidden volume at the end of the data area."""
    payload = ext2_image(payload_size, "inside_vc" if hidden is None else "outer_vc", "secret inside %s\n" % name)
    master = prng(b"master:" + name.encode(), 64 * len(ea))
    total = DATA_START + payload_size + DATA_START
    img = bytearray(total)
    area = xts_sectors(master, DATA_START // 512, payload, ea)
    img[DATA_START:DATA_START + payload_size] = area
    it = iterations(variant, prf, pim)
    img[0:512] = header(variant, prf, password.encode(), it, prng(b"salt:" + name.encode(), 64), master, payload_size, DATA_START, ea=ea)
    img[total - DATA_START:total - DATA_START + 512] = header(variant, prf, password.encode(), it, prng(b"bsalt:" + name.encode(), 64), master, payload_size, DATA_START, ea=ea)
    note = "%s %s %s pim=%d iterations=%d payload=%d" % (variant.decode(), "-".join(ea), prf, pim, it, payload_size)
    if hidden:
        hpass, hprf, hpim, hsize = hidden
        hmaster = prng(b"hidden-master:" + name.encode(), 64)
        hstart = DATA_START + payload_size - hsize
        hpayload = ext2_image(hsize, "hidden_vc", "hidden secret inside %s\n" % name)
        img[hstart:hstart + hsize] = xts_sectors(hmaster, hstart // 512, hpayload)
        hit = iterations(variant, hprf, hpim)
        img[HEADER_AREA:HEADER_AREA + 512] = header(variant, hprf, hpass.encode(), hit, prng(b"hsalt:" + name.encode(), 64), hmaster, hsize, hstart, hidden_size=hsize)
        img[total - HEADER_AREA:total - HEADER_AREA + 512] = header(variant, hprf, hpass.encode(), hit, prng(b"hbsalt:" + name.encode(), 64), hmaster, hsize, hstart, hidden_size=hsize)
        note += "; hidden %s pim=%d iterations=%d size=%d start=%d" % (hprf, hpim, hit, hsize, hstart)
    raw = os.path.join(OUT, name + ".raw")
    open(raw, "wb").write(img)
    here = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([sys.executable, os.path.join(here, "sparsify.py"), "pack", raw, os.path.join(OUT, name + ".sparse")], check=True)
    os.remove(raw)
    open(os.path.join(OUT, name + ".oracle.txt"), "w").write("password %s\n%s\n" % (password, note))
    print("%s: %s" % (name, note))


volume("veracrypt_sha512", "stein-vera", "sha512", 0)
volume("veracrypt_sha256_pim", "stein-pim", "sha256", 3)
volume("truecrypt_sha512", "stein-true", "sha512", 0, variant=b"TRUE")
volume("veracrypt_hidden", "stein-outer", "sha512", 1, payload_size=512 * 1024, hidden=("stein-hidden", "sha256", 1, 256 * 1024))
volume("truecrypt_ripemd160", "stein-rmd", "ripemd160", 0, variant=b"TRUE")
volume("veracrypt_blake2s_pim", "stein-blake", "blake2s256", 2)
volume("veracrypt_ripemd160_pim", "stein-vrmd", "ripemd160", 4)

# Every other VeraCrypt cipher, two cascades, and the two PRFs outside hashlib (PIM 1 keeps the trials cheap).
volume("veracrypt_serpent_pim", "stein-serp", "sha512", 1, ea=("serpent",))
volume("veracrypt_twofish_pim", "stein-two", "sha256", 1, ea=("twofish",))
volume("veracrypt_camellia_whirlpool_pim", "stein-cam", "whirlpool", 1, ea=("camellia",))
volume("veracrypt_kuznyechik_streebog_pim", "stein-kuz", "streebog512", 1, ea=("kuznyechik",))
volume("veracrypt_aes_twofish_serpent_pim", "stein-cascade", "sha512", 1, ea=("aes", "twofish", "serpent"))
volume("veracrypt_kuznyechik_serpent_camellia_pim", "stein-gost", "blake2s256", 1, ea=("kuznyechik", "serpent", "camellia"))
volume("truecrypt_whirlpool", "stein-whirl", "whirlpool", 0, variant=b"TRUE")
volume("truecrypt_serpent_twofish_aes", "stein-tcascade", "sha512", 0, variant=b"TRUE", ea=("serpent", "twofish", "aes"))
