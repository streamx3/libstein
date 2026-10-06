# `.stein` image format, version 1

Status: implemented in `stein_image` (M1). Little-endian throughout. All
multi-byte integers are unsigned unless stated. Offsets are absolute within
the segment file that contains them.

## Files

An image is one or more **segment files**: `name.stein` (segment 0) and,
when split, `name.stein.001`, `name.stein.002`, … Segment 0 carries the
manifest. Every segment carries the same `image_uuid`, so stray parts can be
matched and ordered by `segment_index`.

## Segment header (128 bytes at offset 0)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `magic` | `"STEINIMG"` |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `header_size` | 128 |
| 12 | 4 | `flags` | bit 0: has manifest (segment 0); bit 1: encrypted (see §Encryption); bit 2: complete (writer finished the whole image) |
| 16 | 16 | `image_uuid` | RFC 4122 byte order |
| 32 | 4 | `segment_index` | 0-based |
| 36 | 4 | `chunk_size` | bytes; power of two; ≥ 4096 |
| 40 | 8 | `total_size` | bytes of source data |
| 48 | 4 | `sector_size` | logical sector size of the source |
| 52 | 1 | `compression` | 0 none, 1 LZ4 block, 2 zstd (reserved) |
| 53 | 1 | `chunk_hash` | 1 = CRC-32C over raw chunk bytes |
| 54 | 1 | `image_hash` | 0 none, 1 SHA-256 over all raw bytes (zeros included) |
| 55 | 1 | reserved | 0 |
| 56 | 8 | `manifest_offset` | segment 0: byte offset of the manifest (128); else 0 |
| 64 | 8 | `manifest_length` | bytes of UTF-8 JSON |
| 72 | 8 | `split_size` | maximum bytes per segment; 0 = unlimited |
| 80 | 48 | reserved | 0 |

## Manifest (segment 0, right after the header)

UTF-8 JSON object:

```json
{
  "format": "stein-image", "version": 1,
  "created": "2026-10-06T01:20:00Z", "tool": "libstein 0.1.0",
  "source": { "name": "/dev/sdb", "identity": "wwn:...", "size": 16777216,
              "sector_size": 512, "physical_sector_size": 4096, "model": "...", "serial": "..." },
  "layout": { "chunk_size": 4194304, "total_chunks": 4, "compression": "lz4", "split_size": 0 },
  "topology": { ... probe tree: table type, partitions, filesystem types/labels/uuids ... },
  "notes": ""
}
```

Readers must ignore unknown keys. The manifest is informational except for
`layout` and `source`, which readers may cross-check against the header.

## Chunk records

Chunks cover the source in order; chunk *k* holds bytes
`[k·chunk_size, min((k+1)·chunk_size, total_size))`. Records may appear in
any order and in any segment; a chunk that appears nowhere is **implicitly
zero** (the writer omits all-zero chunks when flag bit 0 says so, see below).

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `magic` | `"CHNK"` |
| 4 | 4 | `flags` | bit 0: zero chunk (no payload, raw bytes are all zero); bit 1: payload is compressed with the header's `compression`; bit 2: partial (last chunk, `raw_length` < `chunk_size`) |
| 8 | 8 | `chunk_index` | |
| 16 | 4 | `raw_length` | bytes of source data represented |
| 20 | 4 | `stored_length` | payload bytes that follow (0 for zero chunks) |
| 24 | 4 | `raw_crc32c` | CRC-32C of the raw bytes |
| 28 | 4 | `stored_crc32c` | CRC-32C of the payload (0 when no payload) |
| 32 | `stored_length` | payload | |

A compressed payload is one LZ4 block (or zstd frame in a later version)
whose decompressed size is `raw_length`. The writer stores a chunk
uncompressed when compression does not shrink it.

## Segment index and trailer (end of each segment)

Index: `index_count` entries of `{u64 chunk_index, u64 record_offset}`
sorted by `chunk_index`, followed by the 80-byte trailer, which is always
the last 80 bytes of the file:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `magic` | `"STEINIDX"` |
| 8 | 8 | `index_offset` | |
| 16 | 8 | `index_count` | |
| 24 | 8 | `chunks_total` | total chunks of the image (0 until known) |
| 32 | 8 | `flags` | bit 0: last segment of the image; bit 1: `image_hash` present; bit 2: zero chunks were omitted (implicitly zero) |
| 40 | 32 | `image_hash` | SHA-256 of the whole source (last segment only) |
| 72 | 4 | `index_crc32c` | CRC-32C over the index entries |
| 76 | 4 | reserved | 0 |

## Recovery

A segment without a valid trailer (crash while writing) is read by scanning
`CHNK` records from the end of the manifest (segment 0) or the header
(others). Each record's `stored_crc32c` confirms its payload; a torn record
ends the scan. Everything recovered is usable; the image is reported as
incomplete.

## Verification levels

1. **Structure**: headers, trailers, index CRCs — milliseconds.
2. **Payload**: every `stored_crc32c` — reads the whole image, no decompression.
3. **Content**: decompress and check `raw_crc32c`, then the SHA-256.

## Not in v1

Encryption (header flag reserved; design in `doc/design/14-imaging.md` §2b),
used-block-only maps (chunks are still omitted when all-zero), piece sets,
incremental references, zstd.

## Encryption (header flag bit 1)

Header bytes 80..87 `keys_offset` and 88..95 `keys_length` (u64 each) locate
the **key area** in segment 0: plaintext JSON, written right after the header
and padded to a multiple of 4096 bytes so slots can be added or removed in
place. The manifest follows the key area.

```json
{"version":1,"cipher":"chacha20-poly1305",
 "digest":{"salt":"<16 bytes hex>","iterations":1000,"hash":"<32 bytes hex>"},
 "slots":[{"id":0,"type":"passphrase","label":"...","salt":"<16 hex>",
           "kdf":"argon2id","time":3,"memory_kib":262144,"parallelism":4,
           "nonce":"<12 hex>","wrapped":"<48 hex>"},
          {"id":1,"type":"passphrase","salt":"<16 hex>",
           "kdf":"pbkdf2-hmac-sha256","iterations":600000,
           "nonce":"<12 hex>","wrapped":"<48 hex>"}]}
```

- One random 256-bit **master key** per image. `digest.hash` is
  PBKDF2-HMAC-SHA256(master key, `digest.salt`, `digest.iterations`, 32) and
  tells a wrong passphrase from a damaged slot (the master key is random, so
  the digest needs no slow KDF).
- A **slot** wraps the master key with AEAD_CHACHA20_POLY1305 under a key
  derived from the passphrase by the slot's `kdf`: `argon2id` (RFC 9106,
  version 0x13; `time` passes, `memory_kib`, `parallelism`; the default is
  t=3, 256 MiB, p=4) or `pbkdf2-hmac-sha256` (`iterations`, at least 1000).
  Nonce `nonce`, additional data `"stein-key-slot"`; `wrapped` is ciphertext
  (32) + tag (16). Up to 8 slots; the last one cannot be removed. A top-level
  `"kdf"` key (first drafts) applies to slots that lack their own.
- **Nonces** are 12 bytes: `le64(n) || tag`, where `tag` is `CHNK` with the
  chunk index, `MANF` with 0 for the manifest, `HASH` with 0 for the image hash.
  The master key is used for one image only, so every nonce is unique.
- **Manifest**: `manifest_offset/length` point at AEAD(key, nonce MANF, aad
  `"manifest"`, plaintext JSON); `manifest_length` includes the 16-byte tag.
- **Chunks**: the stored payload (compressed or raw) is AEAD(key, nonce
  CHNK(index), aad = `le64(index) || le32(flags) || le32(raw_length)`,
  payload); `stored_length` includes the tag, `stored_crc` is the CRC-32C of the
  ciphertext (verifiable without the key), `raw_crc` is 0 (a plaintext CRC
  would leak; the tag authenticates the chunk). Zero chunks are still omitted
  or flagged, so the zero pattern of the source is visible, as with discards
  on LUKS volumes.
- **Image hash**: the trailer's `image_hash` is SHA-256(plaintext image) XOR
  the first 32 bytes of the ChaCha20 keystream for (key, nonce HASH, counter
  0). Readers with the key recover and check it; readers without it see
  random bytes. Keyless integrity comes from the per-chunk `stored_crc`.
- Readers open an encrypted image **locked**: header, segments, chunk map and
  stored CRCs work (`verify --level 2`); the manifest, chunk contents and the
  image hash need a successful unlock.
