# Disk imaging design

Requirement R5: create/restore, split, compress, checksum, describe, and
mount filesystems inside images, on any OS. This is the part the GNOME Disks
maintainers declined; it is also the core of the dr_stein use case.

## 1. Image formats

| Format | Role in libstein | Read | Write | Why |
|---|---|---|---|---|
| Raw (`.img`, `.iso`, `.dd`) | universal interchange | v1 | v1 | everything understands it; sparse files make it cheap on disk |
| Split raw (`.img.000`, `.img.001`, … or `.001` `.002`) | legacy "chopped" images | v1 | v1 | fits FAT32 USB sticks and DVDs; trivially `cat`-able back |
| **Stein image (`.stein`)** | native format | v1 | v1 | chunked (default 4 MiB), per-chunk compression (zstd default; lz4 for speed; xz for archival), per-chunk hash (xxh3-128 fast + BLAKE3 whole-image), sparse/unused chunks elided, **used-block-only** via fs L1 maps, **segmentable** into N-byte pieces, **resumable**, **appendable** (incremental: new chunk index referencing older segments), JSON metadata header (source identity, geometry, partition-table snapshot, probe tree, timestamps, tool version, user notes, bad-sector map), optional authenticated encryption of the payload (XChaCha20-Poly1305 or AES-GCM via `stein_crypto`) |
| EWF / E01 (Expert Witness) | forensic interchange | v2 | v2 | already does segmentation + compression + hashes; libewf (LGPL) is the reference; our own reader keeps the core MIT |
| qcow2 | VM interchange | v2 | v3 | snapshots, backing files; qemu is the oracle |
| VHD / VHDX | Windows-native attach (`Virtual Disk API` mounts VHDX without us) | v2 | v2 | lets Windows users attach images with zero extra drivers |
| VMDK (monolithic sparse, split flat) | VM interchange | v2 | — | |
| DMG (UDIF: UDZO/ULFO/UDRO, with `koly` trailer, plist XML) | macOS interchange; `hdiutil attach` for native mounting | v2 | — | |
| partclone / Clonezilla | migration from popular tools | v3 | — | GPL tools; read their *format* (documented) in our own code |

Design point (R5d — the requirement that has bothered the owner for years):
`ImageFormat` exposes an `ImageDevice : BlockDevice`, so every
other library (probe, pt, fs, container, volume, mount) works on images with
no special cases. "Mount ext4 inside LUKS inside a `.stein` image on Windows"
is the same code path as a physical disk.

## 2. The `.stein` container (sketch, to be specified in `spec/stein-image-v1.md`)

```
segment file N (N = 0..):
  [Segment header 4 KiB]   magic "STEINIMG", version, segment index, image UUID, segment UUID,
                           segment payload size, previous-segment hash
  [Chunk records...]       {chunk index (uint64), stored len, raw len, compression, hash128, payload}
  [Segment index]          sorted table (chunk index → file offset) for O(1) seek
  [Segment trailer]        index offset, index hash, "END" marker  → truncated segment is detectable
image manifest (JSON, stored in segment 0 and duplicated in last segment):
  source: {identity, geometry, sector size, probe tree snapshot, partition-table bytes (base64)}
  layout: {chunk size, total chunks, used-chunk bitmap (RLE), bad-sector map, split size}
  integrity: {per-chunk hash algo, whole-image BLAKE3 (filled on completion), creation state: complete|partial}
  provenance: {tool version, host, created, notes, profile id}
```

Properties we get: random access without decompressing everything; verify a
single segment; resume after a crash (last valid chunk is known); restore a
single partition out of a whole-disk image (chunk range from the table
snapshot); "incremental" = new image whose manifest references unchanged
chunks in a parent image (by chunk hash).

## 2a. Pieces: backing up and restoring individual regions (R5a)

Everything the probe tree knows about is a `Region{device, offset, length,
kind, identity}`; `stein_layout` (`18-structure-layouts.md`) tells us where
the *metadata* regions of each format are. So the image layer can address,
independently:

| Piece | Region(s) | Why you want it alone |
|---|---|---|
| Partition table (GPT) | LBA 0 (PMBR), LBA 1 + entry array, backup array + backup header at the end | "my table got wiped, the data is intact" — restore 34+33 sectors, not 1 TB |
| Partition table (MBR) | LBA 0 + every EBR sector in the chain | same |
| APM | block 0 (DDM) + the map blocks | same |
| Filesystem header | ext: superblock + group descriptors (+ backup superblocks); FAT: reserved sectors + FATs; NTFS: boot sector + `$MFT`/`$MFTMirr` extents; HFS+: volume header + alternate; btrfs: all superblock copies | metadata-only snapshot before a risky operation; restore from a backup copy |
| LUKS header | first 16 MiB (LUKS2) / up to 2 MiB (LUKS1) | the one piece whose loss is unrecoverable |
| LVM metadata | PV label + metadata areas | same |
| One partition | its extent | classic |
| Whole disk | everything | classic |

A `.stein` image whose manifest lists several pieces from the same source is
a **piece set**; `RestoreImage` can restore any subset, and `DumpTable`/
`RestoreTable` are the small special cases. Each piece carries its own
hashes, so a 1 TB image can be verified "table only" in milliseconds.

## 2b. Encryption as a layer (R5b, R5e)

Two independent mechanisms, because they answer different questions:

1. **Payload encryption inside `.stein`**: each chunk is encrypted with
   AES-256-GCM or XChaCha20-Poly1305 under a data key; the data key is
   wrapped by one or more key slots (passphrase via argon2id, keyfile, raw
   key) in the manifest — LUKS2's keyslot idea applied to an image. Chunk
   hashes are computed on the **plaintext** (so verification with the key
   compares content) and the segment index is also hashed over the
   **ciphertext** (so verification without the key still detects corruption
   or truncation). Streaming: read → hash → compress → encrypt → write, one
   pass, bounded memory. A 1 TB source never needs a 1 TB staging copy.
2. **Any `BlockDevice` as the sink**: because a decrypted LUKS/VeraCrypt
   container is itself a `BlockDevice`, an image can be written *into* an
   encrypted container file or partition (`CreateImage` with
   `sink = container.unlock(key)`), and read back the same way. This gives
   compatibility with tools that already understand LUKS at zero extra
   cost.

Hashing through layers is then automatic: `Hasher::hash(BlockDevice&,
Region)` does not care whether the device is a raw disk, a
`DecryptedDevice`, an `ImageDevice` over a compressed segment, or a slice of
any of those. MD5 is supported for interoperability; SHA-256 and BLAKE3 are
the defaults; xxh3-128 is the fast per-chunk hash. Per-piece hashes are
stored alongside per-chunk hashes so "verify this partition inside this
encrypted image" is one bounded read.

## 3. Copy engine

One engine serves clone, image creation, image restore, partition move/copy.

```
Source (BlockDevice or ImageFormat::Reader)  --->  Sink (BlockDevice or ImageFormat::Writer)
                 \_____ UsedBlockMap (optional; from stein_fs L1 or image manifest) ____/
                 \_____ BadSectorPolicy: fail | skip-zero | skip-retry-later (ddrescue-style two pass) _/
                 \_____ Verify: none | hash-while-copying | read-back compare _________________________/
```

- Buffers: 4–64 MiB, sector-aligned (`O_DIRECT`/`FILE_FLAG_NO_BUFFERING` when
  requested), double-buffered: a reader thread, a transformer pool
  (compress/hash), a writer thread. Backpressure via bounded queues.
- Direction-aware for overlapping ranges (partition move left/right), as in
  GParted's `CopyBlocks`.
- Sparse-aware: detect all-zero blocks (fast word compare) and punch holes /
  skip chunk; on restore, optionally write zeros or discard (TRIM).
- Used-block-only: ask `FileSystem::usedBlockMap()`; unknown fs → full copy.
  Restore of a used-block-only image zero-fills or discards unused areas
  (configurable) so the result is consistent.
- Progress: bytes + chunks + phase; ETA from the engine.
- Checkpointing: every K chunks the sink flushes and the manifest's
  `creation state` is updated (restore writes a tiny sidecar).

## 4. Restore validation (the dr_stein lesson)

Before writing a single byte, `RestoreImage::validate` checks: target
identity matches profile rules; target size ≥ image size (or ≥ used extent
when the image carries a table snapshot and the user accepts "partial");
sector-size equality (512 ↔ 4K images are *not* interchangeable for
partitioned images; for a bare filesystem image they may be, per fs); target
not mounted/in use; image integrity (manifest + sampled or full chunk
verification per policy). Post-restore: GPT backup header relocation if the
target is larger, optional fs grow, re-probe and diff.

## 5. Mounting images

- OS-native attach (`stein_platform`): Linux loop device (+ partition scan),
  macOS `hdiutil attach -imagekey diskimage-class=CRawDiskImage` or
  DiskImages framework, Windows Virtual Disk API (VHD/VHDX only; raw needs a
  conversion or our FUSE path). Gives native read/write via the OS driver,
  but only for formats and filesystems the OS understands.
- In-process (`stein_mount`): `ImageDevice` → probe → `FileSystem::Reader/Writer`
  → FUSE/WinFsp. Works for every fs we implement, on every OS, including
  inside LUKS/LVM/compressed/split images. This is the feature no other tool
  has.
