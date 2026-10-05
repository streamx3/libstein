# Structure layouts: manifests and the hexinator-style tree (OQ6)

The owner asked for two related things: (1) a tree view of every field of
every partition-table header and filesystem header, the way Hexinator /
010 Editor / Kaitai Web IDE show a parsed binary; (2) a separate,
declarative description ("manifest") of *what is where* for each format, so
that the parsers get simpler and the knowledge is stored once.

## 1. What a layout is

A `LayoutTree` is the parsed, annotated view of a region of a device:

```
GPT header @ LBA 1 (512 B)                           [valid]
├── signature        @0x00  8 B  ascii   "EFI PART"  [ok]
├── revision         @0x08  4 B  u32le   0x00010000  [ok: 1.0]
├── header_size      @0x0C  4 B  u32le   92          [ok]
├── header_crc32     @0x10  4 B  u32le   0x9E3F1A2B  [MISMATCH: computed 0x9E3F1A2C]
├── reserved         @0x14  4 B  u32le   0
├── my_lba           @0x18  8 B  u64le   1           [ok]
├── alternate_lba    @0x20  8 B  u64le   3907029167  [ok: matches device end]
├── first_usable_lba @0x28  8 B  u64le   34
├── last_usable_lba  @0x30  8 B  u64le   3907029134
├── disk_guid        @0x38 16 B  guid    {1C9F…}
├── entries_lba      @0x48  8 B  u64le   2
├── num_entries      @0x50  4 B  u32le   128
├── entry_size       @0x54  4 B  u32le   128
└── entries_crc32    @0x58  4 B  u32le   0x…         [ok]
GPT entry array @ LBA 2 (16 KiB)
├── [0] EFI System Partition …
│   ├── type_guid    @0x00 16 B  guid    C12A7328-… "EFI System"
│   ├── unique_guid  @0x10 16 B  guid    …
│   ├── first_lba    @0x20  8 B  u64le   2048
│   ├── last_lba     @0x28  8 B  u64le   1050623
│   ├── attributes   @0x30  8 B  bits    0x0000000000000000
│   └── name         @0x38 72 B  utf16le "EFI System Partition"
└── …
```

Each node: `{name, offset (absolute on the device and relative to the
parent), size, type (u8/u16/u32/u64 le/be, ascii, utf16le, guid, uuid,
bitfield, enum, blob, crc32, lba, timestamp variants…), raw bytes, decoded
value, pretty value, validity {ok, warning, error, info} + message, doc
string, children}`. The same node type represents a 1-byte flag and a
16 KiB entry array; UIs render it as a tree with a hex pane; the CLI prints
it; tests assert on it; `Region`s for dump/restore (R5a) are read straight
off it ("the region covered by this subtree").

## 2. Manifests: declarative where possible, code where necessary

The honest split, learned from Kaitai Struct, Hexinator grammars and 010
templates: **fixed-offset field tables are data; everything else is logic.**

- *Data* (manifest): field name, offset, size, type, endianness, enum
  values, bit names, doc string, and simple validity rules (`== "EFI PART"`,
  `in {0x00010000}`, `<= parent.size`). This covers 90 % of every header in
  this domain: GPT header/entry, MBR entry, APM entry and DDM, BSD disklabel,
  ext superblock and group descriptor, FAT BPB/FSInfo, exFAT boot sector,
  NTFS boot sector and MFT record header and attribute headers, HFS+ volume
  header, LUKS1/2 binary headers, LVM PV label, md superblocks, xfs/btrfs/
  f2fs superblocks, ISO9660 descriptors, VHD footer, qcow2 header, DMG koly.
- *Logic* (code): CRCs over computed ranges, EBR chains, APM map
  self-description, variable-length and self-describing structures (NTFS
  attribute lists, ext4 extent trees, HFS+ B-trees, LUKS2 JSON), cross-field
  validation that needs the device (does `alternate_lba` match the device
  size?), and anything that requires reading somewhere else first.

So a format module consists of: `formats/gpt/gpt.layout` (the manifest) +
`GptPartitionTable.cpp` (the logic, which *uses* the manifest both to decode
fields and to emit the `LayoutTree`). One source of truth for offsets and
names; no hand-typed `offset 0x48` constants duplicated between parser,
writer, and visualiser.

### 2.1 Manifest format

A small, readable text format of our own (TOML-like), compiled into C++
tables at build time by a tiny generator (so the runtime library has no
parser for the manifest language, and typos fail the build, not the user):

```toml
[struct.gpt_header]
doc  = "UEFI 2.10 §5.3.2 GPT Header"
size = 92
endian = "le"

[[struct.gpt_header.field]]
name = "signature"     ; offset = 0x00 ; type = "ascii[8]" ; expect = "EFI PART"
[[struct.gpt_header.field]]
name = "revision"      ; offset = 0x08 ; type = "u32" ; enum = { 0x00010000 = "1.0" }
[[struct.gpt_header.field]]
name = "header_size"   ; offset = 0x0C ; type = "u32" ; min = 92 ; max = 512
[[struct.gpt_header.field]]
name = "header_crc32"  ; offset = 0x10 ; type = "crc32" ; over = "0..header_size" ; zeroed = "self"
# …
[[struct.gpt_header.field]]
name = "disk_guid"     ; offset = 0x38 ; type = "guid"
[[struct.gpt_header.field]]
name = "attributes"    ; offset = 0x30 ; type = "bits64"
bits = { 0 = "platform_required", 1 = "no_block_io_protocol", 2 = "legacy_bios_bootable",
         60 = "ms_read_only", 62 = "ms_hidden", 63 = "ms_no_automount" }
```

Why our own and not Kaitai `.ksy`: Kaitai's compiler is GPL-3 (runtime MIT),
its generated C++ uses exceptions and heavy templates, and its expression
language is more than we need. The *format gallery* of `.ksy` files is a
useful reference for offsets; we do not import it.

### 2.2 Generated C++

For each `struct` the generator emits a plain class with: `static
constexpr size_t kSize`, a `Field` table (`name, offset, size, type, doc`),
typed accessors that read from a `std::span<const std::byte>`
(`uint32_t header_size() const`), setters for the writer, and
`LayoutTree describe(std::span<const std::byte>, uint64_t absOffset) const`
that produces the tree with per-field validity from the simple rules. The
module's logic adds the cross-field diagnostics onto that tree. No templates
beyond `std::span`; the generated code is meant to be read.

## 3. Where manifests live

`formats/<family>/<name>.layout` next to the module that uses them; the
generator runs at build time (`stein_layout_gen`, a small C++ or Python
tool — Python only at build time, never at runtime). Manifests are plain
text, diffable, and double as the project's format documentation: the
rendered doc site can be generated from them.

## 4. What this buys

- One place to fix an offset. One place to document a field.
- The visualiser (R5-adjacent, the "hexinator" wish) comes for free for
  every format, including partially broken ones — the tree shows *which*
  field is wrong, which is exactly what a repair UI needs.
- Dump/restore of pieces (R5a) uses the subtree's covered range.
- Fuzzing target: the generated `describe()` must never crash on arbitrary
  bytes; it only annotates.
- Tests: golden `LayoutTree` text dumps per fixture, so a parser change that
  alters a decoded value is a visible diff.
