# Architecture: the libstein library chain

*Draft 2 (2026-10-05). Revised against the reference-project surveys in
`doc/research/`.*

## 1. One library or a chain?

A chain. Reasons:

- A one-button restore app (R12) needs devices + images + a copy engine, but
  not partition editing, filesystem drivers or SMART. It should link ~4 small
  libraries, not one 20 MB blob.
- Userspace filesystem drivers (R7) are large, slow-moving, independently
  testable modules; they must be optional at build time and loadable
  individually.
- Platform code (R2) is the only place with OS `#ifdef`s; isolating it in one
  library is what makes "pure C++ core" verifiable (CI builds the core with
  `-nostdinc`-style hygiene: no `<windows.h>`, no `<sys/ioctl.h>`).
- GPL-adjacent optional backends (R8: wrappers around `mkfs.*`/`fsck.*`) and
  LGPL-linking adapters (R9) must be separate shared objects so that the MIT
  core never links them.

## 2. Dependency DAG

```
                         +----------------+
                         |  stein_core    |  types, Expected, Bytes/Sectors, Uuid,
                         +-------+--------+  byte-order, CRC32/CRC32C, hashing (BLAKE3,
                                 |           SHA-256, xxh3), Progress/Cancel, Logger,
                                 |           Report tree, utf8/utf16, path helpers
             +-------------------+------------------+
             |                   |                  |
     +-------v-------+   +-------v-------+   +------v--------+
     | stein_block   |   | stein_platform|   | stein_crypto  |  AES-XTS/CBC, PBKDF2,
     | BlockDevice   |<--| Linux/macOS/  |   | (backend-     |  argon2id, SHA-512,
     | abstractions, |   | Windows raw   |   |  agnostic:    |  whirlpool..., RNG
     | MemoryDevice, |   | disk access,  |   |  own impl or  |
     | SliceDevice,  |   | enumeration,  |   |  OpenSSL/     |
     | caching, I/O  |   | loop/attach,  |   |  mbedTLS)     |
     | scheduler     |   | mount, SMART, |   +------+--------+
     +---+-----+-----+   | privilege     |          |
         |     |         +-------+-------+          |
         |     |                 |                  |
   +-----v--+  |   +-------------v---+     +--------v--------+
   |stein_pt|  |   | stein_probe     |     | stein_container |  LUKS1/2, VeraCrypt,
   |Partition  |   | signature scan, |     | (unlock -> new  |  BitLocker(detect),
   |tables: |  |   | "what is on     |     |  BlockDevice)   |  plain dm-crypt
   |MBR/EBR,|  |   |  this device"   |     +--------+--------+
   |GPT,APM,|  |   +-------+---------+              |
   |BSD,Sun,|  |           |                        |
   |SGI,RDB,|  |   +-------v---------+     +--------v--------+
   |PC98,AIX|  |   | stein_fs        |     | stein_volume    |  LVM2, mdraid(detect),
   +----+---+  |   | FileSystem base |     | (VG/LV -> new   |  LDM(detect), APFS
        |      |   | + one module per|     |  BlockDevices)  |  container(detect)
        |      |   | fs (ext, fat,   |     +--------+--------+
        |      |   | ntfs, hfs, ...) |              |
        |      |   +-------+---------+              |
        |      |           |                        |
        +------+-----+-----+------------------------+
                     |
             +-------v--------+
             | stein_image    |  image formats: raw, split-raw, "stein" container
             | (ImageFormat,  |  (chunked, compressed, checksummed, with metadata),
             |  copy engine,  |  E01/EWF, qcow2, VHD/VHDX, VMDK (read first),
             |  sparse, used- |  DMG (read) ; fs-aware used-block maps via stein_fs
             |  block maps)   |
             +-------+--------+
                     |
             +-------v--------+
             | stein_ops      |  Operation (planned, previewable, undoable), Job,
             | (operation     |  OperationStack, Runner, Report, dry-run,
             |  stack, jobs)  |  dependency ordering, safety checks
             +-------+--------+
                     |
       +-------------+--------------+----------------------+
       |                            |                      |
+------v--------+        +----------v----------+  +--------v---------+
| stein_app     |        | stein_backend_exec  |  | stein_mount      |
| Profiles,     |        | OPTIONAL: wrappers  |  | FUSE / WinFsp /  |
| "one-button"  |        | around mkfs.*,      |  | macFUSE / NFS    |
| scenarios,    |        | fsck.*, resize2fs,  |  | bridge: exposes  |
| config, i18n  |        | sgdisk, cryptsetup  |  | stein_fs Reader/ |
| catalogue     |        | (Linux only, R8)    |  | Writer as a mount|
+---------------+        +---------------------+  +------------------+
       |
  +----v-----------------------------------------------+
  |  UIs: gtk / cocoa / winui / cli  (link the C++ API directly; no C shim planned) |
  +----------------------------------------------------+
```

Arrows point from dependant to dependency (top is lowest level). Everything
above `stein_platform` is OS-agnostic; `stein_platform` has three
implementations selected by CMake.

### 2.1 Library-by-library

| Library | Depends on | Contents | Notes |
|---|---|---|---|
| `stein_core` | STL | `Expected<T>`, `Error`, `Bytes`, `Sectors`, `Lba`, `Uuid`, `Guid` (mixed-endian GPT GUID vs RFC UUID), `Crc32`, `Crc32c`, `Hash` (SHA-256, BLAKE3, xxh3-128), endian load/store, `Progress`, `CancelToken`, `Report` tree, `Logger`, UTF-8/16 conversion, `Version`, `SizeFormatter` | Header-mostly. Zero platform includes. |
| `stein_block` | core | `BlockDevice` abstract base (read/write at offset, geometry, flags, identity), `MemoryDevice`, `FileDevice` (uses `stein_platform` file I/O via an injected interface, so still portable), `SliceDevice` (offset+length view), `CachedDevice` (LRU sector cache), `ReadOnlyDevice`, `ScatterGather` helpers, `IoScheduler` (double-buffered async copies) | The hub type; everything consumes `BlockDevice&`. |
| `stein_platform` | core, block | Per-OS: enumerate disks (`Disk`, `Drive` identity: model, serial, WWN, bus, removable, rotational), open raw devices (`PlatformDisk : BlockDevice`), re-read partition table, lock/unmount volumes, attach/detach image as OS block device (loop / hdiutil / VHD API), mount/unmount natively, SMART/NVMe health, privilege helper launcher, device-change notifications | The only library with `#ifdef _WIN32`/`__APPLE__`/`__linux__`. Three source dirs, one public header set. |
| `stein_crypto` | core | AES (XTS, CBC-ESSIV, CBC-plain), Serpent, Twofish, Camellia (VeraCrypt cascades), SHA-1/256/512, Whirlpool, RIPEMD-160, Streebog (VeraCrypt), PBKDF2, argon2id, HMAC, CSPRNG | Abstract `CipherBackend`; v1 ships a reference pure-C++ backend (correctness first) and an optional OpenSSL/mbedTLS backend for speed. Constant-time primitives where it matters. |
| `stein_pt` | core, block | `PartitionTable` base, `Partition` entry, `PartitionTypeRegistry` (MBR IDs, GPT GUIDs, APM type strings with OS semantics), concrete tables: MBR+EBR, GPT (with backup-header recovery, CRC repair, header relocation), APM (with the DDM block0), BSD disklabel (incl. nested inside MBR), Sun VTOC, SGI/DVH, Amiga RDB, PC98, AIX, `NoTable` | Pure parsing/serialisation against `BlockDevice`; `PartitionTable::Editor` produces a new in-memory table; `write()` is explicit and ordered (GPT: backup first, then primary, then protective MBR). |
| `stein_probe` | core, block, pt, fs, container, volume | Signature scanning (`blkid`-like): "what is on this device / in this region", nested discovery (disk → GPT → LUKS → LVM PV → LV → ext4), produces a `Topology` tree | This is the glue the UIs render. Keeps probing cheap: reads only superblocks. |
| `stein_fs` | core, block | `FileSystem` base (+ capability objects, `design/11`), `FsRegistry`, one module per filesystem family. Each module has *levels*: L0 detect+geometry+label+uuid (from superblock), L1 used-block bitmap (for imaging), L2 resize/label/uuid/check (metadata editing), L3 read (directory/inode walk, file read), L4 write | Each module is its own CMake target and can be turned off. v1 ships L0 for all, L1 for ext/ntfs/fat/exfat/xfs/btrfs/hfs+, L2 for ext/fat/ntfs-label, L3 for ext4/fat/exfat/ntfs/hfs+/iso9660. |
| `stein_container` | core, block, crypto | `Container` base: LUKS1, LUKS2 (JSON metadata, argon2id, integrity flag awareness), VeraCrypt/TrueCrypt (header decryption with cascades, hidden volumes), BitLocker (detect; unlock later via libbde-like logic), plain dm-crypt (parameters supplied), `DecryptedDevice : BlockDevice` doing transparent XTS | In-process decryption means "open LUKS on Windows" works with zero kernel support. |
| `stein_volume` | core, block, pt | `VolumeGroup` base: LVM2 (text metadata parser, linear/striped/mirror/thin(detect) maps → `LogicalVolumeDevice`), mdraid superblock 0.9/1.x (detect; linear/raid0/raid1 read), Windows LDM (detect), APFS container (detect, list volumes), CoreStorage (detect) | |
| `stein_image` | core, block, fs | `ImageFormat` base; `RawImage`, `SplitRawImage` (`.img.000`…), `SteinImage` (our container: chunked, per-chunk zstd/lz4/xz, per-chunk hash, sparse map, metadata JSON incl. partition-table snapshot and source identity, resumable, appendable), `EwfImage` (E01 read/write — the forensic standard with native segmentation+compression), `Qcow2Image` (read, then write), `VhdxImage` (read), `VmdkImage` (read), `DmgImage` (read: UDIF/UDZO/ULFO), plus the **copy engine** (large aligned buffers, async double-buffering, sparse skipping, used-block-only via `stein_fs` L1, bad-sector skip-and-retry map à la ddrescue, verify pass) | `ImageDevice : BlockDevice` makes any image usable everywhere (mount, probe, partition) without the OS. |
| `stein_ops` | all above | `Operation` (describe, validate against a `Topology` snapshot, estimate, apply via `Job`s, revert), `OperationStack` (pending list with dependency resolution and simulation on a cloned in-memory topology), `Runner` (threads, progress aggregation, report), standard operations: Create/Delete/Resize/Move partition, Format, Resize/Check/Label fs, Create/Restore/Verify/Convert image, Unlock/Lock container, Activate VG, … | The kpmcore/GParted "apply later" model. Simulation on in-memory topology is what makes previews truthful. |
| `stein_backend_exec` | ops, platform | OPTIONAL (default OFF on macOS/Windows): capability providers implemented by running external tools (`mkfs.ext4`, `resize2fs`, `ntfsresize`, `btrfs`, `xfs_growfs`, `sgdisk`, `cryptsetup`, `lvm`). Registers into the same registries as in-process implementations with lower priority. Gives Linux users the GParted feature set on day 1 | Never linked by the core. GPL tools are invoked, not linked. |
| `stein_mount` | fs, platform | Exposes a `stein_fs` `Reader`/`Writer` as an OS mount: libfuse (Linux), macFUSE/FUSE-T (macOS), WinFsp (Windows); fallback: embedded NFSv3/WebDAV server + OS "mount localhost" | Optional. The "open ext4-in-LUKS on Windows" feature (R7). |
| `stein_app` | ops | `Profile` (JSON): device selector rules (by serial/WWN/part UUID/label/size), image location (path, split size, compression, encryption), verification policy, lock policy, post-actions (grow fs, fix bootloader hooks), i18n string catalogue, `Scenario` runners ("backup now", "restore now", "verify") | What dr_stein becomes. |
| `stein_layout` | core | Declarative on-disk structure descriptions (manifests) and the `LayoutTree` every parser emits for hexinator-style visualisation and for dump/restore of individual pieces (`design/18-structure-layouts.md`) | Consumed by `pt`, `fs`, `container`, `volume`, `image`. |

## 3. Core domain model

```
Topology (snapshot, immutable, cloneable for simulation)
 └── Disk (PlatformDisk) : BlockDevice            identity, geometry, bus, smart
      └── PartitionTable (Gpt|Mbr|Apm|...)       header state, errors, free regions
           └── Partition : region + type + flags + name + uuid
                └── Content (one of):
                     • FileSystem (Ext4|Ntfs|Fat32|...)
                     • Container (Luks2|VeraCrypt|...)  --unlock--> DecryptedDevice : BlockDevice
                                                                        └── Content (recursive)
                     • VolumePv (Lvm2 PV|md member)  --group--> VolumeGroup --> LogicalVolume : BlockDevice
                                                                                   └── Content (recursive)
                     • Nested PartitionTable (BSD slice inside MBR, APM inside hybrid...)
                     • Unknown / Empty
 └── ImageDevice (opened image file) : BlockDevice  → same subtree as a Disk
 └── Free regions, alignment info
```

Every node is a `BlockDevice` (or a region of one) plus a `Content`. The
recursion is what lets "ext4 inside LVM inside LUKS inside GPT inside an E01
image" be one uniform tree. UIs render the tree; operations are validated
against a cloned tree.

## 4. Cross-cutting design decisions

- **Sector size is explicit everywhere.** `Sectors{count, size}`; 512e vs 4Kn
  disks, 2048-byte optical, images with recorded sector size. GPT parsing uses
  the *device* sector size; APM uses block0's `sbBlkSize`.
- **Write ordering and torn-write safety** are the responsibility of each
  format module and documented per module (e.g. GPT: write backup → primary →
  PMBR; LUKS2: both header copies with sequence IDs).
- **Alignment policy** is an object (`AlignmentPolicy`: 1 MiB default,
  optimal-I/O-size aware, legacy CHS for MBR when asked), not a hidden global.
- **Identity, not paths.** Devices are matched by `DeviceIdentity` (bus,
  model, serial, WWN, size, partition UUID/GUID, fs UUID/label). Paths are a
  transient attribute. This fixes dr_stein's `/dev/sdc1` problem and is what
  profiles store.
- **Dry-run is the default path.** `Operation::validate()` and `simulate()`
  run on a cloned `Topology`; `apply()` is explicit. The CLI's `--dry-run`
  and the GUI's "pending operations" pane are the same thing.
- **Reports are trees, not logs.** Each job produces a `Report` node
  (command/step, inputs, outcome, duration, children); UIs render it; the
  CLI prints it; tests assert on it.
- **Privilege**: `stein_platform` exposes `PrivilegeBroker` with two
  implementations: in-process (already root/admin) and out-of-process
  (spawn an elevated helper and forward `BlockDevice` and platform calls over
  a local pipe using a tiny length-prefixed RPC). Only `stein_platform` knows
  which is active.

## 5. Build & packaging

- CMake ≥ 3.25, **C++23**, each library a target `stein::<name>`, options
  `STEIN_BUILD_<NAME>`, `STEIN_FS_<MODULE>`, `STEIN_WITH_OPENSSL`,
  `STEIN_WITH_FUSE`, `STEIN_BACKEND_EXEC`.
- **Shared libraries now, one library later:** every module is a CMake
  `OBJECT` library; by default they are wrapped into one shared library per
  module (fast incremental builds, clear boundaries). `STEIN_MONOLITHIC=ON`
  links all enabled objects into a single `libstein` for deployment. The
  dependency DAG is enforced either way by target link rules.
- **Installed package:** `cmake --install` puts the libraries, the public
  headers (including the generated layout headers), the `stein` CLI and a
  CMake package under `lib/cmake/stein` into the prefix; consumers write
  `find_package(stein CONFIG)` and link `stein::<module>` (or `stein::stein`
  for a monolithic build, whose module names alias it). `tests/consumer/` is
  the downstream project CI builds against the installed package on every
  platform. The GUI (`20-gui-toolkit.md`) consumes libstein this way, or as
  a submodule with `add_subdirectory`.
- `ccache` is picked up automatically (`CMAKE_CXX_COMPILER_LAUNCHER`) when
  present; CI and the cloud environment have it installed.
- Toolchains: GCC ≥ 12, Clang ≥ 15, MSVC 2022. Sanitizers in CI.
- Tests: Catch2 or doctest (vendored, permissive), golden image fixtures
  generated by the GPL tools in CI containers (`mkfs.*`, `sgdisk`,
  `cryptsetup`) and *checked in as compressed sparse fixtures* so that
  macOS/Windows CI needs none of those tools.
- Third-party policy: vendored permissive code under `third_party/` with
  SPDX headers; LGPL only as optional dynamic links.

## 6. What the reference projects contributed to this design

| Source | Taken as a design idea (never as code; all three are GPL) | Rejected |
|---|---|---|
| GNOME Disks (`research/01`) | UDisks2 object model (Drive ⊃ Block ⊃ PartitionTable/Partition, Filesystem/Encrypted/Loop as mix-ins) → our `Topology` tree; `CanFormat/CanResize → (available, flags, missing_tool)` → `Capabilities` + `SupportTool`; `OpenForBackup/Restore/Benchmark` fd hand-off → `PrivilegeBroker`; dependency-ordered teardown (`ensure_unused`) → `Runner` pre-flight; zero-fill-and-count on read error → `BadSectorPolicy::SkipZero`; xz-index size trick; non-destructive write benchmark (write back what was read) | D-Bus daemon dependency; raw-only images; 1 MiB fixed buffers; UI-coupled jobs; the Rust split |
| kpmcore / KPM (`research/02`) | `PartitionNode` tree with synthetic *Unallocated* nodes → `FreeRegion`s are first-class; `PartitionRole` bitflags; `PartitionAlignment` as a stateless policy → `AlignmentPolicy`; per-capability provenance enum (`None/Core/FileSystem/Backend`) → our `Provider` priority registry (in-process vs `stein_backend_exec`); LUKS-as-wrapper holding an inner fs → `Container` yielding a `BlockDevice` (generalised); `CopySource/CopyTarget` byte-range interfaces → copy engine; OperationStack with merge rules + `preview()`/`undo()` → `OperationStack` with *simulation on a cloned Topology* instead of hand-written inverses; `Report` tree as audit log; privileged helper with per-client auth caching and typed byte verbs (`ReadData/WriteData/CopyFileData`) → `PrivilegeBroker` RPC; partition-table text export/import → `PartitionTable::serialize()` in image metadata | Qt/QObject in the model; static per-class support flags probed by running ~60 tools as root at startup; regex-scraping `sfdisk --json`/`udevadm`; LVM/RAID as fake partition tables; libparted-era flag enum; generic "run whitelisted command as root" RPC; hard-coded 33-sector GPT reservation |
| GParted (`research/03`) | `struct FS` with a *how* enum per operation + `FS_Limits` + `online_*` variants → `Capabilities` bitset and `ResizeLimits`; one class serving sibling types (`ext2` for ext2/3/4) → `ExtFamily`; `OperationResizeMove` decomposition (shrink→move / move→grow with a temporary strict-aligned partition) and the widen→copy→rollback→narrow move algorithm → `MovePartition` plan; `OperationDetail` tree with cancel-safe vs force cancel → `Report` + `CancelToken` levels; `BlockSpecial` identity by device number → `DeviceIdentity`; detection priority chain and the signature/erase-range *data* → `FsSignature` table and `WipeSignatures`; CopyBlocks adaptive block-size benchmark and reverse copy; `PasswordRAMStore` → `SecureBuffer`; parameterised per-fs integration tests | libparted as the engine; nested GTK main loop as blocking primitive; global singletons; glib strings/gettext inside result data; tool-version sniffing as the primary mechanism |
| dr_stein (`research/04`) | profile-driven one-button app → `stein_app::Profile`/`Scenario`; lock-before-danger policy; `st_blocks` sparse check; checksum-before-restore | 512-byte copy loop; MD5; config-only metadata; path-only device identity |
| Ecosystem (`research/05`) | FreeBSD `sys/geom/part/*` (BSD-2) as the starting point for writing MBR/EBR/GPT/APM/BSD/LDM; FatFs (BSD-1) as the FAT/exFAT r/w engine; lwext4's BSD-3 files for native ext4; tc-play (BSD-2) for TrueCrypt/VeraCrypt headers; libargon2 (CC0); Botan/mbedTLS as crypto backends; zstd seekable format; Dokany (LGPL) as the default Windows mount backend, WinFsp optional; libyal format docs as the reference for BitLocker/FileVault/VHDX/DMG/APFS; GPL tools only as CI oracles | linking libparted/gptfdisk/ntfs-3g/etc.; FUSE-T (proprietary); copying from libblkid/libfdisk/udisks (LGPL) |
