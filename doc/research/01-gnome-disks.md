# Reference survey: GNOME Disks (gnome-disk-utility)

Surveyed snapshot: version **51.beta**, HEAD `836cf716…` (2026-09-25), ~23.8k
lines under `src/` (C + Rust). This is the post-GTK4/libadwaita rewrite with
a partial Rust port in progress (§8). File names changed in 2023: the old
`gducreatediskimagedialog.c` is now `gdu-create-disk-image-dialog.c`, and
the restore dialog no longer exists in C — it is
`src/disks/restore_disk_image_dialog.rs`.

Paths below are relative to the gnome-disk-utility checkout.

## 1. Licenses

| Scope | License | Evidence |
|---|---|---|
| Project | **GPL-2.0-or-later** | `COPYING` is GPLv2; `meson.build` `license: 'GPL2.0'`; `Cargo.toml` `license = "GPL-2.0-or-later"` |
| All C files (libgdu, disks, notify) | GPL-2.0-or-later | header pattern in e.g. `src/libgdu/gduutils.c:4`; SPDX headers in the newer files (`src/disks/gdu-block.c`, `gdu-drive.c`, `gdu-manager.c`, …) |
| All Rust files | GPL-2.0-or-later (inherited from workspace) | no per-file headers |
| `src/libgdu/gettext.rs` | copied from udisks-rs (MIT/Apache-2.0 upstream), no header | `src/libgdu/gettext.rs:1` |
| `src/disks/gduxzdecompressor.c` | GPL-2.0-or-later, derived from GLib's `GZlibDecompressor` (LGPL) | header |
| libgdu (`src/libgdu/`) | **GPL-2.0-or-later, not LGPL**; a private `static_library('gdu')` linked only into gnome-disks | `src/libgdu/meson.build:28-34` |

No vendored third-party C code. The Flatpak manifest
(`flatpak/org.gnome.DiskUtility.json`) builds UDisks' whole dependency chain
from source (dvdread, pwquality, gudev, kmod, libaio, lvm2, parted, mpfr,
libbytesize, json-c, popt, cryptsetup, keyutils, libyaml, libnvme, pam,
libcap-ng, util-linux(fdisk), libatasmart, libblockdev, polkit, udisks) — that
is runtime packaging, not source vendoring.

**Implication for libstein (MIT):** nothing in this tree can be copied
verbatim. Only ideas, algorithms, constants and the UDisks2 D-Bus semantics
are reusable. The partition-type tables GDU displays live in **libudisks2**
(LGPL-2.0-or-later), not here (§7).

## 2. Build system and dependencies

**Meson ≥ 0.59** with languages `['c', 'rust']`, plus **Cargo** invoked from
Meson via `custom_target('cargo-build', …)` in `src/libgdu/meson.build`,
`src/disks/meson.build`, `src/disk-image-mounter/meson.build`. Cargo
workspace root `Cargo.toml` (edition 2024, MSRV 1.85). A hack copies the
generated `config.rs` into the *source* tree because Cargo can't see Meson's
build dir. The Rust `gnome-disks` crate is a `cdylib` (`libgnome_disks.so`)
with a forced soname via `RUSTFLAGS`, installed to a private libdir; the C
executable links it through `gdu-rust.h`.

Meson options (`meson_options.txt`): `logind` (libsystemd/libelogind/none),
`gsd_plugin` (builds `src/notify`), `man`, `profile` (release/development).

### C / pkg-config dependencies (`meson.build:85-110`)

| Dep | Min | Used for | glib/GTK-bound? |
|---|---|---|---|
| `gtk4` | 4.15.2 | all UI | yes |
| `libadwaita-1` | 1.8.alpha | dialogs/rows everywhere; even `libgdu` uses `adw_alert_dialog_*` | yes |
| `gio-unix-2.0` | 2.31 | `GUnixFDList` for fd passing over D-Bus, `GUnixInputStream` | yes |
| `gmodule-2.0` | — | dlopen of `libdvdcss.so.2` in `gdudvdsupport.c` | yes |
| `udisks2` (libudisks2) | 2.7.6 | **all** disk operations; GDBus proxies, `UDisksClient`, partition-type tables, size formatting | yes (GObject/GDBus; LGPL-2.0+) |
| `dvdread` | 4.2.0 | locate VOB sectors for CSS-decrypted DVD imaging | no |
| `liblzma` | 5.0.5 | xz decompression on restore | no |
| `libnotify` | 0.7 | SMART-failure notification (`src/notify`) | glib |
| `libsecret-1` | 0.7 | stored LUKS passphrase lookup (`gdu-unlock-dialog.c`) | glib |
| `pwquality` | 1.0 | passphrase strength meter | no |
| `libsystemd`/`libelogind` | 209 | seat lookup to avoid polkit prompts | no |
| `blueprint-compiler` | 0.19 | `.blp` → `.ui` | build tool |
| `cargo` | — | Rust | build tool |

### Rust crates
`gtk4` 0.8, `libadwaita` 0.6, `glib`/`gio`; `udisks2` — a **git dependency**
on `FineFindus/udisks-rs` (zbus-based async UDisks2 client); `zbus`;
`liblzma` 0.4; `nix` 0.30 (one ioctl: `BLKGETSIZE64`); `tokio` (only for an
async Mutex, flagged TODO), `async-std`, `futures`, `anyhow`, `gettext-rs`,
`systemd` (optional). 250 packages in `Cargo.lock`.

**Every component is glib/GTK-bound.** `libgdu`'s public header includes
`<adwaita.h>` and `<udisks/udisks.h>` (`src/libgdu/gduutils.h:11`).

## 3. Directory layout

```
meson.build, meson_options.txt, Cargo.toml, Cargo.lock
COPYING (GPLv2), HACKING, TODO (stale), NEWS
build-aux/meson/dist-vendor.sh       cargo vendor at dist time
flatpak/org.gnome.DiskUtility.json   builds udisks + libblockdev + parted + fdisk + cryptsetup + lvm2 … in-sandbox
data/                                .desktop, metainfo, D-Bus service, GSettings schema
src/
  libgdu/            C static lib + Rust crate: shared utilities (§7)
  disks/             the gnome-disks app: C GObject UI + Rust cdylib
  disk-image-mounter/ gnome-disk-image-mounter — 100 % Rust
  notify/            gnome-disk-utility-notify — SMART failure notifications
  resources/         31 Blueprint .blp UI files, style.css
```

`src/disks/` map: model layer (`gdu-manager.c` wraps `UDisksClient`;
`gdu-item.c` abstract item with a 27-flag `GduFeature` capability bitmask;
`gdu-drive.c`; `gdu-block.c` derives features from `IdUsage`/`IdType`);
jobs (`gdu-job-manager.c`, `gdulocaljob.c` — a `UDisksJobSkeleton` subclass
run in a worker thread; `gduestimator.c`); window/views; ~20 dialogs;
helpers (`gdudvdsupport.c`, `gduxzdecompressor.c` — now dead code,
`gdu-rust.h`); Rust (`restore_disk_image_dialog.rs`, `estimator.rs`,
`localjob.rs`, `page_aligned_buffer.rs`, `ffi/mod.rs`).

CLI entry points (`gdu-application.c:180-185`): `--block-device DEV`,
`--format-device`, `--restore-disk-image FILE`.

## 4. How disk work is actually done: UDisks2 over D-Bus

GDU contains **zero direct partition-table, filesystem, LUKS, RAID or SMART
code**. Everything goes through `org.freedesktop.UDisks2`:

```
GNOME Disks  --D-Bus-->  udisksd (root, polkit-authorised)
                           └─ libblockdev plugins:
                                part   -> libfdisk (util-linux) (older: libparted)
                                fs     -> mkfs.*/fsck.*/resize2fs/ntfsresize/… CLI tools + libblkid
                                crypto -> libcryptsetup
                                lvm    -> lvm2
                                mdraid -> mdadm CLI
                                loop   -> loop ioctls
                                swap   -> mkswap/swapon
                                nvme   -> libnvme
                                smart  -> libatasmart / libsmart
                           plus udev (libgudev) for enumeration and blkid probing
```

### UDisks2 interfaces used, by GDU file

| Interface | Methods | Properties | GDU files |
|---|---|---|---|
| `.Manager` | `LoopSetup(fd, {read-only})`, `CanFormat/CanResize/CanRepair/CanCheck` | `SupportedFilesystems` | `gdu-manager.c:480`, `gdu-new-disk-image-dialog.c:115`, `libgdu/gduutils.c:660-820`, `window.rs:380` |
| `.Block` | `Format(type, {label, erase, take-ownership, encrypt.passphrase, encrypt.type=luks2, update-partition-type})`, `OpenForBackup`, `OpenForRestore`, `OpenForBenchmark({writable})`, `Rescan`, fstab/crypttab config items, `GetSecretConfiguration` | `Device`, `Size`, `ReadOnly`, `IdUsage/IdType/IdVersion/IdLabel`, `CryptoBackingDevice`, `Drive`, `HintPartitionable` | format dialogs, `gdu-create-disk-image-dialog.c:482`, `gdu-benchmark-dialog.c:826`, `restore_disk_image_dialog.rs:516,571,577` |
| `.PartitionTable` | `CreatePartition(offset, size, type, name, {partition-type=primary/logical/extended})` | `Type` (gpt/dos), `Partitions` | `gdu-format-volume-dialog.c:299`, `gdu-create-partition-page.c:74` |
| `.Partition` | `Delete`, `Resize`, `SetType`, `SetName`, `SetFlags` | `Offset`, `Size`, `Number`, `Type`, `Flags`, `IsContainer`, `IsContained`, `Name`, `UUID` | `gdu-edit-partition-dialog.c:107-127`, `gdu-resize-volume-dialog.c:220` |
| `.Filesystem` | `Mount`, `Unmount`, `SetLabel`, `Resize`, `Repair`, `Check`, `TakeOwnership` | `MountPoints` | `gdu-resize-volume-dialog.c:234-274` (offline resize = resize→repair→grow) |
| `.Encrypted` | `Unlock(passphrase, {keyfiles})`, `Lock`, `ChangePassphrase` | `CleartextDevice` | `gdu-unlock-dialog.c:161`, `window.rs:281-290` |
| `.Loop` | `Delete`, `SetAutoclear(false)` | `BackingFile`, `Autoclear` | `gdu-manager.c:283-294` |
| `.Drive` | `Eject`, `PowerOff`, `SetConfiguration` | vendor/model/serial/size/removable/media… | `gdu-drive.c`, `gdu-disk-settings-dialog.c` |
| `.Drive.Ata` | `SmartUpdate`, `SmartGetAttributes`, `SmartSelftestStart/Abort`, `SmartSetEnabled`, `PmStandby`, `PmWakeup` | `SmartFailing`, `SmartTemperature`, `NumBadSectors`, … | `gdu-ata-smart-dialog.c`, `notify/gdusdmonitor.c:257-271` |
| `.Swapspace` | — | `Active` | `gdu-block.c:300` |
| `.Job` | GDU *implements* `UDisksJobSkeleton` client-side | `Progress`, `Rate`, `Bytes`, `ExpectedEndTime` | `gdulocaljob.c`, `localjob.rs` |

**Not used anywhere in the current tree:** `.MDRaid`, `.NVMe.*`,
`.LogicalVolume`, `.VolumeGroup`, ATA security-erase properties (commented
out). The GTK4 rewrite dropped the RAID and NVMe-SMART UI that 3.x had.

Privilege model: udisksd runs as root; GDU is unprivileged; polkit prompts.
Three fd-returning methods (`OpenForBackup/Restore/Benchmark`) let GDU do raw
I/O itself after the daemon opens the node with `O_EXCL`.

## 5. Disk image features

### 5.1 Create Disk Image — `src/disks/gdu-create-disk-image-dialog.c` (942 lines)
- Source: any block (whole disk or partition) with `GDU_FEATURE_CREATE_IMAGE`.
- Flow: `gdu_utils_ensure_unused()` (unmount/lock everything inside; `/dev/sr*`
  is opened directly `O_RDONLY` to dodge polkit, `:461-476`) →
  `Block.OpenForBackup()` → `ioctl(BLKGETSIZE64)` (`:504`) → `fallocate()` the
  whole output file (`:528`) → loop reading **1 MiB page-aligned** chunks via
  `copy_span()` (`:375-435`): **a short/failed read is not an error — the
  missing tail is zero-padded and counted in `num_error_bytes`** (poor-man's
  ddrescue, single pass, no retries, no reverse pass, no map file) → progress
  via `GduEstimator` every 200 ms → final dialog "%2.1f%% (%s) … unreadable
  and replaced with zeroes" with an option to delete the file (`:299-350`).
- DVD: if `IdType==udf` and media is `optical_dvd`, libdvdread finds VOB
  extents and dlopen'd `libdvdcss` decrypts only those — a CSS-decrypted ISO.
- Output: **raw only**, default name `Disk Image of sdb (date).img` or
  `<label>.iso` for iso9660/udf. Worker thread + `gtk_application_inhibit`.
- The file's own TODO block (`:31-40`) admits: no dd_rescue tolerance, no
  vdi/vmdk/qcow2, no DMG, fixed buffer size.

### 5.2 Restore Disk Image — `src/disks/restore_disk_image_dialog.rs` (631 lines, Rust)
- Input: raw, or **xz-compressed** detected by GIO content type; uncompressed
  size read from the xz stream index (`liblzma::uncompressed_size`; the C
  equivalent parsed footer + index with `lzma_index_buffer_decode`). **No
  gzip/bzip2/zstd, no split images, no qcow2/vmdk/vdi.**
- Size checks (`:244-258`): error if image is 0 or larger than target;
  warning if > 1 MB smaller.
- Copy (`:507-582`): `Block.OpenForRestore()` → `BLKGETSIZE64` → 1 MiB
  `PageAlignedBuffer` → read/write loop → on error `Block.Format("empty")`
  to wipe the partially written device → always `Block.Rescan()`. No
  verification pass, no checksum, no retry.

### 5.3 Attach Disk Image (loop) — `gdu-attach-disk-image-dialog.c`, `gdu-manager.c:446-493`
File chooser filtered to raw/cd images (compressed disallowed), read-only
switch, `open()` → `Manager.LoopSetup`. Kernel probes partitions.

### 5.4 New Disk Image — `gdu-new-disk-image-dialog.c`
Creates an empty **sparse** file (`g_seekable_truncate`) and loop-attaches
it. TODO (`:25-30`) wants a partition-table/filesystem option; not done.

### 5.5 gnome-disk-image-mounter — `src/disk-image-mounter/` (Rust, ~580 lines)
Handles `application/x-cd-image; x-raw-disk-image; x-raw-disk-image-xz-compressed`.
Actions: open read-only / writable, unmount, write (opens Disks' restore
dialog), inspect. `mount()` = `Manager.LoopSetup` read-only; if the loop is
LUKS it waits for `Encrypted.CleartextDevice` (GVfs prompts). Compressed
images are declared "not mountable" (`window.rs:113`). **All mounting is
kernel loop + udisks; no userspace filesystem parsing.**

### 5.6 Limits summary
Raw in/out; xz read-only on restore; no compression on create; no
split/chunked images; no qcow2/vmdk/vdi/dmg; no sparse detection on create
(`fallocate`s the full size); single-pass zero-fill on read errors; no
checksums/verification; no GPT backup-header handling; no partition-only
restore to an offset.

## 6. ATA/SMART, disk settings, benchmarking

### SMART — `gdu-ata-smart-dialog.c` (1472 lines)
Pure presentation over `Drive.Ata`. `SmartGetAttributes()` returns
`a(ysqiiixia{sv})` = (id, name, flags, current, worst, threshold, pretty,
pretty_unit, expansion); pretty_unit codes mirror libatasmart's
`SK_SMART_ATTRIBUTE_UNIT_*`. A static `smart_details[47]` table maps
attribute names (raw-read-error-rate, reallocated-sector-count,
current-pending-sector, udma-crc-error-count, …) to translated
descriptions ("Keep in sync with libatasmart. Last sync: 2009"). The overall
assessment heuristic `gdu_ata_smart_get_one_liner_assessment()` (`:845-910`)
is ~60 lines: failing > bad sectors > failed-in-past > OK, plus self-test
status and temperature. **No NVMe SMART**, no SCSI log pages, no history.

### Notify daemon — `src/notify/gdusdmonitor.c`
systemd user service; on every `UDisksClient::changed` scans for
`Drive.Ata.SmartFailing` and raises one persistent critical notification.

### Disk settings — `gdu-disk-settings-dialog.c`
Standby/APM/AAM/write-cache → `Drive.SetConfiguration`.

### Secure erase — `gdu-format-disk-dialog.c`
`Block.Format(gpt|dos|empty, {erase: ""|"zero"|"ata-secure-erase"|"ata-secure-erase-enhanced"})`;
the ATA-erase selector UI is **commented out** (`:226-249`) in the GTK4 port,
so only "overwrite with zeroes" is reachable.

### Benchmark — `gdu-benchmark-dialog.c` (1317 lines)
GSettings `num-samples`, `sample-size-mib`, `do-write`, `num-access-samples`.
`Block.OpenForBenchmark({writable})` → fd. Transfer rate (`:837-950`): for
n in samples, offset = n·size/num_samples page-aligned; pre-read one page,
timed `read()` of sample size; if write enabled, timed `write()` of the
**same bytes back** + `fsync()` — non-destructive write benchmark. Access
time (`:952-1010`): random page reads with fixed seed 42. Custom graph widget
with monotonic cubic interpolation.

## 7. libgdu: what is pure logic and borrowable

`src/libgdu/gduutils.c` (1427 lines) + Rust mirror `gduutils.rs` (1072
lines). **~90 % is GTK dialog helpers or UDisks proxy traversal.** The
reusable *ideas*:

| Item | Location | What it is | Verdict |
|---|---|---|---|
| `unit_sizes[11]` | `gduutils.h:117-143` | Byte, kB..PB (10^3n), KiB..PiB | trivial constants; re-derive |
| `gdu_utils_get_default_unit` | `gduutils.c:1409-1427` | pick TB/GB/MB/kB when size > 10× unit | rewrite |
| `gdu_utils_format_duration_usec` | `gduutils.c:336-460` | y/mo/d/h/m/s/ms split (365.25-day year) | rewrite |
| `gdu_util_is_same_size` | `gduutils.c:865-895` | "same" = max−min ≤ 1 % of min **and** ≤ 1 MiB | one-line rule |
| `gdu_utils_calc_space_to_grow` | `gduutils.c:1272-1304` | grow limit = next partition start (or disk end) − offset | generic; rewrite |
| `gdu_utils_calc_space_to_shrink_extended` | `gduutils.c:1309-1335` | extended min size = end of last logical | same |
| DOS primary counting / extended checks | `gduutils.c:475-540` | max 4 primaries, logical inside extended | standard MBR semantics |
| `gdu_utils_get_max_label_length` | `gduutils.c:826-838` | exfat 15, vfat 11, else unlimited — incomplete | build our own table |
| `ResizeFlags` | `gduutils.h:76-82` | OFFLINE_SHRINK/GROW, ONLINE_SHRINK/GROW — defined by libblockdev (LGPL) | take the concept |
| `ensure_unused_list` | `gduutils.c:1035-1270` | **dependency-ordered teardown**: cleartext → LUKS → partitions → disk → loop autoclear last | algorithm worth replicating |
| Partition flag bits | `gdu-edit-partition-dialog.c:65-81` | DOS bootable 0x80; GPT bit 0 required, bit 2 legacy BIOS bootable | use the UEFI spec directly |
| `GduEstimator` | `gduestimator.c`, `estimator.rs` | ring of 50 (time,bytes) samples; speed = mean pairwise delta | trivial. **The Rust port has an inverted guard** (`estimator.rs:58`) and stores seconds in `time_usec` — it effectively never records samples |
| `PageAlignedBuffer` | `page_aligned_buffer.rs` | aligned alloc | trivial |
| xz size-from-index | `gduxzdecompressor.c:140-206` | footer → `backward_size` → index → uncompressed size | standard liblzma recipe |
| `copy_span` zero-fill | `gdu-create-disk-image-dialog.c:375-435` | partial read → pad zeros, count, continue | pattern only |

**Partition type tables:** GDU has none. It calls
`udisks_client_get_partition_type_infos()` etc. Those tables
(`known_partition_types[]` with ~100 GPT GUIDs + MBR ids + per-OS grouping,
and `id_types[]`) live in udisks' `udisks/udisksclient.c`, **LGPL-2.0+** —
or regenerate from the UEFI spec / util-linux `libfdisk/src/gpt.c` (LGPL-2.1+).

## 8. The Rust addition

Present since ~v47. Three crates: `libgdu` (1:1 async port of `gduutils.c`
on the `udisks2` zbus crate + gtk-rs), `gnome-disks` (cdylib: the Restore
Disk Image dialog — the only dialog ported — `Estimator`, `LocalJob`,
`PageAlignedBuffer`, three `extern "C"` symbols in `gdu-rust.h`, a
thread-local job registry marked FIXME), `gnome-disk-image-mounter` (full
rewrite). Motivation per NEWS: incremental port, async `udisks-rs`. **It is
not a lower-level storage library — it still only talks D-Bus.** Build
coupling caveats: `build_always_stale`, soname hack, `config.rs` copied into
the source dir, `CARGO_HOME` redirected, offline dist via `cargo vendor`.

## 9. Gaps relative to libstein goals

1. **No on-disk format code at all.** Cannot run without `udisksd`
   (fatal `expect` in `ffi/mod.rs:106`). Nothing maps to macOS/Windows.
2. **No GPT backup-header recovery** — there isn't even a GPT reader.
3. **No image splitting, no compression on create**, xz only on restore; no
   qcow2/vmdk/vdi/dmg; no sparse-aware create; no checksums.
4. **No userspace filesystem access inside images**: kernel loop + kernel fs
   + GVfs automount only.
5. Read errors: single-pass zero-fill, no retries/map file.
6. No RAID / LVM / NVMe / SCSI-SMART UI in the current tree.
7. ATA secure-erase UI commented out.
8. No alignment logic (libblockdev's), no partition move, no custom GUIDs,
   only 3 flag bits.
9. Linux-only syscalls throughout.
10. Not a library: `libgdu` is private with GTK/udisks in its header.
11. Job model UI-coupled; the Rust estimator has a logic bug.
12. Benchmark: sequential samples + random access only, no queue depth.
13. Secrets tied to GNOME keyring / udisks crypttab.

### Worth taking away (design, not code)
- The **UDisks2 object model** (Drive ⊃ Block ⊃ PartitionTable/Partition;
  Filesystem/Encrypted/Loop/Swapspace as mix-in interfaces; Job objects with
  Progress/Rate/ExpectedEndTime), the
  `CanFormat/CanResize/CanRepair/CanCheck → (available, flags, missing_util)`
  capability query, and the 27-bit `GduFeature` mask (`gdu-item.h:20-48`).
- The **privilege split**: unprivileged UI gets an `O_EXCL` fd from a root
  helper and streams itself — portable to macOS (authopen) and Windows
  (handle duplication from an elevated service).
- The dependency-ordered teardown in `ensure_unused`.
- The xz-index trick; zero-fill-and-count with a final report.

The real on-disk logic to study is in libblockdev (LGPL-2.1+), util-linux
libfdisk (LGPL-2.1+), cryptsetup (LGPL-2.1+ lib), libatasmart (LGPL-2.1+)
and udisks' `udisksclient.c` tables (LGPL-2.0+).
