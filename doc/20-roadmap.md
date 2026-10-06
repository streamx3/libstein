# Roadmap

Milestones are feature-complete *vertical slices*, each of which ships a
usable artefact, so that the project is testable end-to-end early and the
dr_stein-style app exists long before the fancy filesystem drivers do.

## M0 — Research and design (this milestone, 2026-10-05)

Done: reference surveys (`research/01..05`), vision (`00-vision.md`),
architecture and design notes (`design/10..18`), owner review round 1 and
the resulting decision log (`DECISIONS.md` D1–D15). Open: OQ3/OQ4/OQ5
(owner still reading).

## M1 — Skeleton + core + block + platform + probe (L0/L1) + imaging v1 — **largely done (2026-10-06)**

Delivered (see `reports/2026-10-06-progress.md` for detail):

- `stein_core` (errors, units, GUIDs, CRC-32/32C with hardware paths, MD5,
  SHA-256 with SHA-NI/ARMv8, BLAKE2b, ChaCha20-Poly1305, HMAC, PBKDF2,
  Argon2id, key slots, JSON, LZ4, progress, reports, logging), `stein_layout`
  (manifest-generated structures, `LayoutTree`), `stein_block` (memory, file,
  slice, concat, overlay, sparse pieces incl. encrypted), `stein_pt`
  (GPT/MBR/EBR/APM read, write, repair; byte-identical with sgdisk/sfdisk),
  `stein_fs` (35 formats at L0; allocation maps for ext2/3/4, FAT, exFAT,
  NTFS, HFS+), `stein_probe`, `stein_platform` (Linux, macOS, Windows:
  enumerate, open, mounts, unmount/lock, re-read, loop/hdiutil attach),
  `stein_image` (`.stein` v1 with split segments, LZ4, used-block-only,
  encryption; raw and split-raw input; create/restore/verify/info/open),
  `stein_ops` (operation stack simulated on an overlay; table create/add/
  delete/update/repair/wipe; surface scan; fake-flash capacity test),
  `stein_app` (profiles and backup/restore/verify scenarios).
- `stein` CLI covering all of the above; CI green on Linux (ASan/UBSan),
  macOS (arm64) and Windows (MSVC).

Still open from the original M1 list: BSD disklabel / LDM parsing, hot-plug
events, SMART, `stein_container`/`stein_volume` beyond detection (LUKS and
LVM are detected, not opened), FUSE browsing of images.

## M2 — dr_stein v2 (the one-button app) + FAT/exFAT r/w + LUKS/LVM open

Started: `stein_app` profiles/scenarios, used-block imaging for ext4/NTFS/
FAT/exFAT/HFS+ and encrypted images landed early (see M1). Remaining
deliverable: a minimal native UI per OS (or one
first, chosen by the owner) that does Backup / Restore / Verify with a locked
device selector; `.stein` images with used-block-only mode for ext4/NTFS/FAT/
exFAT/HFS+/XFS/btrfs (L1 maps); LUKS1/2 unlock in-process; LVM linear/striped
LV mapping; `stein_mount` with FatFs-backed FAT/exFAT r/w on Linux (libfuse),
Windows (Dokany), macOS (macFUSE or NFS loopback); ext4/NTFS/ISO9660 read
(L3) through the same mount path; privileged helper RPC.

## M3 — Partition manager parity on Linux + ext4 write

Deliverable: the GParted/KPM feature set with no external tools for
ext4/FAT/exFAT (native resize/check/create/label), and
`stein_backend_exec` wrappers for the rest (btrfs, xfs, f2fs, jfs, ntfs
resize via `ntfsresize`, …) so Linux users lose nothing; partition move with
rollback; ext4 L4 write (journaled); E01 and VHD/VHDX/qcow2/VMDK/DMG readers;
fixed-VHD write for native Windows attach; APM/BSD label write; benchmark
and SMART self-tests; VeraCrypt open.

## M4 — The native GUIs + NTFS/HFS+ write + BitLocker

Deliverable: the desktop GUI, one Qt 6 / QML codebase for Linux, macOS and
Windows (decision D17, `design/20-gui-toolkit.md`; the earlier plan of three
native UIs was dropped), only a view over `stein_ops` and `stein_probe`,
ported from the Claude Design prototype; `stein_c` bindings, NTFS L4 (clean volumes), HFS+ L3/L4,
BitLocker unlock, md RAID read, APFS read, remaining exotic labels (Sun,
SGI, Amiga, PC98, AIX, Atari).

## Explicitly later

VeraCrypt create/system encryption; APFS write; ZFS anything; btrfs/XFS
write; FSKit backend; RAID management; bootloader fix-ups beyond NTFS
hidden-sectors and GPT relocation.

## Risks and how the design hedges them

| Risk | Hedge |
|---|---|
| Writing userspace fs drivers is a multi-year effort | Levels L0–L4 per fs; every level ships value; optional LGPL backends (libext2fs, libyal) can fill gaps dynamically without touching the MIT core |
| Windows/macOS privilege and mount UX | Block-export path (VHD attach, hdiutil) needs no drivers; file-level FUSE path is optional; NFS loopback is the kext-less fallback |
| License contamination | Per-file SPDX, CI lint of core targets, GPL tools only as CI oracles, FreeBSD/NetBSD/FatFs/tc-play as the only borrowed code |
| Data loss bugs | Simulation on cloned topology, ordered writes, post-apply re-probe diff, fixtures for every format, fuzzing of parsers, "never abort mid-write" helper semantics |
| Scope creep | Capability matrix is the single source of truth for what is in which milestone |
