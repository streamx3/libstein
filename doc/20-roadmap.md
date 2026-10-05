# Roadmap

Milestones are feature-complete *vertical slices*, each of which ships a
usable artefact, so that the project is testable end-to-end early and the
dr_stein-style app exists long before the fancy filesystem drivers do.

## M0 — Research and design (this milestone, 2026-10-05)

Done: reference surveys (`research/01..05`), vision (`00-vision.md`),
architecture and design notes (`design/10..17`). Open: review by the project
owner; decisions on OQ1–OQ5 in `00-vision.md` (recommendations are already
stated in the design docs).

## M1 — Skeleton + core + block + platform (read-only) + probe (L0) + imaging v1

Deliverable: `stein` CLI that on all three OSes can `list` disks with
identity and geometry, `probe` any disk or image and print the Topology tree
with diagnostics (GPT/MBR/APM, nested BSD, LUKS/LVM/md detection, all L0
filesystems), `image create/restore/verify` raw, split-raw and `.stein`
(chunked, zstd, hashed, sparse-aware, resumable), and `gpt verify/repair`.

- `stein_core`, `stein_block`, `stein_platform` (enumerate/open/geometry/
  lock/reread/loop-attach; SMART read), `stein_pt` (GPT/MBR/EBR/APM/BSD/LDM
  read, GPT/MBR write + GPT repair), `stein_fs` L0 for every type in the
  matrix, `stein_container` and `stein_volume` detect-only, `stein_probe`,
  `stein_image` (raw/split/stein + copy engine), `stein_ops` (stack, runner,
  report; operations: CreateTable, RepairTable, Create/Delete/Resize
  partition entries (no fs resize yet), CreateImage, RestoreImage, VerifyImage,
  WipeSignatures).
- CI on Linux/macOS/Windows; fixtures checked in; Linux CI additionally
  cross-checks against `sfdisk --json`, `sgdisk -v`, `blkid -p`, `mmls`.
- Licence lint: core targets compile no non-MIT/BSD code.

## M2 — dr_stein v2 (the one-button app) + FAT/exFAT r/w + LUKS/LVM open

Deliverable: `stein_app` with profiles; a minimal native UI per OS (or one
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

Deliverable: polished platform-native GUIs (GTK4 on Linux, AppKit/SwiftUI on
macOS, WinUI 3 on Windows — each only a view over `stein_ops` and
`stein_probe`), `stein_c` bindings, NTFS L4 (clean volumes), HFS+ L3/L4,
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
