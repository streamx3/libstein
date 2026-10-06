# Operations, jobs, progress and reports

The "plan, preview, apply" model. Both GParted (`Operation*` + `OperationDetail`)
and kpmcore (`Operation` → `Job`s + `Report`, `OperationStack`, `OperationRunner`)
converge on this; libstein adopts it and adds *simulation on an in-memory
topology* so previews are computed, not guessed.

## 1. Vocabulary

| Term | Meaning |
|---|---|
| `Topology` | Immutable snapshot of what is on a set of devices (`stein_probe` output). Cloneable. |
| `Operation` | A user-level intent ("resize partition 2 to 50 GiB", "restore image X to disk Y"). Knows how to *validate* against a Topology, *simulate* (return the Topology after it), *estimate* (time/bytes), *plan* (expand into Jobs), *describe* (human text for the pending list), and where possible *revert plan*. |
| `Job` | One primitive, atomic-ish step ("write GPT", "shrink ext4 to N", "copy 40 GiB from A to B", "set label"). Runs on a worker thread, reports progress, produces a `Report` node. Never prompts. |
| `OperationStack` | Ordered pending operations with their simulated topologies; new operations are validated against the *simulated* state, not the on-disk one (so "create partition, then format it" works before anything is written). Supports remove-last, clear, reorder-with-revalidation. |
| `Runner` | Executes a stack: locks devices, runs Jobs sequentially (parallel only across independent devices), aggregates progress, stops on first error (or continues per policy), emits `Report`. |
| `Report` | Tree: `{title, status, startedAt, duration, details (key/value), children, log lines}`. Serialisable to JSON/text. |
| `Progress` | Thread-safe sink: `setRange`, `advance`, `setPhase`, `message`, `rateHint`; carries a `CancelToken`. Throttling and ETA live here. |

**Implementation note (M1):** simulation is not a model. `OperationStack`
holds an `OverlayDevice` (copy-on-write) over the target; `push()` runs the
operation's jobs on the overlay and probes it for the preview, `apply()`
commits the dirty blocks and re-probes to confirm the device matches the
preview. See `src/ops/`.

## 2. Operation lifecycle

```
             +----------+   validate(topology) -> Diagnostics     +-----------+
  intent --> | Operation| --simulate(topology) -> topology'   --> | Stack     | --> runner.apply()
             +----------+   estimate()        -> {bytes, secs}    +-----------+         |
                            plan()            -> [Job...]                                v
                                                                                   Jobs run, Report built
```

Rules:
- `validate` never touches the device beyond what the Topology already holds.
- `simulate` must be *total*: it edits a cloned Topology using the same
  `PartitionTable::Editor` / `FileSystem::Resizer::limits()` code that
  `apply` uses, so the preview and the result cannot diverge.
- `plan` yields Jobs with explicit ordering constraints (e.g. move partition
  = [shrink fs?] → [copy blocks, direction-aware] → [update table] → [grow fs?]).
- Every destructive Job records in the Report what it overwrote
  (first/last sectors, table snapshots) so that a *best-effort* revert is
  possible for metadata-only changes (table edits, label changes). Data
  overwrites are not revertible and are flagged `Irreversible` for the UI.

## 3. Standard operations (v1 set)

Partition table: `CreateTable`, `RepairTable` (GPT from backup, CRC fix,
relocate backup header), `ConvertTable` (MBR ↔ GPT where entries fit),
`CreatePartition`, `DeletePartition`, `ResizePartition`, `MovePartition`,
`SetPartitionType`, `SetPartitionFlags`, `SetPartitionName`, `SetPartitionUuid`.

Filesystem: `Format` (mkfs), `ResizeFileSystem`, `CheckFileSystem`,
`SetLabel`, `SetUuid`, `WipeSignatures` (secure-ish erase of headers),
`CopyFileSystem` (fs-aware clone using used-block map).

Containers/volumes: `UnlockContainer`, `LockContainer`, `CreateLuks`,
`AddKeyslot`, `RemoveKeyslot`, `ActivateVolumeGroup`, `DeactivateVolumeGroup`.

Images: `CreateImage` (device/partition → image; options: format, chunk size,
split size, compression, hash, used-blocks-only, bad-sector policy),
`RestoreImage` (image → device; checks size/sector-size compatibility, offers
fs grow), `VerifyImage`, `ConvertImage`, `AttachImage` (as OS block device via
platform), `MountImageFileSystem` (via `stein_mount`).

Device: `Benchmark` (sequential read/write, random access; mirrors GNOME Disks
benchmark), `SmartSelfTest`, `SecureErase` (ATA/NVMe sanitize via platform,
or overwrite fallback), `Rescan`.

App-level (in `stein_app`): `BackupScenario`, `RestoreScenario`,
`VerifyScenario` — compositions of the above driven by a `Profile`.

## 4. Safety checks (in `Runner`, not in UIs)

- Refuse to run on a device that has mounted/in-use children unless the
  operation declares `AllowsOnline` and the fs supports online mode.
- Lock devices for the duration (platform: `O_EXCL`/`FSCTL_LOCK_VOLUME`/
  DiskArbitration claim).
- Size and sector-size compatibility checks for restore/copy; warn on
  shrinking targets.
- Re-probe after apply and diff against the simulated topology; mismatches are
  reported as `PostconditionFailed` (never silently ignored).
- Power-loss awareness: table writes are ordered and fsync'ed; the copy
  engine checkpoints its position in the image metadata so restores/clones
  can resume.

## 5. Progress and ETA

The library owns throttling (max N updates/sec), ETA (exponentially-weighted
rate over the last ~10 s, not since start), and phase names; UIs just render.
Nested jobs scale their sub-ranges into the parent's. This is dr_stein's
`update_pb/update_time` done once, properly.

## 6. Privilege boundary

`Runner` is designed to run inside the privileged helper; the UI holds a
proxy that streams `Progress` and `Report` events back. The `Operation`
objects are serialisable (JSON) for this reason — the UI builds the stack,
the helper executes it. On a system where the UI already has rights, the
proxy is in-process. This is also what makes the CLI and GUI identical in
behaviour.
