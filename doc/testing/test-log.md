# Test log

Every test run that counts as verification gets a row here: when it ran
(UTC), which commit (short id), which tag that commit carries (none yet;
`–`), where it ran, how it was built, what it exercised, whether it passed,
and the evidence (a link to the CI job, or who ran it by hand). A row is
written as, for example, `2026-10-06 15:49, d295123, –, …`.

Rows come from two sources:

- **CI** (`.github/workflows/ci.yml`): every push builds and runs all test
  suites on `ubuntu-24.04` (GCC, Debug, ASan+UBSan), `macos-14` (AppleClang,
  Debug) and `windows-2022` (MSVC, Debug), all with `-Werror`, all with the
  mount backend required to really mount (FUSE, the NFS loopback server with
  `mount_nfs`, WinFsp). These runs use fixture images only: filesystems made
  by the reference tools, container images, virtual disks, VeraCrypt/LUKS
  volumes. `python3 tools/testlog.py ci` pulls the completed runs of the
  current branch through `gh` and appends what is missing.
- **By hand**: a run on a developer machine, or on real hardware (USB
  sticks, SD cards, SATA/NVMe disks, card readers), recorded with
  `python3 tools/testlog.py add --platform … --build … --scope … --result pass|fail|partial [--evidence …]`.
  The commit and tag are taken from `HEAD`, so run it from the checkout that
  was tested.

## What still needs a row

Nothing has been run on real hardware yet, and nothing by a person on
macOS or Windows (CI's runners are the only macOS and Windows evidence so
far). The first real-hardware pass per OS should cover, read-only first:

1. `stein list` and `stein probe /dev/…` on an internal disk and a USB stick
   (device enumeration, geometry, partition tables, filesystem detection).
2. `stein inspect … --doc`, `stein verify …` on the same devices.
3. `stein ls` / `stein cat` / `stein cp` out of a partition on the device,
   compared with the OS's own view of the files.
4. `stein mount` (Linux FUSE, macOS NFS loopback, Windows WinFsp) of a
   partition on the device; browse it in the file manager.
5. `stein image create /dev/usb out.stein` then `stein image verify
   --level 3`, `stein probe out.stein`, and a restore to a second scratch
   stick followed by `cmp` against the source.
6. `stein media scan` (read-only) on a stick, then `media test --force` on
   a stick that may be wiped.
7. On Linux only, with a scratch stick: `stein pt create/add/…` with
   `--dry-run` first, then for real, then re-probe.

Record each OS as its own row (one per step group is fine: "steps 1–4
read-only", "steps 5–7 scratch media"), and note the hardware in the
platform column ("Linux x86-64, Fedora 42, SanDisk 32 GB USB + Samsung 980
NVMe").

## Records

<!-- testlog:begin -->
| When (UTC) | Commit | Tag | Platform | Build | Scope | Result | Evidence |
|---|---|---|---|---|---|---|---|
| 2026-10-06 18:50 | 2cbe381 | – | Linux x86-64 (cloud dev container, images only) | GCC 13, Debug, ASan+UBSan | all 13 ctest suites (ctest -j4), plus release-build cipher throughput check | pass | operator record (session 2026-10-06; VeraCrypt cipher work) |
| 2026-10-06 15:56 | 2cbe381 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #97 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37491059819/job/112363601767) |
| 2026-10-06 15:55 | 2cbe381 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #97 windows-2022](https://github.com/streamx3/libstein/actions/runs/37491059819/job/112363601624) |
| 2026-10-06 15:55 | 2cbe381 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #97 macos-14](https://github.com/streamx3/libstein/actions/runs/37491059819/job/112363601704) |
| 2026-10-06 15:49 | d295123 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #96 windows-2022](https://github.com/streamx3/libstein/actions/runs/37490156729/job/112360450421) |
| 2026-10-06 15:49 | d295123 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #96 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37490156729/job/112360450817) |
| 2026-10-06 15:48 | d295123 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #96 macos-14](https://github.com/streamx3/libstein/actions/runs/37490156729/job/112360451067) |
| 2026-10-06 14:48 | 2b3be52 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #95 macos-14](https://github.com/streamx3/libstein/actions/runs/37481450844/job/112330323376) |
| 2026-10-06 14:47 | 2b3be52 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #95 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37481450844/job/112330323142) |
| 2026-10-06 14:47 | 2b3be52 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #95 windows-2022](https://github.com/streamx3/libstein/actions/runs/37481450844/job/112330323455) |
| 2026-10-06 11:34 | 25d630a | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #94 macos-14](https://github.com/streamx3/libstein/actions/runs/37456782368/job/112246233921) |
| 2026-10-06 11:33 | 25d630a | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #94 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37456782368/job/112246233723) |
| 2026-10-06 11:33 | 25d630a | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #94 windows-2022](https://github.com/streamx3/libstein/actions/runs/37456782368/job/112246233908) |
| 2026-10-06 11:29 | 97dabeb | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #93 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37456256087/job/112244498815) |
| 2026-10-06 11:29 | 97dabeb | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #93 macos-14](https://github.com/streamx3/libstein/actions/runs/37456256087/job/112244498935) |
| 2026-10-06 11:28 | 97dabeb | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #93 windows-2022](https://github.com/streamx3/libstein/actions/runs/37456256087/job/112244498561) |
| 2026-10-06 11:28 | 59ae7ae | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #92 windows-2022](https://github.com/streamx3/libstein/actions/runs/37456205427/job/112244335368) |
| 2026-10-06 11:28 | 59ae7ae | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | failure | [CI #92 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37456205427/job/112244335671) |
| 2026-10-06 11:28 | 59ae7ae | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #92 macos-14](https://github.com/streamx3/libstein/actions/runs/37456205427/job/112244335674) |
<!-- testlog:end -->
