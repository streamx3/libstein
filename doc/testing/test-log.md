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
| 2026-10-06 22:02 | 836c361 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #113 macos-14](https://github.com/streamx3/libstein/actions/runs/37537419798/job/112521852551) |
| 2026-10-06 22:01 | 836c361 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #113 windows-2022](https://github.com/streamx3/libstein/actions/runs/37537419798/job/112521852758) |
| 2026-10-06 22:01 | 836c361 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #113 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37537419798/job/112521852798) |
| 2026-10-06 21:57 | 7e8eef3 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #112 macos-14](https://github.com/streamx3/libstein/actions/runs/37536905548/job/112520131924) |
| 2026-10-06 21:57 | 7e8eef3 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #112 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37536905548/job/112520132008) |
| 2026-10-06 21:55 | 7e8eef3 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #112 windows-2022](https://github.com/streamx3/libstein/actions/runs/37536905548/job/112520131638) |
| 2026-10-06 21:55 | 5756fb8 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #111 macos-14](https://github.com/streamx3/libstein/actions/runs/37536722887/job/112519506454) |
| 2026-10-06 21:55 | 5756fb8 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #111 windows-2022](https://github.com/streamx3/libstein/actions/runs/37536722887/job/112519506832) |
| 2026-10-06 21:55 | 5756fb8 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #111 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37536722887/job/112519506835) |
| 2026-10-06 21:54 | 78fb77f | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #110 macos-14](https://github.com/streamx3/libstein/actions/runs/37536554986/job/112518919509) |
| 2026-10-06 21:54 | 78fb77f | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #110 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37536554986/job/112518919538) |
| 2026-10-06 21:52 | 78fb77f | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #110 windows-2022](https://github.com/streamx3/libstein/actions/runs/37536554986/job/112518919170) |
| 2026-10-06 21:49 | b4fa983 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #109 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37536015502/job/112516980101) |
| 2026-10-06 21:49 | b4fa983 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #109 macos-14](https://github.com/streamx3/libstein/actions/runs/37536015502/job/112516980441) |
| 2026-10-06 21:49 | b4fa983 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #109 windows-2022](https://github.com/streamx3/libstein/actions/runs/37536015502/job/112516980631) |
| 2026-10-06 21:48 | 79387f0 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #108 macos-14](https://github.com/streamx3/libstein/actions/runs/37535863055/job/112516468079) |
| 2026-10-06 21:48 | 79387f0 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #108 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37535863055/job/112516468421) |
| 2026-10-06 21:47 | 79387f0 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #108 windows-2022](https://github.com/streamx3/libstein/actions/runs/37535863055/job/112516468338) |
| 2026-10-06 21:47 | 077fac6 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #107 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37535810000/job/112516294710) |
| 2026-10-06 21:47 | 077fac6 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #107 windows-2022](https://github.com/streamx3/libstein/actions/runs/37535810000/job/112516294850) |
| 2026-10-06 21:47 | 077fac6 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #107 macos-14](https://github.com/streamx3/libstein/actions/runs/37535810000/job/112516295108) |
| 2026-10-06 21:46 | 6b646a9 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | pass | [CI #106 macos-14](https://github.com/streamx3/libstein/actions/runs/37535665527/job/112515803304) |
| 2026-10-06 21:46 | 6b646a9 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #106 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37535665527/job/112515803627) |
| 2026-10-06 21:45 | 6b646a9 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | pass | [CI #106 windows-2022](https://github.com/streamx3/libstein/actions/runs/37535665527/job/112515803629) |
| 2026-10-06 21:44 | cc89ba5 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #105 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37535445771/job/112515067347) |
| 2026-10-06 21:42 | cc89ba5 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #105 windows-2022](https://github.com/streamx3/libstein/actions/runs/37535445771/job/112515067093) |
| 2026-10-06 21:40 | cc89ba5 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #105 macos-14](https://github.com/streamx3/libstein/actions/runs/37535445771/job/112515067338) |
| 2026-10-06 21:35 | db1656d | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #104 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37534466576/job/112511787526) |
| 2026-10-06 21:35 | 403e115 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #103 windows-2022](https://github.com/streamx3/libstein/actions/runs/37534388546/job/112511527481) |
| 2026-10-06 21:35 | 403e115 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #103 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37534388546/job/112511527802) |
| 2026-10-06 21:34 | db1656d | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #104 windows-2022](https://github.com/streamx3/libstein/actions/runs/37534466576/job/112511787873) |
| 2026-10-06 21:32 | db1656d | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #104 macos-14](https://github.com/streamx3/libstein/actions/runs/37534466576/job/112511787817) |
| 2026-10-06 21:31 | 403e115 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #103 macos-14](https://github.com/streamx3/libstein/actions/runs/37534388546/job/112511527839) |
| 2026-10-06 21:31 | 286aa48 | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #102 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37533958588/job/112510052501) |
| 2026-10-06 21:29 | 286aa48 | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #102 windows-2022](https://github.com/streamx3/libstein/actions/runs/37533958588/job/112510052933) |
| 2026-10-06 21:29 | d51201e | – | Linux x86-64 (GitHub runner, images only) | GCC 13, Debug, ASan+UBSan, -Werror | all 13 ctest suites against fixtures; FUSE mount required; CLI smoke (GPT repair) | pass | [CI #101 ubuntu-24.04](https://github.com/streamx3/libstein/actions/runs/37533860669/job/112509721676) |
| 2026-10-06 21:27 | 286aa48 | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #102 macos-14](https://github.com/streamx3/libstein/actions/runs/37533958588/job/112510052992) |
| 2026-10-06 21:27 | d51201e | – | Windows Server 2022 x86-64 (GitHub runner, images only) | MSVC 2022, Debug, -Werror | all 13 ctest suites against fixtures; WinFsp mount required | failure | [CI #101 windows-2022](https://github.com/streamx3/libstein/actions/runs/37533860669/job/112509721231) |
| 2026-10-06 21:27 | d51201e | – | macOS 14 arm64 (GitHub runner, images only) | AppleClang, Debug, -Werror | all 13 ctest suites against fixtures; NFS loopback mount_nfs required; CLI smoke (GPT repair) | failure | [CI #101 macos-14](https://github.com/streamx3/libstein/actions/runs/37533860669/job/112509721707) |
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
