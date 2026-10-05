# Reference review: dr_stein (streamx3/dr_stein)

Source: https://github.com/streamx3/dr_stein — 787 lines, Qt 5 widgets app,
**BSD-2-Clause** (so anything here can be reused in libstein without
license concerns; the author is the same person).

## What it is

A deliberately minimal "image and restore one partition" tool, written before
the LLM era, proven to restore a whole Windows installation in two clicks.
It is the archetype of the *user-oriented app* that libstein must make easy.

Files:

| File | Role |
|---|---|
| `src/settings.{h,cpp}` | `Settings` class: INI file in `~/.dr_stein/config.ini` with three keys: `disk_name`, `image_name`, `image_md5`. Mutex-guarded getters/setters. |
| `src/mainwindow.{h,cpp,ui}` | The whole engine: `__copy(E_ACT)` does clone or restore; `md5sum()` verifies; `update_pb()/update_time()` do progress + ETA. |
| `src/dr_stein.pro` | qmake; links `-lblkid -lssl -lcrypto`. |

## The engine, line by line, and what it teaches

1. **Target device is pre-configured and locked behind a 🔒 toggle.** The
   user must consciously unlock before the device path can be edited, and
   unlocking triggers a warning. → *Design input:* "policy" belongs in the
   app profile; the library must expose device identity robustly (by
   serial/WWN/partition UUID, not only `/dev/sdc1`, which can change).
2. **Image path is fixed** (`/opt/dr_stein/backup.img`). Restore button is
   only enabled if the image file exists and is non-empty (`file_empty()`
   uses `st_blocks > 0`, a nice sparse-aware trick).
3. **Clone = `read(fd_disk)` → `write(fd_image)` in 512-byte blocks**, size from
   `blkid_probe_get_size()`. Restore is the reverse with size from
   `stat(image).st_size`.
   - 512-byte I/O is ~100× slower than it should be (no readahead, no
     O_DIRECT, no large buffers). The libstein copy engine must use multi-MiB
     buffers, optionally `O_DIRECT`/unbuffered I/O, and double-buffering.
   - No sparse detection, no used-block-only copying, no compression, no
     splitting. All five are explicit libstein requirements (R5).
   - Errors abort immediately and leak fds; no retry/skip for bad sectors
     (ddrescue-style "skip and come back" is the right model for cloning
     failing disks).
4. **MD5 of the image stored in config and verified before restore.** The
   mismatch dialog lets the user override. → *Design input:* image metadata
   (checksum, source device identity, size, sector size, partition-table
   snapshot, creation time) must live *with* the image (sidecar or container
   header), not only in the app's config, so an image is self-describing.
   Use a modern hash (BLAKE3/SHA-256/xxh3) with per-chunk checksums so a
   split image can be verified piecewise and resumed.
5. **Progress and ETA** are computed in the UI thread with a static call
   counter throttle. → *Design input:* the library must provide a
   `ProgressSink` interface fed from the worker thread with throttling done
   in the library, and ETA derived from a moving average, so every UI gets
   it for free.
6. **No privilege handling** — the app is simply run as root.
   → *Design input:* R11.
7. **Commented-out size check**: "blk_dev_size is based on blocks, not on
   partition size" — the author hit the classic confusion between device
   size, partition size and image size. The library must model these as
   distinct, typed quantities (`Bytes`, `Sectors{count, sector_size}`) and
   validate restore targets (image larger than target → refuse; smaller →
   warn, offer to grow fs afterwards).

## What libstein keeps from dr_stein

- The product idea: a profile-driven, nearly zero-UI restore tool. In
  libstein terms: `stein::app::Profile` (device selector, image location,
  verification policy, post-restore actions) + `stein::ops::RestoreImage`.
- The naming lineage ("stein").
- The lock/unlock-before-danger UX pattern, expressed as a policy flag in
  the profile rather than in the UI.
- Sparse-file awareness (`st_blocks`) — generalised into the image layer.

## What it must not carry over

Qt types in logic, UI-thread I/O, 512-byte copy loops, config-only metadata,
MD5, device identification by path alone, no error recovery.
