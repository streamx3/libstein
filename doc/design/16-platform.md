# Platform layer (`stein_platform`)

The only library with OS-specific code. One public header set, three
implementations (`src/platform/linux`, `src/platform/macos`,
`src/platform/windows`), selected by CMake. Everything above it sees only
abstract interfaces. Details and API names come from
`research/05-library-ecosystem.md` §F/§G.

## 1. Interfaces

```cpp
namespace stein::platform {

class DiskEnumerator {            // "what disks does this machine have"
public:
    virtual Expected<std::vector<DiskInfo>> enumerate(EnumerateOptions) = 0;   // physical, removable, optical, loop/attached images
    virtual Expected<Subscription> watch(std::function<void(DiskEvent)>) = 0;   // hot-plug / media change
};

class DiskOpener {                // raw block access, returns a BlockDevice
public:
    virtual Expected<std::shared_ptr<BlockDevice>> open(const DiskInfo&, OpenMode /*ReadOnly|ReadWrite|Exclusive*/) = 0;
};

class VolumeControl {             // what the OS thinks is mounted on top of a region
public:
    virtual Expected<std::vector<MountInfo>> mounts(const DiskInfo&) = 0;
    virtual Expected<void> unmount(const MountInfo&, UnmountOptions /*force, lazy*/) = 0;
    virtual Expected<void> mount(const BlockDevice&, MountRequest) = 0;         // native mount of a known fs
    virtual Expected<void> lock(const DiskInfo&) = 0;                           // keep automounters away during ops
    virtual Expected<void> rereadPartitionTable(const DiskInfo&) = 0;
};

class ImageAttacher {             // expose an image file as an OS block device
public:
    virtual Expected<AttachedImage> attach(const std::filesystem::path&, AttachOptions /*readOnly, partscan*/) = 0;
    virtual Expected<void> detach(const AttachedImage&) = 0;
    virtual std::vector<ImageFormatId> nativelySupported() const = 0;           // raw on Linux/macOS; VHD/VHDX/ISO on Windows
};

class DriveHealth {               // SMART / NVMe health
public:
    virtual Expected<SmartReport> read(const DiskInfo&) = 0;
    virtual Expected<void> startSelfTest(const DiskInfo&, SelfTestKind) = 0;
};

class PrivilegeBroker {           // see §3
public:
    virtual bool elevated() const = 0;
    virtual Expected<void> ensureElevated(ElevationReason) = 0;
    virtual Expected<std::shared_ptr<Channel>> channel() = 0;                   // RPC to the helper, if out-of-process
};

Platform& current();              // factory for all of the above

} // namespace
```

`DiskInfo`: `{DeviceIdentity id; std::string osPath; Geometry; Bus (sata, nvme, usb, sd, virtual, …); bool removable, rotational, readOnly, optical; MediaState; std::string model, vendor, serial, firmware, wwn; std::optional<std::filesystem::path> backingFile;}`.

## 2. Per-OS mapping

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Enumerate | sysfs `/sys/class/block`, `/sys/block/*/queue/*` (sector sizes, rotational), `/dev/disk/by-id` (identity); optional libudev (LGPL, dynamic) for events, else netlink uevent socket | IOKit: `IOMedia` whole-media objects with `IOMediaWhole`, `IOBSDName`, `IOMediaSize`, `IOMediaPreferredBlockSize`, `IOMediaEjectable`, `IODeviceModel`/`IOSerialNumber` via parent `IOBlockStorageDevice`; DiskArbitration `DADiskCopyDescription`; events via `DARegisterDiskAppearedCallback` | SetupAPI `SetupDiGetClassDevs(GUID_DEVINTERFACE_DISK)`; `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`, `StorageAccessAlignmentProperty`, `StorageDeviceSeekPenaltyProperty`); `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`; `IOCTL_DISK_GET_LENGTH_INFO`; events via `WM_DEVICECHANGE`/`CM_Register_Notification` |
| Open raw | `open("/dev/sdX", O_RDWR|O_EXCL|O_CLOEXEC [|O_DIRECT])`; `BLKGETSIZE64`, `BLKSSZGET`, `BLKPBSZGET`, `BLKIOMIN/OPT`, `BLKALIGNOFF`; `BLKRRPART` for reread; `BLKDISCARD` for TRIM | `open("/dev/rdiskN", O_RDWR)` (raw, unbuffered, needs aligned I/O); `DKIOCGETBLOCKSIZE`, `DKIOCGETBLOCKCOUNT`, `DKIOCGETPHYSICALBLOCKSIZE`; DiskArbitration `DADiskClaim` to keep diskarbitrationd from auto-mounting; `DKIOCUNMAP` for TRIM | `CreateFile("\\\\.\\PhysicalDriveN", GENERIC_READ|WRITE, FILE_SHARE_READ|WRITE, …, FILE_FLAG_NO_BUFFERING)` (sector-aligned I/O only); volumes on it: `FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME` per `\\.\X:` before writing; `IOCTL_DISK_UPDATE_PROPERTIES` to reread; `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES` for TRIM; `IOCTL_DISK_DELETE_DRIVE_LAYOUT` is **never** used (we write bytes ourselves) |
| Mounts | `/proc/self/mountinfo`; `umount2()`; `mount()` syscall for native fs (ext4, xfs, btrfs, vfat, ntfs3, exfat, hfsplus…) | `getmntinfo()`; `DADiskUnmount`/`DADiskMount` (async, run loop) | `GetVolumePathNamesForVolumeName`, `FindFirstVolume`; dismount via `FSCTL_DISMOUNT_VOLUME`; mount = assign letter (`SetVolumeMountPoint`) |
| Attach image | `/dev/loop-control` `LOOP_CTL_GET_FREE` + `LOOP_CONFIGURE` with `LO_FLAGS_PARTSCAN`, `LO_FLAGS_DIRECT_IO`; optional NBD server (own) for non-raw formats | `hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount` (raw) / DMG natively; returns `/dev/diskN`; DiskImages private framework avoided | Virtual Disk API `OpenVirtualDisk`/`AttachVirtualDisk` for VHD/VHDX/ISO (we convert raw → fixed VHD footer in place: a raw image + 512-byte footer *is* a fixed VHD); non-VHD formats via `stein_mount`'s Dokany backend only |
| SMART | `SG_IO` with ATA PASS-THROUGH (16) `SMART READ DATA`/`READ LOG`; NVMe `NVME_IOCTL_ADMIN_CMD` Get Log Page 0x02; SCSI Informational Exceptions log page | IOKit `IOATASMARTInterface` (`SMARTReadData`, `SMARTReadDataThresholds`); NVMe via `NVMeSMARTInterface` (IOKit user client; undocumented but used by smartmontools) | `IOCTL_ATA_PASS_THROUGH`, `SMART_RCV_DRIVE_DATA`; NVMe `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProtocolSpecificProperty` (`ProtocolTypeNvme`, `NVMeDataTypeLogPage`) |
| Secure erase | ATA `SECURITY ERASE UNIT` via SG_IO; NVMe `Format NVM`/`Sanitize`; `BLKSECDISCARD` | IOKit pass-through limited; fall back to overwrite | `IOCTL_ATA_PASS_THROUGH`; `IOCTL_STORAGE_REINITIALIZE_MEDIA` (Win10+ sanitize) |
| Identity source | by-id symlinks + `ID_SERIAL`/WWN from sysfs `device/wwid`, `vpd_pg83` | `IOSerialNumber`, `Device GUID` property, DA description `DADiskDescriptionMediaUUIDKey` | `StorageDeviceProperty.SerialNumber`, `StorageDeviceIdProperty` (VPD 0x83), disk signature / GPT disk GUID |

Design notes:
- Reads are made **alignment-safe in the platform device class**: `PlatformDisk::readAt` bounce-buffers unaligned requests (Windows `NO_BUFFERING` and macOS raw devices require sector alignment; Linux `O_DIRECT` too). The core never cares.
- All blocking OS calls run on the caller's thread; the platform layer never spawns its own threads except for event watchers.
- Optical media, SD/MMC and virtual (loop/attached) disks are flagged, not hidden; the UI decides what to show (GNOME Disks hides zram/ram; we expose and tag).

## 3. Privilege model

Three postures, one interface:

1. **Already elevated** (root / Administrator / `sudo stein …`): `PrivilegeBroker::elevated() == true`; everything in-process.
2. **Elevate self** (CLI convenience): re-exec via `pkexec`/`sudo` (Linux), `osascript … with administrator privileges` or `authopen -w /dev/rdiskN` fd hand-off (macOS), `ShellExecuteEx(runas)` (Windows). Loses stdin/stdout continuity; acceptable for CLI only.
3. **Helper process** (GUI default): the UI spawns `stein-helper` elevated once (polkit action `org.stein.helper.run` with `auth_admin_keep`; macOS `SMAppService` daemon or one-shot `osascript`; Windows elevated child via `runas` + named pipe inherited handle). The helper speaks a **typed, length-prefixed RPC** over a pipe/socket:
   - `Open(DiskId, mode) → handle`, `ReadAt`, `WriteAt`, `Flush`, `Discard`, `Geometry`, `Close`
   - `Enumerate`, `Mounts`, `Unmount`, `Mount`, `Lock`, `Reread`, `Attach`, `Detach`, `Smart`
   - `RunStack(serialized OperationStack) → stream of Progress/Report events` — the *whole* `stein_ops` runner can live in the helper so that bulk copies don't cross the pipe byte-by-byte.
   - No generic "run this command" verb. (kpmcore's whitelist-by-basename design is explicitly rejected.)
   - Per-client authorisation cached for the session; helper exits when the last client disconnects; **never aborts mid-write** on auth timeout.
   - Unprivileged read-only probing stays in-process wherever the OS allows (sysfs/IOKit/SetupAPI metadata), so a "viewer" mode needs no prompt.

The `Channel` abstraction makes the same `PlatformDisk` class usable in all three postures: it either calls the OS directly or forwards over RPC.

## 4. Testing the platform layer

- Linux CI: loop devices in a privileged container; `sfdisk`, `losetup`, `blkid` as oracles.
- macOS CI: `hdiutil create`/`attach` sparse images; `diskutil list -plist` as oracle; no root needed for attached images owned by the user.
- Windows CI: `New-VHD` + `Mount-VHD`; `Get-Disk | ConvertTo-Json`, `diskpart` scripts as oracle. Requires an elevated runner.
- Everything else (core libs) is tested on `MemoryDevice`/`FileDevice` with checked-in fixtures and needs no privileges on any OS.

## 5. Implementation status (M1)

The shipped interface is the flat `Platform` class in
`stein/platform/platform.hpp` (enumerate / describe / open / mounts /
rereadPartitionTable / attach / detach / isElevated); the split into
`DiskEnumerator`, `VolumeControl` etc. above is the target shape once SMART
and the helper RPC arrive.

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Enumerate | sysfs, done | IOKit `IOMedia` whole-disk objects, device/protocol characteristics, done | `PhysicalDriveN` sweep + `STORAGE_QUERY_PROPERTY`, done (SetupAPI interface enumeration later) |
| Open raw | `open` + BLK* ioctls, done | `/dev/rdiskN` + DKIOC*, done; aligned I/O via `AlignedDevice` | `CreateFile` + geometry/alignment ioctls, done; aligned I/O via `AlignedDevice`; volume lock/dismount before writes: M2 |
| Mounts | `/proc/self/mountinfo`, done | `getmntinfo`, done | drive letters → disk extents, done; volume GUID paths later |
| Re-read table | `BLKRRPART`, done | automatic on close | `IOCTL_DISK_UPDATE_PROPERTIES`, done |
| Attach image | loop, done | `hdiutil attach` (raw), done | not available for raw images (VHD attach with the VHD reader, M3) |
| Hot-plug events, SMART, secure erase, privilege broker | planned | planned | planned |

`AlignedDevice` (`src/platform/src/aligned_device.*`) is OS-independent and
unit-tested on Linux against a fake device that rejects unaligned I/O, so the
bounce-buffer logic the macOS and Windows backends depend on is covered by CI
on every platform.
