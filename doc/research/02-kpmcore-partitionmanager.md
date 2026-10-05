# kpmcore / KDE Partition Manager — architecture survey for a pure-C++ disk/partition/filesystem library

Path conventions used below:

* `$K` = `<checkout>/kpmcore`
* `$P` = `<checkout>/partitionmanager`

Both checkouts are single-commit shallow clones (`git rev-list --count HEAD` = 1); kpmcore HEAD `fdc83e3` dated 2026-10-04, partitionmanager HEAD `e231a49` dated 2026-10-05. Version strings in both top-level `CMakeLists.txt` are `26.11.70` (KDE Gear release-service numbering); kpmcore `SOVERSION` is `13`. Because history is absent, anything about *past* changes (e.g. libparted removal) is flagged as upstream knowledge rather than something verified in these trees.

---

## 1. Licensing

### kpmcore (`$K/LICENSES/`: `GPL-3.0-or-later.txt`, `MIT.txt`, `CC0-1.0.txt`, `CC-BY-4.0.txt`)

SPDX identifier census (`grep -rhoE "SPDX-License-Identifier: ..." $K | sort | uniq -c`):

| Identifier | Files |
|---|---|
| GPL-3.0-or-later | 305 |
| CC0-1.0 | 7 |
| MIT | 2 |
| CC-BY-4.0 | 2 |

Every `.cpp`/`.h`/`CMakeLists.txt` under `$K/src` and `$K/test` is **GPL-3.0-or-later**. The non-GPL files are all non-code:

* MIT: `$K/src/util/org.kde.kpmcore.helperinterface.conf` (D-Bus policy, per `$K/.reuse/dep5`) and `$K/.gitignore`-type metadata.
* CC0-1.0: `$K/src/util/org.kde.kpmcore.externalcommand.policy` (polkit policy), `$K/src/util/trustedprefixes`, `$K/metainfo.yaml`, `$K/src/Messages.sh`, `$K/src/XmlMessages.sh`, CI yaml, `$K/test/test_fstab_data/fstab.license`.
* CC-BY-4.0: `$K/README.md`, `$K/INSTALL.md`.
* `$K/.reuse/dep5` additionally assigns GPL-3.0-or-later to `po/*.po` and `src/plugins/*/*.json` (the plugin metadata files that carry no header).

Conclusion: **there is no permissively-licensed code in kpmcore**. Every class you would want to look at is GPL-3.0-or-later. Design ideas can be reused; code cannot be copied into a non-GPL project.

### partitionmanager (`$P/LICENSES/`: adds `LGPL-3.0-or-later.txt`, `GFDL-1.2-or-later.txt`)

| Identifier | Files |
|---|---|
| GPL-3.0-or-later | 121 |
| CC0-1.0 | 3 |
| MIT | 1 (`$P/src/org.kde.partitionmanager.xml`, D-Bus interface, via dep5) |
| LGPL-3.0-or-later | 1 (`$P/icons/sc-apps-partitionmanager.svg`) |
| GFDL-1.2-or-later | 1 (`$P/INSTALL.md`; `$P/.reuse/dep5` also assigns GFDL-1.2-or-later to `doc/*.docbook`, and CC-BY-4.0 or GFDL to `doc/*.png`) |
| CC-BY-4.0 | 1 (`$P/README.md`) |

All C++ in `$P/src` is GPL-3.0-or-later. `$P/src/main.cpp` declares `KAboutLicense::GPL_V3`.

---

## 2. Build system and dependencies

### kpmcore (`$K/CMakeLists.txt`, `$K/src/CMakeLists.txt`)

* CMake ≥ 3.16, KDE ECM (`find_package(ECM ${KF_MIN_VERSION})`), `KDEInstallDirs`, `KDECMakeSettings`, `KDECompilerSettings`, `kde_enable_exceptions()`.
* `QT_MIN_VERSION 6.5.0`, `KF_MIN_VERSION 5.240.0`, `BLKID_MIN_VERSION 2.33.2`.
* Qt6 components **required**: `Core`, `DBus`, `Gui`, `Widgets`. Link visibility (`$K/src/CMakeLists.txt`): `PUBLIC Qt6::Core Qt6::Widgets`; `PRIVATE ${BLKID_LIBRARIES} Qt6::DBus Qt6::Gui KF6::I18n KF6::CoreAddons KF6::WidgetsAddons`. `$K/KPMcoreConfig.cmake.in` propagates `Qt6 Core Widgets` to consumers — i.e. *QtWidgets is a public dependency of the "core" library* (because `src/gui/` is compiled into the same `kpmcore` shared library and `FileSystem::labelValidator()` returns a `QValidator*`).
* KF6 modules: `CoreAddons` (KPluginFactory/KPluginMetaData plugin loading), `I18n` (KLocalizedString, `xi18nc` everywhere), `WidgetsAddons` (KPasswordDialog inside `fs/luks.cpp`).
* `PolkitQt6-1` required (only linked into the helper executable `kpmcore_externalcommand`).
* `libblkid` via pkg-config on Linux only; used in exactly one place: `$K/src/core/fstab.cpp:231` `blkid_evaluate_tag()` to resolve `UUID=`/`LABEL=` fstab specs. Not used for probing devices.
* Runtime (not build) dependencies: util-linux (`sfdisk`, `lsblk`, `blockdev`, `blkid`, `partx`, `wipefs`, `mkswap`...), udev (`udevadm`), smartmontools 7.0 (`smartctl --json`), lvm2, mdadm, cryptsetup, dmsetup and every filesystem's userspace tool set (full list in `$K/src/util/externalcommand_whitelist.h`, ~90 binaries).
* No libparted anywhere: `grep -rni parted $K/src $K/CMakeLists.txt` yields only a comment in `$K/src/fs/luks.cpp:93` ("libparted does not support LUKS, we do this as a special case") and `$K/src/core/diskdevice.cpp:50` ("libblkid ... (not implemented)"). Upstream history (not verifiable in this shallow clone): the libparted backend was the original backend, the sfdisk backend was added in kpmcore 3.3 (2018) and libparted was removed in 4.0 (2019).
* Plugins (`$K/src/plugins/CMakeLists.txt`): `sfdisk` (Linux, default), `geom` (FreeBSD, links `geom`, uses libgeom + `gpart`), `dummy` (always). Installed under the `kpmcore` KPlugin namespace via `kcoreaddons_add_plugin`.
* Tests (`$K/test/CMakeLists.txt`): `testinit`, `testlist`, `testdevicescanner`, `testexternalcommand`, `testdevice`, `test_fstab` — all require a running backend (and for sfdisk, root/polkit).

### How deeply Qt is woven in (line-match counts via `grep -rE pattern dir | wc -l`, `.cpp`+`.h`)

| Pattern | core | fs | ops | jobs | backend | util | plugins |
|---|---|---|---|---|---|---|---|
| `QString` | 575 | 1318 | 176 | 147 | 39 | 311 | 333 |
| `QStringLiteral\|QLatin1String` | 203 | 577 | 32 | 10 | 5 | 189 | 251 |
| `QList` | 31 | 26 | 8 | 8 | 3 | 8 | 24 |
| `QVector` | 16 | 0 | 11 | 6 | 4 | 0 | 0 |
| `QVariant` | 1 | 135 | 2 | 1 | 0 | 22 | 9 |
| `QRegularExpression` | 45 | 96 | 0 | 0 | 0 | 0 | 18 |
| `QJson*` | 20 | 7 | 0 | 0 | 0 | 0 | 21 |
| `QFile` | 28 | 10 | 3 | 0 | 2 | 18 | 5 |
| `QObject` | 18 | 7 | 2 | 2 | 2 | 12 | 6 |
| `Q_OBJECT` macro | 3 | 0 | 1 | 1 | 1 | 5 | 0 |
| `Q_SIGNALS\|signals:` | 3 | 0 | 1 | 1 | 1 | 5 | 0 |
| `Q_EMIT\|emit ` | 13 | 0 | 2 | 5 | 4 | 9 | 0 |
| `connect(` | 3 | 0 | 3 | 4 | 0 | 12 | 0 |
| `qDebug\|qWarning\|qC*` | 10 | 16 | 7 | 4 | 6 | 19 | 3 |
| `QProcess` | 1 | 4 | 0 | 0 | 0 | 12 | 1 |
| `QDBus` | 5 | 0 | 0 | 0 | 0 | 54 | 0 |
| `QThread` | 7 | 0 | 0 | 0 | 0 | 2 | 0 |
| `QMutex` | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| `i18n`/`xi18nc` | 153 | 99 | 66 | 99 | 0 | 47 | 11 |
| `K*` (KLocalizedString, KPluginFactory...) | 11 | 18 | 18 | 27 | 10 | 12 | 11 |

Sizes: core 8 101 lines/56 files, fs 10 223/80, ops 4 273/37, jobs 3 544/54, backend 704/8, util 2 302/17, plugins 2 724/20, gui 1 124/6 (~33 k lines total).

Distinct Qt headers included in `src/core`+`src/fs`: 40 (`QtGlobal` 52×, `QString` 37×, `QRegularExpression` 23×, `QStringList` 21×, `QFile` 9×, `QTemporaryDir` 7×, `QObject` 6×, `QStorageInfo` 4×, `QJson*` 7×, `QUuid` 4×, `QWidget`/`QDialog`/`QColor`/`QRegularExpressionValidator` in fs, `QDBusInterface` in core…).

Classes deriving from `QObject`: `Device` (`$K/src/core/device.h`), `PartitionNode` (hence `Partition`, `PartitionTable`), `OperationStack`, `OperationRunner : QThread`, `DeviceScanner : QThread`, `CoreBackend`, `Operation`, `Job`, `ExternalCommand`, `ExternalCommandHelper`, `GlobalLog`, `Report`, `DeviceReadBenchmark`, `PartWidget`, `PartResizerWidget`. `FileSystem` is **not** a QObject but uses `QString`, `QVariantMap`, `QUrl`, `QColor`, returns `QValidator*`, and `luks::cryptOpen(QWidget*, …)` pops a `KPasswordDialog`. `Partition` holds `QPointer<PartitionNode>`. The verdict: Qt is load-bearing everywhere (strings, containers, regex-based output parsing, JSON, signals/slots for progress, QThread for runner/scanner, QDBus for privilege, QStorageInfo for mounted usage, KI18n for every user-visible string). Nothing in `src/core` or `src/fs` compiles without Qt.

---

## 3. Class hierarchy

### 3.1 `src/core` — device/partition model

* `Device : QObject` (`$K/src/core/device.h`) — pimpl `std::shared_ptr<DevicePrivate>` (`device_p.h`: name, deviceNode, logicalSectorSize, totalLogical, `PartitionTable*`, iconName, `shared_ptr<SmartStatus>`, `Type`). `enum class Type { Unknown_Device, Disk_Device, LVM_Device, SoftwareRAID_Device, FakeRAID_Device }`. Virtual accessors, `capacity() = logicalSize()*totalLogical()`, owns the `PartitionTable`.
  * `DiskDevice : Device` (`diskdevice.h`) — adds `physicalSectorSize()` (ioctl `BLKPBSZGET` or `/sys/block/X/queue/physical_block_size`, `diskdevice.cpp:48-66`), `logicalSectorSize()`, `totalSectors()`.
  * `VolumeManagerDevice : Device` (`volumemanagerdevice.h`) — abstract: `deviceNodes()`, `partitionNodes()`, `partitionSize()`, `initPartitions()`, `mappedSector()`; static `scanDevices(QList<Device*>&)` which calls `SoftwareRAID::scanSoftwareRAID` then `LvmDevice::scanSystemLVM` (`volumemanagerdevice.cpp`). LVs/arrays are presented as a fake `PartitionTable::TableType::vmd` with partitions "strung one after another".
    * `LvmDevice : VolumeManagerDevice` (`lvmdevice.h`) — ~25 static functions wrapping `lvm vgs/lvs/pvs/lvcreate/lvremove/lvresize/vgcreate/vgremove/vgchange/pvmove...` plus `s_DirtyPVs`/`s_OrphanPVs` statics.
    * `SoftwareRAID : VolumeManagerDevice` (`raid/softwareraid.h`) — `mdadm --assemble --scan`, `--manage --stop`, `--misc --detail`, `/proc/mdstat` parsing (`softwareraid.cpp:177,420`).
* `PartitionNode : QObject` (`partitionnode.h`) — abstract tree node: `children()`, `parent()`, `isRoot()`, `append()`, `insert()`, `remove()`, `predecessor()/successor()`, `findPartitionBySector(s, role)`, `reparent()`, `isChildMounted()`.
  * `PartitionTable : PartitionNode` (`partitiontable.h`) — root node; `TableType` enum, `Flag` enum, `firstUsable/lastUsable`, `maxPrimaries`, `updateUnallocated()`/`insertUnallocated()` (synthesises `Unallocated`-role pseudo partitions), static type tables, `freeSectorsBefore/After`.
  * `Partition : PartitionNode` (`partition.h`) — number, devicePath, partitionPath, first/lastSector, sectorSize, `FileSystem*` (owned), `PartitionRole`, mountPoint, isMounted, `activeFlags/availableFlags`, GPT `label/type/uuid/attributes`, `State { None, New, Copy, Restore }` (where a preview partition came from), `mount()/unmount()` delegating to `FileSystem`, `minimumSectors()/maximumSectors()`.
* `PartitionRole` (plain class, `partitionrole.h`) — bitflags `None, Primary, Extended, Logical, Unallocated, Luks, Lvm_Lv, Any`.
* `PartitionAlignment` (static-only, `partitionalignment.h/.cpp`) — `s_sectorAlignment` default 2048 sectors (1 MiB) scaled by `logicalSize/512`; `alignedFirstSector/LastSector`, `isAligned` (logs warnings via `Log`).
* Copy abstraction (`copysource.h`, `copytarget.h`): pure interfaces `open() / path() / length() / firstByte() / lastByte() / overlaps()`.
  * Sources: `CopySourceDevice` (wraps `Device` + byte range + `unique_ptr<CoreBackendDevice>`), `CopySourceFile` (`QFile`), `CopySourceShred(size, random)` (reads `/dev/zero` or `/dev/urandom`).
  * Targets: `CopyTargetDevice`, `CopyTargetFile`, `CopyTargetByteArray` (receives bytes from the helper's reply map).
* `OperationStack : QObject` (`operationstack.h`) — holds `Devices m_PreviewDevices`, `Operations m_Operations`, `QReadWriteLock`; signals `operationsChanged()`, `devicesChanged()`; `push()` with 7 merge heuristics, `pop()`, `clearOperations()`, `findDeviceForPartition()`.
* `OperationRunner : QThread` (`operationrunner.h`) — `run()` loop, `cancel()`, `suspendMutex()`, signals `progressSub(int)`, `opStarted/opFinished(int, Operation*)`, `finished()`, `cancelled()`, `error()`.
* `DeviceScanner : QThread` (`devicescanner.h`) — `scan()` clears stack, calls `backend->scanDevices(ScanFlag::includeLoopback)`, adds devices to the stack; forwards `CoreBackend::scanProgress`.
* SMART: `SmartStatus` (public value class, `Overall`, `SelfTestStatus`, attributes list), `SmartAttribute`, internal `SmartParser` (runs `smartctl --all --json`, `smartparser.cpp:118`, parses JSON into `SmartDiskInformation` and `SmartAttributeParsedData`).
* `FstabEntry` + free functions `readFstabEntries/generateFstab/writeMountpoints` (`fstab.h`); the write goes through the root helper's `WriteFstab`.

### 3.2 `src/fs` — filesystem hierarchy

`FileSystem` (`$K/src/fs/filesystem.h`, non-QObject, pimpl `unique_ptr<FileSystemPrivate>`, `Q_DISABLE_COPY`):

* `enum Type` (36 values): `Unknown, Extended, Ext2, Ext3, Ext4, LinuxSwap, FreeBSDSwap, Fat16, Fat32, Ntfs, ReiserFS, Reiser4, Xfs, Jfs, Hfs, HfsPlus, Ufs, Unformatted, Btrfs, Hpfs, Luks, Ocfs2, Zfs, Exfat, Nilfs2, Lvm2_PV, F2fs, Udf, Iso9660, Luks2, Fat12, LinuxRaidMember, BitLocker, Apfs, Minix, Bcachefs`.
* `enum CommandSupportType { cmdSupportNone=0, cmdSupportCore=1, cmdSupportFileSystem=2, cmdSupportBackend=4 }` — *None*: unsupported; *Core*: kpmcore does it itself (block copy, backend read of label/UUID); *FileSystem*: an external tool does it; *Backend*: the partition-table backend does it (unused by sfdisk; `SfdiskPartitionTable::resizeFileSystem` returns false).
* Capability query virtuals (all default `cmdSupportNone`): `supportGetUsed, supportGetLabel, supportCreate, supportCreateWithLabel, supportCreateWithFeatures, supportGrow, supportGrowOnline, supportShrink, supportShrinkOnline, supportMove, supportCheck, supportCheckOnline, supportCopy, supportBackup, supportSetLabel, supportSetLabelOnline, supportUpdateUUID, supportGetUUID`.
* Action virtuals: `init()`, `scan(deviceNode)` (fills typed `FileSystemProperty` list), `readUsedCapacity`, `readLabel`, `create`, `createWithLabel`, `resize`, `resizeOnline`, `move`, `writeLabel(Online)`, `copy`, `backup`, `remove`, `check`, `updateUUID`, `readUUID`, `updateBootSector`, `mount`, `unmount`, `canMount/canUnmount`, `minCapacity/maxCapacity`, `maxLabelLength`, `labelValidator`, `supportToolName()` (returns `SupportTool{name,url}` for the GUI's support dialog), `supportToolFound()`, posix permission hooks, feature map (`QVariantMap` features such as ext4 `64bit`, FAT `cluster-size`), `supportedClusterSizes()`.
* Static helpers: `detectFileSystem()` → `CoreBackendManager::self()->backend()->detectFileSystem()`; `detectMountPoint()` via `QStorageInfo::mountedVolumes()` + fstab; `findExternal(cmd, args, expectedExit)` — runs the tool (through the root helper) and treats exit 0 or `expectedExit` as "present".
* `FileSystemFactory` (`filesystemfactory.h/.cpp`): `init()` instantiates one prototype of every class, calls `init()` on each (which runs `findExternal` probes and stores results into **static per-class** `m_Create`, `m_Check`, … members), then `backend->initFSSupport()`. `create(type, first, last, sectorSize, used, label, features, uuid)` and `cloneWithNewType()`.
* `FileSystemProperty` (`filesystemproperty.h`): `{id, QVariant value, DisplayType{Text,Number,Bytes,Percent,List}, Group{UnitSizes,Capabilities,Reserved,Metadata,Journal,Specific}}` — a generic typed-property bag for the GUI.
* `FS::ClusterSize` namespace (`clustersize.h/.cpp`): validation of FAT/NTFS/exFAT cluster sizes and `fromBootSector()` which parses raw boot-sector bytes (BPB offsets 11/13, NTFS `spc > 0x80` shift encoding, exFAT shifts at 108/109).

Concrete classes (all in `namespace FS`, 36): `apfs, bcachefs, bitlocker, btrfs, exfat, ext2, ext3 : ext2, ext4 : ext2, extended, f2fs, fat12, fat16 : fat12, fat32 : fat16, freebsdswap, hfs, hfsplus, hpfs, iso9660, jfs, linuxraidmember, linuxswap, luks, luks2 : luks, lvm2_pv, minix, nilfs2, ntfs, ocfs2, reiser4, reiserfs, udf, ufs, unformatted, unknown, xfs, zfs`. `luks` wraps an inner `FileSystem* m_innerFs` and forwards grow/shrink/check/label to it only when `m_isCryptOpen` (`luks.h`); `helpers.h` provides `innerFS<T>()` to unwrap.

### 3.3 `src/ops` and `src/jobs`

`Operation : QObject` (`$K/src/ops/operation.h`): `OperationStatus {StatusNone, StatusPending, StatusRunning, StatusFinishedSuccess, StatusFinishedWarning, StatusError}`; pure virtuals `iconName()`, `description()`, `preview()`, `undo()`, `targets(Device)`, `targets(Partition)`; `execute(Report&)` runs its `QList<Job*>` sequentially; signals `progress(int)`, `jobStarted/jobFinished(Job*, Operation*)`; helpers `insertPreviewPartition()/removePreviewPartition()`.

17 derived operations and the jobs each instantiates (from `grep "new .*Job" $K/src/ops/*.cpp`):

| Operation | Jobs |
|---|---|
| `NewOperation` | CreatePartitionJob, CreateFileSystemJob, SetFileSystemLabelJob, SetPartFlagsJob, SetPartitionLabelJob, SetPartitionUUIDJob, SetPartitionAttributesJob, CheckFileSystemJob, ChangePermissionJob |
| `DeleteOperation` | DeleteFileSystemJob *or* ShredFileSystemJob(zero/random), DeletePartitionJob |
| `ResizeOperation` | CheckFileSystemJob, SetPartGeometryJob, ResizeFileSystemJob, MoveFileSystemJob (combination chosen by `ResizeAction` bitmask MoveLeft/MoveRight/Grow/Shrink) |
| `CopyOperation` | CreatePartitionJob, CopyFileSystemJob, CheckFileSystemJob, ResizeFileSystemJob |
| `RestoreOperation` | CreatePartitionJob, RestoreFileSystemJob, CheckFileSystemJob, ResizeFileSystemJob |
| `BackupOperation` | BackupFileSystemJob |
| `CheckOperation` | CheckFileSystemJob, ResizeFileSystemJob (maximise) |
| `CreateFileSystemOperation` | DeleteFileSystemJob, CreateFileSystemJob, CheckFileSystemJob, ChangePermissionJob |
| `CreatePartitionTableOperation` | CreatePartitionTableJob |
| `SetFileSystemLabelOperation` | SetFileSystemLabelJob |
| `SetPartFlagsOperation` | SetPartFlagsJob |
| `SetPartLabelOperation` | SetPartitionLabelJob |
| `TakeOwnershipOperation` | TakeOwnershipJob |
| `CreateVolumeGroupOperation` / `RemoveVolumeGroupOperation` / `DeactivateVolumeGroupOperation` / `ResizeVolumeGroupOperation` | CreateVolumeGroupJob / RemoveVolumeGroupJob / DeactivateLogicalVolumeJob+DeactivateVolumeGroupJob / MovePhysicalVolumeJob+ResizeVolumeGroupJob |

`Job : QObject` (`$K/src/jobs/job.h`): `Status {Pending, Success, Error}`; `numSteps()`, `description()`, `run(Report&)`; signals `started/progress/finished`; protected `copyBlocks(report, target, source)` (delegates to `ExternalCommand::copyBlocks`) and `rollbackCopyBlocks()` (reverses a partially-done overlapping move, `job.cpp`). 26 derived jobs (list in `$K/src/jobs/CMakeLists.txt`); only `job.h` is an installed public header.

### 3.4 `src/backend` — backend abstraction

* `CoreBackend : QObject` (`$K/src/backend/corebackend.h`): pure virtuals `initFSSupport()`, `scanDevices(ScanFlags{includeReadOnly, includeLoopback})`, `scanDevice(node)`, `detectFileSystem(node)`, `readLabel(node)`, `readUUID(node)`, `openDevice(Device)`, `openDeviceExclusive(Device)`, `closeDevice()`; signals `progress(int)`, `scanProgress(node,int)`; static `isPolkitInstalledCorrectly()` (checks `/usr/share/polkit-1/actions/org.kde.kpmcore.externalcommand.policy` exists); friend-access setters `setPartitionTableForDevice`, `setPartitionTableMaxPrimaries`.
* `CoreBackendManager` singleton (`corebackendmanager.h/.cpp`): `defaultBackendName()` = `pmsfdiskbackendplugin` (or `pmgeombackendplugin` on FreeBSD), `list()` via `KPluginMetaData::findPlugins("kpmcore")`, `load(name)` via `KPluginFactory::instantiatePlugin<CoreBackend>`; `unload()` is an empty stub.
* `CoreBackendDevice` (`corebackenddevice.h`): `open()/openExclusive()/close()`, `openPartitionTable()`, `createPartitionTable(Report&, const PartitionTable&)`.
* `CoreBackendPartitionTable` (`corebackendpartitiontable.h`): `open()`, `commit(timeout)`, `createPartition()` → returns new node path, `deletePartition()`, `updateGeometry()`, `clobberFileSystem()`, `resizeFileSystem()`, `detectFileSystemBySector()`, `getPartitionUUID()`, `setPartitionLabel/UUID/Attributes()`, `setPartitionSystemType()`, `setFlag()`.
* There is no `CoreBackendPartition` class any more (only forward declarations remain in `corebackenddevice.h`/`corebackendpartitiontable.h`; it was a libparted-era type).

### 3.5 `src/plugins`

* `sfdisk/` — `SfdiskBackend : CoreBackend`, `SfdiskDevice : CoreBackendDevice`, `SfdiskPartitionTable : CoreBackendPartitionTable`, `SfdiskGptAttributes` (static converters). Detailed in §5. Note the plugin re-compiles `corebackenddevice.cpp`, `copysourcedevice.cpp`, `copytargetdevice.cpp`, `copytargetbytearray.cpp` into itself (`$K/src/plugins/sfdisk/CMakeLists.txt`) because those symbols are not exported.
* `dummy/` — returns a single fake `/tmp/dev/sda` 256 MiB msdos device; useful for GUI testing without privileges (`dummybackend.cpp`).
* `geom/` — FreeBSD backend added 2023, walks libgeom's `PART` class and shells out to `gpart`/`swapctl` (`geombackend.cpp`).

### 3.6 `src/util`

`ExternalCommand : QObject` (§6), `ExternalCommandHelper` (the root daemon, §6), `Report`/`ReportLine` (§7), `GlobalLog`/`Log` (`globallog.h`: singleton with `newMessage(Level, QString)` signal and RAII `Log() << ...` lines), `Capacity` (`capacity.h`: `Unit {Byte…YiB}`, `formatByteSize`, `unitFactor`), `HtmlReport` (`htmlreport.h`: header/footer/tableLine for the saved report), `helpers.h` (`registerMetaTypes()`, `isMounted()`, `checkAccessibleDevices()`, `aboutKPMcore()`, `innerFS<T>()`), `DeviceReadBenchmark` (`devicereadbenchmark.h`: async O_DIRECT read-latency benchmark via helper `BenchmarkRead`), `externalcommand_whitelist.h`, `trustedprefixes` → generated `externalcommand_trustedprefixes.h`.

### 3.7 `src/gui`

Three QtWidgets classes compiled into the core library: `PartWidgetBase : QWidget`, `PartWidget` (paints a partition rectangle with per-FS colour from `FileSystem::defaultColorCode`), `PartResizerWidget` (drag-to-resize widget with alignment logic). This is why `Qt6::Widgets` is a PUBLIC dependency.

### 3.8 ASCII class diagrams

```
                                  QObject
      ┌──────────────┬──────────────┼────────────────┬──────────────┬────────────┐
   Device       PartitionNode   Operation          Job         CoreBackend  ExternalCommand
   ├ DiskDevice   ├ PartitionTable  ├ NewOperation     ├ CreatePartitionJob   ├ SfdiskBackend
   └ VolumeMgrDev │  (root; TableType,├ DeleteOperation  ├ DeletePartitionJob   ├ DummyBackend
     ├ LvmDevice  │   Flags, usable  ├ ResizeOperation  ├ SetPartGeometryJob   └ GeomBackend
     └ SoftwareRAID│   range)        ├ CopyOperation    ├ CreateFileSystemJob
                  └ Partition       ├ RestoreOperation ├ DeleteFileSystemJob         OperationStack (QObject)
                    (owns FileSystem*├ BackupOperation  ├ ShredFileSystemJob          OperationRunner (QThread)
                     roles, flags,  ├ CheckOperation   ├ ResizeFileSystemJob         DeviceScanner  (QThread)
                     GPT label/type/├ CreateFileSystemOp├ MoveFileSystemJob          Report (QObject, tree)
                     uuid/attrs)    ├ CreatePartTableOp├ CopyFileSystemJob          GlobalLog (QObject)
                                    ├ SetFileSystemLabelOp├ BackupFileSystemJob
   CopySource (iface)               ├ SetPartFlagsOp   ├ RestoreFileSystemJob     CoreBackendDevice (iface)
   ├ CopySourceDevice               ├ SetPartLabelOp   ├ CheckFileSystemJob        ├ SfdiskDevice
   ├ CopySourceFile                 ├ TakeOwnershipOp  ├ SetFileSystemLabelJob     ├ DummyDevice
   └ CopySourceShred                ├ CreateVolumeGroupOp├ SetPartFlagsJob         └ GeomDevice
   CopyTarget (iface)               ├ RemoveVolumeGroupOp├ SetPartitionLabelJob
   ├ CopyTargetDevice               ├ DeactivateVGOp    ├ SetPartitionUUIDJob     CoreBackendPartitionTable (iface)
   ├ CopyTargetFile                 └ ResizeVolumeGroupOp├ SetPartitionAttributesJob├ SfdiskPartitionTable
   └ CopyTargetByteArray                               ├ ChangePermissionJob      ├ DummyPartitionTable
                                                       ├ TakeOwnershipJob         └ GeomPartitionTable
   PartitionRole (bitflags)   PartitionAlignment (static)  ├ CreateVolumeGroupJob / RemoveVolumeGroupJob
   SmartStatus ─ SmartAttribute ─ SmartParser ─ SmartDiskInformation├ DeactivateVolumeGroupJob / DeactivateLogicalVolumeJob
   FstabEntry                                               └ ResizeVolumeGroupJob / MovePhysicalVolumeJob

   FileSystem (plain C++ class, pimpl; static support flags per subclass)
   ├ ext2 ─┬ ext3                     ├ btrfs   ├ xfs    ├ jfs    ├ reiserfs ├ reiser4 ├ nilfs2 ├ f2fs
   │       └ ext4                     ├ ntfs    ├ exfat  ├ udf    ├ ocfs2    ├ minix   ├ bcachefs
   ├ fat12 ─ fat16 ─ fat32            ├ hfs     ├ hfsplus├ hpfs   ├ ufs      ├ apfs    ├ bitlocker
   ├ luks ─ luks2  (wraps innerFS*)   ├ lvm2_pv ├ linuxraidmember ├ linuxswap ├ freebsdswap ├ zfs
   ├ iso9660 ├ extended ├ unformatted └ unknown
   FileSystemFactory (prototype registry)   FileSystemProperty   FS::ClusterSize
```

---

## 4. How each filesystem class actually works: external tools vs in-process

**Headline: with a handful of byte-level exceptions, every filesystem operation shells out.** `grep -c ExternalCommand` on the passive classes (`extended, unformatted, unknown, iso9660, linuxraidmember, bitlocker, apfs, hpfs, ufs`) is 0 — they contain only static support flags. Every active class is a thin wrapper that builds an argv, runs it through `ExternalCommand` (→ root helper → `QProcess`), and regex-parses the text output.

Detection, label and UUID *reading* are not done by the fs classes at all but by the backend: `SfdiskBackend::detectFileSystem` runs `udevadm info --query=property <node>` and matches `ID_FS_TYPE=`/`ID_FS_VERSION=`, falling back to `blkid <node>` (`TYPE="…"`, `SEC_TYPE="…"`) (`$K/src/plugins/sfdisk/sfdiskbackend.cpp:530-560`); `readLabel` uses `ID_FS_LABEL_ENC` (with a hand-written `\xNN` decoder), `readUUID` uses `ID_FS_UUID`. The fs class exposes this as `supportGetLabel()/supportGetUUID() == cmdSupportCore`.

Support-level detection: each `FS::xxx::init()` calls `FileSystem::findExternal("tool", {}, expectedExit)` per capability (e.g. `$K/src/fs/ext2.cpp:40-46`, `ntfs.cpp:51-56`). `findExternal` resolves the binary via `findTrustedCommand()`, *executes it with no arguments through the privileged helper*, and accepts exit 0 or the given code (1 for `mkfs.fat`, 16 for `fsck.*`, 3 for `lvm`, 2 for `zpool`). Results land in `static CommandSupportType m_Create/m_Check/...` members, so support is global per type and probed once at `FileSystemFactory::init()` — roughly 60 privileged process spawns at startup.

| FS (file) | create | check | grow / shrink | label write | UUID update | getUsed | copy / backup / move |
|---|---|---|---|---|---|---|---|
| ext2/3/4 (`ext2.cpp`,`ext3.cpp`,`ext4.cpp`) | `mkfs.ext2/3/4 [-O feat,^feat] -qF` | `e2fsck -f -y -v` (exit 0/1/2/256 ok) | `resize2fs dev Ns` both; ext4 online grow `resize2fs` on mounted | `e2label` | `tune2fs -U random` | `dumpe2fs -h` regex "Block count/Free blocks/Block size" | core block copy |
| btrfs (`btrfs.cpp`) | `mkfs.btrfs` | `btrfs check` | mount to temp dir + `btrfs filesystem resize N <mnt>` (both, online too) | `btrfs filesystem label` | `btrfstune` | `btrfs filesystem show --raw` | core |
| xfs (`xfs.cpp`) | `mkfs.xfs` | `xfs_repair` | grow only: mount + `xfs_growfs` | `xfs_db -x -c "sb 0" -c "label X"` | none | `xfs_db -c "sb 0" -c print` (dblocks/fdblocks/blocksize) | `xfs_copy` for copy; backup core |
| jfs (`jfs.cpp`) | `mkfs.jfs` | `fsck.jfs` | grow only: `mount -o remount,resize` | `jfs_tune -L` | none | `jfs_debugfs` | core |
| reiserfs (`reiserfs.cpp`) | `mkfs.reiserfs` | `fsck.reiserfs` | `resize_reiserfs` both | `reiserfstune -l` | `reiserfstune -u` | `debugreiserfs` | core |
| reiser4 (`reiser4.cpp`) | `mkfs.reiser4` | `fsck.reiser4` | none | none | none | `debugfs.reiser4` | core |
| nilfs2 (`nilfs2.cpp`) | `mkfs.nilfs2` | disabled (commented) | grow: mount + `nilfs-resize` | `nilfs-tune -L` | `nilfs-tune -U` | `nilfs-tune -l` | core |
| f2fs (`f2fs.cpp`) | `mkfs.f2fs` | `fsck.f2fs` | grow: `resize.f2fs` | `f2fslabel` | none | none | core |
| fat12/16/32 (`fat12.cpp`,`fat16.cpp`,`fat32.cpp`) | `mkfs.fat -F12/16/32 [-S sector -s spc]` | `fsck.fat` | fat16/32: `fatresize` both | `fatlabel` | **in-process**: writes 4 bytes at offset 39 (FAT12/16) or 67 (FAT32) via helper `WriteData` | `fsck.fat -n -v` regex | core |
| exfat (`exfat.cpp`) | `mkfs.exfat` / `mkexfatfs` (two toolchains) | `fsck.exfat` | none | `tune.exfat -L` / `exfatlabel` | `tune.exfat` | `dump.exfat`/`dumpexfat` (properties) | core |
| ntfs (`ntfs.cpp`) | `mkfs.ntfs [-c cluster]` | `ntfsresize --info`-style (check via ntfsresize) | `ntfsresize --no-action` dry-run then `ntfsresize --size N` both | `ntfslabel` | `ntfslabel --new-serial` | `ntfsinfo --mft --force` | `ntfsclone --force --overwrite` for copy; **in-process** `updateBootSector()` writes new first-sector LE32 at offset 28 and in the backup boot sector at partition end |
| hfs / hfsplus (`hfs.cpp`,`hfsplus.cpp`) | `hformat` / `mkfs.hfsplus` | `hfsck` / `fsck.hfsplus` | none | none | none | none | core |
| ocfs2 (`ocfs2.cpp`) | `mkfs.ocfs2` | `fsck.ocfs2` | `tunefs.ocfs2` grow | `tunefs.ocfs2 -L` | `tunefs.ocfs2 -U` | `debugfs.ocfs2` | core |
| udf (`udf.cpp`) | `mkudffs [--label]` | none | none | `udflabel` | `udflabel --uuid` | `udfinfo --utf8` | core |
| minix (`minix.cpp`) | `mkfs.minix` | `fsck.minix` | none | none | none | none | core |
| bcachefs (`bcachefs.cpp`) | `bcachefs format` | `bcachefs fsck` | mount + `bcachefs device resize` | via create | none | none | core |
| linuxswap (`linuxswap.cpp`) | `mkswap` | none | re-`mkswap` with same label/UUID | `mkswap -L` | `mkswap -U` | **in-process** parse of `/proc/swaps` | copy = `mkswap` again |
| freebsdswap (`freebsdswap.cpp`) | `swapctl` | none | none | none | none | none | core |
| luks / luks2 (`luks.cpp`,`luks2.cpp`) | `cryptsetup -s 512 luksFormat [--type luks2]` then `cryptsetup open`, then create inner FS | delegates to `m_innerFs->check(mapper)` | `cryptsetup resize` + inner resize | delegates to inner | `cryptsetup luksUUID --uuid <QUuid>` | inner; `cryptsetup luksDump`, `lsblk`, `dmsetup table` for metadata | core when closed; `cryptsetup open/close` for map/unmap; `KPasswordDialog` in `cryptOpen()` |
| lvm2_pv (`lvm2_pv.cpp`) | `lvm pvcreate` | `lvm pvck` | `lvm pvresize [--setphysicalvolumesize]`, shrink after `lvm pvmove` | none | `lvm pvchange -u` | `lvm pvs -o pv_used,pe_start` | move = core block copy + pvmove |
| zfs (`zfs.cpp`) | none | none | none | `zpool export` + `zpool import old new` (rename) | none | none | core backup only |
| apfs, bitlocker, ufs, unknown | none | none | none | none | none | none | core move/copy/backup (raw block copy) |
| extended, unformatted | `cmdSupportFileSystem` flag but no tool (partition-table level) | — | extended: core | — | — | — | — |
| hpfs, iso9660, linuxraidmember | nothing | | | | | | |

In-process device-byte access that exists (the complete list, from `grep -rn "readData\|ioctl\|/proc/\|/sys/" $K/src`):

1. `$K/src/fs/clustersize.cpp:246` — reads 512 bytes at offset 0 via helper `ReadData` and parses FAT/NTFS/exFAT BPB fields (`fromBootSector`).
2. `$K/src/plugins/sfdisk/sfdiskbackend.cpp:487-500` — reads LBA 1 (the primary GPT header) and extracts bytes 80..83 (`NumberOfPartitionEntries`) to set `maxPrimaries`; defaults to 128 on failure.
3. `ntfs::updateBootSector` and `fat12/fat32::updateUUID` — raw 4-byte writes via helper `WriteData`.
4. `linuxswap::readUsedCapacity` (`/proc/swaps`), `SoftwareRAID` (`/proc/mdstat`), `SfdiskBackend::scanDevices` (`/sys/block/X/ro`), `DiskDevice::physicalSectorSize` (`ioctl BLKPBSZGET` / sysfs).
5. The helper's `CopyFileData` / `ReadData` / `WriteData` / `BenchmarkRead` (`$K/src/util/externalcommandhelper.cpp`) are the only code that opens block devices for I/O (chunked `QFile` seek/read/write, `pread` with `O_DIRECT` for the benchmark).

There is **no** superblock parser, no FAT/ext/NTFS metadata reader, no fsck/resize/mkfs logic in-process. `readUsedCapacity` for mounted filesystems uses `QStorageInfo` (statvfs) in `SfdiskBackend::readSectorsUsed`.

---

## 5. Partition-table handling

### Type enumeration (`$K/src/core/partitiontable.h`, `.cpp`)

```cpp
enum TableType : int8_t { unknownTableType=-1, aix, bsd, dasd, msdos, msdos_sectorbased[[deprecated]],
                          dvh, gpt, loop, mac, pc98, amiga, sun, vmd /*Volume Manager Device*/, none /*whole-device FS*/ };
```

Static table `tableTypes[]` in `partitiontable.cpp` (`{name, maxPrimaries, canHaveExtended, isReadOnly, type}`): `aix 4/ro`, `bsd 8/ro`, `dasd 1/ro`, `msdos`/`dos` 4 + extended, `dvh 16/ro`, `gpt 128`, `loop 1/ro`, `mac 0xffff/ro`, `pc98 16/ro`, `amiga 128/ro`, `sun 8/ro`, `vmd 0xffff`, `none 1`. Only **msdos and gpt are writable** (plus the synthetic `vmd`/`none`). `defaultFirstUsable()` = `PartitionAlignment::sectorAlignment(d)` (2048 sectors), `defaultLastUsable()` for GPT = `totalLogical - 1 - 32 - 1` (hard-coded 33 sectors for backup header+entries, regardless of sector size — a latent bug for 4Kn disks).

### Reading (sfdisk backend, `$K/src/plugins/sfdisk/sfdiskbackend.cpp`)

1. `lsblk --nodeps --paths --sort name --json --output type,name` → filter `type == "disk"` (or `"loop"` with `includeLoopback`), skip `/sys/block/X/ro == 1` unless `includeReadOnly`.
2. Per device: `lsblk --output model`, `blockdev --getsize64`, `blockdev --getss`, `sfdisk --json <dev>` (stderr separated). `/proc/mdstat` match → `SoftwareRAID`, else `DiskDevice`. `lsblk --output tran` to pick a USB icon.
3. `fixInvalidJsonFromSFDisk()` strips leading non-JSON text (e.g. `omitting empty partition (5)`) and the trailing-comma bug of util-linux < 2.37.
4. `updateDevicePartitionTable()`: `label` → `nameToTableType` (accepts `"dos"`); for GPT `firstlba`/`lastlba` set the usable range, then raw-reads LBA1 for the entry count; for other types lastUsable = total sectors.
5. `scanDevicePartitions()`: per JSON partition `{node, start, size, type, bootable, name, uuid, attrs}`; MBR type `5`/`f` → `Extended` role and `FileSystem::Type::Extended`; logical detection by `findPartitionBySector(start, Extended)`; `detectFileSystem(node)`; LUKS gets `PartitionRole::Luks` and `initLUKS()`; then `fs->scan(node)`, mount point/status, label/UUID; GPT `name/uuid/type/attrs` stored on `Partition` (`setupPartitionInfo`). Finally `updateUnallocated()` and alignment check.
6. If `sfdisk --json` fails or label is `dos` but the whole device has a FAT signature → `scanWholeDevicePartition()` creates `TableType::none` with one partition spanning the device.

### Writing (`sfdiskpartitiontable.cpp`, `sfdiskdevice.cpp`)

* Create table: `sfdisk --wipe=always <dev>` with stdin `label: gpt|dos\nwrite\n`; success = output contains `Script header accepted.`.
* Create partition: `sfdisk --force --append <dev>` with stdin `start=N[ type=5] size=M\nwrite\n`; new node parsed from `Created a new partition (\d+)`; NVMe-style `p` suffix handled.
* Delete: `sfdisk --force --delete <dev> <n>`. Geometry: `sfdisk --force <dev> -N <n>` with `start= size=\nY\n`. Clobber: `wipefs --all`. GPT label/UUID/attrs/type: `sfdisk --part-label/--part-uuid/--part-attrs/--part-type`. Commit: `udevadm settle`, `partx --update`, `udevadm trigger --subsystem-match=block`, `udevadm settle` (and stop/start udev exec queue around it for md devices). `SfdiskDevice::close()` always runs a commit.

### Flags model

`PartitionTable::Flag` (uint32 bitmask): `Boot, Root, Swap, Hidden, Raid, Lvm, Lba, HpService, Palo, Prep, MsftReserved, BiosGrub, AppleTvRecovery, Diag, LegacyBoot, MsftData, Irst` — a libparted-era vocabulary. The sfdisk backend only *offers* `Boot` for msdos and `Boot|BiosGrub` for GPT (`SfdiskBackend::availableFlags`, with the comment "These are not really flags ... We should implement changing partition type"). Semantics: msdos `Boot` → `sfdisk --activate`; GPT `Boot` → set type GUID `C12A7328-…` (ESP); `BiosGrub` → `21686148-…`; clearing restores the fs-derived type from the `typemap[]` (fs type → GPT GUID / MBR id, `sfdiskpartitiontable.cpp`). Real GPT attribute bits are modelled separately: `Partition::attributes()` (quint64) ↔ sfdisk strings `RequiredPartition`(bit0), `NoBlockIOProtocol`(bit1), `LegacyBIOSBootable`(bit2), `GUID:48..63` (`sfdiskgptattributes.cpp`). GPT partition type GUID and name are free-form `QString`s on `Partition`.

### GPT backup header: does KDE Partition Manager restore the primary header from the backup?

**No.** Evidence:

* `grep -rniE "backup ?header|primary ?header|secondary ?header|gdisk|sgdisk|relocate|pmbr|protective" $K/src $P/src $K/test` → **zero matches**.
* All `backup` hits in both trees are the file-system image feature: `BackupOperation`/`BackupFileSystemJob` (`$K/src/jobs/backupfilesystemjob.cpp`, sector-for-sector copy of a partition's filesystem to a file via `CopyTargetFile`) and `RestoreOperation`/`RestoreFileSystemJob` (file → partition). `$P/doc/referencemanual.docbook:364-399` documents exactly this ("sector-for-sector copy of the file system on the partition").
* The only GPT-header code is the read of `NumberOfPartitionEntries` from LBA 1 in `sfdiskbackend.cpp:487-500`; nothing reads or writes the backup header at the end of the disk, nothing compares CRCs, nothing exposes a "repair" action.
* `$P/src/gui/mainwindow.cpp` has `onExportPartitionTable()`/`onImportPartitionTable()` (lines 1054-1230): these write/parse kpmcore's **own text format** (`##|v1|##` magic, `type: "gpt"`, lines `num;first;last;fsname;role;"label";"flags"`) and replay it as `CreatePartitionTableOperation` + `NewOperation`s. It is a logical re-creation, not a header-level restore, and it loses GPT type GUIDs/attrs.

What *does* happen indirectly: sfdisk is built on libfdisk, which, when the primary GPT header is corrupt but the backup is valid, prints a warning and uses the backup; on the next write (e.g. any `sfdisk --append`) libfdisk rewrites both headers. kpmcore neither detects nor surfaces this — `fixInvalidJsonFromSFDisk()` would silently discard such a warning line. So if the user has seen "KPM fixed my GPT", it was libfdisk's implicit behaviour, not a kpmcore feature. Explicit backup-header recovery is a `gdisk`/`sgdisk` (`-e`, `r`→`c`/`b`), `testdisk` or `parted`/libparted ("Fix/Ignore" prompt) capability. For our library, GPT primary/backup validation, CRC32 checking and header rebuild is a feature we must implement ourselves (it is a well-specified, small task once we have our own GPT reader/writer).

---

## 6. Privilege escalation model

Files: `$K/src/util/externalcommand.{h,cpp}` (client), `$K/src/util/externalcommandhelper.{h,cpp}` (root daemon, built as `kpmcore_externalcommand` in `$K/src/util/CMakeLists.txt`, installed to `libexec`), `$K/src/util/org.kde.kpmcore.helperinterface.conf` (D-Bus system policy: only root may own `org.kde.kpmcore.helperinterface`; anyone may send to interface `org.kde.kpmcore.externalcommand`), `$K/src/util/org.kde.kpmcore.helperinterface.service.in` (D-Bus activation, `User=root`), `$K/src/util/org.kde.kpmcore.externalcommand.policy` (polkit action `org.kde.kpmcore.externalcommand.init`, `allow_active=auth_admin_keep`, `allow_inactive=no`), `$K/src/util/externalcommand_whitelist.h`, `$K/src/util/trustedprefixes` (`/`, `/usr`, `/usr/local`; baked into `externalcommand_trustedprefixes.h` at configure time).

Flow:

1. The unprivileged library never spawns tools itself. `ExternalCommand::start()` resolves the full path with `findTrustedCommand()`, obtains a `QDBusInterface` to `org.kde.kpmcore.helperinterface` `/Helper` on the **system bus** (timeout set to 10 days), and calls `RunCommand(cmd, args, stdinBytes, channelMode)` — blocking the caller in a nested `QEventLoop`. The helper is auto-started by D-Bus activation on first call.
2. `ExternalCommandHelper::isCallerAuthorized()` checks `calledFromDBus()`, then either trusts a bus name it has already authorised (`QDBusServiceWatcher` list) or runs `PolkitQt1::Authority::checkAuthorization("org.kde.kpmcore.externalcommand.init", SystemBusNameSubject, AllowUserInteraction)`. On success the caller's bus name is watched; when all watched clients vanish the helper quits (comment explains `auth_admin_keep` is deliberately *not* relied upon so that a cancelled auth cannot interrupt a half-moved partition).
3. `RunCommand`: rejects empty commands; **basename** must be in `allowedCommands` (`externalcommand_whitelist.h`, ~90 names); the directory (after stripping `bin`/`sbin`) must be in `trustedPrefixes`; environment is reset to `LVM_SUPPRESS_FD_WARNINGS=1`; `QProcess` runs it, writes stdin, waits forever; reply map `{success, exitCode, output}` (stdout only, or merged).
4. Other privileged entry points, each guarded by `isCallerAuthorized()`: `CopyFileData(src, srcOff, len, dst, dstOff, chunk)` (chunked device copy with direction handling for overlapping moves, ≤100 MiB chunks, target must already exist, emits `progress(int)` and `report(QString)` D-Bus signals), `ReadData(dev, off, len)` (≤1 MiB, must be a block device under `/dev/` and not `/dev/shm/`, `O_NOFOLLOW`), `WriteData(buf, dev, off)` (block device under `/dev/`, canonicalised), `WriteFstab(bytes)` (≤1 MiB, truncates `/etc/fstab`), `BenchmarkRead(dev, offsets[], len)` (O_DIRECT `pread` timings).
5. Every call — even `lsblk`, `udevadm info`, `blkid`, `smartctl` and the ~60 startup `findExternal` probes — crosses D-Bus to root (whitelist comments acknowledge "TODO no root needed"). The GUI side additionally unloads Plasma's `device_automounter` kded module over the session bus during `OperationRunner::run()` (`$K/src/core/operationrunner.cpp`).

Design considerations for our own model:

* Separation into an unprivileged model/planning library and a minimal privileged executor is the right shape; kpmcore's executor is a *generic command runner* which makes the trust boundary only as strong as the whitelist + prefix check (argument injection into whitelisted tools is possible, e.g. `mount` with arbitrary options).
* A tighter alternative is a typed RPC with explicit verbs (`read(dev, off, len)`, `write(dev, off, buf)`, `mkfs(type, dev, opts)`) validated by the helper, which is what `ReadData/WriteData/CopyFileData` already do.
* The helper is Linux/polkit/D-Bus specific. Portable equivalents: Linux polkit + D-Bus or a setuid/`pkexec` helper; macOS `SMJobBless`/`AuthorizationExecuteWithPrivileges` successor (XPC helper + `SMAppService`), or just require `sudo`; Windows UAC elevation via a separate elevated process and a named pipe. A single-binary design where the same executable can run as the elevated worker over a pipe/socket with a length-prefixed protocol maps onto all three.
* Keep the "cache authorisation per connected client and exit when clients disappear; never abort mid-write" semantics.
* Keep read-only probing unprivileged where the platform allows it (e.g. `/sys`, `lsblk -J` on Linux, `IOKit` on macOS, `\\.\PhysicalDriveN` metadata on Windows) so a viewer mode needs no elevation.

---

## 7. The Operation / Job / Report pattern

* **Preview model**: `OperationStack::previewDevices()` is the *only* model the GUI sees. `push(op)` first tries merges (`mergeNewOperation` rules 1-6: delete-after-new cancels the new op; resize-after-new rewrites the new op; copy-of-new becomes a new; label/filesystem/check on a new partition fold into it; similar `mergeCopyOperation`, `mergeRestoreOperation`, `mergePartFlagsOperation`, `mergePartLabelOperation`, `mergeCreatePartitionTableOperation`, `mergeResizeVolumeGroupResizeOperation`), then appends, calls `op->preview()` (mutates the preview `Device`/`PartitionTable` tree, e.g. `DeleteOperation::preview()` removes the partition and renumbers logicals) and sets `StatusPending`. `pop()` calls `op->undo()` (inverse mutation) and deletes it. Undo is therefore last-in-first-out only, with the invariant that each op knows how to revert its own preview edit. `Partition::State {New, Copy, Restore}` tags preview-only partitions.
* **Execution**: `OperationRunner` (a `QThread`) iterates ops in order; for each: `setStatus(Running)`, emit `opStarted`, `op->execute(report)`, then `op->preview()` again (re-applies the preview so the model reflects what actually got created — e.g. real partition numbers/nodes), emit `opFinished`. Stops at first failure (`error()`), honours `cancel()` between ops and a `suspendMutex` for pause.
* **Operation::execute** creates `Report* report = parent.newChild(description())`, runs `jobs()` sequentially, breaks on first `false`, sets `StatusFinishedSuccess/StatusError`, writes a status line. `totalProgress()` = Σ `job->numSteps()`; jobs emit `progress(int)` and ops re-emit.
* **Job::run(Report&)** pattern: `Report* report = jobStarted(parent)` (child "Job: …"), do work writing `report->line() << xi18nc(...)`, `jobFinished(*report, ok)`. Jobs are deliberately small and composable; the `ResizeOperation` picks a job sequence from a `ResizeAction` bitmask. `MoveFileSystemJob` demonstrates rollback (`rollbackCopyBlocks`) on failed overlapping copies.
* **Report** (`$K/src/util/report.h`) is a tree: `{command, output, status, children}`; `ExternalCommand(report, cmd, args)` creates a child whose `command` is "Command: cmd args" and whose `output` receives tool stdout; `toHtml()`/`toText()` serialise the whole run; `outputChanged()` lets the GUI live-update (`$P/src/gui/applyprogressdialog.cpp` throttles via `updateReportUnforced`). `ReportLine` is an RAII line builder that appends `\n` on destruction.
* **GlobalLog** is a separate flat log (`Log(Level) << ...`) for informational messages during scanning/planning, shown in the GUI's `TreeLog`.

Worth reusing as a *pattern*: (a) a pending-operation stack with preview-on-a-cloned-model + inverse undo, (b) operation merging to keep the plan minimal, (c) ops as orderly lists of small jobs with first-failure stop and explicit rollback hooks, (d) a hierarchical report that doubles as the audit log of exactly which commands/bytes were run. Improvements for our design: make preview/undo operate on an immutable snapshot (copy-on-write model) rather than in-place mutation with hand-written inverses; give jobs a dry-run/plan description; make progress a structured object (bytes done/total, current job) instead of an `int` percent.

---

## 8. partitionmanager (the GUI application)

Layout (`$P/src/CMakeLists.txt`): `main.cpp` (144 lines) + `config/` (4 KConfig pages + `partitionmanager.kcfg`) + `gui/` (40 widget/dialog classes, ~45 `.ui` files) + `util/guihelpers.{h,cpp}`; total ≈16.5 k lines (`wc -l` across `src`). Links `kpmcore` plus KF6 `Config*`, `CoreAddons`, `Crash`, `DBusAddons` (single-instance), `I18n`, `JobWidgets`, `KIO` (remote import/export), `WidgetsAddons`, `XmlGui`, `WindowSystem`, `PolkitQt6-1::Core`. Docs in `$P/doc/*.docbook` (GFDL), icons in `$P/icons`.

What it adds on top of kpmcore:

* `MainWindow : KXmlGuiWindow` (`$P/src/gui/mainwindow.{h,cpp}`, 1 510 lines): owns `OperationStack`, `OperationRunner`, `DeviceScanner`, `ApplyProgressDialog`, `ScanProgressDialog`, dock widgets (devices, operations, log, info), actions. Slots `onApplyAllOperations()` (shows `ApplyProgressDialog`, `operationRunner().start()`), `onUndoOperation()` (`operationStack().pop()`), `onClearAllOperations()`, `onCreateNewPartitionTable()`, `onExportPartitionTable()/onImportPartitionTable()`, `onRefreshDevices()`, VG create/remove/resize/deactivate, `onSmartStatusDevice()`, `onBenchmarkDevice()`, `onFileSystemSupport()`, `checkFileSystemSupport()` (warns when tools are missing).
* `PartitionManagerWidget` (`partitionmanagerwidget.{h,cpp}`): partition tree + `PartTableWidget` (kpmcore's `PartWidget`s); per-partition actions `onNewPartition, onResizePartition, onDeletePartition(shred), onCopyPartition/onPastePartition (clipboard = a Partition*), onEditMountPoint, onMountPartition, onDecryptPartition, onCheckPartition, onBackupPartition, onRestorePartition, onTakeOwnershipPartition, onPropertiesPartition`. Operations constructed by the GUI (`grep "new .*Operation("`): New, Delete, Resize, Copy, Restore, Backup, Check, CreateFileSystem, CreatePartitionTable, SetPartFlags, SetPartLabel, SetFileSystemLabel, and the four VG ops.
* Dialogs: `NewDialog`/`ResizeDialog`/`InsertDialog` over `SizeDialogBase` (uses `PartResizerWidget`, alignment, LUKS passphrase, feature/cluster-size combos), `PartPropsDialog` (label, flags, GPT label/UUID/attrs, `FileSystemPropertiesWidget` renders `FileSystemProperty` groups), `CreatePartitionTableDialog`, `EditMountPointDialog`/`EditMountOptionsDialog` (edits fstab via kpmcore `writeMountpoints`), `DevicePropsDialog`, `SmartDialog`, `BenchmarkDialog` (uses `DeviceReadBenchmark`), `FileSystemSupportDialog` (matrix of `supportXxx()` per type), `ApplyProgressDialog` (+details widget, save/browse HTML report), `ScanProgressDialog`, `TreeLog` (GlobalLog view), `ListDevices`, `ListOperations`, `ListPhysicalVolumes`, `VolumeGroupDialog`/`CreateVolumeGroupDialog`/`ResizeVolumeGroupDialog`, `InfoPane`.
* Config (`$P/src/partitionmanager.kcfg`): column layouts, `firstRun`, `minLogLevel`, `sectorAlignment` (fed to `PartitionAlignment::setSectorAlignment`), `alignDefault`, `fileSystemColorCode$(FileSystem)`, `showMenuBar`, `backend` (plugin name), `defaultFileSystem`, `preferredUnit`, `shredSource`, `hideDeviceDockWidgetByCmdArgs`.
* `main.cpp`: `--device /dev/sdXN` option with a small `parseDevice()` that splits NVMe `p` suffixes; `loadBackend()` (`guihelpers.cpp`) loads `Config::backend()` falling back to the default plugin.

Non-GUI logic living in the app (i.e. things a library consumer would have to re-implement): the partition-table text export/import format and parser in `MainWindow` (its own `// TODO: This method looks like should live somewhere completely different` comment); `parseDevice()`; `GuiHelpers::populateClusterSizeCombo`/`fileSystemSupportsClusterSize` (thin over `FS::ClusterSize`); the "disallow other devices" policy. Nothing in `$P/src` calls `ExternalCommand` or `QProcess` for disk work (`grep ExternalCommand $P/src` → none; the one `QProcess` include in `guihelpers.cpp` is unused for disk ops). Everything destructive goes through kpmcore operations.

---

## 9. Known gaps relative to our goals

1. **Everything shells out.** No in-process partition-table parser (GPT/MBR are read via `sfdisk --json`, written via sfdisk scripts), no filesystem metadata parsing beyond three boot-sector fields, no mkfs/fsck/resize logic. Behaviour depends on ~90 external binaries, their output formats (regex-parsed, locale-sensitive, version-sensitive — see the sfdisk JSON work-arounds and the two exFAT toolchains) and their presence in `/`, `/usr`, `/usr/local`.
2. **Qt-bound, and KDE-Frameworks-bound.** `QString`/`QList`/`QVariant`/`QRegularExpression`/`QJson`/`QDBus`/`QThread`/`QStorageInfo`/`QProcess`/`QWidget`, KI18n in every message, KPluginFactory for backends, KPasswordDialog inside the LUKS class, QtWidgets as a public link dependency. Nothing is header-only or Qt-free.
3. **Linux-only in practice.** sfdisk backend + udev + polkit/D-Bus helper + `/proc`/`/sys`. A FreeBSD geom backend exists (`$K/src/plugins/geom`) but still routes through the same D-Bus helper and Linux-centric fs tools. No macOS, no Windows.
4. **No disk imaging.** The only image support is a raw sector dump of a single partition's filesystem to a flat file (`BackupFileSystemJob`) and restore with blind filesystem detection afterwards; no sparse/compressed formats, no whole-disk images, no qcow2/VHD/VMDK, no loop-device/partition-in-file addressing, no checksumming.
5. **No in-image partition/filesystem access.** `Device` is always a kernel block device node; there is no "disk backed by a file" abstraction (loop devices are merely scannable as `type == loop`). `CopySource/Target` byte ranges are the closest thing to an offset-addressed I/O layer.
6. **No mounting of filesystems inside images / no file-level access.** Mount means `mount(8)` on a kernel device.
7. **LUKS/LVM/RAID only via tools** (`cryptsetup`, `lvm`, `mdadm`), with LVM/RAID modelled as fake partition tables (`TableType::vmd`), and LUKS modelled as a filesystem wrapping another filesystem.
8. **Partition flags are a legacy libparted vocabulary** half-mapped onto GPT type GUIDs; only `Boot`/`BiosGrub` are settable; arbitrary GPT type GUID editing is a TODO.
9. **No GPT integrity features**: no CRC validation, no backup-header repair, no protective-MBR handling, hard-coded 33-sector GPT reservation.
10. Only msdos and gpt are writable; `bsd/sun/mac/amiga/...` are read-only labels passed through from sfdisk.
11. Privilege model requires polkit + system D-Bus; every read goes through root; whitelist is by basename.
12. Testing: no unit tests of parsing logic (they all need a live backend/root); the dummy backend is a single hard-coded device.
13. Support probing executes ~60 tools at startup; support flags are static per class (no per-device/per-version nuance beyond a couple of version checks like `udf::oldMkudffsVersion`).
14. Threading model is Qt-specific (`QThread` runner with nested event loops inside D-Bus calls); operations are not cancellable mid-job.

---

## 10. Assessment: what to reuse as design ideas, what to avoid

### Reuse (as ideas; the code is GPL-3.0-or-later and Qt)

* **The three-level domain model** `Device → PartitionTable (tree root) → Partition (node, owns FileSystem)`, with `PartitionRole` bitflags (`Primary/Extended/Logical/Unallocated/Luks/Lvm_Lv`) and synthetic `Unallocated` nodes so free space is a first-class object the UI/API can address. `PartitionNode` as a shared base for table and partition with `findPartitionBySector`, `predecessor/successor`, `freeSectorsBefore/After` is clean and worth keeping.
* **`TableType` + static capability table** (`maxPrimaries`, `canHaveExtended`, `isReadOnly`) and `PartitionAlignment` as a stateless policy object (alignment in sectors scaled by logical sector size, `alignedFirstSector/LastSector` with min/max constraints).
* **FileSystem base with explicit capability queries** (`supportCreate/Grow/Shrink/Move/Check/Copy/Backup/SetLabel/UpdateUUID/GetUsed`, each returning *how* it is supported) plus `minCapacity/maxCapacity/maxLabelLength`, typed `FileSystemProperty` bags, and a `features` map for mkfs options. Keep the three-way "none / core (in-process) / external tool" distinction — our library will have *both* native implementations and optional tool-backed fallbacks, so a per-capability provenance enum is exactly right. Also keep `SupportTool{name,url}` so the UI can say which package is missing.
* **The LUKS-as-container pattern** (`luks` holding an `innerFS` and forwarding capabilities only when unlocked) generalises to any container: LUKS, LVM PV, RAID member, and — for us — disk images and partitions-inside-images.
* **`CopySource`/`CopyTarget` byte-range interfaces** with device/file/zero/random sources and device/file/memory targets, directional chunked copying for overlapping moves and rollback — the kernel of a block-copy/imaging engine.
* **Operation/Job/Report** (§7): pending stack with preview + undo, merge rules, job composition, hierarchical report/audit log, progress signals.
* **Backend plugin seam**: `CoreBackend / CoreBackendDevice / CoreBackendPartitionTable` separating "scan and model" from "commit changes to a device", with a dummy backend for UI tests. We should have the same seam but with backends per *platform I/O* (Linux block device, macOS, Windows, file-backed image) rather than per external tool.
* **Privileged-helper split with per-client authorisation caching** and the explicit, narrow byte-level verbs (`ReadData/WriteData/CopyFileData`).
* **Partition-table text export/import** as a logical, human-readable description that replays as operations — a good feature to move into the library (and to extend with GPT GUIDs/attrs).
* **SMART via `smartctl --json`** is a reasonable optional provider, as is `udevadm`/`blkid` as *one* detector among several.

### Avoid

* Qt types in the public API (`QString`, `QList`, signals). Use `std::string`/`std::u8string`, `std::vector`, `std::span`, `std::expected`/error codes, callbacks or `std::function` for progress; make the core header-light and exception-safe.
* `QObject` inheritance in the model (`Device`, `PartitionNode`): it forbids copying, pulls in moc, and kpmcore then has to hand-write `Partition` copy constructors anyway. Use plain value types / `std::shared_ptr` graphs; make preview snapshots cheap to clone.
* **Static per-class support flags** probed by executing tools at startup. Probe lazily, per tool, cache by path+mtime, and never require root for probing.
* **Regex-scraping tool output** as the primary information source. Implement native GPT/MBR (+ APM/BSD read) parsing and native superblock readers (ext*, FAT/exFAT, NTFS, XFS, btrfs, LUKS header, LVM PV label, mdraid superblock, ISO9660, APFS/HFS+ containers) for detection, label/UUID, geometry and used-space where feasible; shell out only for mkfs/fsck/resize where reimplementation is unreasonable (and prefer libraries — libext2fs, libntfs-3g, libfdisk, libblkid/liblvm — behind optional backends).
* Modelling LVM/RAID as fake partition tables with "strung together" sectors; model them as explicit container/volume classes.
* The libparted flag enum; model MBR type byte + boot flag, and GPT type GUID + 64-bit attributes + name + partition GUID, natively.
* A generic "run any whitelisted command as root" RPC; keep the helper's verbs typed and validated.
* Mixing GUI widgets and KPasswordDialog into the core library; keep secrets/passphrase prompting as a callback interface.
* Hard-coded `/dev`, `/sys`, `/proc`, `/etc/fstab` assumptions in core classes; put them behind the platform backend.
* Blocking nested event loops for D-Bus calls inside a worker thread.

### Suggested mapping to our library set

* `disk-core`: value model (Device, PartitionTable, Partition, roles, alignment, capability enums), Operation/Job/Report engine, byte-range copy engine.
* `disk-io`: `BlockDevice` interface with implementations for Linux/macOS/Windows raw devices *and* file-backed images (raw, with pluggable sparse/qcow2/VHD later), plus the elevated-helper transport.
* `disk-tables`: native GPT/MBR readers+writers with CRC validation, protective MBR, backup-header repair, hybrid detection; read-only APM/BSD/Sun.
* `disk-fs`: `FileSystem` base + native probers; tool-backed `Provider`s for mkfs/fsck/resize mirroring the table in §4 (that table is effectively the spec of which tools to support).
* `disk-containers`: LUKS, LVM, mdraid, (later) APFS/BitLocker detection; loop/attach semantics for images.

End of report.