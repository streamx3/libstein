# Design note: "Interfaces" in C++, inheritance, and the diamond question

The brief asks for a class-and-inheritance architecture (base `PartitionTable`,
base `FileSystem`, …) and anticipates two C++ pain points: there is no
`interface` keyword, and multiple inheritance can create diamonds. This note
takes a position.

## 1. Position in one paragraph

Use **abstract base classes as interfaces**, exactly one **concrete
inheritance chain per entity kind** (`FileSystem` → `Ext4FileSystem`), and
model *optional abilities* not as extra base classes but as **capability
objects returned by the entity** (`fs.resizer()`, `fs.labeler()`,
`fs.mounter()`), each of which is itself a small abstract interface. This
gives the inheritance-driven design the brief wants, with no diamonds, no
virtual inheritance, and a capability model that can grow from "detect only"
to "full userspace driver" without changing the base class.

## 2. Why not plain multiple inheritance of interfaces

The tempting layout is:

```cpp
class Ext4FileSystem : public FileSystem,
                       public IResizable, public ILabelable,
                       public IMountable, public ICheckable { ... };
```

It *works* in C++ (interfaces with no data members and no common base don't
form diamonds; `dynamic_cast<IResizable*>(fs)` is the query). Problems:

1. **Capability becomes a compile-time property of the type**, but in this
   domain it is a *run-time* property: ext4 *shrink* is possible offline but
   not online; NTFS resize is possible only if the volume is clean; FAT
   resize is possible only if the new size keeps the same FAT width; a
   filesystem backed by a read-only image cannot be resized at all. Every
   interface method would need to start with "can I actually do this now?".
2. **Diamonds do appear** the moment you want shared implementation in an
   interface (e.g. `IResizable` wanting a default `canShrink()` built on a
   `Geometry` member) and two interfaces share that helper. Then you need
   `virtual` inheritance, and virtual inheritance plus a deep concrete
   hierarchy is where C++ gets unpleasant (constructor ordering, `dynamic_cast`
   cost, no static downcast).
3. The set of abilities per entity is open-ended (grow, shrink, move, check,
   repair, label, uuid, used-space, mount, read, write, defragment, trim,
   encrypt, …). A class inheriting from fifteen interfaces is a smell.

## 3. The chosen pattern: entity + capability objects

```cpp
namespace stein::fs {

// --- the "interface" (abstract base) ---------------------------------------
class FileSystem {
public:
    virtual ~FileSystem() = default;

    // identity / static description
    virtual FsType          type() const = 0;             // enum
    virtual std::string_view typeName() const = 0;        // "ext4"
    virtual Capabilities    capabilities() const = 0;     // bitset of what THIS instance can do NOW

    // every fs has these (may return nullopt)
    virtual Expected<Geometry> geometry() const = 0;      // block size, total/used blocks
    virtual Expected<Label>    label() const = 0;
    virtual Expected<Uuid>     uuid() const = 0;

    // capability objects: non-owning views; nullptr means "not supported by this instance"
    virtual Resizer*   resizer()   { return nullptr; }
    virtual Labeler*   labeler()   { return nullptr; }
    virtual Checker*   checker()   { return nullptr; }
    virtual Creator*   creator()   { return nullptr; }    // "mkfs" for this type
    virtual Reader*    reader()    { return nullptr; }    // in-process read access (R7)
    virtual Writer*    writer()    { return nullptr; }    // in-process write access (R7)
    virtual Mounter*   mounter()   { return nullptr; }    // OS-level mount via platform layer
};

// --- a capability interface --------------------------------------------------
class Resizer {
public:
    virtual ~Resizer() = default;
    virtual ResizeLimits limits(ResizeContext) const = 0;    // min/max/alignment, online/offline
    virtual Expected<void> resize(Bytes newSize, ResizeContext, Progress&) = 0;
};

} // namespace stein::fs
```

Properties:

- **Single inheritance everywhere.** `Ext4FileSystem : FileSystem`. The
  capability classes are nested helpers (`Ext4FileSystem::Resizer : fs::Resizer`)
  owned by the entity. No diamonds, ever.
- **Run-time capability is first-class.** `capabilities()` returns a bitset
  (`CanGrow | CanShrinkOffline | CanLabel | CanRead | …`) computed from the
  instance's actual state (mounted? clean? backed by read-only device?
  backend available?). UIs grey out buttons from this; no `dynamic_cast`.
- **Grows into R7 without redesign.** A detection-only `ZfsFileSystem` returns
  nullptr for everything; a v2 `Ext4FileSystem` returns a `Reader`; a v3 one
  returns a `Writer`. Same base class, same UI code.
- **Multiple implementations behind one capability.** Ext4's `Resizer` can be
  the in-process one or (optional backend, R8) a wrapper that runs
  `resize2fs`. The caller cannot tell; selection is a backend-registry policy.
- **Testable.** Each capability interface is tiny and mockable.

The same pattern applies to every entity kind:

| Entity base | Capability objects |
|---|---|
| `PartitionTable` | `Editor` (add/remove/resize entries), `Repairer` (GPT backup header → primary, CRC fix), `Flagger` |
| `BlockDevice` | `Reader`, `Writer`, `Geometry`, `Discard` (TRIM), `Smart`, `Benchmark` |
| `Container` (LUKS, VeraCrypt, BitLocker…) | `Unlocker` (yields a `BlockDevice`), `KeyManager`, `Creator` |
| `VolumeGroup` (LVM, LDM, mdraid, APFS container…) | `Enumerator`, `Activator`, `Editor` |
| `ImageFormat` (raw, split-raw, our container, E01, qcow2, VHDX…) | `Reader`, `Writer`, `Verifier` |

## 4. Where real inheritance chains *are* used

Inheritance (as opposed to capability composition) is used where there is
genuine *is-a* with shared implementation:

- `FileSystem` → `ExtFamilyFileSystem` → `Ext2FileSystem`, `Ext3FileSystem`,
  `Ext4FileSystem` (one superblock parser, feature-flag differences).
- `FileSystem` → `FatFamilyFileSystem` → `Fat12/16/32`, and separately `ExFat`.
- `FileSystem` → `HfsFamily` → `Hfs`, `HfsPlus` (HFSX as a flag).
- `PartitionTable` → `MbrPartitionTable` → (nothing else; EBR chains are
  handled inside), `GptPartitionTable`, `ApmPartitionTable`,
  `BsdDisklabel`, `SunLabel`, `SgiLabel`, `AmigaRdb`, `Pc98Table`, `AixLabel`,
  `NoPartitionTable` (the libparted "loop" label: whole-device filesystem).
- `BlockDevice` → `PlatformDisk` (Linux/macOS/Windows), `PartitionDevice`
  (slice of a parent), `ImageDevice` (backed by an image reader),
  `MemoryDevice` (tests), `DecryptedDevice` (yielded by a container),
  `LogicalVolumeDevice` (yielded by a volume group), `SparseDevice`, …
- `Operation` → `CreatePartition`, `DeletePartition`, `FormatFileSystem`,
  `ResizeFileSystem`, `CreateImage`, `RestoreImage`, …
- `Job` → one job class per primitive step.

Rule of thumb: **inherit for "is a kind of", compose for "can do".**

## 5. Error handling, ownership, threading conventions

- No exceptions across library boundaries. Public API returns
  `stein::Expected<T>` (= `std::expected<T, stein::Error>` on C++23, a small
  polyfill otherwise). `Error` carries a category, an OS error code, a
  message, and an optional "report node" (see `design/13-operations.md`).
  Exceptions may be used *inside* a module.
- Ownership: entities are owned by the object that discovered them (a
  `Partition` by its `PartitionTable` snapshot, a `FileSystem` by its probe
  result). Returned capability pointers are non-owning and valid only while
  the entity is alive. Cross-module sharing uses `std::shared_ptr` only at
  the `BlockDevice` level (devices are shared by partitions, containers and
  images).
- Threading: entities are not thread-safe; a `Job` runs on one worker thread
  and talks back via `Progress&` (thread-safe sink). Cancellation is
  cooperative via a `CancelToken` passed with `Progress`.
- Strings: UTF-8 `std::string` for names/labels; `std::u16string` only
  inside NTFS/FAT/exFAT/HFS+ parsers; conversion helpers in `stein::core`.
- No RTTI dependence in the public API (we still compile with RTTI on).
- ABI: not stable before 1.0; but public headers avoid STL containers in
  virtual signatures where a span/view works, to keep that option open.

## 6. Alternatives considered

- **C++20 concepts / templates instead of virtual bases.** Rejected for the
  entity layer: the set of filesystems is decided at run time (probe result),
  and UIs in other languages need a vtable to call through. Concepts *are*
  used internally (e.g. `template<ByteSource S>` in the copy engine).
- **Pure C API with opaque handles.** Deferred: a C shim (`stein_c`) for
  bindings is planned on top of the C++ API, not instead of it.
- **Qt-style signals/slots for progress.** No Qt. Progress is a plain
  interface; a UI adapts it to whatever event loop it has.
