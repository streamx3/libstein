# libstein documentation

Pure C++ libraries for disks, partition tables, filesystems, encrypted
containers, volume managers and disk images, portable across Linux, macOS and
Windows, with no Qt/GTK/glib. Designed to power platform-native disk
utilities *and* one-button user apps in the dr_stein tradition.

Reading order:

| File | What |
|---|---|
| [`00-vision.md`](00-vision.md) | The brief: why, hard requirements R1–R12 (R5a–f, R8a added after review), non-goals, open questions |
| [`DECISIONS.md`](DECISIONS.md) | Numbered decision log (D1–D16): C++23, no exceptions, no QtCore, UTF-8, minimal templates, image encryption, … |
| [`research/01-gnome-disks.md`](research/01-gnome-disks.md) | GNOME Disks survey: UDisks2/D-Bus chain, imaging limits, Rust port, borrowable ideas |
| [`research/02-kpmcore-partitionmanager.md`](research/02-kpmcore-partitionmanager.md) | kpmcore / KDE Partition Manager: class hierarchy, tool table, sfdisk backend, privilege helper, Operation/Job/Report; the GPT-backup finding |
| [`research/03-gparted.md`](research/03-gparted.md) | GParted: `FS` capability struct, tool table, libparted usage, CopyBlocks, OperationDetail |
| [`research/04-dr-stein.md`](research/04-dr-stein.md) | dr_stein: what the one-button restore app teaches the library |
| [`research/05-library-ecosystem.md`](research/05-library-ecosystem.md) | Every candidate library with license verdicts, compatibility matrix, recommended v1 stack |
| [`design/10-architecture.md`](design/10-architecture.md) | The library chain, dependency DAG, domain model, cross-cutting decisions, build layout |
| [`design/11-cpp-interfaces.md`](design/11-cpp-interfaces.md) | Abstract bases + capability objects; why not interface multiple inheritance; conventions |
| [`design/12-class-hierarchies.md`](design/12-class-hierarchies.md) | Concrete classes per entity kind and the on-disk facts that shape them |
| [`design/13-operations.md`](design/13-operations.md) | Operation / Job / Stack / Runner / Report / Progress model |
| [`design/14-imaging.md`](design/14-imaging.md) | Image formats, the `.stein` container, copy engine, restore validation |
| [`design/15-userspace-fs.md`](design/15-userspace-fs.md) | Reader/Writer interfaces, per-fs plan, mount backends per OS |
| [`design/16-platform.md`](design/16-platform.md) | Platform layer interfaces, per-OS API mapping, privilege model |
| [`design/17-capability-matrix.md`](design/17-capability-matrix.md) | What is planned at which level in which milestone |
| [`design/18-structure-layouts.md`](design/18-structure-layouts.md) | Format manifests, generated layout classes, the hexinator-style `LayoutTree` |
| [`spec/stein-image-v1.md`](spec/stein-image-v1.md) | The `.stein` image container: segments, chunks, index, trailer, encryption |
| [`20-roadmap.md`](20-roadmap.md) | Milestones M0–M4, status, risks |
| [`reports/`](reports/) | Dated progress reports (`2026-10-05` design, `2026-10-06` M1 status) |

Conventions: design docs are numbered by layer (10–19); research docs by
project (01–05); every requirement in `00-vision.md` has an `R#` that the
design docs cite.
