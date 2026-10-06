# GUI toolkit and the path from a Claude Design prototype to a desktop app

Status: decision D17 (`DECISIONS.md`). The libraries stay free of every
toolkit (D3); this document is about the application layer only.

## 1. Requirements the toolkit must meet

From `00-vision.md` and the owner's brief:

1. One application that is a first-class citizen on Linux (KDE Plasma and
   Deepin named explicitly), macOS and Windows, from one codebase.
2. The app links the C++23 libraries directly (no language bridge in the
   hot path: a partition map redraws from `probe::Node`, a file list from
   `fs::Reader`).
3. The layout designed in Claude Design (an HTML/CSS prototype) must
   carry over: panes, navigation, lists, inspector, dialogs. Pixel parity
   is not required.
4. CMake, no second build system in the application tree.
5. Privilege separation stays as designed in `16-platform.md`: the GUI
   runs unprivileged and talks to a small helper. Any toolkit works with
   that; a toolkit that *must* be in the helper does not exist here.
6. Permissive licensing for the app's own code (MIT like the libraries),
   with the toolkit's licence compatible with shipping binaries on all
   three platforms and in distro repositories.

## 2. Candidates, facts

| | Qt 6 (Qt Quick/QML or Widgets) | GTK 4 + libadwaita | wxWidgets 3.2 | Slint | Native per OS (Kirigami/GTK, AppKit, WinUI) | Web shell (Electron / Tauri) |
|---|---|---|---|---|---|---|
| Language of the UI code | C++ and QML (JS expressions) | C (gtkmm for C++), Vala, Blueprint/UI XML | C++ | `.slint` markup + C++/Rust | Three codebases (C++/QML, Swift/ObjC, C++/WinRT or C#) | HTML/CSS/JS + an IPC bridge to C++ |
| Build | CMake is the first-class build since Qt 6; `find_package(Qt6)` | Meson for GTK itself; an app consumes it via pkg-config from CMake (works, but every GTK-side dependency is Meson) | CMake | CMake (the Rust core ships prebuilt or builds via corrosion) | Three build systems | npm/cargo plus CMake |
| Windows / macOS standing | Supported by the vendor as primary targets: native file/colour dialogs, menus, HiDPI, dark mode (Qt 6.5+ colour schemes), code-signing docs, `windeployqt`/`macdeployqt` | Possible (MSYS2/gvsbuild on Windows, Homebrew on macOS) but GNOME-styled; non-native dialogs and menus; HiDPI and input quirks; few shipping GTK4 apps on those systems | Wraps the native widgets of each OS, so it looks native | Supported, young | Native by definition | Chromium (Electron, ~150 MB) or system webview (Tauri: WebView2, WKWebView, WebKitGTK on Linux) |
| Linux desktop fit | KDE Plasma 6 and Deepin DDE are Qt applications; a Qt app inherits their themes, dialogs and portals. Under GNOME it uses the portal file dialog and the Fusion/Adwaita-like style | First-class under GNOME; alien under KDE/Deepin (own dialogs, own theme) | Uses GTK underneath on Linux | Winit/Qt backends; theming immature | n/a | WebKitGTK pulls GTK in anyway |
| Declarative layout close to HTML/CSS | QML: anchors, `RowLayout`/`ColumnLayout`/`GridLayout`, states, transitions, property bindings; Qt Quick Controls styled by a `Theme` singleton. Widgets: imperative layouts | GTK4 `.ui` XML or Blueprint; CSS theming is real CSS (closest to the prototype's styling) but the layout model is widget boxes, not flex/grid | Imperative sizers | Yes, a CSS-like declarative language | Three different ones | Identical: the prototype *is* the UI |
| Data-heavy views (trees of partitions, 300k-entry directory listings) | `QAbstractItemModel` over `probe::Node`/`fs::Reader`; `TreeView` (QML, 6.3+) and `QTreeView` (Widgets) virtualise rows | `GListModel` + `GtkColumnView`, virtualised | `wxDataViewCtrl` | Models exist; fewer widgets | native | Virtualised lists need a JS library; data crosses the bridge serialised |
| Licence (open-source edition) | LGPLv3 for Core, Gui, Qml, Quick, Quick Controls, Widgets, Network, Svg (the modules this app needs); a few add-ons are GPL-only (Charts, Data Visualization, Virtual Keyboard) and are not needed; dynamic linking satisfies the LGPL, static linking needs object files or relinkable libraries offered | LGPL-2.1+ | wxWindows licence (LGPL with a static-linking exception) | GPLv3, or a royalty-free licence for desktop apps, or commercial | Platform SDK terms | MIT (Electron), MIT/Apache (Tauri) |
| Runtime footprint | Core+Gui+Qml+Quick+QuickControls2+Widgets ≈ 30–40 MB on Windows/macOS; Linux uses distro packages (Qt 6.4 in Ubuntu 24.04/Debian 12, 6.7+ in Fedora/Arch/openSUSE) | ≈ 30 MB with GLib, Pango, Cairo, GdkPixbuf, GraphENE; the same on Linux is already installed | small on top of the OS widgets | small (Rust core, few MB) | n/a | 150+ MB (Electron) / small (Tauri) |
| Rendering | Qt Quick scene graph on the RHI (Metal, D3D11/12, Vulkan, OpenGL) with a software rasteriser fallback (`QT_QUICK_BACKEND=software`) for GPU-less VMs; Widgets paint with the raster engine | GPU renderers (ngl/Vulkan) with a Cairo fallback | OS widgets | GPU (femtovg/Skia) or software | native | GPU via the browser |
| Risk | Qt Company's licensing churn affects the *commercial* edition; the LGPL edition has been continuous since 2009. QML has a JS engine in the process (fine for a desktop tool; not for the privileged helper, which is library-only anyway) | Cross-platform maturity; GNOME-version coupling of libadwaita; GObject in C++ is a style mismatch with this codebase | Dated API, weak for a design-led UI (custom-drawn partition maps and progress views are hand-painted) | Young ecosystem; licence choice needed; fewer widgets | Three times the UI work and three review surfaces; the roadmap's original M4 plan | A second technology stack and an IPC schema for everything the UI shows; Linux still depends on GTK; a disk tool shipping Chromium is hard to justify |

Notes on the GTK column, since the owner's unease deserves facts rather
than agreement: GTK4 is a good toolkit *on GNOME*. The trouble for this
project is everything around it on the other two platforms and on
KDE/Deepin, where a GTK4/libadwaita app brings its own dialogs, menus and
theme and looks like a visitor. Its build culture (Meson, Vala, GObject
introspection, Blueprint) is coherent within GNOME and foreign to a CMake
C++ codebase; consuming GTK from CMake works, but the moment something
like `libadwaita` or a GNOME API is needed the app is tied to a GNOME
release cadence, exactly as the owner feared. The "mess" impression is
real for cross-platform use and not a GNOME-side defect. Nothing here says
GTK is slow; GTK4's renderer is fine. It is the wrong *fit*, not a bad
toolkit.

## 3. Decision

**Qt 6, with Qt Quick (QML) for the application shell and views and C++
models over the libraries.** Reasons, in order of weight:

1. One codebase that is native on KDE Plasma and Deepin (both are Qt),
   acceptable on GNOME (portal dialogs, Fusion style), and vendor-supported
   on Windows and macOS with native dialogs, menus, dark mode and HiDPI.
2. The app's view models are plain C++ over `probe::Node`, `fs::Reader`,
   `ops::OperationStack` and `image::*`: no bridge, no serialisation, the
   data-heavy views virtualise through `QAbstractItemModel`.
3. QML is the closest match to the Claude Design prototype: a declarative
   tree of items with anchors and layouts, bindings instead of event
   plumbing, and a `Theme` singleton that holds the design tokens. The
   port in §4 is mechanical.
4. CMake first class; `qt_add_qml_module` compiles QML ahead of time, so
   there is no runtime file loading and QML type errors surface at build
   time (`qmllint`, `qmlcachegen`).
5. LGPLv3 with dynamic linking keeps the app MIT; distro packaging is
   routine on every Linux; `windeployqt`/`macdeployqt` produce the bundles.

Qt Widgets remain available in the same process for the few things where a
classic widget is better (a native file dialog is one call either way;
`QTreeView` with thousands of columns is not needed here). A Widgets-only UI
was considered and rejected only because the prototype is design-led:
custom-styled panels, a disk map, inline progress, and a sidebar
navigation that Widgets would have to hand-paint.

What this does *not* change: D3 stands (no Qt in the libraries), the
privileged helper stays toolkit-free, and the CLI remains the reference
client for every feature before the GUI exposes it.

## 4. From the Claude Design prototype to QML

Claude Design produces an HTML/CSS (optionally React) prototype. It cannot
be imported by Qt Design Studio (that tool imports Figma, Sketch and Adobe
XD through Qt Bridge, not HTML), so the port is a translation, which is
routine and best done once, systematically:

1. **Check the prototype into the repository** under `doc/design/gui/`
   (the exported HTML, CSS and any assets). It becomes the specification
   the QML is reviewed against; every QML component carries a comment
   naming the prototype element it realises. Screenshots of each screen
   go next to it for reviewers without a browser.
2. **Extract the tokens** into `Theme.qml` (a QML singleton): colour
   roles (surface, surface-raised, text, text-muted, accent, danger,
   warning, success, partition-type colours), the type scale (family,
   sizes, weights), spacing steps, radii, elevation/shadow, icon size.
   CSS custom properties, if the prototype uses them, map one to one.
   Light and dark variants become two token sets selected by
   `Qt.styleHints.colorScheme`.
3. **Map the layout.** Each prototype screen becomes a QML page; CSS
   `grid`/`flex` containers become `GridLayout`/`RowLayout`/`ColumnLayout`
   with `Layout.fillWidth`/`preferredWidth` for the fractions; fixed
   sidebars and inspectors become `SplitView` panes with the prototype's
   widths as initial sizes. Scrolling regions become `ScrollView` or
   `ListView`/`TreeView`.
4. **Inventory the components** (sidebar item, device card, partition
   bar/map, property table, file list row, progress banner, dialog with
   the preview/apply two-step, toast) and write each once in
   `qml/components/`, styled from `Theme`. Qt Quick Controls 2 provides
   the behaviour (focus, keyboard, accessibility); the look is a custom
   style so the prototype's visuals survive instead of Fusion's.
5. **Bind the data.** C++ `QAbstractItemModel`s and `QObject` facades
   over the libraries (`DeviceListModel`, `TopologyModel`,
   `FileTreeModel`, `OperationStackModel`, `ImageJob`) expose exactly the
   fields `19-gui-brief.md` lists. Long operations run on a worker thread
   with `Progress` forwarded through signals; cancellation uses the
   library's `CancelToken`.
6. **Platform touches.** Native menu bar on macOS (`MenuBar` is native
   there), the system file dialogs everywhere (`FileDialog` from
   `QtQuick.Dialogs`), drag-out of files via `QMimeData` with
   `text/uri-list` after `fs::copyTree` into a temporary directory (the
   viewer's drag-and-drop-out), and the privileged helper per
   `16-platform.md`.
7. **Iterate against the prototype.** Side-by-side screenshots at the
   same window size; differences are either accepted (platform
   conventions: title bars, scrollbars, menu placement) or fixed in QML.

The library side needs nothing new for step 5 beyond what exists; the
viewer's "drag out" is `fs::copyTree` to a temporary directory plus the
toolkit's drag source.

## 5. Risks and how they are contained

- **GPU-less environments** (VMs, remote desktops): ship with the
  software backend selectable (`QT_QUICK_BACKEND=software`), test it in CI
  with the offscreen platform plugin.
- **Qt version spread on Linux**: target Qt 6.4 as the floor (Ubuntu
  24.04, Debian 12) and avoid newer-only QML types or wrap them.
- **Binary size on Windows/macOS**: 30–40 MB is the price of one codebase;
  acceptable for a disk utility and far below a web shell.
- **Licence hygiene**: dynamic linking against the LGPL modules only; the
  GPL-only add-ons are excluded by a CMake check.
