# catscan v0.9.1 ASCII maps

A high-contrast, monochrome ncurses system monitor for macOS, built in C. Based
on the prior v0.8 release; includes the existing `netinspect.c` socket → packet
→ payload workflow, live CPU/Memory/Network/Disk monitoring, filesystem events,
and the right-side hardware status panel. No new dependency on the `pi` command.

## Build

```sh
make clean && make CC=clang
make test                       # includes deterministic VM map unit tests
sudo -v && ./catscan           # preauthorize packet / sensor capture
```

`./catscan --demo` shows sample network data without packet-capture privileges.

The Mac build needs Apple SDK/Xcode command line tools and ncurses. The build
system links IOKit and CoreFoundation on macOS for the hardware collector.

## Linux and FreeBSD builds

Native Linux and FreeBSD builds use ncurses and pthreads:

```sh
make -C platforms/linux
# or on FreeBSD:
make -C platforms/freebsd

# Stage the program for a package build without installing it on the host:
make -C platforms/linux install DESTDIR=/tmp/catscan-stage PREFIX=/usr
```

Linux and FreeBSD Makefiles accept `ARCH` and `CC` for arm64, x86, and x64 targets. Cross builds require a matching target sysroot and ncurses libraries; configure `PKG_CONFIG_LIBDIR`/`PKG_CONFIG_SYSROOT_DIR` if the target uses pkg-config metadata.

On Debian or Ubuntu, `packaging/debian/build.sh` can create a `.deb` from a
native build; set `VERSION` and `MAINTAINER` before running it.

On Fedora, install `gcc make ncurses-devel rpm-build`, then build an RPM with
`VERSION=0.9.1 packaging/fedora/build.sh`. Set `ARCH=aarch64`, `ARCH=x86_64`,
or `ARCH=i686` for another target; cross builds require the matching compiler
and target ncurses libraries.

The Debian builder accepts `ARCH=x64`, `ARCH=x86`, or `ARCH=arm64` and forwards
`CC` to the Linux Makefile. Cross builds require matching ncurses libraries and
target pkg-config paths when the target provides them.

These builds collect process, CPU, memory, network-counter, and mount data. Live
packet capture uses `sudo -v` followed by `sudo -n tcpdump`; Linux captures on
`any`, while FreeBSD uses tcpdump's default interface. Without permission or
tcpdump, the rest of the monitor remains available and packet details stay empty.
Process-to-packet association is by endpoint tuple on Linux and FreeBSD; macOS
pktap can also supply process IDs. The thread-state map, virtual-memory region
map, `iostat` detail, filesystem-event stream, and specialized hardware readings
remain macOS-only. Linux and FreeBSD native builds and runtime behavior still
need validation on those systems.

## Windows

The Windows port is not implemented yet. The current source depends on POSIX
process, socket, filesystem, pthread, and ncurses interfaces. A native Windows
version will need a separate collector/UI backend, likely using Windows process
and performance APIs with a Windows terminal library. The `platforms/windows`
directory is reserved for that port; it is not a build target today.

## Fixed in v0.9.1

**CPU thread map now opens by default**, just like Memory's virtual-address
raster. Press `1`, select a process, and press Enter. Press `t` to switch to the
thread table; Enter on a selected thread opens its live counters. The overview
process shortcut also opens the map, rather than the table.

The new thread-state raster is a true character grid: `R` running, `W` waiting,
`S` stopped, `?` other, `@` selected, and `.` unused slot. It adapts to terminal
width and scrolls as you select a thread, with stable TID ordering and a selected
thread diagnostics area. It is **logical thread state**, *not* a fabricated
physical CPU/core topology. When macOS refuses thread enumeration, the UI says
so rather than displaying an empty map. Run `make test` for ASCII unit tests.

## New in v0.9

**Real ASCII virtual address map.** On the **Memory** page, select a process and
press Enter. When macOS permits inspection, you see a two-dimensional,
terminal-width address raster, e.g.:

```text
VIRTUAL ADDRESS RASTER | t: table   +/-: zoom   j/k: region
0x0000000100000000 ... 0x0000000101000000 | 16.0M window
  0000000100000000 |FFEEEEEEEE....WWWWWWWWWWWW..............|
  0000000108000000 |........WWWWWW@@@@@@FFFFF......AAAAAAA|

@ selected  E executable  F file-backed  W anonymous writable
A other anonymous  * multiple types in one sample  . unmapped gap
Selected: 0x0000000108...  4.0M  rw-  anonymous region
```

Addresses, region sizes, permissions, and file paths come from the macOS
`vm_region_64` walk. They are **mapped virtual address regions**, not physical
RAM addresses or individual `malloc`/ASan heap allocations. Unmapped spans are
shown as dots. A `*` cell means multiple different mapping types fell into
one raster cell, which can happen when zoomed out. The map follows the selected
region as it moves and preserves the region identity across live refreshes.

- `j/k` or up/down: select an actual mapped region and pan the map to it.
- `+` / `-`: zoom in/out by changing how many neighboring regions are visible.
- `t`: toggle between the ASCII map and full region table.
- `Enter`: inspect region address, permissions, file mapping, neighboring gaps,
  and (in tall terminals) a smaller local ASCII map.
- `Backspace` / `h`: go back one level.
- `gg` / `G`: first/last region. `Ctrl-d` / `Ctrl-u`: page through regions.

If a process's task port is inaccessible, the map will say so. The ordinary
RSS, virtual memory, footprint, page-fault, and rusage numbers remain where
macOS exposes them. The collector is still asynchronous.

**More populated views.** Previously unused overview lines now contain total
process/thread counts, active and wired memory, discovered sockets and packet
count, and the filesystem-event capture status. On wide panes, the right-side
hardware area also uses spare space for measured Wi-Fi SNR/noise/link rate,
power source, and hardware model when available. The CPU thread topology view
has a more structured ASCII state/TID grid, rather than an implied physical
core map. All readings are live snapshots and are absent if a collector cannot
get them.

## Existing navigation

- `0` overview, `1` CPU, `2` Memory, `3` Network, `4` Disk.
- `h/j/k/l`, arrows, Enter and Backspace for navigation.
- On overview: `Tab` switches process/hardware panels; hardware is beside
  processes at widths at least 100 columns and swaps in narrow panes.
- Network retains `lsof → tcpdump → packet hex/text` navigation.
- Disk: `f` toggles the opt-in system-wide `fs_usage` event collector.
- Thread details remain available in CPU → process → thread.
- `q` quits.

## Limits and testing

Memory maps are capped at 4,096 regions in this version. A very large process
may have more mappings than that; only the captured regions can be displayed.
The raster loses details when zoomed out: each character summarizes an address
interval. Per-thread CPU/IDs do not expose a reliable physical-core topology.
Other processes may be protected against VM inspection even as root.

The standalone ASCII-mapping module has deterministic tests for known address
ranges, gaps, selection, zoom, sub-cell mappings, and near-64-bit-boundary
arithmetic. The current checkout builds and passes its self-test on macOS arm64.
The Linux and FreeBSD make targets were checked for their generated compile
commands, but require native target builds and runtime checks. Windows remains
unimplemented.
