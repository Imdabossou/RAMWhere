# RAM Where

A Windows app that accounts for every byte of RAM, including the parts Task Manager never itemizes:
kernel pool (with the driver that owns each tag), Memory Compression, VBS, WSL2/VMs, file cache,
hardware-reserved memory and, with **Deep Scan**, a page-by-page walk of physical memory
(the same source RAMMap uses) that splits shared/mapped files, page tables, driver-locked pages and more.

## Use

Run `ramwhere.exe`. Click **Restart as administrator** for the full picture (memory lists, Deep Scan).

- **Overview**: memory map, plain-English findings, every category with an explanation.
- **Processes**: private / shared / committed per process, including the hidden OS ones.
- **Drivers**: kernel pool tags matched to the driver files that use them.
- **Set baseline**: every table gains a Δ column, so you can leave it running and catch a leak.
- **Copy report / Save report**: text + JSON summary for tickets.

Theme follows the Windows light/dark setting (override in the top right).

Command line: `ramwhere.exe --report out.txt [--deep]` writes a report without a window;
`--glow` forces the OpenGL renderer (it also falls back automatically if DirectX fails).
Drop Microsoft's `pooltag.txt` next to the exe for richer tag descriptions (it's found automatically
if the Debugging Tools for Windows are installed).

## Build

```
cargo build --release --target x86_64-pc-windows-gnu   # needs mingw-w64-gcc
cargo run                                              # on Linux/macOS: runs against simulated data
```
