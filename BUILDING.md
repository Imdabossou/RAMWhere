# Building RAMWhere

## Requirements

- Rust (stable)
- To cross-compile from Linux: `mingw-w64-gcc` and the `x86_64-pc-windows-gnu` target (`rustup target add x86_64-pc-windows-gnu`)

## Commands

```sh
cargo test --locked                                     # tests
cargo build --release                                   # on Windows
cargo build --release --target x86_64-pc-windows-gnu    # cross-compile from Linux
cargo run                                               # on Linux or macOS: runs against simulated data
```

## Command line

- `RAMWhere.exe --report out.txt [--deep]` writes a text and JSON report without opening a window.
- `RAMWhere.exe --glow` uses OpenGL instead of DirectX 12. The app switches to it by itself if DirectX fails to start.
- For screenshots: `--tab <name> --theme light|dark --size WxH --baseline --deep`.

Put Microsoft's `pooltag.txt` next to the exe for richer pool tag descriptions. It's picked up automatically when the Debugging Tools for Windows are installed.

## How it works

Built in Rust with [egui](https://github.com/emilk/egui).

- `src/platform/windows.rs` reads the kernel counters. `src/platform/mock.rs` provides simulated data on other systems.
- `src/breakdown.rs` sorts memory into categories: apps, kernel pools, Memory Compression, VBS, WSL2 and VMs, file cache, standby, modified, free and hardware-reserved.
- `src/culprits.rs` is the built-in list of known drivers and programs used for "What's using it". Additions are welcome.
- `src/pooltags.rs` matches kernel pool tags to the driver files that allocate them.
- `src/report.rs` writes the text and JSON reports.

## Status

The live counters use the same well-established kernel queries as Task Manager and Process Explorer. Deep Scan walks the physical page database (the same source RAMMap uses) through undocumented interfaces, so it may not work on every Windows build. If it misbehaves, please open an issue with the output of **Copy report**.
