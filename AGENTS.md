# AGENTS.md

Windows RAM accounting GUI in Rust and egui. Runs on Linux and macOS with simulated data for development.

## Commands

- Tests: `cargo test --locked`
- Cross-build for Windows: `cargo build --release --target x86_64-pc-windows-gnu`
- Run with simulated data: `cargo run`
- Headless report: `--report out.txt [--deep]`. Screenshot flags: `--tab --theme --size --baseline --deep`
- More in [BUILDING.md](BUILDING.md)

## Conventions

- Branches: work on `development`; `main` only gets tested releases.
- The name is always written `RAMWhere`, no space.
- UI follows the Windows light/dark setting and accent colour (monochrome when there is no accent), with a Light/Dark/System switch in the app.
- Keep README.md short (what it is, screenshots, download). Technical detail goes in BUILDING.md.

## Traps

- The renderer is forced to DirectX 12 (`WGPU_BACKEND=dx12`) because Intel's Vulkan driver crashed at startup on real hardware. A marker file in `%LOCALAPPDATA%\RAMWhere` makes the next launch use OpenGL if GPU startup crashes the process. Keep that fallback working.
- Don't read other processes' working sets, mapped file names, version resources or services to attribute memory. That approach was dropped on purpose; attribution goes through pool tags, drivers and the `culprits.rs` table.
- Deep Scan uses undocumented Superfetch page-database queries. Structure layouts are best-effort and not verified on every Windows build, so reports include consistency notes for debugging.

## Testing

- CI runs `cargo test` and a release build on Windows.
- Under Wine, set `WINEDLLOVERRIDES="mscoree,mshtml="` and run inside Xvfb, or wineboot hangs. The DirectX 12 renderer panics under Wine and the app relaunches itself with `--glow`, which is expected.
- Real numbers, Deep Scan and admin-only data need a real Windows machine. Ask for the **Copy report** output (as administrator, after a Deep Scan) when debugging.
