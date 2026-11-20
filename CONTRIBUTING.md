# Contributing to RAMWhere

Thanks for helping! A few things to know first.

- **Bugs:** open an issue and paste the output of **Copy report**, run as administrator and after a Deep Scan if you can. Include your Windows version.
- **Unrecognised drivers or programs:** additions to the list in `src/culprits.rs` are very welcome. Say what the product is and how you identified it.
- **Branches:** open pull requests against `development`. `main` only gets tested releases.
- **Checks:** `cargo test --locked` and `cargo build --release --locked` must pass. CI runs both on Windows. See [BUILDING.md](BUILDING.md) for setup.
- **Read-only:** RAMWhere only reads memory statistics. It must never change system settings, end processes or read other programs' memory contents.
- **Licence:** contributions are accepted under the project's licence (GPL-3.0-or-later). Third-party code must be GPL-compatible.
- **Security issues:** please report them privately, see [SECURITY.md](SECURITY.md).
