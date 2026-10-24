#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod breakdown;
mod model;
mod platform;
mod pooltags;
mod report;
mod theme;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--report") {
        let out = args.get(i + 1).cloned().unwrap_or_else(|| "ramwhere-report.txt".into());
        let deep = args.iter().any(|a| a == "--deep");
        std::process::exit(app::headless_report(&out, deep));
    }
    app::run(args.iter().any(|a| a == "--glow"));
}
