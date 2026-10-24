//! The GUI.

use crate::breakdown::{self, fmt_bytes, fmt_delta, Breakdown, Category, Confidence, Finding, Group, Severity};
use crate::model::*;
use crate::theme::{self, card, palette, text_on};
use crate::{platform, pooltags, report};
use eframe::egui::{self, Color32, RichText, Sense, Stroke};
use egui_extras::{Column, TableBuilder};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const OWNER_SCAN_TOP: usize = 120;

/// Marker that exists only while the GPU renderer is starting. If it survives to the next
/// launch, the graphics driver crashed the process (e.g. Intel's Vulkan driver, igvk64.dll),
/// which no in-process fallback can catch, so we go straight to OpenGL instead.
fn renderer_marker() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).or_else(|| std::env::temp_dir().into())?;
    let dir = base.join("RAMWhere");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("gpu-renderer-starting"))
}

static RENDERER_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn renderer_started() {
    if !RENDERER_OK.swap(true, Ordering::Relaxed) {
        if let Some(m) = renderer_marker() {
            let _ = std::fs::remove_file(m);
        }
    }
}

pub fn run(force_glow: bool) {
    let marker = renderer_marker();
    let crashed_before = marker.as_ref().is_some_and(|m| m.exists());
    let force_glow = force_glow || crashed_before;
    if !force_glow {
        if let Some(m) = &marker {
            let _ = std::fs::write(m, b"");
        }
    }
    // Only use DirectX 12 on Windows. Probing Vulkan loads the vendor's Vulkan driver, and some
    // (Intel igvk64.dll) crash outright while being enumerated.
    #[cfg(windows)]
    if std::env::var_os("WGPU_BACKEND").is_none() {
        std::env::set_var("WGPU_BACKEND", "dx12");
    }
    let args: Vec<String> = std::env::args().collect();
    let size = args
        .iter()
        .position(|a| a == "--size")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.split_once('x'))
        .and_then(|(w, h)| Some([w.parse::<f32>().ok()?, h.parse::<f32>().ok()?]))
        .unwrap_or([1280.0, 860.0]);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RAM Where")
            .with_inner_size(size)
            .with_min_inner_size([760.0, 480.0])
            .with_icon(Arc::new(icon())),
        renderer: if force_glow { eframe::Renderer::Glow } else { eframe::Renderer::Wgpu },
        ..Default::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eframe::run_native("RAM Where", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
    }));
    let err = match result {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e.to_string(),
        Err(_) => "the graphics driver rejected the renderer".to_string(),
    };
    // Some GPUs/VMs can't run the DirectX renderer; a fresh process can retry with OpenGL
    // (winit doesn't allow a second event loop in the same process).
    if !force_glow {
        if let Ok(exe) = std::env::current_exe() {
            if std::process::Command::new(exe).arg("--glow").spawn().is_ok() {
                return;
            }
        }
    }
    fatal(&format!("RAM Where couldn't start its window: {err}\n\nUse --report <file> for a text report instead."));
}

fn fatal(msg: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let w: Vec<u16> = std::ffi::OsStr::new(msg).encode_wide().chain(Some(0)).collect();
        let t: Vec<u16> = std::ffi::OsStr::new("RAM Where").encode_wide().chain(Some(0)).collect();
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(std::ptr::null_mut(), w.as_ptr(), t.as_ptr(), 0x10);
        }
    }
    eprintln!("{msg}");
}

fn icon() -> egui::IconData {
    // A tiny stacked-bar icon, drawn in code so there's no asset to ship.
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    let colors = [[66u8, 133, 244], [229, 57, 53], [251, 140, 0], [102, 187, 106]];
    let bounds = [0usize, 22, 38, 48, 64];
    for y in 8..56 {
        for x in 4..60 {
            let seg = (0..4).find(|&i| x - 4 < bounds[i + 1] * 56 / 64).unwrap_or(3);
            let i = (y * n + x) * 4;
            rgba[i..i + 3].copy_from_slice(&colors[seg]);
            rgba[i + 3] = 255;
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Processes,
    Drivers,
    Deep,
    Help,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcCol {
    Name,
    Pid,
    Private,
    Shared,
    Ws,
    Commit,
    Threads,
    Handles,
    Delta,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PoolCol {
    Tag,
    Nonpaged,
    Paged,
    Total,
    Allocs,
    Delta,
    Owner,
}

enum Msg {
    Snapshot(Box<Snapshot>),
    Owners(pooltags::ScanResult),
    Deep(Result<DeepScan, String>),
}

struct App {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    snap: Option<Arc<Snapshot>>,
    baseline: Option<Arc<Snapshot>>,
    deep: Option<Arc<DeepScan>>,
    use_deep: bool,
    owners: HashMap<String, TagOwner>,
    owners_requested: HashSet<String>,
    owner_scan_running: bool,
    owner_status: String,
    refreshing: bool,
    last_refresh: Instant,
    auto_refresh: bool,
    interval: f32,
    tab: Tab,
    deep_progress: Arc<AtomicU32>,
    deep_running: bool,
    deep_error: Option<String>,
    proc_filter: String,
    group_procs: bool,
    proc_sort: (ProcCol, bool),
    pool_filter: String,
    pool_sort: (PoolCol, bool),
    status: Option<(String, Instant)>,
    theme_pref: egui::ThemePreference,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        cc.egui_ctx.set_theme(egui::ThemePreference::System);

        let (tx, rx) = channel();
        let mut app = App {
            tx,
            rx,
            snap: None,
            baseline: None,
            deep: None,
            use_deep: true,
            owners: HashMap::new(),
            owners_requested: HashSet::new(),
            owner_scan_running: false,
            owner_status: "Waiting for first snapshot".into(),
            refreshing: false,
            last_refresh: Instant::now(),
            auto_refresh: true,
            interval: 3.0,
            tab: Tab::Overview,
            deep_progress: Arc::new(AtomicU32::new(0)),
            deep_running: false,
            deep_error: None,
            proc_filter: String::new(),
            group_procs: false,
            proc_sort: (ProcCol::Private, true),
            pool_filter: String::new(),
            pool_sort: (PoolCol::Total, true),
            status: None,
            theme_pref: egui::ThemePreference::System,
        };
        let args: Vec<String> = std::env::args().collect();
        let arg = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).map(|s| s.as_str());
        app.tab = match arg("--tab") {
            Some("processes") => Tab::Processes,
            Some("drivers") => Tab::Drivers,
            Some("deep") => Tab::Deep,
            Some("help") => Tab::Help,
            _ => Tab::Overview,
        };
        app.theme_pref = match arg("--theme") {
            Some("light") => egui::ThemePreference::Light,
            Some("dark") => egui::ThemePreference::Dark,
            _ => egui::ThemePreference::System,
        };
        cc.egui_ctx.set_theme(app.theme_pref);
        if args.iter().any(|a| a == "--baseline") {
            app.baseline = Some(Arc::new(platform::collect()));
        }
        if args.iter().any(|a| a == "--deep") {
            app.refresh(&cc.egui_ctx);
            while app.snap.is_none() {
                if let Ok(Msg::Snapshot(s)) = app.rx.recv() {
                    app.refreshing = false;
                    app.snap = Some(Arc::new(*s));
                }
            }
            app.start_deep(&cc.egui_ctx);
        }
        app.refresh(&cc.egui_ctx);
        app
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        if self.refreshing {
            return;
        }
        self.refreshing = true;
        self.last_refresh = Instant::now();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let s = platform::collect();
            let _ = tx.send(Msg::Snapshot(Box::new(s)));
            ctx.request_repaint();
        });
    }

    fn maybe_scan_owners(&mut self, ctx: &egui::Context) {
        if self.owner_scan_running {
            return;
        }
        let Some(snap) = &self.snap else { return };
        let mut pool: Vec<&PoolTag> = snap.pool.iter().collect();
        pool.sort_by_key(|t| std::cmp::Reverse(t.total()));
        let mut want: Vec<(String, [u8; 4])> = pool
            .iter()
            .take(OWNER_SCAN_TOP)
            .filter(|t| !self.owners_requested.contains(&t.tag))
            .map(|t| (t.tag.clone(), t.raw))
            .collect();
        // Also look up anything that is growing, even if small.
        if let Some(base) = &self.baseline {
            let before: HashMap<&str, u64> = base.pool.iter().map(|t| (t.tag.as_str(), t.total())).collect();
            for t in &snap.pool {
                let grew = t.total() as i64 - *before.get(t.tag.as_str()).unwrap_or(&0) as i64;
                if grew > 8 << 20 && !self.owners_requested.contains(&t.tag) && !want.iter().any(|w| w.0 == t.tag) {
                    want.push((t.tag.clone(), t.raw));
                }
            }
        }
        if want.is_empty() {
            return;
        }
        for (t, _) in &want {
            self.owners_requested.insert(t.clone());
        }
        self.owner_scan_running = true;
        self.owner_status = format!("Matching {} pool tags to drivers…", want.len());
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = pooltags::scan(&platform::driver_files(), &want, descriptions());
            let _ = tx.send(Msg::Owners(r));
            ctx.request_repaint();
        });
    }

    fn start_deep(&mut self, ctx: &egui::Context) {
        let Some(snap) = self.snap.clone() else { return };
        self.deep_running = true;
        self.deep_error = None;
        self.deep_progress.store(0, Ordering::Relaxed);
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let prog = self.deep_progress.clone();
        std::thread::spawn(move || {
            let ctx2 = ctx.clone();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                platform::deep_scan(&snap, &|f| {
                    prog.store((f * 1000.0) as u32, Ordering::Relaxed);
                    ctx2.request_repaint_after(Duration::from_millis(100));
                })
            }))
            .unwrap_or_else(|_| Err("Deep Scan crashed. Please send the report to the developer.".into()));
            let _ = tx.send(Msg::Deep(r));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Snapshot(s) => {
                    self.refreshing = false;
                    self.snap = Some(Arc::new(*s));
                    self.maybe_scan_owners(ctx);
                }
                Msg::Owners(r) => {
                    self.owner_scan_running = false;
                    self.owner_status = format!(
                        "Searched {} driver files{}.",
                        r.files_scanned,
                        if r.files_unreadable > 0 { format!(" ({} unreadable)", r.files_unreadable) } else { String::new() }
                    );
                    self.owners.extend(r.owners);
                    self.maybe_scan_owners(ctx);
                }
                Msg::Deep(r) => {
                    self.deep_running = false;
                    match r {
                        Ok(d) => {
                            self.deep = Some(Arc::new(d));
                            self.use_deep = true;
                        }
                        Err(e) => self.deep_error = Some(e),
                    }
                }
            }
        }
    }

    fn breakdown(&self) -> Option<Breakdown> {
        let snap = self.snap.as_ref()?;
        let deep = if self.use_deep { self.deep.as_deref() } else { None };
        Some(breakdown::compute(snap, deep))
    }

    fn set_status(&mut self, s: impl Into<String>) {
        self.status = Some((s.into(), Instant::now()));
    }

    fn report_text(&self) -> Option<String> {
        let snap = self.snap.as_ref()?;
        let bd = self.breakdown()?;
        let f = breakdown::findings(snap, &bd, &self.owners);
        Some(report::text(snap, &bd, &f, &self.owners, self.deep.as_deref()))
    }

    fn save_report(&mut self) {
        let (Some(text), Some(snap)) = (self.report_text(), self.snap.clone()) else { return };
        let json = report::json(&snap, &self.owners, self.deep.as_deref());
        let dir = report_dir();
        let stem = format!("ramwhere-{}-{}", snap.computer_name, snap.taken_at);
        let txt = dir.join(format!("{stem}.txt"));
        let js = dir.join(format!("{stem}.json"));
        match std::fs::write(&txt, text).and_then(|_| std::fs::write(&js, json)) {
            Ok(()) => self.set_status(format!("Saved {} and .json", txt.display())),
            Err(e) => self.set_status(format!("Couldn't save report: {e}")),
        }
    }
}

fn report_dir() -> PathBuf {
    if let Ok(p) = std::env::var("USERPROFILE") {
        let d = PathBuf::from(p).join("Desktop");
        if d.is_dir() {
            return d;
        }
    }
    std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())).unwrap_or_else(|| PathBuf::from("."))
}

fn descriptions() -> &'static HashMap<String, (String, String)> {
    static D: OnceLock<HashMap<String, (String, String)>> = OnceLock::new();
    D.get_or_init(|| {
        let mut m = HashMap::new();
        for p in platform::pooltag_txt_candidates() {
            if p.is_file() {
                for (k, v) in pooltags::load_pooltag_txt(&p) {
                    m.entry(k).or_insert(v);
                }
            }
        }
        m
    })
}

pub fn headless_report(out: &str, deep: bool) -> i32 {
    let snap = platform::collect();
    let mut pool: Vec<&PoolTag> = snap.pool.iter().collect();
    pool.sort_by_key(|t| std::cmp::Reverse(t.total()));
    let want: Vec<(String, [u8; 4])> = pool.iter().take(OWNER_SCAN_TOP).map(|t| (t.tag.clone(), t.raw)).collect();
    let owners = pooltags::scan(&platform::driver_files(), &want, descriptions()).owners;
    let mut deep_res = None;
    let mut deep_err = None;
    if deep {
        match platform::deep_scan(&snap, &|_| {}) {
            Ok(d) => deep_res = Some(d),
            Err(e) => deep_err = Some(e),
        }
    }
    let bd = breakdown::compute(&snap, deep_res.as_ref());
    let f = breakdown::findings(&snap, &bd, &owners);
    let mut text = report::text(&snap, &bd, &f, &owners, deep_res.as_ref());
    if let Some(e) = deep_err {
        text.push_str(&format!("\nDeep Scan failed: {e}\n"));
    }
    let json = report::json(&snap, &owners, deep_res.as_ref());
    let ok = std::fs::write(out, text).is_ok() && std::fs::write(format!("{out}.json"), json).is_ok();
    if ok {
        0
    } else {
        1
    }
}

// ------------------------------------------------------------------ colors

pub fn color_for(key: &str) -> Color32 {
    match key {
        "reserved" => Color32::from_rgb(120, 120, 128),
        "apps" => Color32::from_rgb(66, 133, 244),
        "compression" => Color32::from_rgb(149, 117, 205),
        "vm" => Color32::from_rgb(0, 150, 136),
        "secure" => Color32::from_rgb(92, 107, 192),
        "registry" => Color32::from_rgb(141, 110, 99),
        "nonpaged" => Color32::from_rgb(229, 57, 53),
        "paged" => Color32::from_rgb(251, 140, 0),
        "filecache" => Color32::from_rgb(38, 198, 218),
        "unexplained" => Color32::from_rgb(236, 64, 122),
        "mapped" => Color32::from_rgb(38, 198, 218),
        "shareable" => Color32::from_rgb(236, 64, 122),
        "pagetable" => Color32::from_rgb(192, 202, 51),
        "systempte" => Color32::from_rgb(161, 136, 127),
        "kstack" => Color32::from_rgb(255, 202, 40),
        "session" => Color32::from_rgb(121, 134, 203),
        "metafile" => Color32::from_rgb(255, 112, 67),
        "locked" => Color32::from_rgb(183, 28, 28),
        "awe" => Color32::from_rgb(216, 27, 96),
        "largepage" => Color32::from_rgb(0, 121, 107),
        "other" => Color32::from_rgb(158, 158, 158),
        "modified" => Color32::from_rgb(253, 216, 53),
        "standby" => Color32::from_rgb(129, 199, 132),
        "available" => Color32::from_rgb(129, 199, 132),
        "free" => Color32::from_rgb(56, 142, 60),
        "bad" => Color32::BLACK,
        _ => Color32::GRAY,
    }
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::Warning => Color32::from_rgb(229, 57, 53),
        Severity::Notice => Color32::from_rgb(251, 140, 0),
        Severity::Info => Color32::from_rgb(66, 133, 244),
    }
}

fn ago(ts: u64) -> String {
    let d = platform::mock_now().saturating_sub(ts);
    match d {
        0..=4 => "just now".into(),
        5..=59 => format!("{d} s ago"),
        60..=3599 => format!("{} min ago", d / 60),
        _ => format!("{} h {} min ago", d / 3600, d / 60 % 60),
    }
}

// ------------------------------------------------------------------ UI

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        renderer_started();
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        if self.auto_refresh && self.last_refresh.elapsed().as_secs_f32() >= self.interval {
            self.refresh(&ctx);
        }
        if self.auto_refresh {
            ctx.request_repaint_after(Duration::from_secs_f32(self.interval.max(0.5)));
        }

        let pal = palette(ui);
        let bar_frame = egui::Frame::new().fill(pal.card).inner_margin(egui::Margin::symmetric(16, 10)).stroke(Stroke::new(1.0, pal.card_stroke));
        egui::Panel::top("top").frame(bar_frame).show(ui, |ui| {
            self.top_bar(ui, &ctx);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                for (t, label) in [
                    (Tab::Overview, "Overview"),
                    (Tab::Processes, "Processes"),
                    (Tab::Drivers, "Drivers"),
                    (Tab::Deep, "Deep Scan"),
                    (Tab::Help, "Help"),
                ] {
                    let selected = self.tab == t;
                    let text = RichText::new(label).size(15.0).color(if selected { pal.accent } else { pal.weak });
                    let resp = ui.add(egui::Button::new(text).frame(false).min_size(egui::vec2(0.0, 30.0)));
                    if selected {
                        let r = resp.rect;
                        ui.painter().line_segment([egui::pos2(r.left() + 4.0, r.bottom() + 1.0), egui::pos2(r.right() - 4.0, r.bottom() + 1.0)], Stroke::new(2.5, pal.accent));
                    }
                    if resp.clicked() {
                        self.tab = t;
                    }
                    ui.add_space(10.0);
                }
            });
        });

        let status_frame = egui::Frame::new().fill(pal.card).inner_margin(egui::Margin::symmetric(16, 6)).stroke(Stroke::new(1.0, pal.card_stroke));
        egui::Panel::bottom("status").frame(status_frame).show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(s) = &self.snap {
                    ui.weak(format!("{} · {} · snapshot {}", s.computer_name, s.os_version, ago(s.taken_at)));
                    if !s.elevated {
                        ui.colored_label(severity_color(Severity::Notice), "Not elevated: some numbers are limited");
                    }
                }
                if let Some((msg, t)) = &self.status {
                    if t.elapsed() < Duration::from_secs(12) {
                        ui.separator();
                        ui.label(msg);
                    }
                }
            });
        });

        let central = egui::Frame::new().fill(pal.bg).inner_margin(egui::Margin::symmetric(18, 14));
        egui::CentralPanel::default().frame(central).show(ui, |ui| {
            if self.snap.is_none() {
                ui.centered_and_justified(|ui| ui.spinner());
                return;
            }
            match self.tab {
                Tab::Overview => self.overview(ui),
                Tab::Processes => self.processes(ui),
                Tab::Drivers => self.drivers(ui),
                Tab::Deep => self.deep_tab(ui, &ctx),
                Tab::Help => help(ui),
            }
        });
    }
}

impl App {
    fn top_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let pal = palette(ui);
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), Sense::hover());
            let segs = [(0.0, 0.4, "apps"), (0.4, 0.68, "nonpaged"), (0.68, 0.84, "paged"), (0.84, 1.0, "standby")];
            for (a, b, k) in segs {
                let seg = egui::Rect::from_min_max(egui::pos2(r.left() + r.width() * a, r.top() + 4.0), egui::pos2(r.left() + r.width() * b, r.bottom() - 4.0));
                ui.painter().rect_filled(seg, 0.0, color_for(k));
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new("RAM Where").size(19.0).strong());
                ui.label(RichText::new("Where every byte of memory is going").size(11.5).color(pal.weak));
            });
            ui.add_space(14.0);
            if ui.add_enabled(!self.refreshing, egui::Button::new("Refresh")).clicked() {
                self.refresh(ctx);
            }
            ui.checkbox(&mut self.auto_refresh, "Auto");
            if self.auto_refresh {
                egui::ComboBox::from_id_salt("interval")
                    .width(60.0)
                    .selected_text(format!("{} s", self.interval))
                    .show_ui(ui, |ui| {
                        for v in [1.0, 3.0, 10.0, 30.0] {
                            ui.selectable_value(&mut self.interval, v, format!("{v} s"));
                        }
                    });
            }
            ui.separator();
            let base_label = match &self.baseline {
                Some(b) => format!("Baseline set {}", ago(b.taken_at)),
                None => "Set baseline".into(),
            };
            if ui.button(base_label).on_hover_text("Remember these numbers so every table shows how much each item has grown since now. Leave it running to catch a leak.").clicked() {
                self.baseline = self.snap.clone();
            }
            if self.baseline.is_some() && ui.small_button("Clear").on_hover_text("Clear baseline").clicked() {
                self.baseline = None;
            }
            ui.separator();
            if ui.button("Copy report").on_hover_text("Copies a plain-text summary to the clipboard").clicked() {
                if let Some(t) = self.report_text() {
                    ui.ctx().copy_text(t);
                    self.set_status("Report copied to clipboard");
                }
            }
            if ui.button("Save report").on_hover_text("Saves a .txt summary and a full .json to your Desktop").clicked() {
                self.save_report();
            }
            let elevated = self.snap.as_ref().is_some_and(|s| s.elevated);
            if !elevated && !platform::is_simulated() {
                ui.separator();
                let b = egui::Button::new(RichText::new("Restart as administrator").strong().color(Color32::WHITE)).fill(pal.accent);
                if ui.add(b).on_hover_text("Unlocks the standby/modified breakdown and Deep Scan").clicked() {
                    match platform::relaunch_elevated() {
                        Ok(()) => std::process::exit(0),
                        Err(e) => self.set_status(e),
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let before = self.theme_pref;
                for (pref, label) in [(egui::ThemePreference::Dark, "Dark"), (egui::ThemePreference::Light, "Light"), (egui::ThemePreference::System, "System")] {
                    ui.selectable_value(&mut self.theme_pref, pref, label);
                }
                ui.label(RichText::new("Theme").color(pal.weak));
                if self.theme_pref != before {
                    ui.ctx().set_theme(self.theme_pref);
                }
            });
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let snap = self.snap.clone().unwrap();
        let Some(bd) = self.breakdown() else { return };
        let findings = breakdown::findings(&snap, &bd, &self.owners);
        let base_bd = self.baseline.as_ref().map(|b| breakdown::compute(b, None));
        let base_map: HashMap<&str, u64> = base_bd.as_ref().map(|b| b.categories.iter().map(|c| (c.key, c.bytes)).collect()).unwrap_or_default();

        let pal = palette(ui);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // Leave room for the scroll bar so cards don't run under it.
            ui.set_max_width(ui.available_width() - 14.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(12.0, 12.0);
                let gap = bd.in_use.saturating_sub(bd.task_manager_sum);
                stat(ui, "Installed RAM", &fmt_bytes(bd.installed), "Physical memory in the machine", None);
                stat(ui, "In use", &fmt_bytes(bd.in_use), "Same idea as Task Manager's \"In use\"", None);
                stat(ui, "Task Manager's list adds up to", &fmt_bytes(bd.task_manager_sum), "Sum of the Memory column across every process", None);
                stat(ui, "Hidden from Task Manager", &fmt_bytes(gap), "The gap this tool explains", Some(color_for("unexplained")));
                stat(ui, "Committed", &format!("{} / {}", fmt_bytes(snap.commit_total), fmt_bytes(snap.commit_limit)), "Memory promised to programs, against RAM + pagefile", None);
            });
            ui.add_space(14.0);

            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Memory map").size(16.0).strong());
                    ui.label(RichText::new(if bd.from_deep_scan { "from Deep Scan page walk" } else { "from live counters" }).color(pal.weak));
                    if self.deep.is_some() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.checkbox(&mut self.use_deep, "Use Deep Scan results");
                            if let Some(d) = &self.deep {
                                ui.label(RichText::new(format!("scanned {}", ago(d.taken_at))).color(pal.weak));
                            }
                        });
                    }
                });
                ui.add_space(6.0);
                stacked_bar(ui, &bd);
            });
            ui.add_space(14.0);

            for f in &findings {
                finding_card(ui, f);
            }
            ui.add_space(10.0);

            let groups = [
                (Group::InUse, "In use", "Taken right now"),
                (Group::Reclaimable, "Cache & reclaimable", "Counts as available: Windows reuses it on demand"),
                (Group::Free, "Free", ""),
                (Group::Reserved, "Not usable by Windows", ""),
            ];
            for (g, title, sub) in groups {
                let mut cats: Vec<&Category> = bd.categories.iter().filter(|c| c.group == g && (c.bytes > 0 || c.key == "unexplained")).collect();
                if cats.is_empty() {
                    continue;
                }
                cats.sort_by_key(|c| std::cmp::Reverse(c.bytes));
                let total: u64 = cats.iter().map(|c| c.bytes).sum();
                let biggest = cats.first().map(|c| c.bytes).unwrap_or(1).max(1);
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(title).size(16.0).strong());
                        ui.label(RichText::new(sub).color(pal.weak));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(fmt_bytes(total)).size(16.0).strong());
                        });
                    });
                    ui.add_space(4.0);
                    for c in cats {
                        ui.separator();
                        let delta = base_map.get(c.key).filter(|_| !bd.from_deep_scan).map(|&b| c.bytes as i64 - b as i64);
                        category_row(ui, c, bd.installed, biggest, delta);
                    }
                });
                ui.add_space(12.0);
            }
            if !snap.warnings.is_empty() {
                for w in &snap.warnings {
                    ui.colored_label(severity_color(Severity::Notice), format!("Note: {w}"));
                }
            }
        });
    }

    fn processes(&mut self, ui: &mut egui::Ui) {
        let snap = self.snap.clone().unwrap();
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.proc_filter).desired_width(200.0));
            ui.checkbox(&mut self.group_procs, "Group by name");
            ui.separator();
            let total_private: u64 = snap.procs.iter().map(|p| p.private_ws).sum();
            ui.weak(format!("{} processes · {} private in RAM", snap.procs.len(), fmt_bytes(total_private)));
        });
        ui.weak("\"Private\" is what Task Manager shows. \"Shared / mapped\" is DLLs and files the process maps, also counted by every other process that maps them. \"Committed\" includes memory that's been compressed or paged out.");
        ui.add_space(4.0);

        struct Row {
            name: String,
            pid: String,
            count: usize,
            private: u64,
            shared: u64,
            ws: u64,
            commit: u64,
            threads: u64,
            handles: u64,
            delta: Option<i64>,
            special: bool,
        }
        let shown = |p: &ProcInfo| if matches!(special_kind(&p.name), Some(SpecialProc::MemoryCompression | SpecialProc::SecureSystem | SpecialProc::Registry)) { p.ws } else { p.private_ws };
        let base: Option<HashMap<(u32, &str), u64>> = self.baseline.as_ref().map(|b| b.procs.iter().map(|p| ((p.pid, p.name.as_str()), shown(p))).collect());
        let filter = self.proc_filter.to_lowercase();
        let mut rows: Vec<Row> = Vec::new();
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for p in &snap.procs {
            if !filter.is_empty() && !p.name.to_lowercase().contains(&filter) && !p.pid.to_string().contains(&filter) {
                continue;
            }
            let special = special_kind(&p.name).is_some();
            let private = shown(p);
            let delta = base.as_ref().map(|b| private as i64 - *b.get(&(p.pid, p.name.as_str())).unwrap_or(&0) as i64);
            let r = Row {
                name: p.name.clone(),
                pid: p.pid.to_string(),
                count: 1,
                private,
                shared: p.shared_ws().min(p.ws.saturating_sub(private)),
                ws: p.ws,
                commit: p.private_commit,
                threads: p.threads as u64,
                handles: p.handles as u64,
                delta,
                special,
            };
            if self.group_procs {
                if let Some(&i) = by_name.get(&p.name.to_lowercase()) {
                    let g = &mut rows[i];
                    g.count += 1;
                    g.pid = format!("×{}", g.count);
                    g.private += r.private;
                    g.shared += r.shared;
                    g.ws += r.ws;
                    g.commit += r.commit;
                    g.threads += r.threads;
                    g.handles += r.handles;
                    g.delta = g.delta.zip(r.delta).map(|(a, b)| a + b);
                    continue;
                }
                by_name.insert(p.name.to_lowercase(), rows.len());
            }
            rows.push(r);
        }
        let (col, desc) = self.proc_sort;
        rows.sort_by(|a, b| {
            let o = match col {
                ProcCol::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                ProcCol::Pid => a.pid.parse::<u32>().unwrap_or(0).cmp(&b.pid.parse::<u32>().unwrap_or(0)),
                ProcCol::Private => a.private.cmp(&b.private),
                ProcCol::Shared => a.shared.cmp(&b.shared),
                ProcCol::Ws => a.ws.cmp(&b.ws),
                ProcCol::Commit => a.commit.cmp(&b.commit),
                ProcCol::Threads => a.threads.cmp(&b.threads),
                ProcCol::Handles => a.handles.cmp(&b.handles),
                ProcCol::Delta => a.delta.unwrap_or(0).cmp(&b.delta.unwrap_or(0)),
            };
            if desc {
                o.reverse()
            } else {
                o
            }
        });

        let has_delta = self.baseline.is_some();
        let mut sort = self.proc_sort;
        let mut table = TableBuilder::new(ui)
            .id_salt("procs")
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(260.0).at_least(120.0).clip(true))
            .column(Column::initial(70.0))
            .columns(Column::initial(110.0), 4)
            .columns(Column::initial(80.0), 2);
        if has_delta {
            table = table.column(Column::initial(110.0));
        }
        table
            .header(26.0, |mut h| {
                let mut cols = vec![
                    (ProcCol::Name, "Name"),
                    (ProcCol::Pid, "PID"),
                    (ProcCol::Private, "Private (RAM)"),
                    (ProcCol::Shared, "Shared / mapped"),
                    (ProcCol::Ws, "Total working set"),
                    (ProcCol::Commit, "Committed"),
                    (ProcCol::Threads, "Threads"),
                    (ProcCol::Handles, "Handles"),
                ];
                if has_delta {
                    cols.push((ProcCol::Delta, "Δ private"));
                }
                for (c, label) in cols {
                    h.col(|ui| sort_header(ui, label, c, &mut sort));
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let r = &rows[row.index()];
                    row.col(|ui| {
                        if r.special {
                            ui.label(RichText::new("OS").small().color(Color32::WHITE).background_color(Color32::from_rgb(92, 107, 192)))
                                .on_hover_text("Part of Windows itself; Task Manager hides or understates this one.");
                        }
                        ui.label(&r.name);
                    });
                    row.col(|ui| {
                        ui.weak(&r.pid);
                    });
                    for v in [r.private, r.shared, r.ws, r.commit] {
                        row.col(|ui| num(ui, &fmt_bytes(v)));
                    }
                    for v in [r.threads, r.handles] {
                        row.col(|ui| num(ui, &v.to_string()));
                    }
                    if has_delta {
                        row.col(|ui| delta_label(ui, r.delta.unwrap_or(0)));
                    }
                });
            });
        self.proc_sort = sort;
    }

    fn drivers(&mut self, ui: &mut egui::Ui) {
        let snap = self.snap.clone().unwrap();
        ui.horizontal_wrapped(|ui| {
            stat(ui, "Nonpaged pool", &fmt_bytes(snap.nonpaged_pool), "Kernel memory that is always in RAM", Some(color_for("nonpaged")));
            stat(ui, "Paged pool", &fmt_bytes(snap.paged_pool), "Kernel memory that can be paged out", Some(color_for("paged")));
        });
        ui.weak(
            "Drivers label every kernel allocation with a 4-letter tag. This tab lists the tags and searches every installed driver file \
to find who uses each one. A tag that keeps growing after you set a baseline is a leak; its driver is the culprit.",
        );
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.pool_filter).desired_width(160.0));
            ui.separator();
            if self.owner_scan_running {
                ui.spinner();
            }
            ui.weak(&self.owner_status);
            if descriptions().is_empty() {
                ui.weak("· Tip: drop Microsoft's pooltag.txt next to the exe for more descriptions");
            }
        });
        ui.add_space(4.0);

        let base: Option<HashMap<&str, u64>> = self.baseline.as_ref().map(|b| b.pool.iter().map(|t| (t.tag.as_str(), t.total())).collect());
        let filter = self.pool_filter.to_lowercase();
        let empty = TagOwner::default();
        let mut rows: Vec<(&PoolTag, &TagOwner, Option<i64>)> = snap
            .pool
            .iter()
            .map(|t| {
                let o = self.owners.get(&t.tag).unwrap_or(&empty);
                let d = base.as_ref().map(|b| t.total() as i64 - *b.get(t.tag.as_str()).unwrap_or(&0) as i64);
                (t, o, d)
            })
            .filter(|(t, o, _)| {
                filter.is_empty()
                    || t.tag.to_lowercase().contains(&filter)
                    || o.drivers.iter().any(|d| d.to_lowercase().contains(&filter))
                    || o.description.as_ref().is_some_and(|d| d.to_lowercase().contains(&filter))
            })
            .collect();
        let (col, desc) = self.pool_sort;
        rows.sort_by(|a, b| {
            let o = match col {
                PoolCol::Tag => a.0.tag.cmp(&b.0.tag),
                PoolCol::Nonpaged => a.0.nonpaged.cmp(&b.0.nonpaged),
                PoolCol::Paged => a.0.paged.cmp(&b.0.paged),
                PoolCol::Total => a.0.total().cmp(&b.0.total()),
                PoolCol::Allocs => (a.0.paged_outstanding + a.0.nonpaged_outstanding).cmp(&(b.0.paged_outstanding + b.0.nonpaged_outstanding)),
                PoolCol::Delta => a.2.unwrap_or(0).cmp(&b.2.unwrap_or(0)),
                PoolCol::Owner => a.1.drivers.first().cmp(&b.1.drivers.first()),
            };
            if desc {
                o.reverse()
            } else {
                o
            }
        });

        let has_delta = self.baseline.is_some();
        let mut sort = self.pool_sort;
        let mut table = TableBuilder::new(ui)
            .id_salt("pool")
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(70.0))
            .columns(Column::initial(100.0), 3)
            .column(Column::initial(90.0));
        if has_delta {
            table = table.column(Column::initial(100.0));
        }
        table = table.column(Column::initial(230.0).clip(true)).column(Column::remainder().clip(true));
        table
            .header(26.0, |mut h| {
                let mut cols = vec![
                    (PoolCol::Tag, "Tag"),
                    (PoolCol::Nonpaged, "Nonpaged"),
                    (PoolCol::Paged, "Paged"),
                    (PoolCol::Total, "Total"),
                    (PoolCol::Allocs, "Allocations"),
                ];
                if has_delta {
                    cols.push((PoolCol::Delta, "Δ since baseline"));
                }
                cols.push((PoolCol::Owner, "Likely driver"));
                for (c, label) in cols {
                    h.col(|ui| sort_header(ui, label, c, &mut sort));
                }
                h.col(|ui| {
                    ui.strong("Description");
                });
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let (t, o, d) = rows[row.index()];
                    row.col(|ui| {
                        ui.label(RichText::new(format!("'{}'", t.tag)).monospace().strong());
                    });
                    for v in [t.nonpaged, t.paged, t.total()] {
                        row.col(|ui| num(ui, &fmt_bytes(v)));
                    }
                    row.col(|ui| num(ui, &(t.paged_outstanding + t.nonpaged_outstanding).to_string()));
                    if has_delta {
                        row.col(|ui| delta_label(ui, d.unwrap_or(0)));
                    }
                    row.col(|ui| {
                        if o.drivers.is_empty() {
                            ui.weak(if self.owners.contains_key(&t.tag) { "not found" } else { "…" });
                        } else {
                            ui.label(o.drivers[0].as_str()).on_hover_text(format!("Candidates: {}", o.drivers.join(", ")));
                            if o.drivers.len() > 1 {
                                ui.weak(format!("+{}", o.drivers.len() - 1));
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.weak(o.description.as_deref().unwrap_or(""));
                    });
                });
            });
        self.pool_sort = sort;
    }

    fn deep_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let elevated = self.snap.as_ref().is_some_and(|s| s.elevated);
        ui.label(
            "Deep Scan reads the memory manager's record of every physical page of RAM and what it is used for, \
the same source RAMMap uses. Every page gets counted exactly once, so the result adds up to the RAM in the machine. \
It takes a few seconds and needs administrator rights.",
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let can = elevated && !self.deep_running;
            if ui.add_enabled(can, egui::Button::new(RichText::new("Run Deep Scan").size(16.0))).clicked() {
                self.start_deep(ctx);
            }
            if !elevated {
                ui.colored_label(severity_color(Severity::Notice), "Needs administrator — use \"Restart as administrator\" at the top.");
            }
            if self.deep_running {
                let p = self.deep_progress.load(Ordering::Relaxed) as f32 / 1000.0;
                ui.add(egui::ProgressBar::new(p).show_percentage().desired_width(300.0));
            }
        });
        if let Some(e) = &self.deep_error {
            ui.colored_label(severity_color(Severity::Warning), e);
        }
        let Some(d) = self.deep.clone() else { return };
        let pal = palette(ui);
        ui.add_space(8.0);
        ui.label(RichText::new(format!(
            "Scanned {} pages ({}) in {} ms, {}.",
            d.pages_scanned,
            fmt_bytes(d.pages_scanned * d.page_size),
            d.elapsed_ms,
            ago(d.taken_at)
        )).color(pal.weak));
        for n in &d.notes {
            ui.label(RichText::new(format!("• {n}")).color(pal.weak));
        }
        ui.add_space(8.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(ui.available_width() - 14.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Every page, by what it's used for").size(16.0).strong());
                ui.label(RichText::new("Active = in use now · Standby = cached, free to reuse · Modified = waiting to be written out").color(pal.weak));
                ui.add_space(6.0);
                let mut order: Vec<usize> = (0..16).filter(|&u| d.by_use_list[u][2..5].iter().sum::<u64>() + d.by_use_list[u][6] + d.by_use_list[u][7] > 0).collect();
                let in_ram = |u: usize| -> u64 { let r = &d.by_use_list[u]; r[2] + r[3] + r[4] + r[6] + r[7] };
                order.sort_by_key(|&u| std::cmp::Reverse(in_ram(u)));
                let biggest = order.first().map(|&u| in_ram(u)).unwrap_or(1).max(1);
                let mut rows: Vec<(String, &'static str, [u64; 4])> = order
                    .iter()
                    .map(|&u| {
                        let r = &d.by_use_list[u];
                        (PFN_USES[u].to_string(), pfn_color_key(u), [r[6] + r[7], r[2], r[3] + r[4], in_ram(u)])
                    })
                    .collect();
                let free = d.list_total(0) + d.list_total(1);
                rows.push(("Free & zeroed".into(), "free", [0, 0, 0, free]));
                if d.list_total(5) > 0 {
                    rows.push(("Bad pages".into(), "bad", [0, 0, 0, d.list_total(5)]));
                }
                TableBuilder::new(ui)
                    .id_salt("deepuse")
                    .striped(true)
                    .vscroll(false)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(300.0).clip(true))
                    .columns(Column::initial(100.0), 4)
                    .column(Column::remainder().at_least(120.0))
                    .header(26.0, |mut h| {
                        for t in ["Use", "Active", "Standby", "Modified", "Total"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                        h.col(|_| {});
                    })
                    .body(|mut body| {
                        for (name, key, v) in &rows {
                            body.row(24.0, |mut row| {
                                row.col(|ui| {
                                    let (r, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), Sense::hover());
                                    ui.painter().rect_filled(r, 3.0, color_for(key));
                                    ui.label(name.as_str());
                                });
                                for x in v {
                                    row.col(|ui| num(ui, &fmt_bytes(*x)));
                                }
                                row.col(|ui| {
                                    let w = ui.available_width().min(220.0);
                                    let (bar, _) = ui.allocate_exact_size(egui::vec2(w, 8.0), Sense::hover());
                                    ui.painter().rect_filled(bar, 4.0, pal.track);
                                    let mut fill = bar;
                                    fill.set_width(bar.width() * (v[3] as f32 / biggest as f32).clamp(0.0, 1.0));
                                    ui.painter().rect_filled(fill, 4.0, color_for(key));
                                });
                            });
                        }
                    });
            });
            if !d.procs.is_empty() {
                ui.add_space(14.0);
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("Private pages per process, including cached").size(16.0).strong());
                    ui.label(RichText::new("Unlike Task Manager this includes each process's pages sitting on the standby and modified lists.").color(pal.weak));
                    ui.add_space(6.0);
                    let mut procs: Vec<&DeepProc> = d.procs.iter().filter(|p| p.active + p.standby + p.modified > 0).collect();
                    procs.sort_by_key(|p| std::cmp::Reverse(p.active + p.standby + p.modified));
                    TableBuilder::new(ui)
                        .id_salt("deepprocs")
                        .striped(true)
                        .vscroll(false)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(300.0).clip(true))
                        .column(Column::initial(70.0))
                        .columns(Column::initial(100.0), 4)
                        .header(26.0, |mut h| {
                            for t in ["Process", "PID", "Active", "Standby", "Modified", "Total"] {
                                h.col(|ui| {
                                    ui.strong(t);
                                });
                            }
                        })
                        .body(|mut body| {
                            for p in procs.iter().take(80) {
                                body.row(22.0, |mut row| {
                                    row.col(|ui| {
                                        ui.label(&p.name);
                                    });
                                    row.col(|ui| {
                                        ui.weak(p.pid.to_string());
                                    });
                                    for v in [p.active, p.standby, p.modified, p.active + p.standby + p.modified] {
                                        row.col(|ui| num(ui, &fmt_bytes(v)));
                                    }
                                });
                            }
                        });
                });
            }
        });
    }
}

fn pfn_color_key(u: usize) -> &'static str {
    ["apps", "mapped", "shareable", "pagetable", "paged", "nonpaged", "systempte", "session", "metafile", "awe", "locked", "kstack", "largepage"]
        .get(u)
        .copied()
        .unwrap_or("other")
}

fn stat(ui: &mut egui::Ui, title: &str, value: &str, hint: &str, accent: Option<Color32>) {
    let pal = palette(ui);
    card(ui, |ui| {
        ui.set_min_width(190.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(title).color(pal.weak));
            ui.label(RichText::new(value).size(24.0).strong().color(accent.unwrap_or(pal.text)));
        });
    })
    .response
    .on_hover_text(hint);
}

fn category_row(ui: &mut egui::Ui, c: &Category, installed: u64, biggest: u64, delta: Option<i64>) {
    let pal = palette(ui);
    let pct = c.bytes as f64 * 100.0 / installed.max(1) as f64;
    let width = ui.available_width();
    let (row, _) = ui.allocate_exact_size(egui::vec2(width, 24.0), Sense::hover());
    let p = ui.painter();
    let cy = row.center().y;
    p.rect_filled(egui::Rect::from_center_size(egui::pos2(row.left() + 6.0, cy), egui::vec2(12.0, 12.0)), 3.0, color_for(c.key));
    let body = egui::FontId::proportional(14.5);
    let label = p.layout_no_wrap(c.label.clone(), body.clone(), pal.text);
    let label_w = label.size().x;
    p.galley(egui::pos2(row.left() + 22.0, cy - label.size().y / 2.0), label, pal.text);
    let tag = match c.confidence {
        Confidence::Estimate => Some("estimate"),
        Confidence::Remainder => Some("remainder"),
        Confidence::Exact => None,
    };
    if let Some(t) = tag {
        let g = p.layout_no_wrap(t.to_string(), egui::FontId::proportional(11.0), pal.weak);
        let r = egui::Rect::from_min_size(egui::pos2(row.left() + 32.0 + label_w, cy - 9.0), egui::vec2(g.size().x + 12.0, 18.0));
        p.rect_filled(r, 9.0, pal.track);
        p.galley(egui::pos2(r.left() + 6.0, cy - g.size().y / 2.0), g, pal.weak);
    }
    // Right side, from the edge inwards: size, percent, relative bar, delta.
    let mut x = row.right();
    let size = p.layout_no_wrap(fmt_bytes(c.bytes), egui::FontId::monospace(14.0), pal.text);
    p.galley(egui::pos2(x - size.size().x, cy - size.size().y / 2.0), size, pal.text);
    x -= 84.0;
    let pc = p.layout_no_wrap(format!("{pct:.1}%"), egui::FontId::proportional(13.0), pal.weak);
    let pc_w = pc.size().x;
    p.galley(egui::pos2(x - 44.0 + (44.0 - pc_w), cy - pc.size().y / 2.0), pc, pal.weak);
    x -= 44.0 + 14.0;
    let bar_w = (width * 0.16).clamp(60.0, 180.0);
    let bar = egui::Rect::from_min_size(egui::pos2(x - bar_w, cy - 4.0), egui::vec2(bar_w, 8.0));
    p.rect_filled(bar, 4.0, pal.track);
    let mut fill = bar;
    fill.set_width((bar_w * (c.bytes as f32 / biggest as f32)).clamp(0.0, bar_w));
    p.rect_filled(fill, 4.0, color_for(c.key));
    x -= bar_w + 14.0;
    if let Some(d) = delta.filter(|d| d.unsigned_abs() >= 1 << 20) {
        let col = if d > 1 << 20 {
            Color32::from_rgb(229, 57, 53)
        } else if d < -(1 << 20) {
            Color32::from_rgb(67, 160, 71)
        } else {
            pal.weak
        };
        let g = p.layout_no_wrap(fmt_delta(d), egui::FontId::monospace(13.0), col);
        p.galley(egui::pos2(x - g.size().x, cy - g.size().y / 2.0), g, col);
    }
    ui.horizontal(|ui| {
        ui.add_space(22.0);
        ui.add(egui::Label::new(RichText::new(&c.explain).size(12.5).color(pal.weak)).wrap());
    });
}

fn finding_card(ui: &mut egui::Ui, f: &Finding) {
    let pal = palette(ui);
    let c = severity_color(f.severity);
    let resp = egui::Frame::new()
        .fill(pal.card)
        .stroke(Stroke::new(1.0, pal.card_stroke))
        .corner_radius(10.0)
        .inner_margin(egui::Margin { left: 20, right: 14, top: 10, bottom: 10 })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let label = match f.severity {
                Severity::Warning => " PROBLEM ",
                Severity::Notice => " WORTH A LOOK ",
                Severity::Info => " INFO ",
            };
            let mut job = egui::text::LayoutJob::default();
            job.append(label, 0.0, egui::TextFormat { font_id: egui::FontId::proportional(11.5), color: c, background: c.gamma_multiply(0.18), valign: egui::Align::Center, ..Default::default() });
            job.append(&f.title, 10.0, egui::TextFormat { font_id: egui::FontId::proportional(15.0), color: pal.text, valign: egui::Align::Center, ..Default::default() });
            ui.add(egui::Label::new(job).wrap());
            if !f.detail.is_empty() {
                ui.add(egui::Label::new(RichText::new(&f.detail).color(pal.weak)).wrap());
            }
        })
        .response;
    let r = resp.rect;
    let stripe = egui::Rect::from_min_max(egui::pos2(r.left() + 1.0, r.top() + 1.0), egui::pos2(r.left() + 6.0, r.bottom() - 1.0));
    ui.painter().rect_filled(stripe, egui::CornerRadius { nw: 9, sw: 9, ne: 0, se: 0 }, c);
    ui.add_space(8.0);
}

fn stacked_bar(ui: &mut egui::Ui, bd: &Breakdown) {
    let pal = palette(ui);
    let height = 44.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    let total: u64 = bd.categories.iter().map(|c| c.bytes).sum::<u64>().max(1);
    let mut order: Vec<&Category> = bd.categories.iter().filter(|c| c.bytes > 0).collect();
    let rank = |g: Group| match g {
        Group::InUse => 0,
        Group::Reclaimable => 1,
        Group::Free => 2,
        Group::Reserved => 3,
    };
    order.sort_by_key(|c| (rank(c.group), std::cmp::Reverse(c.bytes)));
    ui.painter().rect_filled(rect, 8.0, pal.track);
    let painter = ui.painter().with_clip_rect(rect);
    // Clip the segments to a rounded track by drawing the outer ones with rounded corners.
    let mut x = rect.left();
    let n = order.len();
    for (i, c) in order.iter().enumerate() {
        let w = rect.width() * c.bytes as f32 / total as f32;
        let seg = egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(w, height));
        let cr = egui::CornerRadius {
            nw: if i == 0 { 8 } else { 0 },
            sw: if i == 0 { 8 } else { 0 },
            ne: if i + 1 == n { 8 } else { 0 },
            se: if i + 1 == n { 8 } else { 0 },
        };
        let col = color_for(c.key);
        painter.rect_filled(seg, cr, col);
        if i > 0 {
            painter.line_segment([seg.left_top(), seg.left_bottom()], Stroke::new(1.5, pal.card));
        }
        if w > 64.0 {
            painter.text(seg.center(), egui::Align2::CENTER_CENTER, fmt_bytes(c.bytes), egui::FontId::proportional(13.0), text_on(col));
        }
        let resp = ui.interact(seg, ui.scope_id().with(c.key), Sense::hover());
        if resp.hovered() {
            painter.rect_stroke(seg.shrink(1.0), cr, Stroke::new(2.0, pal.text), egui::StrokeKind::Inside);
        }
        resp.on_hover_text(format!("{}: {}\n{}", c.label, fmt_bytes(c.bytes), c.explain));
        x += w;
    }
    // Legend under the bar.
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        for c in &order {
            let mut job = egui::text::LayoutJob::default();
            job.append("\u{2002}\u{2002}", 0.0, egui::TextFormat { font_id: egui::FontId::proportional(9.0), background: color_for(c.key), valign: egui::Align::Center, ..Default::default() });
            job.append(&c.label, 6.0, egui::TextFormat { font_id: egui::FontId::proportional(12.5), color: pal.weak, ..Default::default() });
            ui.label(job);
        }
    });
}

fn num(ui: &mut egui::Ui, s: &str) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.label(RichText::new(s).monospace());
    });
}

fn delta_label(ui: &mut egui::Ui, d: i64) {
    let c = if d > 1 << 20 {
        Color32::from_rgb(229, 57, 53)
    } else if d < -(1 << 20) {
        Color32::from_rgb(67, 160, 71)
    } else {
        ui.visuals().weak_text_color()
    };
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.label(RichText::new(fmt_delta(d)).monospace().color(c));
    });
}

fn sort_header<C: PartialEq + Copy>(ui: &mut egui::Ui, label: &str, col: C, sort: &mut (C, bool)) {
    let active = sort.0 == col;
    let pal = palette(ui);
    let text = RichText::new(label).strong().color(if active { pal.accent } else { pal.text });
    let resp = ui.add(egui::Button::new(text).frame(false));
    if active {
        let r = resp.rect;
        let c = egui::pos2(r.right() + 8.0, r.center().y);
        let pts = if sort.1 {
            vec![egui::pos2(c.x - 4.0, c.y - 2.0), egui::pos2(c.x + 4.0, c.y - 2.0), egui::pos2(c.x, c.y + 3.0)]
        } else {
            vec![egui::pos2(c.x - 4.0, c.y + 2.0), egui::pos2(c.x + 4.0, c.y + 2.0), egui::pos2(c.x, c.y - 3.0)]
        };
        ui.painter().add(egui::Shape::convex_polygon(pts, pal.accent, Stroke::NONE));
    }
    if resp.clicked() {
        if active {
            sort.1 = !sort.1;
        } else {
            *sort = (col, true);
        }
    }
}

fn help(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(900.0);
        let sections: [(&str, &str); 9] = [
            ("Why doesn't Task Manager add up?", "Task Manager's Memory column shows each process's private working set: pages only that process uses, and only those in RAM right now. It leaves out the kernel and drivers, the Memory Compression store, shared DLLs and mapped files, the file cache, page tables and VBS. On a typical work laptop these add up to several gigabytes."),
            ("Standby is not \"used\"", "Windows fills spare RAM with a cache of recently used files and pages (the standby list). It's handed back instantly when a program needs memory, so it counts as available. A small \"free\" number is normal and healthy."),
            ("Memory Compression", "Instead of writing idle app memory to the pagefile, Windows compresses it and keeps it in a hidden process called Memory Compression. A big number means apps have allocated a lot they aren't actively using. Look at the Committed column in Processes to see who."),
            ("Nonpaged / paged pool", "Memory the kernel and drivers allocate for themselves. It's tagged with a 4-character tag per allocation type. Antivirus/EDR, DLP, VPN, network, storage and graphics drivers are the usual heavy users, and a leaking driver shows up as a tag that only ever grows. Set a baseline, leave the app running, then sort the Drivers tab by Δ."),
            ("Shared / mapped memory", "DLLs, EXEs and memory-mapped files are shared between every process that uses them, so no single process \"owns\" them and Task Manager counts none of them. Browsers and Electron apps (Teams, Slack, VS Code) also use big shared memory sections."),
            ("Hardware reserved", "RAM the firmware keeps for itself or gives to integrated graphics before Windows starts. You can sometimes change the graphics share in the BIOS/UEFI."),
            ("Virtual machines / WSL2", "WSL2, Docker Desktop, Windows Sandbox and Hyper-V VMs run in vmmem processes. `wsl --shutdown` releases WSL2 memory; `.wslconfig` caps it."),
            ("Secure System / VBS", "With virtualization-based security (Credential Guard, memory integrity / HVCI), part of Windows runs in an isolated secure kernel. Its memory shows as Secure System, and some is held by the hypervisor and never visible to Windows at all."),
            ("Deep Scan", "Reads the page frame database: one entry per physical page saying what it's used for (process private, mapped file, page table, pool, driver locked, and so on) and which list it's on. Because every page is counted exactly once, nothing can hide. Needs administrator rights."),
        ];
        for (title, body) in sections {
            ui.add_space(8.0);
            ui.label(RichText::new(title).strong().size(16.0));
            ui.label(body);
        }
        ui.add_space(12.0);
        ui.weak(format!("RAM Where v{}. Command line: --report <file> [--deep] writes a text + JSON report without opening a window; --glow uses OpenGL instead of DirectX.", env!("CARGO_PKG_VERSION")));
    });
}
