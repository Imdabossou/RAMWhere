//! Plain-text and JSON reports, for pasting into a ticket or chat.

use crate::breakdown::{fmt_bytes, Breakdown, Finding, Severity};
use crate::model::*;
use std::collections::HashMap;
use std::fmt::Write;

pub fn text(snap: &Snapshot, bd: &Breakdown, findings: &[Finding], owners: &HashMap<String, TagOwner>, deep: Option<&DeepScan>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "RAMWhere report v{}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(s, "{} | {} | admin: {} | VBS: {}", snap.computer_name, snap.os_version, snap.elevated, snap.vbs_running.map(|v| v.to_string()).unwrap_or("?".into()));
    let _ = writeln!(
        s,
        "Installed {} | usable {} | in use {} | Task Manager column total {} | commit {} / {}",
        fmt_bytes(bd.installed),
        fmt_bytes(snap.visible_total),
        fmt_bytes(bd.in_use),
        fmt_bytes(bd.task_manager_sum),
        fmt_bytes(snap.commit_total),
        fmt_bytes(snap.commit_limit)
    );
    let _ = writeln!(s, "Source: {}", if bd.from_deep_scan { "Deep Scan (page walk)" } else { "Level 1 counters" });

    let _ = writeln!(s, "\n== Findings");
    for f in findings {
        let sev = match f.severity {
            Severity::Warning => "!!",
            Severity::Notice => " !",
            Severity::Info => "  ",
        };
        let _ = writeln!(s, "{sev} {}", f.title);
        if !f.detail.is_empty() {
            let _ = writeln!(s, "   {}", f.detail);
        }
    }

    let _ = writeln!(s, "\n== Where the RAM is");
    for c in &bd.categories {
        let pct = c.bytes as f64 * 100.0 / bd.installed.max(1) as f64;
        let _ = writeln!(s, "{:>10}  {:>5.1}%  {}{}", fmt_bytes(c.bytes), pct, c.label, if c.confidence == crate::breakdown::Confidence::Estimate { " (estimate)" } else { "" });
    }

    let _ = writeln!(s, "\n== Top processes by private RAM");
    let mut procs: Vec<&ProcInfo> = snap.procs.iter().collect();
    procs.sort_by_key(|p| std::cmp::Reverse(p.private_ws.max(p.ws * special_kind(&p.name).is_some() as u64)));
    let _ = writeln!(s, "{:>10} {:>10} {:>10}  {:>6}  name", "private", "total WS", "commit", "pid");
    for p in procs.iter().take(25) {
        let _ = writeln!(s, "{:>10} {:>10} {:>10}  {:>6}  {}", fmt_bytes(p.private_ws), fmt_bytes(p.ws), fmt_bytes(p.private_commit), p.pid, p.name);
    }

    let _ = writeln!(s, "\n== Top kernel pool tags (paged {}, nonpaged {})", fmt_bytes(snap.paged_pool), fmt_bytes(snap.nonpaged_pool));
    let mut pool: Vec<&PoolTag> = snap.pool.iter().collect();
    pool.sort_by_key(|t| std::cmp::Reverse(t.total()));
    let _ = writeln!(s, "{:<6} {:>10} {:>10}  owner / description", "tag", "nonpaged", "paged");
    for t in pool.iter().take(25) {
        let o = owners.get(&t.tag);
        let who = o.map(|o| o.drivers.join(", ")).unwrap_or_default();
        let desc = o.and_then(|o| o.description.clone()).unwrap_or_default();
        let _ = writeln!(s, "{:<6} {:>10} {:>10}  {} {}", format!("'{}'", t.tag), fmt_bytes(t.nonpaged), fmt_bytes(t.paged), who, if desc.is_empty() { String::new() } else { format!("— {desc}") });
    }

    if let Some(d) = deep {
        let _ = writeln!(s, "\n== Deep Scan ({} pages, {} ms)", d.pages_scanned, d.elapsed_ms);
        let _ = writeln!(s, "{:<42} {:>10} {:>10} {:>10} {:>10}", "use", "active", "standby", "modified", "other");
        for (u, name) in PFN_USES.iter().enumerate() {
            let r = &d.by_use_list[u];
            if r.iter().sum::<u64>() == 0 {
                continue;
            }
            let _ = writeln!(s, "{:<42} {:>10} {:>10} {:>10} {:>10}", name, fmt_bytes(r[6] + r[7]), fmt_bytes(r[2]), fmt_bytes(r[3] + r[4]), fmt_bytes(r[0] + r[1] + r[5]));
        }
        for n in &d.notes {
            let _ = writeln!(s, "note: {n}");
        }
    }
    if !snap.warnings.is_empty() {
        let _ = writeln!(s, "\n== Warnings");
        for w in &snap.warnings {
            let _ = writeln!(s, "- {w}");
        }
    }
    s
}

pub fn json(snap: &Snapshot, owners: &HashMap<String, TagOwner>, deep: Option<&DeepScan>) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "snapshot": snap,
        "tag_owners": owners,
        "deep_scan": deep,
    }))
    .unwrap_or_default()
}

pub fn offender_text(o: &crate::culprits::Offender) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{} [{}]{}: total {} | in RAM {} | kernel {} | compressed/paged {}{}",
        o.name,
        o.kind.map(|k| k.label()).unwrap_or("App"),
        if o.vendor.is_empty() { String::new() } else { format!(" ({})", o.vendor) },
        fmt_bytes(o.total()),
        fmt_bytes(o.private_ram),
        fmt_bytes(o.kernel_pool),
        fmt_bytes(o.compressed),
        if o.vm > 0 { format!(" | VMs {}", fmt_bytes(o.vm)) } else { String::new() }
    );
    if !o.drivers.is_empty() {
        let _ = writeln!(s, "   drivers: {}", o.drivers.join(", "));
    }
    if !o.tags.is_empty() {
        let t: Vec<String> = o.tags.iter().take(6).map(|(t, b)| format!("'{t}' {}", fmt_bytes(*b))).collect();
        let _ = writeln!(s, "   pool tags: {}", t.join(", "));
    }
    if let Some(g) = o.pool_growth.filter(|g| g.unsigned_abs() >= 1 << 20) {
        let _ = writeln!(s, "   kernel growth since baseline: {}", crate::breakdown::fmt_delta(g));
    }
    let p: Vec<String> = o.processes.iter().take(6).map(|(n, pid, b)| format!("{n} ({pid}) {}", fmt_bytes(*b))).collect();
    if !p.is_empty() {
        let _ = writeln!(s, "   processes: {}", p.join(", "));
    }
    s
}

pub fn culprits(list: &[crate::culprits::Offender], unattributed_pool: u64) -> String {
    let mut s = String::from("\n== What's using it (by product)\n");
    for o in list.iter().take(15) {
        s.push_str(&offender_text(o));
    }
    if unattributed_pool > 0 {
        let _ = writeln!(s, "Kernel memory not tied to a driver: {}", fmt_bytes(unattributed_pool));
    }
    s
}
