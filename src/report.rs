//! Plain-text and JSON reports, for pasting into a ticket or chat.

use crate::breakdown::{fmt_bytes, Breakdown, Finding, Severity};
use crate::model::*;
use std::collections::HashMap;
use std::fmt::Write;

pub fn text(snap: &Snapshot, bd: &Breakdown, findings: &[Finding], owners: &HashMap<String, TagOwner>, deep: Option<&DeepScan>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "RAM Where report v{}", env!("CARGO_PKG_VERSION"));
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
