//! Turns raw measurements into a list of categories that add up to the installed RAM,
//! plus plain-English findings.

use crate::model::*;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// Measured directly.
    Exact,
    /// Upper bound or approximation.
    Estimate,
    /// Whatever is left after everything else.
    Remainder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Reserved,
    InUse,
    Reclaimable,
    Free,
}

#[derive(Clone, Debug)]
pub struct Category {
    pub key: &'static str,
    pub label: String,
    pub bytes: u64,
    pub group: Group,
    pub confidence: Confidence,
    pub explain: String,
}

#[derive(Clone, Debug)]
pub struct Breakdown {
    pub installed: u64,
    pub in_use: u64,
    /// What summing Task Manager's Memory column gives.
    pub task_manager_sum: u64,
    pub categories: Vec<Category>,
    pub from_deep_scan: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Notice,
    Warning,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

pub fn fmt_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.2} GB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.0} MB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KB", f / K)
    } else {
        format!("{b} B")
    }
}

pub fn fmt_delta(d: i64) -> String {
    if d == 0 {
        return "0".into();
    }
    let s = fmt_bytes(d.unsigned_abs());
    if d > 0 {
        format!("+{s}")
    } else {
        format!("-{s}")
    }
}

#[derive(Default)]
struct SpecialSums {
    apps_private: u64,
    task_manager_sum: u64,
    mem_compression: u64,
    secure_system: u64,
    registry: u64,
    vm: u64,
}

fn special_sums(snap: &Snapshot) -> SpecialSums {
    let mut s = SpecialSums::default();
    for p in &snap.procs {
        match special_kind(&p.name) {
            // These processes hold nothing but private memory; their working set is the number that matters.
            Some(SpecialProc::MemoryCompression) => s.mem_compression += p.ws,
            Some(SpecialProc::SecureSystem) => s.secure_system += p.ws,
            Some(SpecialProc::Registry) => s.registry += p.ws,
            Some(SpecialProc::VmWorker) => s.vm += p.private_ws,
            None => {
                s.apps_private += p.private_ws;
            }
        }
        if !matches!(special_kind(&p.name), Some(SpecialProc::MemoryCompression) | Some(SpecialProc::SecureSystem)) {
            s.task_manager_sum += p.private_ws;
        }
    }
    s
}

fn cat(key: &'static str, label: &str, bytes: u64, group: Group, confidence: Confidence, explain: &str) -> Category {
    Category { key, label: label.into(), bytes, group, confidence, explain: explain.into() }
}

pub fn compute(snap: &Snapshot, deep: Option<&DeepScan>) -> Breakdown {
    match deep {
        Some(d) if d.pages_scanned > 0 => compute_deep(snap, d),
        _ => compute_level1(snap),
    }
}

fn installed_of(snap: &Snapshot, usable: u64) -> u64 {
    snap.installed.filter(|&i| i >= usable).unwrap_or(usable)
}

const EXPLAIN_RESERVED: &str = "Never handed to Windows: firmware, integrated graphics carve-out, \
hypervisor or devices. Nothing you can close will free this.";
const EXPLAIN_APPS: &str = "Memory belonging to exactly one process. This is all Task Manager's \
Memory column adds up.";
const EXPLAIN_COMPRESSION: &str = "Compressed app memory. Windows squeezes idle pages here instead of \
writing them to disk. Task Manager hides this process.";
const EXPLAIN_VM: &str = "WSL2, Docker, Windows Sandbox or Hyper-V virtual machines (vmmem). \
Task Manager shows it but often understates it.";
const EXPLAIN_SECURE: &str = "Virtualization-based security (Credential Guard, memory integrity). \
Runs beside Windows and is hidden from Task Manager.";
const EXPLAIN_REGISTRY: &str = "Registry hives held in memory.";
const EXPLAIN_NONPAGED: &str = "Kernel and driver memory that can never leave RAM. Antivirus/EDR, VPN, \
network and storage drivers allocate here; leaks show up here. See the Drivers tab.";
const EXPLAIN_PAGED: &str = "Kernel and driver memory that can be paged out. Shown at its committed \
size (an upper bound on what is in RAM). See the Drivers tab.";
const EXPLAIN_FILECACHE: &str = "Files Windows is actively caching for reads and writes (system file cache).";
const EXPLAIN_MODIFIED: &str = "Changed pages waiting to be written to disk or pagefile. Becomes \
available once written.";
const EXPLAIN_STANDBY: &str = "Cache of recently used data. Counts as available: Windows hands it \
to apps instantly when needed. Not a problem.";
const EXPLAIN_FREE: &str = "Genuinely unused.";

fn compute_level1(snap: &Snapshot) -> Breakdown {
    let visible = snap.visible_total;
    let installed = installed_of(snap, visible);
    let s = special_sums(snap);

    let (free, standby, modified) = match &snap.lists {
        Some(l) => (l.zeroed + l.free, Some(l.standby()), l.modified + l.modified_no_write),
        None => (0, None, 0),
    };
    let in_use = visible.saturating_sub(snap.available).saturating_sub(modified);

    let mut cats = vec![cat("reserved", "Hardware / firmware reserved", installed - visible, Group::Reserved, Confidence::Exact, EXPLAIN_RESERVED)];

    let file_cache = snap.file_cache_ws.unwrap_or(0);
    let known = [s.apps_private, s.mem_compression, s.vm, s.secure_system, s.registry, snap.nonpaged_pool, file_cache];
    let known_sum: u64 = known.iter().sum();
    let left = in_use.saturating_sub(known_sum);
    let paged = snap.paged_pool.min(left);
    let remainder = left - paged;

    cats.push(cat("apps", "Apps & services (private)", s.apps_private, Group::InUse, Confidence::Exact, EXPLAIN_APPS));
    cats.push(cat("compression", "Memory Compression store", s.mem_compression, Group::InUse, Confidence::Exact, EXPLAIN_COMPRESSION));
    cats.push(cat("vm", "Virtual machines / WSL2", s.vm, Group::InUse, Confidence::Exact, EXPLAIN_VM));
    cats.push(cat("secure", "Secure System (VBS)", s.secure_system, Group::InUse, Confidence::Exact, EXPLAIN_SECURE));
    cats.push(cat("registry", "Registry", s.registry, Group::InUse, Confidence::Exact, EXPLAIN_REGISTRY));
    cats.push(cat("nonpaged", "Kernel nonpaged pool (drivers)", snap.nonpaged_pool, Group::InUse, Confidence::Exact, EXPLAIN_NONPAGED));
    cats.push(cat("paged", "Kernel paged pool (drivers)", paged, Group::InUse, Confidence::Estimate, EXPLAIN_PAGED));
    if snap.file_cache_ws.is_some() {
        cats.push(cat("filecache", "System file cache", file_cache, Group::InUse, Confidence::Exact, EXPLAIN_FILECACHE));
    }
    cats.push(cat(
        "unexplained",
        "Shared, mapped & other kernel memory",
        remainder,
        Group::InUse,
        Confidence::Remainder,
        "Shared DLLs and memory-mapped files, page tables, driver-locked memory, kernel stacks and \
driver code. Run a Deep Scan (needs admin) to split this up exactly.",
    ));

    match standby {
        Some(sb) => {
            cats.push(cat("modified", "Modified (waiting to write)", modified, Group::Reclaimable, Confidence::Exact, EXPLAIN_MODIFIED));
            cats.push(cat("standby", "Standby cache", sb, Group::Reclaimable, Confidence::Exact, EXPLAIN_STANDBY));
            cats.push(cat("free", "Free", free, Group::Free, Confidence::Exact, EXPLAIN_FREE));
        }
        None => cats.push(cat(
            "available",
            "Available (standby cache + free)",
            snap.available,
            Group::Reclaimable,
            Confidence::Exact,
            "Cache and free memory Windows can hand out immediately. Run as administrator to split this further.",
        )),
    }

    Breakdown { installed, in_use, task_manager_sum: s.task_manager_sum, categories: cats, from_deep_scan: false }
}

fn compute_deep(snap: &Snapshot, d: &DeepScan) -> Breakdown {
    let scanned = d.pages_scanned * d.page_size;
    let installed = installed_of(snap, scanned);
    let s = special_sums(snap);

    // Active + transition pages per use; modified is reported on its own, like Task Manager does.
    let act = |u: usize| d.by_use_list[u][6] + d.by_use_list[u][7];
    let modified = d.list_total(3) + d.list_total(4);
    let standby = d.list_total(2);
    let free = d.list_total(0) + d.list_total(1);
    let bad = d.list_total(5);

    let mut cats = vec![cat("reserved", "Hardware / firmware reserved", installed - scanned, Group::Reserved, Confidence::Exact, EXPLAIN_RESERVED)];

    // Split "process private" into the OS pseudo-processes and real apps.
    let mut private = act(0);
    let mut take = |want: u64| {
        let t = want.min(private);
        private -= t;
        t
    };
    let mc = take(s.mem_compression);
    let vm = take(s.vm);
    let sec = take(s.secure_system);
    let reg = take(s.registry);

    cats.push(cat("apps", "Apps & services (private)", private, Group::InUse, Confidence::Exact, EXPLAIN_APPS));
    cats.push(cat("compression", "Memory Compression store", mc, Group::InUse, Confidence::Exact, EXPLAIN_COMPRESSION));
    cats.push(cat("vm", "Virtual machines / WSL2", vm, Group::InUse, Confidence::Exact, EXPLAIN_VM));
    cats.push(cat("secure", "Secure System (VBS)", sec, Group::InUse, Confidence::Exact, EXPLAIN_SECURE));
    cats.push(cat("registry", "Registry", reg, Group::InUse, Confidence::Exact, EXPLAIN_REGISTRY));

    let deep_cats: [(&'static str, usize, &str, &str); 12] = [
        ("nonpaged", 5, "Kernel nonpaged pool (drivers)", EXPLAIN_NONPAGED),
        ("paged", 4, "Kernel paged pool (drivers)", "Kernel and driver memory that can be paged out. See the Drivers tab."),
        ("mapped", 1, "Mapped files (DLLs, EXEs, data files)", "Program files and documents mapped into memory, including the active file cache. Shared between processes, so Task Manager doesn't count it."),
        ("shareable", 2, "Shared memory sections", "Pagefile-backed shared memory: browsers, Teams/Electron apps and GPU drivers use this to share buffers between processes. Not in Task Manager's column."),
        ("pagetable", 3, "Page tables", "The memory manager's own bookkeeping for every process's address space. Grows with huge or many processes."),
        ("systempte", 6, "Driver code & system mappings", "Loaded driver images and kernel mappings."),
        ("kstack", 11, "Kernel stacks", "One per thread. Many thousands of threads add up."),
        ("session", 7, "Session private", "Per-login-session kernel memory (desktop, window manager)."),
        ("metafile", 8, "NTFS metadata (Metafile)", "File system metadata. Grows huge when something touches millions of files (backup, indexing, AV scans)."),
        ("locked", 10, "Driver locked", "Pages a driver has pinned in RAM: VM balloon drivers, GPU drivers, capture cards, some security software."),
        ("awe", 9, "AWE (locked app memory)", "Memory locked by an application through AWE, typically SQL Server. Invisible in Task Manager."),
        ("largepage", 12, "Large pages", "Memory allocated as large pages (databases, VMs, games)."),
    ];
    for (key, u, label, explain) in deep_cats {
        cats.push(cat(key, label, act(u), Group::InUse, Confidence::Exact, explain));
    }
    let other: u64 = (13..16).map(act).sum();
    cats.push(cat("other", "Other / unknown page type", other, Group::InUse, Confidence::Exact, "Page types this tool doesn't recognize on this Windows build."));
    cats.push(cat("modified", "Modified (waiting to write)", modified, Group::Reclaimable, Confidence::Exact, EXPLAIN_MODIFIED));
    cats.push(cat("standby", "Standby cache", standby, Group::Reclaimable, Confidence::Exact, EXPLAIN_STANDBY));
    cats.push(cat("free", "Free", free, Group::Free, Confidence::Exact, EXPLAIN_FREE));
    if bad > 0 {
        cats.push(cat("bad", "Bad pages", bad, Group::Reserved, Confidence::Exact, "Pages Windows has taken out of use because they failed a memory test. Possible failing RAM."));
    }

    let in_use = cats.iter().filter(|c| c.group == Group::InUse).map(|c| c.bytes).sum();
    Breakdown { installed, in_use, task_manager_sum: s.task_manager_sum, categories: cats, from_deep_scan: true }
}

pub fn findings(snap: &Snapshot, bd: &Breakdown, owners: &HashMap<String, TagOwner>) -> Vec<Finding> {
    let mut out = Vec::new();
    let total = bd.installed.max(1);
    let pct = |b: u64| b as f64 * 100.0 / total as f64;
    let get = |k: &str| bd.categories.iter().find(|c| c.key == k).map(|c| c.bytes).unwrap_or(0);
    let owner_of = |tag: &str| -> String {
        match owners.get(tag) {
            Some(o) if !o.drivers.is_empty() => format!(" (likely {})", o.drivers[0]),
            Some(o) if o.description.is_some() => format!(" ({})", o.description.as_deref().unwrap_or("")),
            _ => String::new(),
        }
    };

    let gap = bd.in_use.saturating_sub(bd.task_manager_sum);
    out.push(Finding {
        severity: Severity::Info,
        title: format!(
            "Task Manager's process list accounts for {} of {} in use",
            fmt_bytes(bd.task_manager_sum),
            fmt_bytes(bd.in_use)
        ),
        detail: format!("The other {} is the categories below that Task Manager never itemizes.", fmt_bytes(gap)),
    });

    for (key, kind, threshold) in [("nonpaged", "nonpaged", 1u64 << 30), ("paged", "paged", 3u64 << 29)] {
        let bytes = if key == "nonpaged" { snap.nonpaged_pool } else { snap.paged_pool };
        if bytes > threshold || pct(bytes) > 10.0 {
            let mut top: Vec<&PoolTag> = snap.pool.iter().collect();
            top.sort_by_key(|t| std::cmp::Reverse(if kind == "nonpaged" { t.nonpaged } else { t.paged }));
            let tops: Vec<String> = top
                .iter()
                .take(3)
                .map(|t| {
                    let b = if kind == "nonpaged" { t.nonpaged } else { t.paged };
                    format!("'{}' {}{}", t.tag, fmt_bytes(b), owner_of(&t.tag))
                })
                .collect();
            out.push(Finding {
                severity: Severity::Warning,
                title: format!("Kernel {kind} pool is {} — higher than normal", fmt_bytes(bytes)),
                detail: if tops.is_empty() {
                    "Pool tag details were unavailable.".into()
                } else {
                    format!(
                        "Largest tags: {}. A healthy PC is usually well under 1 GB. A tag that keeps growing \
points at a leaking driver; update or remove it.",
                        tops.join(", ")
                    )
                },
            });
        }
    }

    let unexplained = get("unexplained");
    if !bd.from_deep_scan && pct(unexplained) > 10.0 {
        out.push(Finding {
            severity: Severity::Notice,
            title: format!("{} is shared, mapped or other kernel memory", fmt_bytes(unexplained)),
            detail: if snap.elevated {
                "Run a Deep Scan to split it into mapped files, shared sections, page tables, driver-locked pages and so on.".into()
            } else {
                "Restart as administrator, then run a Deep Scan to split it exactly.".into()
            },
        });
    }

    let reserved = get("reserved");
    if reserved > 512 << 20 {
        out.push(Finding {
            severity: Severity::Info,
            title: format!("{} is reserved by hardware", fmt_bytes(reserved)),
            detail: "Usually integrated graphics memory or firmware. It shows in Task Manager as \"Hardware reserved\" and is not a leak.".into(),
        });
    }

    let mc = get("compression");
    if mc > 1 << 30 {
        out.push(Finding {
            severity: Severity::Info,
            title: format!("Memory Compression holds {}", fmt_bytes(mc)),
            detail: "This is idle app memory, compressed. It's normal; it means apps have more allocated than fits comfortably. The apps that own it are in the Processes tab, sorted by commit.".into(),
        });
    }

    let vm = get("vm");
    if vm > 512 << 20 {
        out.push(Finding {
            severity: Severity::Notice,
            title: format!("Virtual machines / WSL2 use {}", fmt_bytes(vm)),
            detail: "Run `wsl --shutdown` or stop Docker Desktop / VMs to release it. WSL2's limit is set in %UserProfile%\\.wslconfig.".into(),
        });
    }

    for (key, threshold, what) in [
        ("locked", 512u64 << 20, "Drivers have locked {} in RAM. Common causes: VMware/Hyper-V balloon drivers, GPU drivers, security software."),
        ("metafile", 1 << 30, "NTFS metadata uses {}. Something has touched a huge number of files: backup, indexing or antivirus scans."),
        ("awe", 256 << 20, "{} is locked by an application through AWE (usually SQL Server's \"lock pages in memory\")."),
        ("pagetable", 1 << 30, "Page tables use {}. A process with an enormous address space (or thousands of processes) is the cause."),
        ("shareable", 2 << 30, "Shared memory sections use {}. Browsers, Electron apps (Teams, Slack) and GPU drivers are the usual owners."),
        ("kstack", 512 << 20, "Kernel stacks use {}: there are an unusual number of threads. Check the Threads column in Processes."),
    ] {
        let b = get(key);
        if b > threshold {
            out.push(Finding { severity: Severity::Warning, title: what.replace("{}", &fmt_bytes(b)), detail: String::new() });
        }
    }

    if let Some(top) = snap.procs.iter().filter(|p| special_kind(&p.name).is_none()).max_by_key(|p| p.private_commit) {
        if pct(top.private_commit) > 25.0 {
            out.push(Finding {
                severity: Severity::Notice,
                title: format!("{} (PID {}) has {} committed", top.name, top.pid, fmt_bytes(top.private_commit)),
                detail: format!("{} of that is in RAM right now; the rest is compressed or in the pagefile.", fmt_bytes(top.private_ws)),
            });
        }
    }

    if snap.commit_limit > 0 && snap.commit_total as f64 > snap.commit_limit as f64 * 0.9 {
        out.push(Finding {
            severity: Severity::Warning,
            title: format!("Commit charge is {} of a {} limit", fmt_bytes(snap.commit_total), fmt_bytes(snap.commit_limit)),
            detail: "Programs will start failing to allocate memory. Increase the pagefile or close the biggest committers.".into(),
        });
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_adds_up() {
        let snap = crate::platform::mock_snapshot();
        let bd = compute(&snap, None);
        let sum: u64 = bd.categories.iter().map(|c| c.bytes).sum();
        assert_eq!(sum, bd.installed);
    }

    #[test]
    fn deep_adds_up() {
        let snap = crate::platform::mock_snapshot();
        let deep = crate::platform::mock_deep(&snap);
        let bd = compute(&snap, Some(&deep));
        let sum: u64 = bd.categories.iter().map(|c| c.bytes).sum();
        assert_eq!(sum, bd.installed);
    }
}
