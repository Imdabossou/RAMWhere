#![cfg_attr(windows, allow(dead_code))]

//! A believable, internally consistent fake PC: 16 GB, a leaky security driver, WSL running.

use crate::model::*;

const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;

fn proc(pid: u32, name: &str, private_mb: u64, shared_mb: u64, commit_mb: u64) -> ProcInfo {
    ProcInfo {
        pid,
        ppid: 4,
        name: name.into(),
        session: if pid < 1000 { 0 } else { 1 },
        private_ws: private_mb * MB,
        ws: (private_mb + shared_mb) * MB,
        private_commit: commit_mb * MB,
        virtual_size: (commit_mb * 8 + 2048) * MB,
        threads: 12 + pid % 40,
        handles: 300 + pid % 900,
        unique_key: 0xffff_a000_0000_0000 | (pid as u64) << 12,
    }
}

fn tag(t: &str, paged_mb: u64, nonpaged_mb: u64) -> PoolTag {
    let mut raw = [b' '; 4];
    raw[..t.len()].copy_from_slice(t.as_bytes());
    PoolTag {
        tag: t.into(),
        raw,
        paged: paged_mb * MB,
        nonpaged: nonpaged_mb * MB,
        paged_outstanding: paged_mb * 40,
        nonpaged_outstanding: nonpaged_mb * 25,
    }
}

pub fn mock_snapshot() -> Snapshot {
    let procs = vec![
        proc(4, "System", 0, 2, 0),
        proc(140, "Registry", 0, 52, 14),
        proc(188, "Secure System", 0, 180, 180),
        proc(2900, "Memory Compression", 0, 1180, 2),
        proc(1200, "msedge.exe", 410, 220, 520),
        proc(1204, "msedge.exe", 96, 140, 150),
        proc(1208, "msedge.exe", 64, 120, 90),
        proc(1310, "ms-teams.exe", 280, 190, 610),
        proc(1400, "OUTLOOK.EXE", 190, 160, 420),
        proc(1500, "explorer.exe", 88, 140, 160),
        proc(700, "svchost.exe", 22, 30, 30),
        proc(704, "svchost.exe", 48, 34, 60),
        proc(720, "MsMpEng.exe", 160, 70, 260),
        proc(760, "csfalconservice.exe", 34, 20, 60),
        proc(3100, "vmmemWSL", 1450, 0, 1460),
        proc(1600, "dwm.exe", 70, 120, 110),
    ];
    let pool = vec![
        tag("Leak", 2, 2380),
        tag("MmSt", 310, 0),
        tag("FMfn", 160, 0),
        tag("File", 0, 120),
        tag("Ntfx", 90, 30),
        tag("Thre", 0, 40),
        tag("CM31", 150, 0),
        tag("TcpE", 0, 24),
        tag("smNp", 0, 70),
    ];
    let paged: u64 = pool.iter().map(|t| t.paged).sum::<u64>() + 380 * MB;
    let nonpaged: u64 = pool.iter().map(|t| t.nonpaged).sum::<u64>() + 160 * MB;
    let lists = MemLists {
        zeroed: 600 * MB,
        free: 40 * MB,
        modified: 210 * MB,
        modified_no_write: 0,
        bad: 0,
        standby_by_priority: [0, 120 * MB, 300 * MB, 200 * MB, 400 * MB, 900 * MB, 600 * MB, 200 * MB],
    };
    let visible = 16 * GB - 300 * MB;
    let available = lists.standby() + lists.zeroed + lists.free;
    Snapshot {
        taken_at: now(),
        elevated: true,
        os_version: "Simulated Windows 11 (build 26100)".into(),
        computer_name: "DEMO-LAPTOP".into(),
        installed: Some(16 * GB),
        visible_total: visible,
        available,
        commit_total: 13 * GB,
        commit_limit: 20 * GB,
        paged_pool: paged,
        nonpaged_pool: nonpaged,
        system_cache_perfinfo: lists.standby() + 900 * MB,
        file_cache_ws: Some(420 * MB),
        lists: Some(lists),
        procs,
        pool,
        vbs_running: Some(true),
        warnings: vec!["Simulated data: this build is not running on Windows.".into()],
    }
}

pub fn mock_snapshot_jittered() -> Snapshot {
    let mut s = mock_snapshot();
    // Let the leaky tag grow so the "since baseline" columns have something to show.
    let t = now() % 600;
    if let Some(leak) = s.pool.iter_mut().find(|p| p.tag == "Leak") {
        leak.nonpaged += t * 512 * 1024;
    }
    s.nonpaged_pool += t * 512 * 1024;
    s.lists.as_mut().unwrap().zeroed -= t * 512 * 1024;
    s.available -= t * 512 * 1024;
    s
}

pub fn mock_deep(snap: &Snapshot) -> DeepScan {
    let mut d = DeepScan { taken_at: now(), page_size: 4096, ..Default::default() };
    let visible = snap.visible_total;
    let l = snap.lists.clone().unwrap_or_default();
    let set = |d: &mut DeepScan, u: usize, li: usize, b: u64| d.by_use_list[u][li] += b;
    let private: u64 = snap.procs.iter().map(|p| p.private_ws).sum::<u64>() + 1180 * MB + 180 * MB + 52 * MB;
    set(&mut d, 0, 6, private);
    set(&mut d, 5, 6, snap.nonpaged_pool);
    set(&mut d, 4, 6, snap.paged_pool - 200 * MB);
    set(&mut d, 3, 6, 260 * MB);
    set(&mut d, 6, 6, 180 * MB);
    set(&mut d, 11, 6, 90 * MB);
    set(&mut d, 7, 6, 60 * MB);
    set(&mut d, 8, 6, 140 * MB);
    set(&mut d, 10, 6, 310 * MB);
    set(&mut d, 2, 6, 690 * MB);
    set(&mut d, 0, 3, l.modified / 2);
    set(&mut d, 2, 3, l.modified - l.modified / 2);
    set(&mut d, 1, 2, l.standby() * 3 / 4);
    set(&mut d, 0, 2, l.standby() - l.standby() * 3 / 4);
    set(&mut d, 0, 0, l.zeroed);
    set(&mut d, 0, 1, l.free);
    let used: u64 = d.by_use_list.iter().flatten().sum();
    set(&mut d, 1, 6, visible.saturating_sub(used));
    d.pages_scanned = visible / 4096;
    d.ranges_bytes = visible;
    d.procs = snap
        .procs
        .iter()
        .map(|p| DeepProc { pid: p.pid, name: p.name.clone(), active: p.private_ws, standby: p.private_ws / 10, modified: 0 })
        .collect();
    d.elapsed_ms = 800;
    d.notes.push("Simulated deep scan.".into());
    d
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
