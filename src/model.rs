//! Platform-independent data model: what we measured, plus the deep-scan result.

use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub session: u32,
    /// Pages only this process uses that are currently in RAM (what Task Manager shows).
    pub private_ws: u64,
    /// Everything in RAM mapped by the process, including shared DLLs and mapped files.
    pub ws: u64,
    /// Private committed memory (may be partly paged out / compressed).
    pub private_commit: u64,
    pub virtual_size: u64,
    pub threads: u32,
    pub handles: u32,
    /// Kernel-side key, used to match deep-scan pages back to processes.
    #[serde(skip)]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub unique_key: u64,
}

impl ProcInfo {
    pub fn shared_ws(&self) -> u64 {
        self.ws.saturating_sub(self.private_ws)
    }
}

/// Special "processes" that are really pieces of the OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialProc {
    MemoryCompression,
    SecureSystem,
    Registry,
    VmWorker,
}

pub fn special_kind(name: &str) -> Option<SpecialProc> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "memory compression" => Some(SpecialProc::MemoryCompression),
        "secure system" => Some(SpecialProc::SecureSystem),
        "registry" => Some(SpecialProc::Registry),
        _ if n.starts_with("vmmem") || n == "vmwp.exe" || n == "vmcompute.exe" => Some(SpecialProc::VmWorker),
        _ => None,
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PoolTag {
    pub tag: String,
    /// The tag's bytes as they appear in driver code.
    #[serde(skip)]
    pub raw: [u8; 4],
    pub paged: u64,
    pub nonpaged: u64,
    pub paged_outstanding: u64,
    pub nonpaged_outstanding: u64,
}

impl PoolTag {
    pub fn total(&self) -> u64 {
        self.paged + self.nonpaged
    }
}

/// Physical page lists (needs admin). All values in bytes.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MemLists {
    pub zeroed: u64,
    pub free: u64,
    pub modified: u64,
    pub modified_no_write: u64,
    pub bad: u64,
    pub standby_by_priority: [u64; 8],
}

impl MemLists {
    pub fn standby(&self) -> u64 {
        self.standby_by_priority.iter().sum()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    /// Seconds since UNIX epoch.
    pub taken_at: u64,
    pub elevated: bool,
    pub os_version: String,
    pub computer_name: String,
    /// RAM sticks installed, according to firmware (SMBIOS).
    pub installed: Option<u64>,
    /// RAM Windows can actually use.
    pub visible_total: u64,
    /// Standby + free + zeroed.
    pub available: u64,
    pub commit_total: u64,
    pub commit_limit: u64,
    pub paged_pool: u64,
    pub nonpaged_pool: u64,
    /// GetPerformanceInfo's SystemCache field (standby + system working set).
    pub system_cache_perfinfo: u64,
    /// The file cache working set (class 21).
    pub file_cache_ws: Option<u64>,
    pub lists: Option<MemLists>,
    pub procs: Vec<ProcInfo>,
    pub pool: Vec<PoolTag>,
    pub vbs_running: Option<bool>,
    pub warnings: Vec<String>,
}

/// Who most likely owns a pool tag.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TagOwner {
    /// Best guess first.
    pub drivers: Vec<String>,
    pub description: Option<String>,
}

// ---------------------------------------------------------------- deep scan

/// Page use categories reported by the memory manager's PFN database.
pub const PFN_USES: [&str; 16] = [
    "Process private",
    "Mapped file",
    "Shareable (pagefile-backed)",
    "Page table",
    "Paged pool",
    "Nonpaged pool",
    "System PTE (driver images, kernel stacks)",
    "Session private",
    "Metafile (NTFS metadata)",
    "AWE",
    "Driver locked",
    "Kernel stack",
    "Large page",
    "Other (13)",
    "Other (14)",
    "Other (15)",
];

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeepProc {
    pub pid: u32,
    pub name: String,
    pub active: u64,
    pub standby: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeepScan {
    pub taken_at: u64,
    pub page_size: u64,
    /// Total bytes covered by the physical ranges Windows reported.
    pub ranges_bytes: u64,
    pub pages_scanned: u64,
    /// bytes[use][list]
    pub by_use_list: [[u64; 8]; 16],
    /// Private pages per process, if the process keys could be matched.
    pub procs: Vec<DeepProc>,
    pub unmatched_private: u64,
    pub notes: Vec<String>,
    pub elapsed_ms: u64,
}

impl DeepScan {
    pub fn list_total(&self, l: usize) -> u64 {
        self.by_use_list.iter().map(|r| r[l]).sum()
    }
}
