//! Real Windows implementation.
//!
//! Level 1 uses `NtQuerySystemInformation` classes that Task Manager, Process Explorer and
//! System Informer have relied on for years. Level 2 walks the physical page (PFN) database
//! through the Superfetch information class, the same interface RAMMap uses.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

use crate::model::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of, zeroed};
use std::path::{Path, PathBuf};
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumDeviceDrivers, K32GetDeviceDriverFileNameW, K32GetPerformanceInfo, PERFORMANCE_INFORMATION,
};
use windows_sys::Win32::System::SystemInformation::{
    GetPhysicallyInstalledSystemMemory, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

type NTSTATUS = i32;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> NTSTATUS;
    fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> NTSTATUS;
}

const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC000_0004u32 as i32;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;
const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x8000_0005u32 as i32;

const SystemProcessInformation: u32 = 5;
const SystemFileCacheInformation: u32 = 21;
const SystemPoolTagInformation: u32 = 22;
const SystemExtendedProcessInformation: u32 = 57;
const SystemSuperfetchInformation: u32 = 79;
const SystemMemoryListInformation: u32 = 80;

#[repr(C)]
struct OSVERSIONINFOW {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [u16; 128],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_PROCESS_INFORMATION {
    NextEntryOffset: u32,
    NumberOfThreads: u32,
    WorkingSetPrivateSize: i64,
    HardFaultCount: u32,
    NumberOfThreadsHighWatermark: u32,
    CycleTime: u64,
    CreateTime: i64,
    UserTime: i64,
    KernelTime: i64,
    ImageName: UNICODE_STRING,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
    HandleCount: u32,
    SessionId: u32,
    UniqueProcessKey: usize,
    PeakVirtualSize: usize,
    VirtualSize: usize,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivatePageCount: usize,
}
const _: () = assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, ImageName) == 56);
const _: () = assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 80);
const _: () = assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, WorkingSetSize) == 144);
const _: () = assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, PrivatePageCount) == 200);

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_POOLTAG {
    Tag: [u8; 4],
    PagedAllocs: u32,
    PagedFrees: u32,
    PagedUsed: usize,
    NonPagedAllocs: u32,
    NonPagedFrees: u32,
    NonPagedUsed: usize,
}
const _: () = assert!(size_of::<SYSTEM_POOLTAG>() == 40);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SYSTEM_MEMORY_LIST_INFORMATION {
    ZeroPageCount: usize,
    FreePageCount: usize,
    ModifiedPageCount: usize,
    ModifiedNoWritePageCount: usize,
    BadPageCount: usize,
    PageCountByPriority: [usize; 8],
    RepurposedPagesByPriority: [usize; 8],
    ModifiedPageCountPageFile: usize,
}
const _: () = assert!(size_of::<SYSTEM_MEMORY_LIST_INFORMATION>() == 176);

/// 8-byte aligned buffer filled by NtQuerySystemInformation.
struct InfoBuf {
    words: Vec<u64>,
    len: usize,
}

impl InfoBuf {
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }
    fn read<T: Copy>(&self, offset: usize) -> Option<T> {
        if offset + size_of::<T>() > self.len {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(self.bytes().as_ptr().add(offset) as *const T) })
    }
}

fn query(class: u32, initial: usize) -> Result<InfoBuf, NTSTATUS> {
    let mut size = initial.max(64);
    for _ in 0..12 {
        let mut words = vec![0u64; size.div_ceil(8)];
        let mut ret = 0u32;
        let st = unsafe { NtQuerySystemInformation(class, words.as_mut_ptr() as *mut c_void, (words.len() * 8) as u32, &mut ret) };
        if st >= 0 {
            let len = if ret == 0 { words.len() * 8 } else { (ret as usize).min(words.len() * 8) };
            return Ok(InfoBuf { words, len });
        }
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW {
            size = (ret as usize).max(size * 2) + 64 * 1024;
            continue;
        }
        return Err(st);
    }
    Err(STATUS_INFO_LENGTH_MISMATCH)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ntstatus(st: NTSTATUS) -> String {
    format!("0x{:08X}", st as u32)
}

// ------------------------------------------------------------------ privileges

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut el: TOKEN_ELEVATION = zeroed();
        let mut ret = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, &mut el as *mut _ as *mut c_void, size_of::<TOKEN_ELEVATION>() as u32, &mut ret);
        CloseHandle(tok);
        ok != 0 && el.TokenIsElevated != 0
    }
}

fn enable_privilege(name: &str) -> bool {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut luid: LUID = zeroed();
        let n = wide(name);
        let mut ok = LookupPrivilegeValueW(std::ptr::null(), n.as_ptr(), &mut luid) != 0;
        if ok {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            ok = AdjustTokenPrivileges(tok, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
                // AdjustTokenPrivileges "succeeds" without assigning when we don't hold it.
                && windows_sys::Win32::Foundation::GetLastError() == 0;
        }
        CloseHandle(tok);
        ok
    }
}

pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let r = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), exe_w.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
    if r as isize > 32 {
        Ok(())
    } else {
        Err("Windows didn't start the elevated copy (UAC prompt cancelled?)".into())
    }
}

pub fn is_simulated() -> bool {
    false
}

fn shell_open(file: &str, params: Option<&str>) -> Result<(), String> {
    let f = wide(file);
    let verb = wide("open");
    let p = params.map(wide);
    let r = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), f.as_ptr(), p.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()), std::ptr::null(), SW_SHOWNORMAL)
    };
    if r as isize > 32 {
        Ok(())
    } else {
        Err(format!("Couldn't open {file}"))
    }
}

/// Opens Explorer with the file selected.
pub fn open_location(path: &str) -> Result<(), String> {
    shell_open("explorer.exe", Some(&format!("/select,\"{path}\"")))
}

pub fn open_apps_settings() -> Result<(), String> {
    shell_open("ms-settings:appsfeatures", None)
}

pub fn open_services() -> Result<(), String> {
    shell_open("services.msc", None)
}

// ------------------------------------------------------------------ level 1

fn os_version() -> String {
    unsafe {
        let mut v: OSVERSIONINFOW = zeroed();
        v.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;
        if RtlGetVersion(&mut v) < 0 {
            return "Windows".into();
        }
        let name = if v.dwMajorVersion == 10 && v.dwBuildNumber >= 22000 { "Windows 11".to_string() } else { format!("Windows {}.{}", v.dwMajorVersion, v.dwMinorVersion) };
        format!("{name} (build {})", v.dwBuildNumber)
    }
}

fn read_processes(warnings: &mut Vec<String>) -> Vec<ProcInfo> {
    let buf = match query(SystemExtendedProcessInformation, 1 << 20).or_else(|_| query(SystemProcessInformation, 1 << 20)) {
        Ok(b) => b,
        Err(st) => {
            warnings.push(format!("Could not list processes ({}).", ntstatus(st)));
            return Vec::new();
        }
    };
    let base = buf.bytes().as_ptr() as usize;
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        let Some(p) = buf.read::<SYSTEM_PROCESS_INFORMATION>(off) else { break };
        let pid = p.UniqueProcessId as u32;
        let mut name = String::new();
        if !p.ImageName.Buffer.is_null() && p.ImageName.Length > 0 {
            let start = p.ImageName.Buffer as usize;
            let chars = p.ImageName.Length as usize / 2;
            // The name lives inside our buffer; refuse anything that points elsewhere.
            if start >= base && start + chars * 2 <= base + buf.len {
                let s = unsafe { std::slice::from_raw_parts(p.ImageName.Buffer, chars) };
                name = String::from_utf16_lossy(s);
            }
        }
        if name.is_empty() {
            name = if pid == 0 { "System Idle Process".into() } else { format!("<pid {pid}>") };
        }
        out.push(ProcInfo {
            pid,
            ppid: p.InheritedFromUniqueProcessId as u32,
            name,
            session: p.SessionId,
            private_ws: p.WorkingSetPrivateSize.max(0) as u64,
            ws: p.WorkingSetSize as u64,
            private_commit: p.PagefileUsage as u64,
            virtual_size: p.VirtualSize as u64,
            threads: p.NumberOfThreads,
            handles: p.HandleCount,
            unique_key: p.UniqueProcessKey as u64,
        });
        if p.NextEntryOffset == 0 {
            break;
        }
        off += p.NextEntryOffset as usize;
    }
    out
}

fn tag_display(raw: [u8; 4]) -> String {
    raw.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect()
}

fn read_pool(warnings: &mut Vec<String>) -> Vec<PoolTag> {
    let buf = match query(SystemPoolTagInformation, 512 * 1024) {
        Ok(b) => b,
        Err(st) => {
            warnings.push(format!("Kernel pool tags unavailable ({}).", ntstatus(st)));
            return Vec::new();
        }
    };
    let count = buf.read::<u32>(0).unwrap_or(0) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(t) = buf.read::<SYSTEM_POOLTAG>(8 + i * size_of::<SYSTEM_POOLTAG>()) else { break };
        let mut raw = t.Tag;
        raw[3] &= 0x7f; // strip the "protected pool" bit
        if t.PagedUsed == 0 && t.NonPagedUsed == 0 {
            continue;
        }
        out.push(PoolTag {
            tag: tag_display(raw),
            raw,
            paged: t.PagedUsed as u64,
            nonpaged: t.NonPagedUsed as u64,
            paged_outstanding: t.PagedAllocs.wrapping_sub(t.PagedFrees) as u64,
            nonpaged_outstanding: t.NonPagedAllocs.wrapping_sub(t.NonPagedFrees) as u64,
        });
    }
    out
}

fn read_memory_lists(page: u64) -> Option<MemLists> {
    let buf = query(SystemMemoryListInformation, size_of::<SYSTEM_MEMORY_LIST_INFORMATION>()).ok()?;
    let m: SYSTEM_MEMORY_LIST_INFORMATION = buf.read(0)?;
    let mut standby = [0u64; 8];
    for (i, s) in standby.iter_mut().enumerate() {
        *s = m.PageCountByPriority[i] as u64 * page;
    }
    Some(MemLists {
        zeroed: m.ZeroPageCount as u64 * page,
        free: m.FreePageCount as u64 * page,
        modified: m.ModifiedPageCount as u64 * page,
        modified_no_write: m.ModifiedNoWritePageCount as u64 * page,
        bad: m.BadPageCount as u64 * page,
        standby_by_priority: standby,
    })
}

pub fn collect() -> Snapshot {
    let mut snap = Snapshot { taken_at: super::mock::now(), elevated: is_elevated(), os_version: os_version(), ..Default::default() };
    snap.computer_name = std::env::var("COMPUTERNAME").unwrap_or_default();
    if snap.elevated {
        enable_privilege("SeProfileSingleProcessPrivilege");
        enable_privilege("SeDebugPrivilege");
    }

    let mut page = 4096u64;
    unsafe {
        let mut pi: PERFORMANCE_INFORMATION = zeroed();
        pi.cb = size_of::<PERFORMANCE_INFORMATION>() as u32;
        if K32GetPerformanceInfo(&mut pi, pi.cb) != 0 {
            page = pi.PageSize as u64;
            snap.visible_total = pi.PhysicalTotal as u64 * page;
            snap.available = pi.PhysicalAvailable as u64 * page;
            snap.commit_total = pi.CommitTotal as u64 * page;
            snap.commit_limit = pi.CommitLimit as u64 * page;
            snap.paged_pool = pi.KernelPaged as u64 * page;
            snap.nonpaged_pool = pi.KernelNonpaged as u64 * page;
            snap.system_cache_perfinfo = pi.SystemCache as u64 * page;
        } else {
            snap.warnings.push("GetPerformanceInfo failed.".into());
        }
        let mut ms: MEMORYSTATUSEX = zeroed();
        ms.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        if snap.visible_total == 0 && GlobalMemoryStatusEx(&mut ms) != 0 {
            snap.visible_total = ms.ullTotalPhys;
            snap.available = ms.ullAvailPhys;
        }
        let mut kb = 0u64;
        if GetPhysicallyInstalledSystemMemory(&mut kb) != 0 && kb > 0 {
            snap.installed = Some(kb * 1024);
        }
    }

    snap.file_cache_ws = query(SystemFileCacheInformation, 64).ok().and_then(|b| b.read::<usize>(0)).map(|v| v as u64);
    snap.lists = read_memory_lists(page);
    if snap.lists.is_none() {
        snap.warnings.push(if snap.elevated {
            "Standby/modified/free lists unavailable.".into()
        } else {
            "Not running as administrator: standby/modified lists and Deep Scan are unavailable.".into()
        });
    }
    snap.procs = read_processes(&mut snap.warnings);
    snap.pool = read_pool(&mut snap.warnings);
    snap.vbs_running = Some(snap.procs.iter().any(|p| p.name.eq_ignore_ascii_case("Secure System")));
    snap
}

// ------------------------------------------------------------------ drivers

fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

fn normalize_driver_path(raw: &str) -> PathBuf {
    let root = system_root();
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return root.join(&raw[raw.len() - rest.len()..]);
    }
    if let Some(stripped) = raw.strip_prefix(r"\??\") {
        return PathBuf::from(stripped);
    }
    if raw.starts_with('\\') {
        let drive: String = root.to_string_lossy().chars().take(2).collect();
        return PathBuf::from(format!("{drive}{raw}"));
    }
    if !raw.contains(':') {
        return root.join(raw);
    }
    PathBuf::from(raw)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if depth < 3 {
                walk(&p, out, depth + 1);
            }
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("sys")) {
            out.push(p);
        }
    }
}

/// Every kernel module we can find, loaded drivers first.
pub fn driver_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    unsafe {
        let mut bases = vec![std::ptr::null_mut::<c_void>(); 2048];
        let mut needed = 0u32;
        if K32EnumDeviceDrivers(bases.as_mut_ptr(), (bases.len() * size_of::<usize>()) as u32, &mut needed) != 0 {
            let n = (needed as usize / size_of::<usize>()).min(bases.len());
            for &b in &bases[..n] {
                let mut name = [0u16; 520];
                let len = K32GetDeviceDriverFileNameW(b, name.as_mut_ptr(), name.len() as u32);
                if len > 0 {
                    out.push(normalize_driver_path(&String::from_utf16_lossy(&name[..len as usize])));
                }
            }
        }
    }
    let root = system_root();
    out.push(root.join(r"System32\ntoskrnl.exe"));
    for f in ["win32k.sys", "win32kbase.sys", "win32kfull.sys"] {
        out.push(root.join("System32").join(f));
    }
    walk(&root.join(r"System32\drivers"), &mut out, 0);
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.to_string_lossy().to_ascii_lowercase()));
    out
}

pub fn pooltag_txt_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        v.push(dir.join("pooltag.txt"));
    }
    for pf in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(p) = std::env::var(pf) {
            for arch in ["x64", "arm64", "x86"] {
                v.push(PathBuf::from(&p).join(format!(r"Windows Kits\10\Debuggers\{arch}\triage\pooltag.txt")));
            }
        }
    }
    v
}

// ------------------------------------------------------------------ level 2: PFN walk

const SUPERFETCH_VERSION: u32 = 45;
const SUPERFETCH_MAGIC: u32 = u32::from_le_bytes(*b"Chuk");
const SuperfetchPfnQuery: u32 = 6;
const SuperfetchMemoryRangesQuery: u32 = 17;

#[repr(C)]
struct SUPERFETCH_INFORMATION {
    Version: u32,
    Magic: u32,
    InfoClass: u32,
    Data: *mut c_void,
    Length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MMPFN_IDENTITY {
    u1: u64,
    PageFrameIndex: u64,
    u2: u64,
}
const PFN_REQUEST_HEADER: usize = 8 + 8 + size_of::<SYSTEM_MEMORY_LIST_INFORMATION>();

fn superfetch(class: u32, data: *mut c_void, len: usize) -> (NTSTATUS, u32) {
    let mut info = SUPERFETCH_INFORMATION { Version: SUPERFETCH_VERSION, Magic: SUPERFETCH_MAGIC, InfoClass: class, Data: data, Length: len as u32 };
    let mut ret = 0u32;
    let st = unsafe { NtQuerySystemInformation(SystemSuperfetchInformation, &mut info as *mut _ as *mut c_void, size_of::<SUPERFETCH_INFORMATION>() as u32, &mut ret) };
    (st, ret)
}

/// Physical memory ranges as (base PFN, page count).
fn memory_ranges() -> Result<Vec<(u64, u64)>, String> {
    // Version 2 layout: Version, Flags, RangeCount, (pad), ranges at +16. Version 1: Version, RangeCount, ranges at +8.
    for (version, count_off, ranges_off) in [(2u32, 8usize, 16usize), (1, 4, 8)] {
        let mut size = 4096usize;
        for _ in 0..4 {
            let mut buf = vec![0u64; size / 8];
            buf[0] = version as u64;
            let (st, ret) = superfetch(SuperfetchMemoryRangesQuery, buf.as_mut_ptr() as *mut c_void, size);
            if st == STATUS_BUFFER_TOO_SMALL || st == STATUS_INFO_LENGTH_MISMATCH {
                size = (ret as usize).max(size * 2).next_multiple_of(8);
                continue;
            }
            if st < 0 {
                break;
            }
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, size) };
            let count = u32::from_le_bytes(bytes[count_off..count_off + 4].try_into().unwrap()) as usize;
            if count == 0 || ranges_off + count * 16 > size {
                break;
            }
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let o = ranges_off + i * 16;
                let basepfn = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
                let pages = u64::from_le_bytes(bytes[o + 8..o + 16].try_into().unwrap());
                out.push((basepfn, pages));
            }
            return Ok(out);
        }
    }
    Err("Windows refused the physical memory range query. Deep Scan needs administrator rights.".into())
}

pub fn deep_scan(snap: &Snapshot, progress: &dyn Fn(f32)) -> Result<DeepScan, String> {
    if !is_elevated() {
        return Err("Deep Scan needs administrator rights. Use \"Restart as administrator\".".into());
    }
    if !enable_privilege("SeProfileSingleProcessPrivilege") {
        return Err("Couldn't enable SeProfileSingleProcessPrivilege (is this an administrator account?).".into());
    }
    enable_privilege("SeDebugPrivilege");
    let started = Instant::now();
    let ranges = memory_ranges()?;
    let page_size = 4096u64;
    let total_pages: u64 = ranges.iter().map(|r| r.1).sum();
    let mut d = DeepScan { taken_at: super::mock::now(), page_size, ranges_bytes: total_pages * page_size, ..Default::default() };

    // Private pages by process key: [active, standby, modified]
    let mut by_key: HashMap<u64, [u64; 3]> = HashMap::new();
    let mut pfn_mismatch = 0u64;
    let mut failed_chunks = 0u32;
    let mut first_error = None;
    const CHUNK: u64 = 32 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut done = 0u64;

    for &(base, count) in &ranges {
        let mut start = 0u64;
        while start < count {
            let n = CHUNK.min(count - start);
            let bytes = PFN_REQUEST_HEADER + n as usize * size_of::<MMPFN_IDENTITY>();
            buf.clear();
            buf.resize(bytes / 8, 0);
            buf[0] = 1 | (1u64 << 32); // Version = 1, RequestFlags = 1
            buf[1] = n; // PfnCount
            let entries = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().add(PFN_REQUEST_HEADER / 8) as *mut MMPFN_IDENTITY, n as usize) };
            for (i, e) in entries.iter_mut().enumerate() {
                e.PageFrameIndex = base + start + i as u64;
            }
            let (st, _) = superfetch(SuperfetchPfnQuery, buf.as_mut_ptr() as *mut c_void, bytes);
            if st < 0 {
                failed_chunks += 1;
                first_error.get_or_insert(st);
            } else {
                let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(PFN_REQUEST_HEADER / 8) as *const MMPFN_IDENTITY, n as usize) };
                for (i, e) in entries.iter().enumerate() {
                    if e.PageFrameIndex != base + start + i as u64 {
                        pfn_mismatch += 1;
                    }
                    let use_ = (e.u1 & 0xf) as usize;
                    let list = ((e.u1 >> 4) & 7) as usize;
                    d.by_use_list[use_][list] += page_size;
                    if use_ == 0 && list >= 2 {
                        let key = (e.u1 >> 9) & 0xFFFF_FFFF_FFFF;
                        let slot = match list {
                            6 | 7 => Some(0),
                            2 => Some(1),
                            3 | 4 => Some(2),
                            _ => None,
                        };
                        if let Some(s) = slot {
                            by_key.entry(key).or_default()[s] += page_size;
                        }
                    }
                }
                d.pages_scanned += n;
            }
            start += n;
            done += n;
            progress(done as f32 / total_pages.max(1) as f32);
        }
    }

    if d.pages_scanned == 0 {
        return Err(format!(
            "Windows refused every page query ({}). This Windows build may block the interface RAMMap uses.",
            first_error.map(ntstatus).unwrap_or_default()
        ));
    }
    if failed_chunks > 0 {
        d.notes.push(format!("{failed_chunks} chunk(s) of physical memory couldn't be read (first error {}).", first_error.map(ntstatus).unwrap_or_default()));
    }
    if pfn_mismatch > 0 {
        d.notes.push(format!("{pfn_mismatch} pages came back with an unexpected frame number; results may be unreliable."));
    }

    match_process_keys(snap, &by_key, &mut d);

    // Cross-check against the kernel's own list counters.
    if let Some(l) = &snap.lists {
        let pfn_standby = d.list_total(2);
        let pfn_free = d.list_total(0) + d.list_total(1);
        d.notes.push(format!(
            "Consistency check: standby {} by page walk vs {} by counter; free {} vs {}.",
            crate::breakdown::fmt_bytes(pfn_standby),
            crate::breakdown::fmt_bytes(l.standby()),
            crate::breakdown::fmt_bytes(pfn_free),
            crate::breakdown::fmt_bytes(l.zeroed + l.free)
        ));
    }
    d.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(d)
}

/// The PFN database tags private pages with a 48-bit process key. Its exact relation to the
/// key that SystemExtendedProcessInformation reports varies between builds, so try a few
/// transforms and keep whichever explains the most pages.
fn match_process_keys(snap: &Snapshot, by_key: &HashMap<u64, [u64; 3]>, d: &mut DeepScan) {
    const M48: u64 = 0xFFFF_FFFF_FFFF;
    let total: u64 = by_key.values().map(|v| v[0] + v[1] + v[2]).sum();
    if total == 0 {
        return;
    }
    let mut best: Option<(u64, HashMap<u64, usize>, String)> = None;
    let mut candidates: Vec<(String, Box<dyn Fn(&ProcInfo) -> u64>)> = vec![("pid".into(), Box::new(|p: &ProcInfo| p.pid as u64))];
    for s in 0..=12u32 {
        candidates.push((format!("key>>{s}"), Box::new(move |p: &ProcInfo| (p.unique_key >> s) & M48)));
    }
    for (label, f) in &candidates {
        let map: HashMap<u64, usize> = snap.procs.iter().enumerate().filter(|(_, p)| p.unique_key != 0 || label == "pid").map(|(i, p)| (f(p), i)).collect();
        let matched: u64 = by_key.iter().filter(|(k, _)| map.contains_key(k)).map(|(_, v)| v[0] + v[1] + v[2]).sum();
        if best.as_ref().is_none_or(|b| matched > b.0) {
            best = Some((matched, map, label.clone()));
        }
    }
    let Some((matched, map, label)) = best else { return };
    if matched * 10 < total * 3 {
        d.unmatched_private = total;
        d.notes.push("Per-process private page attribution unavailable on this Windows build (process keys didn't match).".into());
        return;
    }
    let mut per: HashMap<usize, DeepProc> = HashMap::new();
    for (k, v) in by_key {
        match map.get(k) {
            Some(&i) => {
                let p = &snap.procs[i];
                let e = per.entry(i).or_insert_with(|| DeepProc { pid: p.pid, name: p.name.clone(), ..Default::default() });
                e.active += v[0];
                e.standby += v[1];
                e.modified += v[2];
            }
            None => d.unmatched_private += v[0] + v[1] + v[2],
        }
    }
    d.procs = per.into_values().collect();
    d.procs.sort_by_key(|p| std::cmp::Reverse(p.active + p.standby + p.modified));
    d.notes.push(format!(
        "Matched {:.0}% of private pages to processes (method {label}).",
        matched as f64 * 100.0 / total as f64
    ));
}
