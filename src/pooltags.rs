//! Works out which driver owns a kernel pool tag.
//!
//! Drivers pass their 4-byte tag as an immediate operand when allocating, so the tag's
//! bytes appear verbatim in the driver's code. We search every loaded driver image for
//! them and score hits that look like `mov reg, imm32` / `push imm32` higher than hits
//! inside random data. Descriptions come from a small built-in table, plus Microsoft's
//! pooltag.txt when it is installed (Debugging Tools for Windows) or placed next to the exe.

use crate::model::TagOwner;
use aho_corasick::{AhoCorasick, MatchKind};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// (tag or prefix ending in '*', owner, description)
const KNOWN: &[(&str, &str, &str)] = &[
    ("MmSt", "ntoskrnl.exe", "Mapped file bookkeeping (section prototype PTEs)"),
    ("MmCa", "ntoskrnl.exe", "Mapped file control areas"),
    ("Mm*", "ntoskrnl.exe", "Memory manager"),
    ("File", "ntoskrnl.exe", "File objects (open files)"),
    ("Thre", "ntoskrnl.exe", "Thread objects"),
    ("Proc", "ntoskrnl.exe", "Process objects"),
    ("Toke", "ntoskrnl.exe", "Security tokens"),
    ("Even", "ntoskrnl.exe", "Event objects"),
    ("Irp ", "ntoskrnl.exe", "I/O request packets"),
    ("Mdl ", "ntoskrnl.exe", "Memory descriptor lists"),
    ("Cont", "ntoskrnl.exe", "Contiguous physical memory for device drivers"),
    ("Vad*", "ntoskrnl.exe", "Virtual address descriptors (process address space)"),
    ("Ob*", "ntoskrnl.exe", "Object manager"),
    ("Se*", "ntoskrnl.exe", "Security"),
    ("Etw*", "ntoskrnl.exe", "Event tracing (ETW) buffers"),
    ("CM*", "ntoskrnl.exe", "Registry (configuration manager)"),
    ("Pp*", "ntoskrnl.exe", "Plug and Play"),
    ("sm*", "ntoskrnl.exe", "Store manager (memory compression / ReadyBoost)"),
    ("Vi*", "verifier", "Driver Verifier"),
    ("Ntf*", "ntfs.sys", "NTFS file system"),
    ("NtF*", "ntfs.sys", "NTFS file system"),
    ("FM*", "fltmgr.sys", "Filter Manager (used by antivirus/backup file system filters)"),
    ("Tcp*", "tcpip.sys", "TCP/IP"),
    ("Ale*", "tcpip.sys", "Windows Filtering Platform (firewall) endpoints"),
    ("Wfp*", "netio.sys", "Windows Filtering Platform"),
    ("Nd*", "ndis.sys", "Network driver interface"),
    ("Afd*", "afd.sys", "Winsock (network sockets)"),
    ("Dx*", "dxgkrnl.sys", "DirectX graphics kernel"),
    ("Gh*", "win32k", "GDI graphics objects"),
    ("Gla*", "win32k", "GDI graphics objects"),
    ("Us*", "win32k", "Window manager (USER)"),
];

pub fn known_owner(tag: &str) -> Option<(&'static str, &'static str)> {
    KNOWN
        .iter()
        .find(|(t, _, _)| *t == tag)
        .or_else(|| {
            KNOWN.iter().filter(|(t, _, _)| t.ends_with('*')).find(|(t, _, _)| tag.starts_with(&t[..t.len() - 1]))
        })
        .map(|(_, o, d)| (*o, *d))
}

/// Parses Microsoft's pooltag.txt ("Tag  - driver.sys  - description").
pub fn load_pooltag_txt(path: &Path) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    let Ok(bytes) = std::fs::read(path) else { return out };
    for line in String::from_utf8_lossy(&bytes).lines() {
        if line.starts_with("//") || line.trim().is_empty() || line.len() < 6 {
            continue;
        }
        let mut parts = line.splitn(3, " - ");
        let (Some(tag), Some(owner)) = (parts.next(), parts.next()) else { continue };
        let tag = tag.trim_end_matches(['\t']).to_string();
        let tag: String = if tag.len() >= 4 { tag[..4].to_string() } else { format!("{tag:<4}") };
        let desc = parts.next().unwrap_or("").trim().to_string();
        out.entry(tag).or_insert((owner.trim().to_string(), desc));
    }
    out
}

fn looks_like_immediate(data: &[u8], at: usize) -> bool {
    let b1 = if at >= 1 { data[at - 1] } else { 0 };
    let b2 = if at >= 2 { data[at - 2] } else { 0 };
    let b3 = if at >= 3 { data[at - 3] } else { 0 };
    let b4 = if at >= 4 { data[at - 4] } else { 0 };
    (0xB8..=0xBF).contains(&b1)       // mov r32, imm32
        || b1 == 0x68                  // push imm32
        || (b2 == 0xC7 && (b1 & 0xC0) == 0xC0) // mov r/m32, imm32 (register form)
        || (b3 == 0xC7 && (0x40..0x80).contains(&b2)) // mov [reg+disp8], imm32
        || (b4 == 0xC7 && b3 == 0x44 && b2 == 0x24) // mov [rsp+disp8], imm32
        || (b2 == 0x81 && (b1 & 0xF8) == 0xF8) // cmp reg, imm32
        || (b2 == 0x41 && (0xB8..=0xBF).contains(&b1))
}

pub struct ScanResult {
    pub owners: HashMap<String, TagOwner>,
    pub files_scanned: usize,
    pub files_unreadable: usize,
}

/// Search driver images for the given tags. `tags` are (display string, raw bytes).
pub fn scan(drivers: &[PathBuf], tags: &[(String, [u8; 4])], descriptions: &HashMap<String, (String, String)>) -> ScanResult {
    let mut owners: HashMap<String, TagOwner> = HashMap::new();
    let mut files_scanned = 0;
    let mut files_unreadable = 0;
    if !tags.is_empty() {
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(tags.iter().map(|(_, raw)| raw.to_vec()))
            .expect("pattern build");
        // scores[tag][driver] = (strong hits, weak hits)
        let mut scores: Vec<HashMap<String, (u32, u32)>> = vec![HashMap::new(); tags.len()];
        for path in drivers {
            let Ok(data) = std::fs::read(path) else {
                files_unreadable += 1;
                continue;
            };
            files_scanned += 1;
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            for m in ac.find_overlapping_iter(&data) {
                let e = scores[m.pattern().as_usize()].entry(name.clone()).or_default();
                if looks_like_immediate(&data, m.start()) {
                    e.0 += 1;
                } else {
                    e.1 += 1;
                }
            }
        }
        for (i, (tag, _)) in tags.iter().enumerate() {
            let mut cands: Vec<(&String, &(u32, u32))> = scores[i].iter().filter(|(_, s)| s.0 > 0).collect();
            cands.sort_by_key(|(n, s)| (std::cmp::Reverse(s.0), (*n).clone()));
            let mut drivers: Vec<String> = cands.iter().take(3).map(|(n, _)| (*n).clone()).collect();
            if drivers.is_empty() {
                // Only data hits: much weaker evidence, but still better than nothing if unique.
                let weak: Vec<&String> = scores[i].keys().collect();
                if weak.len() == 1 {
                    drivers.push(format!("{} (weak match)", weak[0]));
                }
            }
            owners.insert(tag.clone(), TagOwner { drivers, description: None });
        }
    }
    for (tag, _) in tags {
        let e = owners.entry(tag.clone()).or_default();
        if let Some((owner, desc)) = descriptions.get(tag) {
            if !desc.is_empty() {
                e.description = Some(desc.clone());
            }
            if e.drivers.is_empty() && !owner.is_empty() && owner != "<unknown>" {
                e.drivers.push(owner.clone());
            }
        }
        if let Some((owner, desc)) = known_owner(tag) {
            if e.description.is_none() {
                e.description = Some(desc.to_string());
            }
            if e.drivers.is_empty() {
                e.drivers.push(owner.to_string());
            }
        }
    }
    ScanResult { owners, files_scanned, files_unreadable }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_immediate_tag() {
        let dir = std::env::temp_dir().join(format!("ramwhere-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("good.sys");
        let b = dir.join("other.sys");
        // 41 B8 'Leak' = mov r8d, 'kaeL' (tag shows as "Leak")
        std::fs::write(&a, [0x90, 0x41, 0xB8, b'L', b'e', b'a', b'k', 0x90]).unwrap();
        std::fs::write(&b, b"nothing Leak here").unwrap();
        let r = scan(&[a, b], &[("Leak".into(), *b"Leak")], &HashMap::new());
        assert_eq!(r.owners["Leak"].drivers, vec!["good.sys".to_string()]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn prefix_lookup() {
        assert_eq!(known_owner("FMfn").unwrap().0, "fltmgr.sys");
        assert_eq!(known_owner("MmSt").unwrap().1, "Mapped file bookkeeping (section prototype PTEs)");
    }
}
