//! "What's using it": groups memory by the product responsible (drivers + processes) and
//! says what to do about it.

use crate::breakdown::fmt_bytes;
use crate::model::*;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Security,
    Vpn,
    Oem,
    Hardware,
    Vm,
    Browser,
    Windows,
    App,
    UnknownDriver,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Security => "Security software",
            Kind::Vpn => "VPN / network client",
            Kind::Oem => "Manufacturer utility",
            Kind::Hardware => "Hardware driver",
            Kind::Vm => "Virtual machines",
            Kind::Browser => "Web browser",
            Kind::Windows => "Part of Windows",
            Kind::App => "App",
            Kind::UnknownDriver => "Unrecognised driver",
        }
    }
}

struct Known {
    /// Lower-case file name, or a prefix ending in '*'.
    pattern: &'static str,
    product: &'static str,
    vendor: &'static str,
    kind: Kind,
}

const fn k(pattern: &'static str, product: &'static str, vendor: &'static str, kind: Kind) -> Known {
    Known { pattern, product, vendor, kind }
}

/// Well-known drivers and programs. Matching is on file name only.
const KNOWN: &[Known] = &[
    // Security
    k("csagent.sys", "CrowdStrike Falcon", "CrowdStrike", Kind::Security),
    k("csfalconservice.exe", "CrowdStrike Falcon", "CrowdStrike", Kind::Security),
    k("wdfilter.sys", "Microsoft Defender", "Microsoft", Kind::Security),
    k("wdboot.sys", "Microsoft Defender", "Microsoft", Kind::Security),
    k("wdnisdrv.sys", "Microsoft Defender", "Microsoft", Kind::Security),
    k("msmpeng.exe", "Microsoft Defender", "Microsoft", Kind::Security),
    k("nissrv.exe", "Microsoft Defender", "Microsoft", Kind::Security),
    k("mssense.exe", "Microsoft Defender for Endpoint", "Microsoft", Kind::Security),
    k("sentinel*", "SentinelOne", "SentinelOne", Kind::Security),
    k("mfe*", "McAfee / Trellix", "McAfee", Kind::Security),
    k("mcshield.exe", "McAfee / Trellix", "McAfee", Kind::Security),
    k("symefasi*", "Symantec / Norton", "Broadcom", Kind::Security),
    k("srtsp*", "Symantec / Norton", "Broadcom", Kind::Security),
    k("ccsvchst.exe", "Symantec / Norton", "Broadcom", Kind::Security),
    k("sophos*", "Sophos", "Sophos", Kind::Security),
    k("savonaccess.sys", "Sophos", "Sophos", Kind::Security),
    k("tmcomm.sys", "Trend Micro", "Trend Micro", Kind::Security),
    k("tmactmon.sys", "Trend Micro", "Trend Micro", Kind::Security),
    k("eamonm.sys", "ESET", "ESET", Kind::Security),
    k("ehdrv.sys", "ESET", "ESET", Kind::Security),
    k("ekrn.exe", "ESET", "ESET", Kind::Security),
    k("klif.sys", "Kaspersky", "Kaspersky", Kind::Security),
    k("avp.exe", "Kaspersky", "Kaspersky", Kind::Security),
    k("trufos.sys", "Bitdefender", "Bitdefender", Kind::Security),
    k("bdservicehost.exe", "Bitdefender", "Bitdefender", Kind::Security),
    k("mbam*", "Malwarebytes", "Malwarebytes", Kind::Security),
    k("cyprotectdrv*", "Palo Alto Cortex XDR", "Palo Alto Networks", Kind::Security),
    k("aswsp.sys", "Avast / AVG", "Gen Digital", Kind::Security),
    k("avastsvc.exe", "Avast / AVG", "Gen Digital", Kind::Security),
    // VPN / network security
    k("acsock64.sys", "Cisco Secure Client (AnyConnect)", "Cisco", Kind::Vpn),
    k("vpnva*", "Cisco Secure Client (AnyConnect)", "Cisco", Kind::Vpn),
    k("vpnagent.exe", "Cisco Secure Client (AnyConnect)", "Cisco", Kind::Vpn),
    k("pangpd.sys", "Palo Alto GlobalProtect", "Palo Alto Networks", Kind::Vpn),
    k("pangps.exe", "Palo Alto GlobalProtect", "Palo Alto Networks", Kind::Vpn),
    k("forti*", "Fortinet FortiClient", "Fortinet", Kind::Vpn),
    k("zsa*", "Zscaler", "Zscaler", Kind::Vpn),
    k("wintun.sys", "WireGuard / Wintun VPN adapter", "WireGuard", Kind::Vpn),
    k("wireguard.sys", "WireGuard", "WireGuard", Kind::Vpn),
    k("tap0901.sys", "OpenVPN TAP adapter", "OpenVPN", Kind::Vpn),
    // Hardware drivers
    k("nvlddmkm.sys", "NVIDIA graphics driver", "NVIDIA", Kind::Hardware),
    k("nvcontainer.exe", "NVIDIA app / GeForce Experience", "NVIDIA", Kind::Oem),
    k("igdkmd*", "Intel graphics driver", "Intel", Kind::Hardware),
    k("amdkmdag.sys", "AMD graphics driver", "AMD", Kind::Hardware),
    k("atikmdag.sys", "AMD graphics driver", "AMD", Kind::Hardware),
    k("netwtw*", "Intel Wi-Fi driver", "Intel", Kind::Hardware),
    k("rtwlan*", "Realtek Wi-Fi driver", "Realtek", Kind::Hardware),
    k("rt640x64.sys", "Realtek Ethernet driver", "Realtek", Kind::Hardware),
    k("kfeco*", "Killer networking driver", "Intel (Rivet Networks)", Kind::Hardware),
    // Manufacturer utilities
    k("supportassist*", "Dell SupportAssist", "Dell", Kind::Oem),
    k("delloptimizer*", "Dell Optimizer", "Dell", Kind::Oem),
    k("dell.techhub*", "Dell SupportAssist / TechHub", "Dell", Kind::Oem),
    k("lenovovantage*", "Lenovo Vantage", "Lenovo", Kind::Oem),
    k("lghub*", "Logitech G HUB", "Logitech", Kind::Oem),
    k("icue*", "Corsair iCUE", "Corsair", Kind::Oem),
    k("razer*", "Razer Synapse", "Razer", Kind::Oem),
    k("killernetworkservice.exe", "Killer Intelligence Center", "Intel (Rivet Networks)", Kind::Oem),
    k("waveslib*", "Waves MaxxAudio", "Waves", Kind::Oem),
    // Virtual machines
    k("vmmemctl.sys", "VMware memory balloon driver", "VMware", Kind::Vm),
    k("vboxdrv.sys", "VirtualBox", "Oracle", Kind::Vm),
    k("vmswitch.sys", "Hyper-V virtual switch", "Microsoft", Kind::Vm),
    k("docker desktop.exe", "Docker Desktop", "Docker", Kind::Vm),
    k("com.docker.backend.exe", "Docker Desktop", "Docker", Kind::Vm),
    // Browsers
    k("msedge.exe", "Microsoft Edge", "Microsoft", Kind::Browser),
    k("msedgewebview2.exe", "Edge WebView2 (used inside other apps)", "Microsoft", Kind::Browser),
    k("chrome.exe", "Google Chrome", "Google", Kind::Browser),
    k("firefox.exe", "Mozilla Firefox", "Mozilla", Kind::Browser),
    k("brave.exe", "Brave", "Brave", Kind::Browser),
    k("opera.exe", "Opera", "Opera", Kind::Browser),
    k("vivaldi.exe", "Vivaldi", "Vivaldi", Kind::Browser),
    // Common apps
    k("ms-teams.exe", "Microsoft Teams", "Microsoft", Kind::App),
    k("teams.exe", "Microsoft Teams", "Microsoft", Kind::App),
    k("outlook.exe", "Microsoft Outlook", "Microsoft", Kind::App),
    k("olk.exe", "Microsoft Outlook (new)", "Microsoft", Kind::App),
    k("onedrive.exe", "OneDrive", "Microsoft", Kind::App),
    k("slack.exe", "Slack", "Slack", Kind::App),
    k("discord.exe", "Discord", "Discord", Kind::App),
    k("code.exe", "Visual Studio Code", "Microsoft", Kind::App),
    k("spotify.exe", "Spotify", "Spotify", Kind::App),
    k("zoom.exe", "Zoom", "Zoom", Kind::App),
    // Windows
    k("searchindexer.exe", "Windows Search indexer", "Microsoft", Kind::Windows),
    k("explorer.exe", "Windows Explorer", "Microsoft", Kind::Windows),
    k("dwm.exe", "Desktop Window Manager", "Microsoft", Kind::Windows),
    k("svchost.exe", "Windows services (svchost)", "Microsoft", Kind::Windows),
    k("system", "Windows kernel", "Microsoft", Kind::Windows),
];

/// Windows' own kernel modules: their pool goes to one "Windows kernel & drivers" entry.
const WINDOWS_DRIVERS: &[&str] = &[
    "ntoskrnl.exe", "win32k", "win32k.sys", "win32kbase.sys", "win32kfull.sys", "verifier", "ntfs.sys", "tcpip.sys", "netio.sys", "ndis.sys",
    "afd.sys", "dxgkrnl.sys", "fltmgr.sys", "refs.sys", "storport.sys", "volsnap.sys", "cng.sys", "ksecdd.sys", "http.sys", "srv2.sys",
    "mrxsmb.sys", "rdbss.sys", "fvevol.sys", "wof.sys", "cldflt.sys", "ci.dll", "clfs.sys", "acpi.sys", "pci.sys",
];

fn lookup(file: &str) -> Option<&'static Known> {
    let f = file.to_ascii_lowercase();
    KNOWN.iter().find(|k| k.pattern == f).or_else(|| {
        KNOWN
            .iter()
            .filter(|k| k.pattern.ends_with('*'))
            .find(|k| f.starts_with(&k.pattern[..k.pattern.len() - 1]))
    })
}

#[derive(Clone, Debug, Default)]
pub struct Offender {
    pub key: String,
    pub name: String,
    pub vendor: String,
    pub kind: Option<Kind>,
    /// Private memory in RAM: the part Task Manager shows.
    pub private_ram: u64,
    /// Committed but not in RAM: compressed or in the pagefile.
    pub compressed: u64,
    /// Kernel pool owned by this product's drivers.
    pub kernel_pool: u64,
    /// Growth of kernel pool since the baseline, if one is set.
    pub pool_growth: Option<i64>,
    pub private_growth: Option<i64>,
    pub vm: u64,
    pub processes: Vec<(String, u32, u64)>,
    pub drivers: Vec<String>,
    /// Paths of driver files, for "Open file location".
    pub driver_paths: Vec<String>,
    pub tags: Vec<(String, u64)>,
    pub advice: Vec<String>,
}

impl Offender {
    pub fn hidden(&self) -> u64 {
        self.kernel_pool + self.compressed
    }
    pub fn total(&self) -> u64 {
        self.private_ram + self.hidden() + self.vm
    }
}

fn entry<'a>(map: &'a mut HashMap<String, Offender>, key: &str, name: &str, vendor: &str, kind: Option<Kind>) -> &'a mut Offender {
    map.entry(key.to_string()).or_insert_with(|| Offender { key: key.into(), name: name.into(), vendor: vendor.into(), kind, ..Default::default() })
}

fn strong_owner(o: &TagOwner) -> Option<String> {
    o.drivers.first().filter(|d| !d.contains("(weak")).map(|d| d.to_ascii_lowercase())
}

pub fn compute(snap: &Snapshot, owners: &HashMap<String, TagOwner>, baseline: Option<&Snapshot>, driver_paths: &HashMap<String, String>) -> (Vec<Offender>, u64) {
    let mut map: HashMap<String, Offender> = HashMap::new();
    let mut unattributed_pool = 0u64;

    // Kernel pool, by owning driver.
    let base_pool: Option<HashMap<&str, u64>> = baseline.map(|b| b.pool.iter().map(|t| (t.tag.as_str(), t.total())).collect());
    for t in &snap.pool {
        let Some(driver) = owners.get(&t.tag).and_then(strong_owner) else {
            unattributed_pool += t.total();
            continue;
        };
        let o = if let Some(kn) = lookup(&driver) {
            entry(&mut map, kn.product, kn.product, kn.vendor, Some(kn.kind))
        } else if driver == "fltmgr.sys" {
            entry(&mut map, "fltmgr", "File system filters (via Filter Manager)", "Microsoft, on behalf of filter drivers", Some(Kind::Windows))
        } else if WINDOWS_DRIVERS.contains(&driver.as_str()) || driver.starts_with("win32k") {
            entry(&mut map, "windows-kernel", "Windows kernel & built-in drivers", "Microsoft", Some(Kind::Windows))
        } else {
            entry(&mut map, &format!("drv:{driver}"), &driver, "", Some(Kind::UnknownDriver))
        };
        o.kernel_pool += t.total();
        o.tags.push((t.tag.clone(), t.total()));
        if !o.drivers.contains(&driver) {
            o.drivers.push(driver.clone());
            if let Some(p) = driver_paths.get(&driver) {
                o.driver_paths.push(p.clone());
            }
        }
        if let Some(b) = &base_pool {
            let before = *b.get(t.tag.as_str()).unwrap_or(&0) as i64;
            *o.pool_growth.get_or_insert(0) += t.total() as i64 - before;
        }
    }

    // Processes.
    let base_procs: Option<HashMap<(u32, &str), u64>> = baseline.map(|b| b.procs.iter().map(|p| ((p.pid, p.name.as_str()), p.private_ws)).collect());
    for p in &snap.procs {
        if p.pid == 0 {
            continue;
        }
        let o = match special_kind(&p.name) {
            // Its contents belong to other processes and are charged to them as "compressed".
            Some(SpecialProc::MemoryCompression) => continue,
            Some(SpecialProc::VmWorker) => {
                let o = entry(&mut map, "vm", "Virtual machines / WSL2 / Docker", "", Some(Kind::Vm));
                o.vm += p.private_ws;
                o.processes.push((p.name.clone(), p.pid, p.private_ws));
                continue;
            }
            Some(SpecialProc::SecureSystem) => entry(&mut map, "vbs", "Virtualization-based security (Secure System)", "Microsoft", Some(Kind::Windows)),
            Some(SpecialProc::Registry) => entry(&mut map, "registry", "Windows registry", "Microsoft", Some(Kind::Windows)),
            None => match lookup(&p.name) {
                Some(kn) => entry(&mut map, kn.product, kn.product, kn.vendor, Some(kn.kind)),
                None => {
                    let name = p.name.clone();
                    entry(&mut map, &format!("proc:{}", name.to_ascii_lowercase()), &name, "", None)
                }
            },
        };
        let in_ram = if matches!(special_kind(&p.name), Some(SpecialProc::SecureSystem | SpecialProc::Registry)) { p.ws } else { p.private_ws };
        o.private_ram += in_ram;
        o.compressed += p.private_commit.saturating_sub(in_ram);
        o.processes.push((p.name.clone(), p.pid, in_ram));
        if let Some(b) = &base_procs {
            let before = *b.get(&(p.pid, p.name.as_str())).unwrap_or(&0) as i64;
            *o.private_growth.get_or_insert(0) += p.private_ws as i64 - before;
        }
    }

    let mut list: Vec<Offender> = map.into_values().filter(|o| o.total() >= 32 << 20).collect();
    for o in &mut list {
        o.processes.sort_by_key(|p| std::cmp::Reverse(p.2));
        o.tags.sort_by_key(|t| std::cmp::Reverse(t.1));
        o.advice = advice(o);
    }
    list.sort_by_key(|o| std::cmp::Reverse(o.total()));
    (list, unattributed_pool)
}

fn advice(o: &Offender) -> Vec<String> {
    let mut a = Vec::new();
    if o.kernel_pool >= 64 << 20 {
        let tags: Vec<String> = o.tags.iter().take(3).map(|(t, b)| format!("'{t}' {}", fmt_bytes(*b))).collect();
        a.push(format!(
            "Its drivers hold {} of kernel memory ({}). Kernel memory never shows in Task Manager and can't be compressed or paged out.",
            fmt_bytes(o.kernel_pool),
            tags.join(", ")
        ));
    }
    if let Some(g) = o.pool_growth.filter(|&g| g > 32 << 20) {
        a.push(format!("Its kernel memory has grown by {} since the baseline. Steady growth like this is a driver leak.", fmt_bytes(g as u64)));
    }
    if o.compressed >= 128 << 20 {
        a.push(format!("{} of its memory is compressed or in the pagefile (counted in Memory Compression, not under its own name).", fmt_bytes(o.compressed)));
    }
    let kind_advice = match o.kind {
        Some(Kind::Security) => "Security software. On a work PC IT installs and manages this, so don't remove it yourself: send them this report (Copy report). On your own PC, make sure only one antivirus is installed; two at once is a classic cause of high kernel memory.",
        Some(Kind::Vpn) => "VPN / network security client. Updating to the latest version is the usual fix for high or growing kernel memory. On a work PC, report it to IT.",
        Some(Kind::Oem) => "Manufacturer utility. Usually safe to uninstall if you don't use its features (Settings > Apps); Windows and your drivers keep working without it.",
        Some(Kind::Hardware) => "Hardware driver. If it's large or growing, install the newest driver from the manufacturer (Dell/Intel/NVIDIA/AMD site) rather than relying on Windows Update.",
        Some(Kind::Vm) => "Virtual machines. Run `wsl --shutdown` or quit Docker Desktop / your VM to give the memory back. Cap WSL2 with a .wslconfig file.",
        Some(Kind::Browser) => "Web browser. Every tab and extension is a separate process. Close tabs you don't need, remove unused extensions, or turn on Memory Saver / sleeping tabs.",
        Some(Kind::Windows) if o.key == "fltmgr" => "Memory the Filter Manager allocates on behalf of file system filters: antivirus, backup, sync and DLP tools. If it's large, one of those is the real cause; check the security software entries above.",
        Some(Kind::Windows) if o.key == "windows-kernel" => "Windows itself. Large values here are usually driven by something else, e.g. 'MmSt' grows when software maps huge numbers of files (antivirus scans, backup, indexing). See the Drivers tab for which tags are big.",
        Some(Kind::Windows) => "Part of Windows. Normally nothing to remove; only worth investigating if it keeps growing.",
        Some(Kind::App) | None => "An app. Close it when you're not using it, or uninstall it if you don't need it (Settings > Apps).",
        Some(Kind::UnknownDriver) => "A driver this tool doesn't recognise. Click \"Open file location\", then right-click the file > Properties > Details to see which product it belongs to. If it's something you don't need, uninstall that product.",
    };
    a.push(kind_advice.into());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_driver_and_process() {
        let snap = crate::platform::mock_snapshot();
        let mut owners = HashMap::new();
        owners.insert("Leak".to_string(), TagOwner { drivers: vec!["csagent.sys".into()], description: None });
        let (list, _) = compute(&snap, &owners, None, &HashMap::new());
        let cs = list.iter().find(|o| o.name == "CrowdStrike Falcon").expect("crowdstrike entry");
        assert!(cs.kernel_pool > 2 << 30);
        assert!(cs.processes.iter().any(|p| p.0 == "csfalconservice.exe"));
        assert_eq!(list[0].name, "CrowdStrike Falcon");
    }
}
