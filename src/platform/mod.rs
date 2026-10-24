//! OS access. The real implementation is Windows-only; other platforms get a simulated
//! machine so the UI can be developed and tested anywhere.

mod mock;
pub use mock::now as mock_now;
#[cfg(test)]
pub use mock::{mock_deep, mock_snapshot};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

#[cfg(not(windows))]
mod fallback {
    use crate::model::{DeepScan, Snapshot};
    use std::path::PathBuf;

    pub fn collect() -> Snapshot {
        super::mock::mock_snapshot_jittered()
    }
    pub fn driver_files() -> Vec<PathBuf> {
        Vec::new()
    }
    pub fn pooltag_txt_candidates() -> Vec<PathBuf> {
        Vec::new()
    }
    pub fn deep_scan(snap: &Snapshot, progress: &dyn Fn(f32)) -> Result<DeepScan, String> {
        for i in 0..20 {
            progress(i as f32 / 20.0);
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        Ok(super::mock::mock_deep(snap))
    }
    pub fn relaunch_elevated() -> Result<(), String> {
        Err("Only available on Windows".into())
    }
    pub fn is_simulated() -> bool {
        true
    }
    pub fn open_location(_path: &str) -> Result<(), String> {
        Err("Only available on Windows".into())
    }
    pub fn open_apps_settings() -> Result<(), String> {
        Err("Only available on Windows".into())
    }
    pub fn open_services() -> Result<(), String> {
        Err("Only available on Windows".into())
    }
}
#[cfg(not(windows))]
pub use fallback::*;
