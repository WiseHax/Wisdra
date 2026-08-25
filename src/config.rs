//! Configuration constants and path resolution for Wisdra.

use std::path::{Path, PathBuf};

/// Default analysis timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Name of the Python extraction script executed inside Ghidra.
pub const EXTRACTION_SCRIPT: &str = "WisdraExtract.java";

/// Ghidra headless analyzer binary name (platform-dependent).
#[cfg(windows)]
pub const HEADLESS_BINARY: &str = "analyzeHeadless.bat";

#[cfg(not(windows))]
pub const HEADLESS_BINARY: &str = "analyzeHeadless";

/// Resolve the Ghidra headless analyzer path.
///
/// Search order:
/// 1. Explicit `--ghidra-path` argument
/// 2. `GHIDRA_INSTALL_DIR` environment variable
/// 3. `vendor/ghidra` relative to the executable
pub fn resolve_ghidra_path(explicit: Option<&str>) -> Option<PathBuf> {
    // 1. Explicit CLI argument
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }

    // 2. Environment variable
    if let Ok(env_path) = std::env::var("GHIDRA_INSTALL_DIR") {
        let path = PathBuf::from(&env_path);
        if path.exists() {
            return Some(path);
        }
    }

    // 3. Vendor directory relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let vendor = exe_dir.join("vendor").join("ghidra");
            if vendor.exists() {
                return Some(vendor);
            }
            // Also check relative to CWD
            let cwd_vendor = PathBuf::from("vendor").join("ghidra");
            if cwd_vendor.exists() {
                return Some(cwd_vendor);
            }
        }
    }

    None
}

/// Resolve the path to the extraction script.
pub fn resolve_script_path() -> PathBuf {
    // Check next to executable first
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let script = exe_dir.join("scripts").join(EXTRACTION_SCRIPT);
            if script.exists() {
                return script;
            }
        }
    }

    // Fall back to CWD-relative
    PathBuf::from("scripts").join(EXTRACTION_SCRIPT)
}

/// Resolve the headless analyzer executable within a Ghidra installation.
pub fn resolve_headless_exe(ghidra_root: &Path) -> PathBuf {
    ghidra_root.join("support").join(HEADLESS_BINARY)
}

/// Get the default output directory, creating it if needed.
pub fn output_dir() -> PathBuf {
    let dir = PathBuf::from("output");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).ok();
    }
    dir
}

/// Generate a temporary Ghidra project directory for analysis.
pub fn temp_project_dir() -> PathBuf {
    let id = uuid::Uuid::new_v4();
    let dir = std::env::temp_dir().join(format!("wisdra_proj_{}", id.as_simple()));
    std::fs::create_dir_all(&dir).ok();
    dir
}
