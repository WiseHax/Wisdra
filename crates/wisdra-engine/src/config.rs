//! Path resolution for Ghidra, the extraction script, and external tools.
//!
//! Nothing here depends on the current working directory alone: every lookup
//! also checks next to the executable and (for dev builds) the source tree.

use crate::error::{Result, WisdraError};
use std::path::{Path, PathBuf};

pub const EXTRACTION_SCRIPT: &str = "WisdraExtract.java";

#[cfg(windows)]
const HEADLESS_BINARY: &str = "analyzeHeadless.bat";
#[cfg(not(windows))]
const HEADLESS_BINARY: &str = "analyzeHeadless";

#[cfg(windows)]
const VERIFIER_BINARY: &str = "exposure_z3.exe";
#[cfg(not(windows))]
const VERIFIER_BINARY: &str = "exposure_z3";

/// Resolve the Ghidra install root: explicit flag, then `GHIDRA_HOME`,
/// then `GHIDRA_INSTALL_DIR`.
pub fn resolve_ghidra_root(explicit: Option<&Path>) -> Result<PathBuf> {
    let candidates = explicit
        .map(Path::to_path_buf)
        .into_iter()
        .chain(["GHIDRA_HOME", "GHIDRA_INSTALL_DIR"].iter().filter_map(|v| std::env::var_os(v).map(PathBuf::from)));

    for root in candidates {
        if root.is_dir() {
            return Ok(root);
        }
        tracing::warn!("ignoring Ghidra path that is not a directory: {}", root.display());
    }
    Err(WisdraError::GhidraNotFound)
}

/// Locate `support/analyzeHeadless[.bat]` inside a Ghidra install.
pub fn resolve_headless(ghidra_root: &Path) -> Result<PathBuf> {
    let exe = ghidra_root.join("support").join(HEADLESS_BINARY);
    if exe.is_file() { Ok(exe) } else { Err(WisdraError::HeadlessNotFound(exe)) }
}

/// Locate the extraction script directory: next to the executable,
/// in the source tree (dev builds), then relative to the CWD.
pub fn resolve_script_dir() -> Result<PathBuf> {
    let mut searched = Vec::new();
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir() {
        candidates.push(dir.join("scripts"));
    }
    candidates.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("scripts"));
    candidates.push(PathBuf::from("scripts"));

    for dir in candidates {
        if dir.join(EXTRACTION_SCRIPT).is_file() {
            return Ok(std::path::absolute(&dir)?);
        }
        searched.push(dir.display().to_string());
    }
    Err(WisdraError::ScriptNotFound(searched.join(", ")))
}

/// Locate the ExposureZ3 binary: explicit flag / `WISDRA_EXPOSURE_Z3`,
/// next to the wisdra executable, then `PATH`.
pub fn resolve_verifier(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return if p.is_file() { Ok(p.to_path_buf()) } else { Err(WisdraError::VerifierNotFound) };
    }
    if let Some(dir) = exe_dir() {
        let local = dir.join(VERIFIER_BINARY);
        if local.is_file() {
            return Ok(local);
        }
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(VERIFIER_BINARY))
        .find(|p| p.is_file())
        .ok_or(WisdraError::VerifierNotFound)
}

/// Create (if needed) and return the output directory.
pub fn ensure_output_dir(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    Ok(std::path::absolute(dir)?)
}

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ghidra_path_must_be_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(resolve_ghidra_root(Some(tmp.path())).unwrap(), tmp.path());
    }

    #[test]
    fn headless_missing_is_reported_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        match resolve_headless(tmp.path()) {
            Err(WisdraError::HeadlessNotFound(p)) => assert!(p.ends_with(HEADLESS_BINARY)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn script_dir_is_found_in_source_tree() {
        assert!(resolve_script_dir().unwrap().join(EXTRACTION_SCRIPT).is_file());
    }
}
