//! Wisdra analysis engines.
//!
//! - [`native`]: pure-Rust structural triage of PE/ELF/Mach-O (milliseconds, no Java).
//! - [`ghidra`]: headless Ghidra + `WisdraExtract.java` deep analysis.
//!
//! Both return a [`wisdra_model::WisdraReport`]; [`reporter`], [`yara`] and
//! [`mitre`] consume reports regardless of which engine produced them.

pub mod config;
pub mod error;
pub mod ghidra;
pub mod hashing;
pub mod heuristics;
pub mod memory;
pub mod mitre;
pub mod native;
mod ordinals;
pub mod radar;
pub mod reporter;
pub mod verifier;
pub mod yara;

pub use error::{Result, WisdraError};
pub use wisdra_model as model;

use std::path::{Path, PathBuf};

/// Which analysis engine to run.
#[derive(Debug, Clone)]
pub enum Engine {
    /// Pure-Rust structural triage; writes reports to the given directory.
    Native { output_dir: PathBuf },
    /// Ghidra headless deep analysis.
    Ghidra(ghidra::GhidraOptions),
}

impl Engine {
    /// Analyze one file, returning the report and where it was saved.
    pub fn analyze(&self, target: &Path) -> Result<(model::WisdraReport, PathBuf)> {
        match self {
            Engine::Native { output_dir } => {
                native::analyze_file(target, output_dir).map(|a| (a.report, a.report_path))
            }
            Engine::Ghidra(opts) => ghidra::run_headless_analysis(target, opts).map(|a| (a.report, a.report_path)),
        }
    }
}

/// Load a previously saved report.
pub fn load_report(path: &Path) -> Result<model::WisdraReport> {
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|source| WisdraError::ReportParse { path: path.to_path_buf(), source })
}

/// Write `<output_dir>/<sha256>.json` and return its path.
pub fn save_report(report: &model::WisdraReport, output_dir: &Path) -> Result<PathBuf> {
    let dir = config::ensure_output_dir(output_dir)?;
    let path = dir.join(format!("{}.json", report.metadata.sha256));
    std::fs::write(&path, serde_json::to_string_pretty(report).expect("report is always serializable"))?;
    Ok(path)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use wisdra_model::WisdraReport;

    pub const SAMPLE_REPORT: &str = r#"{
        "metadata": {"file_name": "evil.exe", "sha256": "DUMMY_SHA256",
                     "file_format": "Portable Executable (PE)", "architecture": "x86:LE:64:default",
                     "analysis_date": "2026-10-13T00:00:00Z", "wisdra_version": "2.0.0"},
        "threat_indicators": {"risk_label": "HIGH", "risk_score": 60, "packing_detected": true,
                              "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory"],
                              "anti_debug": ["IsDebuggerPresent"], "network_indicators": []},
        "vulnerabilities": [{"type": "buffer_overflow", "cwe": "CWE-120", "description": "d",
                             "dangerous_function": "strcpy", "caller_function": "main",
                             "caller_address": "0x1", "call_address": "0x2", "severity": "HIGH",
                             "code_context": "strcpy(a,b)"}],
        "strings": ["http://c2.example/gate.php", "C:\\Users\\\"quoted\"", "abc"],
        "imports": [{"library": "KERNEL32.DLL", "function": "VirtualAlloc", "address": "0x3"}]
    }"#;

    pub fn sample() -> WisdraReport {
        serde_json::from_str(SAMPLE_REPORT).unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_triage_over_a_directory() {
        let samples = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // An extensionless copy of a real binary is detected by magic number.
        std::fs::copy(std::env::current_exe().unwrap(), samples.path().join("sample")).unwrap();
        std::fs::write(samples.path().join("notes.txt"), "not a binary").unwrap();
        let engine = crate::Engine::Native { output_dir: out.path().to_path_buf() };
        let summary = crate::radar::run_bulk_triage(samples.path(), &engine, 2).unwrap();
        assert_eq!((summary.scanned, summary.failed), (1, 0));
        assert!(summary.entries[0].report.as_ref().is_some_and(|p| p.is_file()));
    }
}
