//! Typed errors for the analysis pipeline.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WisdraError {
    #[error("target not found: {0}")]
    TargetNotFound(PathBuf),

    #[error("Ghidra installation not found. Pass --ghidra-path or set GHIDRA_HOME / GHIDRA_INSTALL_DIR")]
    GhidraNotFound,

    #[error("headless analyzer not found at {0}")]
    HeadlessNotFound(PathBuf),

    #[error("extraction script WisdraExtract.java not found (searched: {0})")]
    ScriptNotFound(String),

    #[error("Ghidra analysis timed out after {secs}s (log: {log})")]
    Timeout { secs: u64, log: PathBuf },

    #[error("Ghidra exited with {status} (log: {log})\n{tail}")]
    GhidraFailed { status: String, log: PathBuf, tail: String },

    #[error("Ghidra finished but produced no report (log: {0})")]
    NoReport(PathBuf),

    #[error("cannot parse {path} as PE/ELF/Mach-O: {reason}")]
    Unparseable { path: PathBuf, reason: String },

    #[error("failed to parse report {path}: {source}")]
    ReportParse { path: PathBuf, source: serde_json::Error },

    #[error("ExposureZ3 binary not found. Pass --z3-path or set WISDRA_EXPOSURE_Z3")]
    VerifierNotFound,

    #[cfg_attr(windows, allow(dead_code))]
    #[error("live memory scanning is only supported on Windows")]
    UnsupportedPlatform,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WisdraError>;
