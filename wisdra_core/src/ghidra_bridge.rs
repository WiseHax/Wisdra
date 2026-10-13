//! Ghidra headless orchestration and the report data model.
//!
//! Each analysis runs in its own temporary Ghidra project with its own report
//! path, so concurrent jobs (see `radar`) never share state. The temp project
//! is removed on drop, even on error or timeout.

use crate::config;
use crate::error::{Result, WisdraError};
use crate::hashing::{self, FileHashes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscationData {
    pub r#type: String,
    pub function: String,
    #[serde(default)]
    pub reconstructed_string: Option<String>,
    #[serde(default)]
    pub key_value: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainData {
    pub chain_name: String,
    pub function: String,
    pub address: String,
    pub sequence: Vec<String>,
}

/// The JSON report exported by WisdraExtract.java, enriched with Rust-side hashes.
/// Unknown fields emitted by the script are preserved in `extra` so a saved
/// report round-trips without data loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WisdraReport {
    pub metadata: Metadata,
    pub threat_indicators: ThreatIndicators,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilityData>,
    #[serde(default)]
    pub kill_chains: Vec<KillChainData>,
    #[serde(default)]
    pub deobfuscation: Vec<DeobfuscationData>,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityData {
    pub r#type: String,
    pub cwe: String,
    pub description: String,
    pub dangerous_function: String,
    pub caller_function: String,
    pub caller_address: String,
    pub call_address: String,
    pub severity: String,
    pub code_context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub file_name: String,
    pub sha256: String,
    #[serde(default)]
    pub md5: String,
    #[serde(default)]
    pub sha1: String,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub file_format: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub analysis_date: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Metadata {
    pub fn is_pe(&self) -> bool {
        self.file_format.to_ascii_lowercase().contains("portable executable")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicators {
    pub risk_label: String,
    pub risk_score: u32,
    #[serde(default)]
    pub vulnerability_count: u32,
    #[serde(default)]
    pub kill_chain_count: u32,
    #[serde(default)]
    pub deobfuscation_artifacts: u32,
    #[serde(default)]
    pub critical_vulns: u32,
    pub packing_detected: bool,
    #[serde(default)]
    pub suspicious_imports: Vec<String>,
    #[serde(default)]
    pub anti_debug: Vec<String>,
    #[serde(default)]
    pub network_indicators: Vec<String>,
}

/// Settings for a single headless run.
#[derive(Debug, Clone)]
pub struct GhidraOptions {
    pub ghidra_root: PathBuf,
    pub output_dir: PathBuf,
    pub timeout: Duration,
    pub deep: bool,
}

/// Result of a successful analysis.
#[derive(Debug)]
pub struct Analysis {
    pub report: WisdraReport,
    pub report_path: PathBuf,
    pub log_path: PathBuf,
}

/// Load a previously saved report.
pub fn load_report(path: &Path) -> Result<WisdraReport> {
    let data = fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|source| WisdraError::ReportParse { path: path.to_path_buf(), source })
}

/// Run Ghidra headless on `target` and return the parsed, hash-enriched report.
/// The final report is written to `<output_dir>/<sha256>.json` and the
/// Ghidra log to `<output_dir>/<sha256>.ghidra.log`.
pub fn run_headless_analysis(target: &Path, opts: &GhidraOptions) -> Result<Analysis> {
    let target_abs = fs::canonicalize(target).map_err(|_| WisdraError::TargetNotFound(target.to_path_buf()))?;
    let headless = config::resolve_headless(&opts.ghidra_root)?;
    let script_dir = config::resolve_script_dir()?;
    let output_dir = config::ensure_output_dir(&opts.output_dir)?;

    let hashes = hashing::hash_file(&target_abs)?;
    tracing::info!(target = %target_abs.display(), sha256 = %hashes.sha256, "starting Ghidra headless analysis");

    let project = tempfile::Builder::new().prefix("wisdra_proj_").tempdir()?;
    let raw_report = project.path().join("report.json");
    let log_path = output_dir.join(format!("{}.ghidra.log", hashes.sha256));
    let log = fs::File::create(&log_path)?;

    let mut cmd = Command::new(&headless);
    cmd.arg(project.path())
        .arg(format!("wisdra_{}", &hashes.sha256[..12]))
        .arg("-import")
        .arg(&target_abs)
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-postScript")
        .arg(config::EXTRACTION_SCRIPT)
        .arg(&raw_report)
        .arg(&hashes.sha256)
        .arg("-deleteProject")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if opts.deep {
        cmd.env("WISDRA_DEEP_ANALYSIS", "1");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // lets us kill the JVM together with the launcher script
    }

    let mut child = cmd.spawn()?;
    let status = match wait_with_timeout(&mut child, opts.timeout)? {
        Some(status) => status,
        None => {
            kill_tree(&mut child);
            return Err(WisdraError::Timeout { secs: opts.timeout.as_secs(), log: log_path });
        }
    };

    if !status.success() {
        return Err(WisdraError::GhidraFailed {
            status: status.to_string(),
            tail: log_tail(&log_path, 20),
            log: log_path,
        });
    }
    if !raw_report.is_file() {
        return Err(WisdraError::NoReport(log_path));
    }

    let mut report = load_report(&raw_report)?;
    apply_hashes(&mut report, &hashes);

    let report_path = output_dir.join(format!("{}.json", hashes.sha256));
    let json = serde_json::to_string_pretty(&report).expect("report is always serializable");
    fs::write(&report_path, json)?;

    Ok(Analysis { report, report_path, log_path })
}

fn apply_hashes(report: &mut WisdraReport, hashes: &FileHashes) {
    report.metadata.sha256.clone_from(&hashes.sha256);
    report.metadata.md5.clone_from(&hashes.md5);
    report.metadata.sha1.clone_from(&hashes.sha1);
    report.metadata.file_size = hashes.size;
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Kill the launcher and every descendant (the Ghidra JVM is a grandchild of
/// `analyzeHeadless`, so killing only the direct child would orphan it).
fn kill_tree(child: &mut Child) {
    let pid = child.id().to_string();
    #[cfg(windows)]
    let _ =
        Command::new("taskkill").args(["/T", "/F", "/PID", &pid]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    #[cfg(unix)]
    let _ = Command::new("kill").args(["-KILL", &format!("-{pid}")]).status();
    let _ = child.kill();
    let _ = child.wait();
}

fn log_tail(path: &Path, lines: usize) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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

    #[test]
    fn unknown_fields_round_trip() {
        let report = sample();
        assert!(report.extra.contains_key("imports"));
        assert!(report.metadata.extra.contains_key("wisdra_version"));
        let again: WisdraReport = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert!(again.extra.contains_key("imports"));
    }

    #[test]
    fn hashes_replace_placeholder() {
        let mut report = sample();
        let h = FileHashes { md5: "m".into(), sha1: "s1".into(), sha256: "s256".into(), size: 9 };
        apply_hashes(&mut report, &h);
        assert_eq!(report.metadata.sha256, "s256");
        assert_eq!(report.metadata.file_size, 9);
    }

    #[test]
    fn log_tail_returns_last_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), "a\nb\nc\nd").unwrap();
        assert_eq!(log_tail(tmp.path(), 2), "c\nd");
    }
}
