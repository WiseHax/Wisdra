//! Ghidra headless orchestration.
//!
//! Each analysis runs in its own temporary Ghidra project with its own report
//! path, so concurrent jobs (see `radar`) never share state. The temp project
//! is removed on drop, even on error or timeout.

use crate::error::{Result, WisdraError};
use crate::hashing::{self, FileHashes};
use crate::model::{SCHEMA_VERSION, WisdraReport};
use crate::{config, native};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

    let mut report = crate::load_report(&raw_report)?;
    enrich(&mut report, &hashes, &target_abs);
    let report_path = crate::save_report(&report, &output_dir)?;

    Ok(Analysis { report, report_path, log_path })
}

/// Add Rust-side facts the Java script cannot provide: real hashes and the
/// native parser's format details (imphash, signature, overlay, ...).
fn enrich(report: &mut WisdraReport, hashes: &FileHashes, target: &Path) {
    report.schema_version = SCHEMA_VERSION;
    report.metadata.engine = "ghidra".into();
    apply_hashes(report, hashes);
    match fs::read(target).map_err(|e| e.to_string()).and_then(|data| native::binary_info(&data)) {
        Ok(info) => report.binary = Some(info),
        Err(e) => tracing::debug!("native enrichment skipped: {e}"),
    }
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
mod tests {
    use super::*;
    use crate::fixtures::sample;

    #[test]
    fn hashes_replace_placeholder() {
        let mut report = sample();
        let h = FileHashes { md5: "m".into(), sha1: "s1".into(), sha256: "s256".into(), size: 9 };
        apply_hashes(&mut report, &h);
        assert_eq!(report.metadata.sha256, "s256");
        assert_eq!(report.metadata.file_size, 9);
    }

    #[test]
    fn enrich_marks_engine_and_adds_native_info() {
        let mut report = sample();
        let exe = std::env::current_exe().unwrap();
        let h = hashing::hash_file(&exe).unwrap();
        enrich(&mut report, &h, &exe);
        assert_eq!(report.metadata.engine, "ghidra");
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert!(report.binary.is_some());
    }

    #[test]
    fn log_tail_returns_last_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), "a\nb\nc\nd").unwrap();
        assert_eq!(log_tail(tmp.path(), 2), "c\nd");
    }
}
