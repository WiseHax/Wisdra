//! Radar bulk triage: analyze a directory of samples with a bounded worker
//! pool and cluster results by behavioral profile.

use crate::Engine;
use anyhow::{Context, bail};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const EXTENSIONS: &[&str] = &["exe", "dll", "sys", "bin", "elf", "so", "scr", "ocx"];

#[derive(Debug, Serialize)]
pub struct TriageEntry {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub risk_label: Option<String>,
    pub risk_score: Option<u32>,
    pub cluster: Option<String>,
    pub report: Option<PathBuf>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TriageSummary {
    pub scanned: usize,
    pub failed: usize,
    pub clusters: BTreeMap<String, Vec<PathBuf>>,
    pub entries: Vec<TriageEntry>,
}

/// Run triage with at most `jobs` concurrent analyses. For the Ghidra engine
/// each job is a JVM using 1-4 GB, so keep `jobs` small; native jobs are cheap.
pub fn run_bulk_triage(directory: &Path, engine: &Engine, jobs: usize) -> anyhow::Result<TriageSummary> {
    let targets: Vec<PathBuf> = WalkDir::new(directory)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| is_candidate(p))
        .collect();

    if targets.is_empty() {
        bail!("no candidate binaries ({}) found in {}", EXTENSIONS.join(", "), directory.display());
    }
    println!("[+] {} target(s), {} concurrent job(s)", targets.len(), jobs);

    let pool = rayon::ThreadPoolBuilder::new().num_threads(jobs.max(1)).build().context("building worker pool")?;
    let entries: Vec<TriageEntry> = pool.install(|| {
        targets
            .par_iter()
            .map(|target| {
                tracing::info!("analyzing {}", target.display());
                match engine.analyze(target) {
                    Ok((report, report_path)) => TriageEntry {
                        path: target.clone(),
                        sha256: Some(report.metadata.sha256.clone()),
                        risk_label: Some(report.threat_indicators.risk_label.clone()),
                        risk_score: Some(report.threat_indicators.risk_score),
                        cluster: Some(cluster_key(&report)),
                        report: Some(report_path),
                        error: None,
                    },
                    Err(e) => {
                        eprintln!("    [-] {}: {e}", target.display());
                        TriageEntry {
                            path: target.clone(),
                            sha256: None,
                            risk_label: None,
                            risk_score: None,
                            cluster: None,
                            report: None,
                            error: Some(e.to_string()),
                        }
                    }
                }
            })
            .collect()
    });

    let mut clusters: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    let mut failed = 0;
    for e in &entries {
        match &e.cluster {
            Some(key) => clusters.entry(key.clone()).or_default().push(e.path.clone()),
            None => failed += 1,
        }
    }

    Ok(TriageSummary { scanned: entries.len() - failed, failed, clusters, entries })
}

/// A file is a candidate if it has a known executable extension or starts
/// with a PE (`MZ`), ELF or Mach-O magic number.
fn is_candidate(path: &Path) -> bool {
    if path.extension().is_some_and(|ext| EXTENSIONS.contains(&ext.to_string_lossy().to_lowercase().as_str())) {
        return true;
    }
    let mut magic = [0u8; 4];
    let ok = std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok();
    ok && (magic.starts_with(b"MZ")
        || magic == [0x7F, b'E', b'L', b'F']
        || matches!(u32::from_be_bytes(magic), 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE))
}

/// Cluster by import hash when available (strong family signal), otherwise
/// by a heuristic profile: risk label, packing, and the top suspicious API.
fn cluster_key(r: &crate::model::WisdraReport) -> String {
    if let Some(h) = r.binary.as_ref().and_then(|b| b.imphash.as_deref()) {
        return format!("imphash={h}");
    }
    let top_api = r.threat_indicators.suspicious_imports.first().map_or("none", String::as_str);
    format!(
        "risk={} packed={} top_api={}",
        r.threat_indicators.risk_label, r.threat_indicators.packing_detected, top_api
    )
}

pub fn print_summary(summary: &TriageSummary) {
    println!("\n============================================================");
    println!("[ WISDRA RADAR :: THREAT CLUSTERING REPORT ]");
    println!("============================================================");
    println!("Scanned: {}   Failed: {}", summary.scanned, summary.failed);
    for (cluster, files) in &summary.clusters {
        println!("\n[ {cluster} ]  ({} member(s))", files.len());
        for f in files.iter().take(5) {
            println!("    - {}", f.display());
        }
        if files.len() > 5 {
            println!("    - ... and {} more", files.len() - 5);
        }
    }
}
