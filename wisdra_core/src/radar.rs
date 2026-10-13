//! Radar bulk triage: analyze a directory of samples with a bounded worker
//! pool and cluster results by behavioral profile.

use crate::ghidra_bridge::{GhidraOptions, run_headless_analysis};
use anyhow::{Context, bail};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;
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

/// Run triage with at most `jobs` concurrent Ghidra instances (each is a JVM
/// using 1-4 GB, so this is deliberately not tied to the CPU count).
pub fn run_bulk_triage(directory: &Path, opts: &GhidraOptions, jobs: usize) -> anyhow::Result<TriageSummary> {
    let targets: Vec<PathBuf> = WalkDir::new(directory)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension().is_some_and(|ext| EXTENSIONS.contains(&ext.to_string_lossy().to_lowercase().as_str()))
        })
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
                println!("    [>] {}", target.display());
                match run_headless_analysis(target, opts) {
                    Ok(a) => TriageEntry {
                        path: target.clone(),
                        sha256: Some(a.report.metadata.sha256.clone()),
                        risk_label: Some(a.report.threat_indicators.risk_label.clone()),
                        risk_score: Some(a.report.threat_indicators.risk_score),
                        cluster: Some(cluster_key(&a.report)),
                        report: Some(a.report_path),
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

/// Heuristic profile: risk label, packing, and the top suspicious API.
fn cluster_key(r: &crate::ghidra_bridge::WisdraReport) -> String {
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
