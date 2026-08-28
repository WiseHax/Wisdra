use crate::ghidra_bridge::run_headless_analysis;
use rayon::prelude::*;
use std::collections::HashMap;
use walkdir::WalkDir;

/// The Radar Bulk Triage Engine
/// Scans entire directories concurrently and clusters files based on behavioral heuristics.
pub fn run_bulk_triage(directory: &str, ghidra_path: &str) -> Result<(), String> {
    println!("\n[*] Initializing Wisdra Radar (Bulk Triage Engine)...");
    
    let mut targets = Vec::new();
    for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() {
            if let Some(ext) = entry.path().extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if ext_str == "exe" || ext_str == "dll" || ext_str == "sys" || ext_str == "bin" {
                    targets.push(entry.path().to_path_buf());
                }
            }
        }
    }
    
    if targets.is_empty() {
        return Err(format!("No executable files found in {}", directory));
    }
    
    println!("[+] Found {} potential targets. Initiating parallel analysis...", targets.len());
    
    // Process files in parallel using Rayon.
    // Ghidra is heavy, Rayon will bound the threads to the CPU core count automatically.
    let reports: Vec<_> = targets.par_iter()
        .map(|target| {
            println!("    [>] Scanning: {}", target.display());
            let result = run_headless_analysis(target.to_str().unwrap(), ghidra_path);
            (target.clone(), result)
        })
        .collect();
        
    // Grouping Logic (Threat Actor Clustering)
    let mut actor_groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut successful_scans = 0;
    
    for (target_path, result) in reports {
        match result {
            Ok(report) => {
                successful_scans += 1;
                // Heuristic Clustering: Cluster based on Risk, Packing, and top suspicious API
                let top_api = report.threat_indicators.suspicious_imports.first()
                    .map(|s| s.as_str())
                    .unwrap_or("NoSuspiciousAPIs");
                    
                let group_key = format!("Risk:{}_Packed:{}_TopAPI:{}", 
                    report.threat_indicators.risk_label, 
                    report.threat_indicators.packing_detected,
                    top_api
                );
                
                actor_groups.entry(group_key).or_insert_with(Vec::new)
                    .push(target_path.file_name().unwrap().to_str().unwrap().to_string());
            },
            Err(e) => {
                eprintln!("    [-] Failed to analyze {}: {}", target_path.display(), e);
            }
        }
    }
    
    println!("\n============================================================");
    println!("[ WISDRA RADAR :: THREAT CLUSTERING REPORT ]");
    println!("============================================================");
    println!("Total Scanned: {}", successful_scans);
    
    for (cluster, files) in actor_groups {
        println!("\n[ Cluster Profile: {} ]", cluster);
        println!("  |- Members ({}):", files.len());
        for f in files.iter().take(5) {
            println!("      - {}", f);
        }
        if files.len() > 5 {
            println!("      - ... and {} more", files.len() - 5);
        }
    }
    
    Ok(())
}
