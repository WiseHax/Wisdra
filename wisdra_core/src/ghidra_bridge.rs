use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Represents the final JSON report exported by WisdraExtract.java
#[derive(Debug, Deserialize)]
pub struct WisdraReport {
    pub metadata: Metadata,
    pub threat_indicators: ThreatIndicators,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilityData>,
    #[serde(default)]
    pub strings: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VulnerabilityData {
    pub r#type: String, // Note: type is a reserved keyword in Rust
    pub cwe: String,
    pub description: String,
    pub dangerous_function: String,
    pub caller_function: String,
    pub caller_address: String,
    pub call_address: String,
    pub severity: String,
    pub code_context: String,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub file_name: String,
    pub sha256: String,
    #[serde(default)]
    pub analysis_date: String,
}

#[derive(Debug, Deserialize)]
pub struct ThreatIndicators {
    pub risk_label: String,
    pub risk_score: u32,
    pub vulnerability_count: u32,
    pub critical_vulns: u32,
    pub packing_detected: bool,
    #[serde(default)]
    pub suspicious_imports: Vec<String>,
    #[serde(default)]
    pub anti_debug: Vec<String>,
    #[serde(default)]
    pub network_indicators: Vec<String>,
}

/// Executes Ghidra headless analyzer and orchestrates the extraction payload
pub fn run_headless_analysis(target_path: &str, ghidra_path: &str) -> Result<WisdraReport, String> {
    let output_dir = Path::new("output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    }
    
    let report_path = output_dir.join("wisdra_report.json");
    
    // Clean up any old report
    if report_path.exists() {
        let _ = fs::remove_file(&report_path);
    }
    
    let ghidra_root = Path::new(ghidra_path);
    let headless_bat = ghidra_root.join("support").join("analyzeHeadless.bat");
    
    if !headless_bat.exists() {
        return Err(format!("Headless analyzer not found at: {}", headless_bat.display()));
    }
    
    let temp_proj_dir = Path::new("wisdra_temp_proj");
    if !temp_proj_dir.exists() {
        fs::create_dir_all(temp_proj_dir).map_err(|e| e.to_string())?;
    }
    
    let script_dir = std::env::current_dir().unwrap().join("scripts");
    let script_name = "WisdraExtract.java";
    
    let target_abs = std::fs::canonicalize(target_path).map_err(|e| format!("Target not found: {}", e))?;
    let report_abs = std::env::current_dir().unwrap().join(&report_path);
    
    println!("[*] Executing Ghidra Headless Analyzer...");
    println!("    Target: {}", target_abs.display());
    println!("    Script: {}", script_name);
    
    let status = Command::new(headless_bat)
        .arg(temp_proj_dir.to_str().unwrap())
        .arg("DummyProject")
        .arg("-import").arg(target_abs.to_str().unwrap())
        .arg("-scriptPath").arg(script_dir.to_str().unwrap())
        .arg("-postScript").arg(script_name).arg(report_abs.to_str().unwrap()).arg("DUMMY_SHA256")
        .arg("-deleteProject")
        .status()
        .map_err(|e| format!("Failed to execute headless analyzer: {}", e))?;
        
    if !status.success() {
        return Err(format!("Ghidra Headless exited with status: {}", status));
    }
    
    // Cleanup temp dir just in case Ghidra didn't clean it fully
    let _ = fs::remove_dir_all(temp_proj_dir);
    
    if !report_path.exists() {
        return Err("Analysis completed but wisdra_report.json was not generated.".to_string());
    }
    
    let json_data = fs::read_to_string(&report_path).map_err(|e| e.to_string())?;
    let report: WisdraReport = serde_json::from_str(&json_data).map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    Ok(report)
}
