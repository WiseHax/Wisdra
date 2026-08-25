//! JSON report parser — deserializes the extraction script output.

use serde::Deserialize;
use std::path::Path;

/// Top-level analysis report structure.
#[derive(Debug, Deserialize)]
pub struct AnalysisReport {
    pub metadata: Metadata,
    pub imports: Vec<ImportEntry>,
    pub sections: Vec<SectionInfo>,
    pub entropy_analysis: Vec<EntropyEntry>,
    pub decompilation: DecompiledFunction,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub threat_indicators: ThreatIndicators,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub file_name: String,
    pub file_format: String,
    pub architecture: String,
    pub compiler: Option<String>,
    pub entry_point: String,
    pub image_base: String,
    pub timestamp: Option<String>,
    pub sha256: String,
    pub analysis_date: String,
    pub wisdra_version: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
    pub address: String,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub permissions: String,
}

#[derive(Debug, Deserialize)]
pub struct EntropyEntry {
    pub section: String,
    pub entropy: f64,
    pub suspicious: bool,
    pub verdict: String,
}

#[derive(Debug, Deserialize)]
pub struct DecompiledFunction {
    pub name: String,
    pub address: String,
    pub code: String,
    pub line_count: usize,
}

#[derive(Debug, Default, Deserialize)]
pub struct ThreatIndicators {
    #[serde(default)]
    pub suspicious_imports: Vec<String>,
    #[serde(default)]
    pub packing_detected: bool,
    #[serde(default)]
    pub anti_debug: Vec<String>,
    #[serde(default)]
    pub network_indicators: Vec<String>,
    #[serde(default)]
    pub risk_score: u8,
    #[serde(default)]
    pub risk_label: String,
}

/// Parse a JSON report file into an AnalysisReport.
pub fn parse_report(path: &Path) -> Result<AnalysisReport, crate::engine::EngineError> {
    let content = std::fs::read_to_string(path)?;
    let report: AnalysisReport = serde_json::from_str(&content)?;
    Ok(report)
}
