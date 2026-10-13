//! Wisdra report schema.
//!
//! A [`WisdraReport`] is produced either by the Ghidra engine
//! (`WisdraExtract.java`) or by the native Rust engine. Both emit the same
//! JSON shape; fields only one engine fills are optional or default to empty.
//! Unknown fields are preserved in `extra` so reports round-trip losslessly.

use serde::{Deserialize, Serialize};

/// Bumped whenever the JSON shape changes incompatibly.
pub const SCHEMA_VERSION: u32 = 2;

pub type Extra = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WisdraReport {
    #[serde(default = "default_schema")]
    pub schema_version: u32,
    pub metadata: Metadata,
    pub threat_indicators: ThreatIndicators,
    #[serde(default)]
    pub imports: Vec<ImportEntry>,
    #[serde(default)]
    pub sections: Vec<SectionInfo>,
    #[serde(default)]
    pub entropy_analysis: Vec<EntropyEntry>,
    /// Format-level details from the native parser (imphash, signature, overlay...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<BinaryInfo>,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilityData>,
    #[serde(default)]
    pub kill_chains: Vec<KillChainData>,
    #[serde(default)]
    pub deobfuscation: Vec<DeobfuscationData>,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

fn default_schema() -> u32 {
    1 // reports written before the field existed
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub entry_point: String,
    #[serde(default)]
    pub image_base: String,
    #[serde(default)]
    pub analysis_date: String,
    /// `"ghidra"` or `"native"`.
    #[serde(default = "default_engine")]
    pub engine: String,
    #[serde(flatten)]
    pub extra: Extra,
}

fn default_engine() -> String {
    "ghidra".into()
}

impl Metadata {
    pub fn is_pe(&self) -> bool {
        self.file_format.to_ascii_lowercase().contains("portable executable")
    }

    pub fn is_elf(&self) -> bool {
        let f = self.file_format.to_ascii_lowercase();
        f.contains("elf") || f.contains("executable and linking format")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    /// Any combination of `R`, `W`, `X`.
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyEntry {
    pub section: String,
    pub entropy: f64,
    pub suspicious: bool,
    pub verdict: String,
}

/// Format-level facts only a structural parser can provide.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub is_64bit: bool,
    pub is_library: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_timestamp: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// An Authenticode certificate table is present (not cryptographically verified).
    pub has_signature: bool,
    /// Bytes appended after the last section (excluding the certificate table).
    pub overlay_size: u64,
    #[serde(default)]
    pub export_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packer_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    #[serde(default)]
    pub stripped: bool,
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
pub struct KillChainData {
    pub chain_name: String,
    pub function: String,
    pub address: String,
    pub sequence: Vec<String>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape emitted by WisdraExtract.java v2.0 (no schema_version/engine fields).
    const GHIDRA_V1: &str = r#"{
        "metadata": {"file_name": "evil.exe", "sha256": "x", "file_format": "Portable Executable (PE)",
                     "architecture": "x86:LE:64:default", "compiler": "windows", "wisdra_version": "2.0.0"},
        "imports": [{"library": "KERNEL32.DLL", "function": "VirtualAlloc", "address": "EXTERNAL:0001", "category": "injection"}],
        "sections": [{"name": ".text", "virtual_address": "00401000", "virtual_size": 4096, "raw_size": 4096, "permissions": "RX"}],
        "entropy_analysis": [{"section": ".text", "entropy": 6.1, "suspicious": false, "verdict": "NORMAL"}],
        "decompilation": {"name": "entry", "address": "0x1", "code": "", "line_count": 0},
        "threat_indicators": {"risk_label": "LOW", "risk_score": 5, "packing_detected": false}
    }"#;

    #[test]
    fn legacy_ghidra_report_parses_with_defaults() {
        let r: WisdraReport = serde_json::from_str(GHIDRA_V1).unwrap();
        assert_eq!(r.schema_version, 1);
        assert_eq!(r.metadata.engine, "ghidra");
        assert_eq!(r.imports[0].category.as_deref(), Some("injection"));
        assert_eq!(r.sections[0].permissions, "RX");
        assert!(r.binary.is_none());
        assert!(r.extra.contains_key("decompilation"));
        assert!(r.metadata.extra.contains_key("compiler"));
    }

    #[test]
    fn round_trip_preserves_unknown_fields() {
        let r: WisdraReport = serde_json::from_str(GHIDRA_V1).unwrap();
        let again: WisdraReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert!(again.extra.contains_key("decompilation"));
        assert_eq!(again.imports, r.imports);
    }

    #[test]
    fn format_predicates() {
        let mut m = Metadata { file_format: "Portable Executable (PE)".into(), ..Default::default() };
        assert!(m.is_pe() && !m.is_elf());
        m.file_format = "Executable and Linking Format (ELF)".into();
        assert!(m.is_elf() && !m.is_pe());
    }
}
