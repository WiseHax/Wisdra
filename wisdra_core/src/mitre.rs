use crate::ghidra_bridge::WisdraReport;
use std::collections::HashSet;

pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
    pub id: String,
}

pub fn map_to_mitre(report: &WisdraReport) -> Vec<MitreMapping> {
    let mut mappings = Vec::new();
    let mut mapped_ids = HashSet::new(); // Prevent duplicates

    let mut add_mapping = |tactic: &str, technique: &str, id: &str| {
        if mapped_ids.insert(id.to_string()) {
            mappings.push(MitreMapping {
                tactic: tactic.to_string(),
                technique: technique.to_string(),
                id: id.to_string(),
            });
        }
    };

    // Heuristics Mapping
    if !report.threat_indicators.anti_debug.is_empty() {
        add_mapping("Defense Evasion", "Debugger Evasion", "T1622");
    }

    if !report.threat_indicators.network_indicators.is_empty() {
        add_mapping("Command and Control", "Application Layer Protocol", "T1071");
    }

    if report.threat_indicators.packing_detected {
        add_mapping("Defense Evasion", "Obfuscated Files or Information", "T1027");
        add_mapping("Defense Evasion", "Software Packing", "T1027.002");
    }

    let all_imports: Vec<&String> = report
        .threat_indicators
        .suspicious_imports
        .iter()
        .chain(report.threat_indicators.anti_debug.iter())
        .chain(report.threat_indicators.network_indicators.iter())
        .collect();

    for api in &all_imports {
        let api_lower = api.to_lowercase();
        if api_lower.contains("alloc") || api_lower.contains("virtualprotect") || api_lower.contains("writeprocessmemory") || api_lower.contains("remotethread") {
            add_mapping("Defense Evasion", "Process Injection", "T1055");
        }
        if api_lower.contains("crypt") {
            add_mapping("Impact", "Data Encrypted for Impact", "T1486");
        }
        if api_lower.contains("regcreate") || api_lower.contains("regset") {
            add_mapping("Persistence", "Registry Run Keys / Startup Folder", "T1547.001");
            add_mapping("Defense Evasion", "Modify Registry", "T1112");
        }
    }

    // Vulnerability Mapping
    for vuln in &report.vulnerabilities {
        if vuln.cwe.contains("CWE-78") {
            add_mapping("Execution", "Command and Scripting Interpreter", "T1059");
        }
        // Memory corruption vulnerabilities often map to exploitation for defense evasion or privilege escalation
        if vuln.cwe.contains("CWE-120") || vuln.cwe.contains("CWE-190") || vuln.cwe.contains("CWE-134") || vuln.cwe.contains("CWE-416") {
            add_mapping("Defense Evasion", "Exploitation for Defense Evasion", "T1211");
            add_mapping("Privilege Escalation", "Exploitation for Privilege Escalation", "T1068");
        }
    }

    mappings
}
