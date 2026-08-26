use crate::ghidra_bridge::WisdraReport;
use std::collections::HashSet;

pub fn generate_yara_rule(report: &WisdraReport) -> String {
    let mut rule = String::new();
    
    // Sanitize rule name
    let file_name = &report.metadata.file_name;
    let safe_rule_name = file_name.replace(|c: char| !c.is_alphanumeric(), "_");
    // Ensure rule name doesn't start with a number
    let rule_name = if safe_rule_name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("wisdra_{}", safe_rule_name)
    } else {
        safe_rule_name
    };

    rule.push_str(&format!("rule {} {{\n", rule_name));
    rule.push_str("    meta:\n");
    rule.push_str("        author = \"Wisdra Automated Engine\"\n");
    rule.push_str(&format!("        description = \"Auto-generated rule for {}\"\n", file_name));
    if !report.metadata.sha256.is_empty() && report.metadata.sha256 != "DUMMY_SHA256" {
        rule.push_str(&format!("        hash = \"{}\"\n", report.metadata.sha256));
    }
    rule.push_str(&format!("        date = \"{}\"\n", report.metadata.analysis_date));
    rule.push_str(&format!("        risk_level = \"{}\"\n", report.threat_indicators.risk_label));
    rule.push_str("    strings:\n");

    let mut string_idx = 0;
    let mut string_vars = Vec::new();
    let mut added_strings = HashSet::new();

    // 1. Add suspicious APIs as strings
    let all_imports: Vec<&String> = report
        .threat_indicators
        .suspicious_imports
        .iter()
        .chain(report.threat_indicators.anti_debug.iter())
        .chain(report.threat_indicators.network_indicators.iter())
        .collect();

    for api in all_imports {
        if added_strings.insert(api.clone()) {
            let var_name = format!("$api_{}", string_idx);
            rule.push_str(&format!("        {} = \"{}\" ascii wide\n", var_name, api));
            string_vars.push(var_name);
            string_idx += 1;
        }
    }

    // 2. Add some unique strings from the binary itself (limit to prevent huge rules)
    for s in report.strings.iter().take(10) {
        // Simple sanitization for YARA string block (escape quotes and slashes)
        let safe_s = s.replace("\\", "\\\\").replace("\"", "\\\"");
        if safe_s.len() > 4 && added_strings.insert(safe_s.clone()) {
             let var_name = format!("$str_{}", string_idx);
             rule.push_str(&format!("        {} = \"{}\" ascii wide\n", var_name, safe_s));
             string_vars.push(var_name);
             string_idx += 1;
        }
    }

    rule.push_str("    condition:\n");
    
    // Always start with MZ header check for Windows executables, as Wisdra typically handles PEs
    rule.push_str("        uint16(0) == 0x5A4D\n");
    
    if !string_vars.is_empty() {
        rule.push_str("        and (\n");
        if report.threat_indicators.risk_label == "CRITICAL" {
            // For critical threats, match if a significant portion of indicators are present
            let threshold = std::cmp::max(1, string_vars.len() / 2);
            rule.push_str(&format!("            {} of them\n", threshold));
        } else {
            // For lower threats, require all of them or just any of them depending on logic
            // Using 'any of them' as a fallback simple condition
            rule.push_str("            any of them\n");
        }
        rule.push_str("        )\n");
    }

    // Add packing check if applicable
    if report.threat_indicators.packing_detected {
        rule.push_str("        // Note: High entropy / packed payload detected. Consider adding entropy conditions if using math module.\n");
    }

    rule.push_str("}\n");

    rule
}
