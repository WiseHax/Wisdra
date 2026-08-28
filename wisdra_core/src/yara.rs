use crate::ghidra_bridge::WisdraReport;
use std::collections::HashSet;
use std::fmt::Write; // Advanced idiomatic Rust string formatting

/// YaraGen Z: Advanced Auto-YARA Signature Orchestrator
/// Generates intelligence-grade YARA rules using strings, API imports, and behavioral opcode patterns.
pub fn generate_yara_rule(report: &WisdraReport) -> String {
    let mut rule = String::with_capacity(2048); // Pre-allocate memory for performance

    // 1. Sanitize and structure the Rule Name
    let raw_name = report.metadata.file_name.trim();
    let safe_rule_name = raw_name.replace(|c: char| !c.is_alphanumeric(), "_");
    let rule_name = if safe_rule_name.chars().next().map_or(true, |c| c.is_ascii_digit()) {
        format!("apt_{}", safe_rule_name)
    } else {
        format!("YaraGenZ_{}", safe_rule_name)
    };

    // 2. Build the Meta Block
    let _ = writeln!(rule, "import \"pe\"");
    let _ = writeln!(rule, "import \"math\"\n");
    let _ = writeln!(rule, "rule {} {{", rule_name);
    let _ = writeln!(rule, "    meta:");
    let _ = writeln!(rule, "        author = \"Wisdra YaraGen Z :: Intelligence Engine\"");
    let _ = writeln!(rule, "        description = \"Automated behavioral signature for {}\"", raw_name);
    
    if !report.metadata.sha256.is_empty() && report.metadata.sha256 != "DUMMY_SHA256" {
        let _ = writeln!(rule, "        hash = \"{}\"", report.metadata.sha256);
    }
    
    let _ = writeln!(rule, "        date = \"{}\"", report.metadata.analysis_date);
    let _ = writeln!(rule, "        risk_level = \"{}\"", report.threat_indicators.risk_label);
    let _ = writeln!(rule, "        generated_by = \"Wisdra P-Code Engine\"");

    // 3. Build the Strings Block
    let _ = writeln!(rule, "\n    strings:");
    let mut string_idx = 0;
    let mut added_strings: HashSet<String> = HashSet::new();

    // 3A. Extracted Strings (Deobfuscated & Raw)
    let safe_strings: Vec<&String> = report.strings.iter()
        .filter(|s| s.len() >= 5 && s.is_ascii())
        .take(15)
        .collect();

    for s in safe_strings {
        let sanitized = s.replace('\\', "\\\\").replace('"', "\\\"");
        if added_strings.insert(sanitized.clone()) {
            let _ = writeln!(rule, "        $s_{:02} = \"{}\" ascii wide nocase", string_idx, sanitized);
            string_idx += 1;
        }
    }

    // 3B. Behavioral Hex Patterns (Generated from Vulnerabilities/Kill Chains)
    // In YaraGen Z, we map vulnerabilities to wild-carded assembly (x86_64) signatures.
    let mut hex_idx = 0;
    for vuln in &report.vulnerabilities {
        if vuln.cwe.contains("120") || vuln.cwe.contains("190") {
            // Memory Corruption / Integer Overflow pattern (mov rax, [rbx]; add eax, 1; push)
            let _ = writeln!(rule, "        $hex_vuln_{:02} = {{ 48 8B ?? ?? ?? 83 C0 01 50 }}", hex_idx);
            hex_idx += 1;
        }
        if vuln.dangerous_function.contains("memcpy") || vuln.dangerous_function.contains("strcpy") {
            // Unsafe buffer copy pattern with wildcards
            let _ = writeln!(rule, "        $hex_buf_{:02} = {{ E8 ?? ?? ?? ?? 48 89 ?? 48 8D ?? }}", hex_idx);
            hex_idx += 1;
        }
    }

    // 4. Build the Condition Block
    let _ = writeln!(rule, "\n    condition:");
    let _ = writeln!(rule, "        uint16(0) == 0x5A4D // MZ Header");

    // 4A. PE Imports Conditions
    let mut api_conditions = Vec::new();
    for api in &report.threat_indicators.suspicious_imports {
        api_conditions.push(format!("pe.imports(\".*\", \"{}\")", api));
    }
    
    if !api_conditions.is_empty() {
        let _ = writeln!(rule, "        and (");
        let _ = writeln!(rule, "            {}", api_conditions.join(" or\n            "));
        let _ = writeln!(rule, "        )");
    }

    // 4B. String & Hex Matching Logic
    if string_idx > 0 || hex_idx > 0 {
        let _ = writeln!(rule, "        and (");
        if report.threat_indicators.risk_label == "CRITICAL" {
            let threshold = std::cmp::max(1, (string_idx + hex_idx) / 3);
            let _ = writeln!(rule, "            {} of ($s_*, $hex_*)", threshold);
        } else {
            let _ = writeln!(rule, "            any of ($s_*, $hex_*)");
        }
        let _ = writeln!(rule, "        )");
    }

    // 4C. Packing & Entropy Logic
    if report.threat_indicators.packing_detected {
        let _ = writeln!(rule, "        and (math.entropy(0, filesize) >= 7.0) // Packed or Encrypted");
    }

    let _ = writeln!(rule, "}}");
    rule
}
