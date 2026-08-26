use crate::ghidra_bridge::WisdraReport;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn export_markdown(report: &WisdraReport) -> std::io::Result<()> {
    let output_dir = Path::new("output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let file_name = &report.metadata.file_name;
    let safe_file_name = file_name.replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-', "_");
    
    let report_path = output_dir.join(format!("{}_report.md", safe_file_name));
    let mut file = fs::File::create(&report_path)?;

    writeln!(file, "# WISDRA AUTOMATED BINARY ANALYSIS REPORT")?;
    writeln!(file, "=========================================\n")?;
    
    writeln!(file, "## 1. TARGET METADATA")?;
    writeln!(file, "- **File Name:** {}", report.metadata.file_name)?;
    writeln!(file, "- **SHA-256:** {}", report.metadata.sha256)?;
    writeln!(file)?;

    writeln!(file, "## 2. THREAT ASSESSMENT")?;
    writeln!(file, "- **Overall Risk Level:** {} (Score: {})", report.threat_indicators.risk_label, report.threat_indicators.risk_score)?;
    writeln!(file, "- **Total Vulnerabilities Detected:** {}", report.threat_indicators.vulnerability_count)?;
    writeln!(file, "- **Critical Vulnerabilities:** {}", report.threat_indicators.critical_vulns)?;
    
    let packing_verdict = if report.threat_indicators.packing_detected {
        "DETECTED (High Entropy / Known Packer Signature)"
    } else {
        "NOT DETECTED (Normal Entropy)"
    };
    writeln!(file, "- **Packing Verdict:** {}\n", packing_verdict)?;

    writeln!(file, "## 3. SUSPICIOUS API HEURISTICS")?;
    
    if report.threat_indicators.anti_debug.is_empty() && report.threat_indicators.suspicious_imports.is_empty() {
        writeln!(file, "No high-risk APIs detected.")?;
    } else {
        if !report.threat_indicators.anti_debug.is_empty() {
            writeln!(file, "### `<anti_debug>` Capabilities")?;
            for api in &report.threat_indicators.anti_debug {
                writeln!(file, "- `{}`", api)?;
            }
            writeln!(file)?;
        }

        let other_suspicious: Vec<_> = report.threat_indicators.suspicious_imports
            .iter()
            .filter(|api| !report.threat_indicators.anti_debug.contains(api))
            .collect();

        if !other_suspicious.is_empty() {
            writeln!(file, "### `<suspicious>` / General Malicious Operations")?;
            for api in other_suspicious {
                writeln!(file, "- `{}`", api)?;
            }
            writeln!(file)?;
        }
    }

    writeln!(file, "\n## 4. VULNERABILITY INTELLIGENCE (P-CODE ANALYSIS)")?;
    if report.vulnerabilities.is_empty() {
        writeln!(file, "No high-confidence vulnerabilities detected.")?;
    } else {
        writeln!(file, "| CWE | Severity | Function | Caller Address | Context |")?;
        writeln!(file, "|-----|----------|----------|----------------|---------|")?;
        for vuln in &report.vulnerabilities {
            writeln!(file, "| {} | {} | `{}` | `{}` | `{}` |", 
                vuln.cwe, vuln.severity, vuln.dangerous_function, vuln.caller_address, vuln.code_context.replace("|", "\\|"))?;
        }
        
        writeln!(file, "\n### Detailed Vulnerability Analysis")?;
        for (i, vuln) in report.vulnerabilities.iter().enumerate() {
            writeln!(file, "#### {}. {} in `{}`", i + 1, vuln.cwe, vuln.dangerous_function)?;
            writeln!(file, "- **Type:** {}", vuln.r#type)?;
            writeln!(file, "- **Severity:** {}", vuln.severity)?;
            writeln!(file, "- **Caller:** {} at `{}`", vuln.caller_function, vuln.caller_address)?;
            writeln!(file, "- **Call Site:** `{}`", vuln.call_address)?;
            writeln!(file, "- **Context:**\n```c\n{}\n```", vuln.code_context)?;
            writeln!(file, "- **Description:**\n{}", vuln.description)?;
            writeln!(file)?;
        }
    }

    writeln!(file, "\n## 5. BEHAVIORAL KILL CHAINS (EXECUTION FLOW)")?;
    if report.kill_chains.is_empty() {
        writeln!(file, "No weaponized kill chains detected.")?;
    } else {
        for (i, chain) in report.kill_chains.iter().enumerate() {
            writeln!(file, "### {}. {}", i + 1, chain.chain_name)?;
            writeln!(file, "- **Host Function:** `{}` at `{}`", chain.function, chain.address)?;
            writeln!(file, "- **Execution Sequence:**")?;
            for (j, step) in chain.sequence.iter().enumerate() {
                writeln!(file, "  {}. `{}`", j + 1, step)?;
            }
            writeln!(file)?;
        }
    }

    writeln!(file, "\n## 6. DYNAMIC DEOBFUSCATION (XOR & STACK STRINGS)")?;
    if report.deobfuscation.is_empty() {
        writeln!(file, "No obfuscation mechanisms detected.")?;
    } else {
        for (i, artifact) in report.deobfuscation.iter().enumerate() {
            if artifact.r#type == "stack_string" {
                writeln!(file, "### {}. Reconstructed Stack String in `{}`", i + 1, artifact.function)?;
                if let Some(s) = &artifact.reconstructed_string {
                    writeln!(file, "- **Extracted Payload:** `{}`", s)?;
                }
            } else if artifact.r#type == "xor_decryption_routine" {
                writeln!(file, "### {}. XOR Decryption Routine in `{}`", i + 1, artifact.function)?;
                if let Some(k) = &artifact.key_value {
                    writeln!(file, "- **XOR Key:** `{}`", k)?;
                }
                if let Some(a) = &artifact.address {
                    writeln!(file, "- **Address:** `{}`", a)?;
                }
            }
            writeln!(file)?;
        }
    }

    let mitre_mappings = crate::mitre::map_to_mitre(report);
    if !mitre_mappings.is_empty() {
        writeln!(file, "\n## 7. MITRE ATT&CK MAPPINGS")?;
        writeln!(file, "| Tactic | Technique | ID |")?;
        writeln!(file, "|--------|-----------|----|")?;
        for mapping in mitre_mappings {
            writeln!(file, "| {} | {} | {} |", mapping.tactic, mapping.technique, mapping.id)?;
        }
    }

    let yara_rule = crate::yara::generate_yara_rule(report);
    writeln!(file, "\n## 8. GENERATED YARA RULE")?;
    writeln!(file, "```yara\n{}\n```", yara_rule)?;

    writeln!(file, "---\n*Report automatically generated by Wisdra V2 Core.*")?;

    println!("[+] Markdown report exported to: {}", report_path.display());
    
    Ok(())
}
