//! Auto-YARA rule generation from a Wisdra report.
//!
//! Rules are built only from evidence observed in the sample (strings,
//! imports, section entropy). The file-format check is chosen from the
//! report metadata, and every string literal is escaped for YARA.

use crate::model::WisdraReport;
use std::collections::HashSet;
use std::fmt::Write;

const MAX_STRINGS: usize = 15;
const MIN_STRING_LEN: usize = 6;

pub fn generate_yara_rule(report: &WisdraReport) -> String {
    let meta = &report.metadata;
    let is_pe = meta.is_pe();
    let is_elf = meta.is_elf();
    let has_hash = is_real_sha256(&meta.sha256);

    let strings = select_strings(&report.strings);
    let apis: Vec<&str> = if is_pe {
        report.threat_indicators.suspicious_imports.iter().map(String::as_str).filter(|a| is_identifier(a)).collect()
    } else {
        Vec::new()
    };
    let packed = is_pe && report.threat_indicators.packing_detected;
    // Without observed strings or imports a heuristic rule would match far too
    // broadly, so fall back to an exact hash match.
    let hash_only = strings.is_empty() && apis.is_empty() && has_hash;

    let mut rule = String::with_capacity(2048);
    if is_pe {
        let _ = writeln!(rule, "import \"pe\"");
    }
    if packed {
        let _ = writeln!(rule, "import \"math\"");
    }
    if hash_only {
        let _ = writeln!(rule, "import \"hash\"");
    }
    if !rule.is_empty() {
        rule.push('\n');
    }

    let _ = writeln!(rule, "rule {} {{", rule_name(&meta.file_name));
    let _ = writeln!(rule, "    meta:");
    let _ = writeln!(rule, "        author = \"Wisdra\"");
    let _ = writeln!(rule, "        description = \"Auto-generated signature for {}\"", escape(&meta.file_name));
    if has_hash {
        let _ = writeln!(rule, "        hash = \"{}\"", meta.sha256);
    }
    if !meta.analysis_date.is_empty() {
        let _ = writeln!(rule, "        date = \"{}\"", escape(&meta.analysis_date));
    }
    let _ = writeln!(rule, "        risk_level = \"{}\"", escape(&report.threat_indicators.risk_label));

    if !strings.is_empty() {
        let _ = writeln!(rule, "\n    strings:");
        for (i, s) in strings.iter().enumerate() {
            let _ = writeln!(rule, "        $s{:02} = \"{}\" ascii wide", i, escape(s));
        }
    }

    let mut clauses: Vec<String> = Vec::new();
    if is_pe {
        clauses.push("uint16(0) == 0x5A4D".into());
    } else if is_elf {
        clauses.push("uint32(0) == 0x464C457F".into());
    }
    if hash_only {
        clauses.push(format!("hash.sha256(0, filesize) == \"{}\"", meta.sha256));
    }
    if !apis.is_empty() {
        let ors: Vec<String> = apis.iter().map(|a| format!("pe.imports(/.*/, /^{a}$/)")).collect();
        clauses.push(format!("(\n            {}\n        )", ors.join(" or\n            ")));
    }
    if !strings.is_empty() {
        let quorum = if strings.len() >= 3 { "2" } else { "any" };
        clauses.push(format!("{quorum} of ($s*)"));
    }
    if packed {
        clauses.push(
            "for any section in pe.sections : (math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.2)"
                .into(),
        );
    }
    if clauses.is_empty() {
        clauses.push("false // insufficient evidence to build a safe signature".into());
    }

    let _ = writeln!(rule, "\n    condition:");
    let _ = writeln!(rule, "        {}", clauses.join("\n        and "));
    let _ = writeln!(rule, "}}");
    rule
}

fn select_strings(strings: &[String]) -> Vec<&str> {
    let mut seen = HashSet::new();
    strings
        .iter()
        .map(|s| s.trim())
        .filter(|s| s.len() >= MIN_STRING_LEN && s.chars().all(|c| c.is_ascii_graphic() || c == ' '))
        .filter(|s| seen.insert(*s))
        .take(MAX_STRINGS)
        .collect()
}

/// YARA identifiers: `[A-Za-z_][A-Za-z0-9_]*`, max 128 chars.
fn rule_name(file_name: &str) -> String {
    let body: String =
        file_name.trim().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).take(120).collect();
    format!("wisdra_{body}")
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_real_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Escape text for a YARA double-quoted string literal.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    let _ = write!(out, "\\x{b:02X}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::sample;

    #[test]
    fn pe_rule_uses_regex_imports_and_no_fabricated_hex() {
        let rule = generate_yara_rule(&sample());
        assert!(rule.contains("pe.imports(/.*/, /^VirtualAlloc$/)"));
        assert!(!rule.contains("$hex"));
        assert!(rule.contains("uint16(0) == 0x5A4D"));
        assert!(rule.contains("math.entropy(section.raw_data_offset"));
        assert!(!rule.contains("hash = \"DUMMY_SHA256\""));
    }

    #[test]
    fn strings_are_escaped_and_short_ones_dropped() {
        let rule = generate_yara_rule(&sample());
        assert!(rule.contains(r#""C:\\Users\\\"quoted\"" ascii wide"#));
        assert!(!rule.contains("\"abc\""));
    }

    #[test]
    fn elf_rule_has_elf_magic_and_no_pe_module() {
        let mut r = sample();
        r.metadata.file_format = "Executable and Linking Format (ELF)".into();
        let rule = generate_yara_rule(&r);
        assert!(rule.contains("uint32(0) == 0x464C457F"));
        assert!(!rule.contains("import \"pe\""));
        assert!(!rule.contains("pe.imports"));
    }

    #[test]
    fn no_evidence_falls_back_to_exact_hash() {
        let mut r = sample();
        r.strings.clear();
        r.threat_indicators.suspicious_imports.clear();
        r.metadata.sha256 = "a".repeat(64);
        let rule = generate_yara_rule(&r);
        assert!(rule.contains(&format!("hash.sha256(0, filesize) == \"{}\"", "a".repeat(64))));
    }

    #[test]
    fn rule_name_is_a_valid_identifier() {
        assert_eq!(rule_name("1 bad-näme.exe"), "wisdra_1_bad_n_me_exe");
    }
}
