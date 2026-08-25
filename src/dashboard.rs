//! Terminal dashboard — renders analysis report in an intelligence-style format.
//! Designed to look like actual government/military SIGINT tooling output.
//! No decorative elements. Dense, clinical, functional.

use crate::parser::AnalysisReport;
use colored::Colorize;
use std::path::Path;

type Result<T> = std::result::Result<T, crate::engine::EngineError>;

pub fn render_from_file(path: &str) -> Result<()> {
    let report = crate::parser::parse_report(Path::new(path))?;
    render(&report)
}

pub fn render(report: &AnalysisReport) -> Result<()> {
    let w = 78;
    let line = "=".repeat(w);
    let thin = "-".repeat(w);

    // ── Classification Banner ────────────────────────────────────────
    println!();
    println!("{}", line);
    println!("UNCLASSIFIED // FOUO                                    WISDRA v{}", env!("CARGO_PKG_VERSION"));
    println!("AUTOMATED BINARY ANALYSIS REPORT");
    println!("{}", line);

    // DTG line
    let dtg = &report.metadata.analysis_date;
    let sha = if report.metadata.sha256.len() >= 12 { &report.metadata.sha256[..12] } else { "UNKNOWN_HASH" };
    let case_id = format!("WIS-{}", sha.to_uppercase());
    println!(
        "DTG: {}    ANALYST: AUTOMATED    CASE: {}",
        dtg, case_id
    );
    println!("{}", line);

    // ── Section 1: Subject Binary ────────────────────────────────────
    println!();
    println!("{}", "1. SUBJECT BINARY".bold());
    println!("{}", thin);
    field("FILE", &report.metadata.file_name);
    field("FORMAT", &report.metadata.file_format);
    field("ARCH", &report.metadata.architecture);
    if let Some(ref c) = report.metadata.compiler {
        field("COMPILER", c);
    }
    field("ENTRY POINT", &report.metadata.entry_point);
    field("IMAGE BASE", &report.metadata.image_base);
    field("SHA-256", &report.metadata.sha256);
    if let Some(ref ts) = report.metadata.timestamp {
        field("PE TIMESTAMP", ts);
    }

    // ── Section 2: Threat Assessment ─────────────────────────────────
    if report.threat_indicators.risk_score > 0 {
        println!();
        println!("{}", "2. THREAT ASSESSMENT".bold());
        println!("{}", thin);

        let score = report.threat_indicators.risk_score;
        let label = &report.threat_indicators.risk_label;

        let risk_line = format!("   RISK LEVEL: {} ({}/100)", label, score);
        if score >= 75 {
            println!("{}", risk_line.red().bold());
        } else if score >= 40 {
            println!("{}", risk_line.yellow().bold());
        } else {
            println!("{}", risk_line.green());
        }

        println!();

        if !report.threat_indicators.suspicious_imports.is_empty() {
            println!("   [!] SUSPICIOUS API CALLS:");
            // Group by category
            let injection: Vec<&str> = report.threat_indicators.suspicious_imports.iter()
                .filter(|s| is_category(s, "injection")).map(|s| s.as_str()).collect();
            let anti_dbg: Vec<&str> = report.threat_indicators.anti_debug.iter()
                .map(|s| s.as_str()).collect();
            let network: Vec<&str> = report.threat_indicators.network_indicators.iter()
                .map(|s| s.as_str()).collect();
            let remaining: Vec<&str> = report.threat_indicators.suspicious_imports.iter()
                .filter(|s| !is_category(s, "injection") && !is_category(s, "anti_debug") && !is_category(s, "network"))
                .map(|s| s.as_str()).collect();

            if !injection.is_empty() {
                println!("       - Process injection: {}", injection.join(", "));
            }
            if !anti_dbg.is_empty() {
                println!("       - Anti-debug/anti-analysis: {}", anti_dbg.join(", "));
            }
            if !network.is_empty() {
                println!("       - Network/C2 capability: {}", network.join(", "));
            }
            if !remaining.is_empty() {
                println!("       - Other high-risk calls: {}", remaining.join(", "));
            }
        }

        if report.threat_indicators.packing_detected {
            println!(
                "   {} Packed/encrypted section detected",
                "[!]".red().bold()
            );
        }
    }

    // ── Section 3: Section Map ───────────────────────────────────────
    println!();
    println!("{}", "3. SECTION MAP".bold());
    println!("{}", thin);
    println!(
        "   {:<10} {:<14} {:<9} {:<9} {:<6} {:<9} {}",
        "NAME", "VADDR", "VSIZE", "RSIZE", "PERM", "ENTROPY", "STATUS"
    );
    println!(
        "   {:<10} {:<14} {:<9} {:<9} {:<6} {:<9} {}",
        "----------", "-----------", "--------", "--------", "-----", "--------", "----------"
    );

    for (i, section) in report.sections.iter().enumerate() {
        let entropy_val = report
            .entropy_analysis
            .iter()
            .find(|e| e.section == section.name)
            .map(|e| e.entropy)
            .unwrap_or(0.0);

        let suspicious = report
            .entropy_analysis
            .iter()
            .find(|e| e.section == section.name)
            .map(|e| e.suspicious)
            .unwrap_or(false);

        let perm_str = format_perms(&section.permissions);
        let status = if suspicious {
            "**CRITICAL**"
        } else if entropy_val > 6.0 {
            "ELEVATED"
        } else {
            "NORMAL"
        };

        let row = format!(
            "   {:<10} {:<14} {:<9} {:<9} {:<6} {:<9.4} {}",
            section.name,
            section.virtual_address,
            format_size(section.virtual_size),
            format_size(section.raw_size),
            perm_str,
            entropy_val,
            status
        );

        if suspicious {
            println!("{}", row.red());
        } else {
            println!("{}", row);
        }
    }

    // ── Section 4: Import Table ──────────────────────────────────────
    println!();
    println!("{}", "4. IMPORT TABLE".bold());
    println!("{}", thin);

    let mut libs: std::collections::BTreeMap<&str, Vec<&crate::parser::ImportEntry>> =
        std::collections::BTreeMap::new();
    for imp in &report.imports {
        libs.entry(&imp.library).or_default().push(imp);
    }

    for (lib, funcs) in &libs {
        println!();
        println!("   {} ({} imports)", lib.bold(), funcs.len());
        for f in funcs {
            let flagged = is_suspicious_api(&f.function);
            let tag = f.category.as_deref().unwrap_or("");
            if flagged {
                println!(
                    "   {}  {:<36} {}",
                    "[!]".red(),
                    f.function.red().bold(),
                    if tag.is_empty() { String::new() } else { format!("<{}>", tag) }
                );
            } else {
                println!(
                    "        {:<36} {}",
                    f.function,
                    if tag.is_empty() { String::new() } else { format!("<{}>", tag).to_string() }
                );
            }
        }
    }

    // ── Section 5: Decompiled Entry Point ────────────────────────────
    println!();
    println!("{}", "5. DECOMPILED ENTRY POINT".bold());
    println!("{}", thin);
    println!(
        "   Function: {}  Address: {}  Lines: {}",
        report.decompilation.name,
        report.decompilation.address,
        report.decompilation.line_count,
    );
    println!();

    for (i, line) in report.decompilation.code.lines().enumerate() {
        let line_no = format!("{:>5} |", i + 1);
        println!("{} {}", line_no.bright_black(), line);
    }

    // ── Section 6: Strings ───────────────────────────────────────────
    if !report.strings.is_empty() {
        println!();
        println!("{}", "6. NOTABLE STRINGS".bold());
        println!("{}", thin);

        for (i, s) in report.strings.iter().enumerate() {
            let idx = format!("   [{:>3}]", i + 1);
            // Flag strings that look like IOCs
            if is_ioc(s) {
                println!("{} {} {}", idx, "[IOC]".red(), s.bold());
            } else {
                println!("{}       {}", idx, s);
            }
        }
    }

    // ── Footer ───────────────────────────────────────────────────────
    println!();
    println!("{}", line);
    println!("END REPORT  |  CASE: {}  |  UNCLASSIFIED//FOUO", case_id_from(report));
    println!("{}", line);
    println!();

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

fn field(key: &str, val: &str) {
    println!("   {:<14} {}", format!("{}:", key), val);
}

fn format_perms(perms: &str) -> String {
    let mut result = String::with_capacity(3);
    result.push(if perms.contains('R') { 'R' } else { '-' });
    result.push(if perms.contains('W') { 'W' } else { '-' });
    result.push(if perms.contains('X') { 'X' } else { '-' });
    result
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{}B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1}K", bytes as f64 / 1024.0);
    }
    format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
}

fn is_suspicious_api(name: &str) -> bool {
    const LIST: &[&str] = &[
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "NtUnmapViewOfSection", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "GetProcAddress", "LoadLibrary",
        "WinExec", "ShellExecute", "URLDownloadToFile",
        "InternetOpen", "HttpSendRequest", "WSAStartup",
        "RegSetValue", "RegCreateKey", "CryptEncrypt",
        "CryptDecrypt", "NtQueryInformationProcess",
    ];
    LIST.iter().any(|s| name.contains(s))
}

fn is_category(name: &str, cat: &str) -> bool {
    match cat {
        "injection" => ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection"]
            .iter().any(|s| name.contains(s)),
        "anti_debug" => ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount"]
            .iter().any(|s| name.contains(s)),
        "network" => ["WSAStartup", "socket", "connect", "InternetOpen",
            "HttpSendRequest", "URLDownloadToFile"]
            .iter().any(|s| name.contains(s)),
        _ => false,
    }
}

fn is_ioc(s: &str) -> bool {
    // Flag IP addresses, URLs, file paths, registry keys, encoded commands
    s.contains(":\\") || s.contains("//") || s.contains(".exe")
        || s.contains(".dll") || s.contains("HTTP")
        || s.contains("powershell") || s.contains("cmd.exe")
        || (s.chars().filter(|c| *c == '.').count() == 3
            && s.chars().all(|c| c.is_ascii_digit() || c == '.'))
        || s.contains("HKEY_") || s.contains("CurrentVersion\\Run")
        || s.contains("AppData")
}

fn case_id_from(report: &AnalysisReport) -> String {
    let sha = if report.metadata.sha256.len() >= 12 { &report.metadata.sha256[..12] } else { "UNKNOWN_HASH" };
    format!("WIS-{}", sha.to_uppercase())
}
