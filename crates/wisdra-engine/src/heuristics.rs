//! Import-based threat heuristics for the native engine.
//!
//! API lists and score weights mirror `WisdraExtract.java` so native and
//! Ghidra risk scores are comparable. Matching is stricter than the Java
//! substring check: a name matches an API if it is the API itself or the API
//! plus a Win32 `A`/`W`/`Ex` suffix (so `send` no longer matches `SendMessageW`).
//! These lists move to a shared rule pack in a later release.

use crate::model::{EntropyEntry, ImportEntry, ThreatIndicators};

pub const SUSPICIOUS_APIS: &[&str] = &[
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "WinExec",
    "ShellExecute",
    "CreateProcess",
    "GetProcAddress",
    "LoadLibrary",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "InternetOpen",
    "HttpSendRequest",
    "URLDownloadToFile",
    "RegSetValue",
    "RegCreateKey",
    "CryptEncrypt",
    "CryptDecrypt",
];

pub const ANTI_DEBUG_APIS: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugString",
    "NtSetInformationThread",
    "GetTickCount",
    "QueryPerformanceCounter",
];

pub const NETWORK_APIS: &[&str] = &[
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "InternetOpen",
    "InternetOpenUrl",
    "HttpSendRequest",
    "URLDownloadToFile",
    "WinHttpOpen",
];

/// Entropy above which an executable section counts as packed (same as Java).
pub const PACKED_ENTROPY: f64 = 7.2;

/// True if `name` is `api` or `api` + a Win32 suffix (`A`, `W`, `Ex`, `ExA`, `ExW`).
pub fn api_matches(name: &str, api: &str) -> bool {
    name.strip_prefix(api).is_some_and(|rest| matches!(rest, "" | "A" | "W" | "Ex" | "ExA" | "ExW"))
}

fn matches_any(name: &str, list: &[&str]) -> bool {
    list.iter().any(|api| api_matches(name, api))
}

/// Capability bucket used for the `category` field of an import.
pub fn categorize(name: &str) -> Option<&'static str> {
    const TABLE: &[(&str, &[&str])] = &[
        ("injection", &["WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC"]),
        ("memory", &["VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "VirtualProtectEx"]),
        ("dynamic_load", &["LoadLibrary", "GetProcAddress", "LdrLoadDll"]),
        ("execution", &["WinExec", "ShellExecute", "CreateProcess"]),
        ("anti_debug", ANTI_DEBUG_APIS),
        ("network", NETWORK_APIS),
        ("registry", &["RegCreateKey", "RegSetValue", "RegOpenKey"]),
        ("crypto", &["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt"]),
    ];
    TABLE.iter().find(|(_, apis)| matches_any(name, apis)).map(|(cat, _)| *cat)
}

/// Build threat indicators from imports, executable-section entropy and packer hints.
pub fn assess(
    imports: &[ImportEntry],
    entropy: &[EntropyEntry],
    exec_sections: &[&str],
    packer_hints: &[String],
) -> ThreatIndicators {
    let mut suspicious = Vec::new();
    let mut anti_debug = Vec::new();
    let mut network = Vec::new();
    for imp in imports {
        let f = imp.function.as_str();
        let push = |list: &mut Vec<String>| {
            if !list.iter().any(|x| x == f) {
                list.push(f.to_string());
            }
        };
        if matches_any(f, SUSPICIOUS_APIS) {
            push(&mut suspicious);
        }
        if matches_any(f, ANTI_DEBUG_APIS) {
            push(&mut anti_debug);
        }
        if matches_any(f, NETWORK_APIS) {
            push(&mut network);
        }
    }

    let high_entropy_code =
        entropy.iter().any(|e| e.entropy > PACKED_ENTROPY && exec_sections.contains(&e.section.as_str()));
    let packing = high_entropy_code || !packer_hints.is_empty();

    let mut score = 0u32;
    score += (suspicious.len() as u32 * 5).min(40);
    score += anti_debug.len() as u32 * 10;
    if packing {
        score += 20;
    }
    score += (network.len() as u32 * 5).min(20);
    let score = score.min(100);

    ThreatIndicators {
        risk_label: risk_label(score).into(),
        risk_score: score,
        packing_detected: packing,
        suspicious_imports: suspicious,
        anti_debug,
        network_indicators: network,
        ..Default::default()
    }
}

pub fn risk_label(score: u32) -> &'static str {
    match score {
        75.. => "CRITICAL",
        50..=74 => "HIGH",
        25..=49 => "MODERATE",
        1..=24 => "LOW",
        0 => "CLEAN",
    }
}

/// Shannon entropy in bits per byte (0.0 - 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / len).map(|p| -p * p.log2()).sum()
}

pub fn entropy_verdict(e: f64) -> &'static str {
    if e > 7.5 {
        "CRITICAL - likely encrypted/compressed"
    } else if e > 7.0 {
        "HIGH - possibly packed"
    } else if e > 6.0 {
        "ELEVATED - unusual density"
    } else if e > 4.0 {
        "NORMAL - standard code/data"
    } else {
        "LOW - sparse data"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imp(f: &str) -> ImportEntry {
        ImportEntry { library: "kernel32.dll".into(), function: f.into(), address: String::new(), category: None }
    }

    #[test]
    fn suffix_matching_is_strict() {
        assert!(api_matches("CreateProcessW", "CreateProcess"));
        assert!(api_matches("VirtualAllocEx", "VirtualAlloc"));
        assert!(!api_matches("SendMessageW", "send"));
        assert!(!api_matches("connectionless", "connect"));
    }

    #[test]
    fn categories() {
        assert_eq!(categorize("WriteProcessMemory"), Some("injection"));
        assert_eq!(categorize("VirtualAllocEx"), Some("memory"));
        assert_eq!(categorize("IsDebuggerPresent"), Some("anti_debug"));
        assert_eq!(categorize("ExitProcess"), None);
    }

    #[test]
    fn scoring_matches_java_weights() {
        let imports = [imp("VirtualAlloc"), imp("IsDebuggerPresent"), imp("WSAStartup"), imp("ExitProcess")];
        let t = assess(&imports, &[], &[], &[]);
        // 3 suspicious * 5 + 1 anti-debug * 10 + 1 network * 5
        assert_eq!(t.risk_score, 30);
        assert_eq!(t.risk_label, "MODERATE");
        assert!(!t.packing_detected);
    }

    #[test]
    fn high_entropy_code_or_packer_hint_means_packed() {
        let ent = [EntropyEntry { section: ".text".into(), entropy: 7.9, suspicious: true, verdict: String::new() }];
        assert!(assess(&[], &ent, &[".text"], &[]).packing_detected);
        assert!(!assess(&[], &ent, &[".data"], &[]).packing_detected);
        assert!(assess(&[], &[], &[], &["UPX".into()]).packing_detected);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[0u8; 64]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }
}
