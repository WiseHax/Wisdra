<p align="center">
  <img src="https://img.shields.io/badge/WISDRA-v0.1.0-0d1117?style=for-the-badge&labelColor=161b22&color=58a6ff" alt="version"/>
  <img src="https://img.shields.io/badge/Rust-Memory%20Safe-0d1117?style=for-the-badge&logo=rust&labelColor=161b22&color=f97583" alt="rust"/>
  <img src="https://img.shields.io/badge/Ghidra-12.x%20Native-0d1117?style=for-the-badge&labelColor=161b22&color=56d364" alt="ghidra"/>
  <img src="https://img.shields.io/badge/License-MIT-0d1117?style=for-the-badge&labelColor=161b22&color=d2a8ff" alt="license"/>
</p>

<h1 align="center">WISDRA</h1>
<p align="center">
  <strong>Automated Binary Intelligence & Threat Analysis Engine</strong>
</p>
<p align="center">
  A high-performance CLI tool that orchestrates NSA's Ghidra reverse engineering framework<br/>
  to perform deep static analysis on PE binaries and generate intelligence-grade threat reports.
</p>

---

## Overview

**Wisdra** is a memory-safe Rust CLI that wraps Ghidra's headless analysis engine to automate binary reverse engineering. Instead of manually navigating Ghidra's GUI, Wisdra commands the engine in the background — extracting metadata, decompiling entry points, calculating section entropy, cataloging API imports, and producing a structured threat assessment — all from a single terminal command.

The output is formatted as a clinical, intelligence-style report modeled after real-world SIGINT/forensic tooling used in government and defense environments.

```
$ wisdra analyze suspicious.exe --ghidra-path /opt/ghidra

==============================================================================
UNCLASSIFIED // FOUO                                    WISDRA v0.1.0
AUTOMATED BINARY ANALYSIS REPORT
==============================================================================
DTG: 2026-08-24T17:54:30Z    ANALYST: AUTOMATED    CASE: WIS-2A005904A24A

1. SUBJECT BINARY
------------------------------------------------------------------------------
   FILE:          suspicious.exe
   FORMAT:        Portable Executable (PE)
   ARCH:          x86:LE:64:default
   ENTRY POINT:   1400125e0

2. THREAT ASSESSMENT
------------------------------------------------------------------------------
   RISK LEVEL: HIGH (55/100)

   [!] SUSPICIOUS API CALLS:
       - Anti-debug/anti-analysis: IsDebuggerPresent, QueryPerformanceCounter
       - Other high-risk calls: GetProcAddress, LoadLibraryA, ShellExecuteW
...
```

## Features

| Capability | Description |
|---|---|
| **Automated Analysis** | Single-command binary analysis — no GUI interaction required |
| **Threat Scoring** | Risk assessment (0–100) based on API imports, entropy anomalies, and behavioral indicators |
| **Section Entropy** | Per-section Shannon entropy calculation to detect packing, encryption, or obfuscation |
| **API Cataloging** | Full import table extraction with automatic categorization (`injection`, `anti_debug`, `network`, `execution`, `crypto`) |
| **Decompilation** | Automatic entry point decompilation to C pseudocode via Ghidra's decompiler |
| **String Extraction** | Extracts embedded strings and flags potential IOCs (IP addresses, URLs, registry keys, file paths) |
| **Intelligence Reports** | Output formatted as a structured SIGINT-style classified report |
| **SHA-256 Fingerprinting** | Cryptographic hashing of target binaries for chain-of-custody tracking |
| **JSON Export** | Machine-readable JSON output for integration with SIEM/SOAR pipelines |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        WISDRA CLI                            │
│                      (Rust / Tokio)                          │
├──────────┬──────────┬───────────┬────────────┬───────────────┤
│  cli.rs  │engine.rs │ parser.rs │dashboard.rs│   config.rs   │
│  Routing │Subprocess│   JSON    │  Report    │   Path        │
│  & Args  │  Mgmt    │  Deser    │  Render    │   Resolution  │
└────┬─────┴────┬─────┴─────┬─────┴──────┬─────┴───────────────┘
     │          │           │            │
     │    ┌─────▼─────┐     │      ┌─────▼─────┐
     │    │  Ghidra    │     │      │ Terminal  │
     │    │  Headless  │─────┘      │ Dashboard │
     │    │  Analyzer  │            └───────────┘
     │    └─────┬──────┘
     │    ┌─────▼──────────────┐
     │    │ WisdraExtract.java │
     │    │  (Ghidra Script)   │
     │    └────────────────────┘
     │
┌────▼────────────┐
│  Target Binary  │
│   (.exe/.dll)   │
└─────────────────┘
```

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) (11.x or 12.x)
- Java 21+ (bundled with most Ghidra distributions)

### Build from Source

```bash
git clone https://github.com/WiseHax/Wisdra.git
cd Wisdra
cargo build --release
```

The compiled binary will be at `target/release/wisdra` (or `wisdra.exe` on Windows).

## Usage

### Analyze a Binary

```bash
# Using --ghidra-path flag
wisdra analyze target.exe --ghidra-path /path/to/ghidra

# Using environment variable
export GHIDRA_INSTALL_DIR=/path/to/ghidra
wisdra analyze target.exe

# Deep analysis mode (extended decompilation)
wisdra analyze target.exe --deep --ghidra-path /path/to/ghidra

# Custom output path
wisdra analyze target.exe -o report.json --ghidra-path /path/to/ghidra
```

### Re-render a Previous Report

```bash
wisdra report output/previous_scan.json
```

### Environment Setup Check

```bash
wisdra setup
wisdra setup --ghidra-path /path/to/ghidra
```

## Understanding the Report

### Threat Risk Levels

| Score | Label | Meaning |
|---|---|---|
| 0 | `CLEAN` | No suspicious indicators detected |
| 1–24 | `LOW` | Minor flags, likely benign |
| 25–49 | `MODERATE` | Some suspicious APIs present — warrants review |
| 50–74 | `HIGH` | Multiple threat indicators — likely malicious or adversarial tooling |
| 75–100 | `CRITICAL` | Strong malware indicators — packed code, injection APIs, C2 networking |

### Entropy Analysis

| Entropy | Verdict |
|---|---|
| < 4.0 | `LOW` — Sparse data, minimal information density |
| 4.0–6.0 | `NORMAL` — Standard compiled code or data |
| 6.0–7.0 | `ELEVATED` — Unusual density, may warrant inspection |
| 7.0–7.5 | `HIGH` — Possibly packed or compressed |
| > 7.5 | `CRITICAL` — Likely encrypted or compressed to evade detection |

### API Categories

Wisdra automatically classifies imported APIs into behavioral categories:

- `injection` — Process injection primitives (`WriteProcessMemory`, `CreateRemoteThread`)
- `anti_debug` — Anti-analysis techniques (`IsDebuggerPresent`, `NtQueryInformationProcess`)
- `network` — Network/C2 capability (`WSAStartup`, `HttpSendRequest`, `InternetOpen`)
- `execution` — Process/command execution (`ShellExecute`, `CreateProcess`, `WinExec`)
- `dynamic_load` — Runtime library loading (`LoadLibrary`, `GetProcAddress`)
- `crypto` — Cryptographic operations (`CryptEncrypt`, `CryptDecrypt`)
- `registry` — Persistence mechanisms (`RegSetValue`, `RegCreateKey`)

## Project Structure

```
Wisdra/
├── src/
│   ├── main.rs          # Entry point, command dispatch
│   ├── cli.rs           # CLI argument definitions (clap)
│   ├── engine.rs        # Ghidra subprocess orchestration
│   ├── parser.rs        # JSON report deserialization
│   ├── dashboard.rs     # Intelligence report renderer
│   ├── config.rs        # Path resolution & constants
│   └── banner.rs        # CLI header banner
├── scripts/
│   └── WisdraExtract.java   # Ghidra headless extraction script
├── output/              # Generated reports (gitignored)
├── Cargo.toml
├── Cargo.lock
└── README.md
```

## Roadmap

- [ ] YARA rule integration for signature-based detection
- [ ] SQLite database for historical analysis tracking
- [ ] Multi-binary batch scanning
- [ ] HTML/PDF report export
- [ ] Linux ELF and macOS Mach-O support
- [ ] VirusTotal API integration for hash lookups

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

Wisdra is a defensive security research tool intended for authorized binary analysis, malware research, and educational purposes only. The author assumes no liability for misuse. Always ensure you have proper authorization before analyzing any binary.

---

<p align="center">
  <sub>Built with Rust & Ghidra — Engineered for threat intelligence.</sub>
</p>
