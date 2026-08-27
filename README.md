<p align="center">
  <img src="https://img.shields.io/badge/WISDRA-v2.0.0-0d1117?style=for-the-badge&labelColor=161b22&color=58a6ff" alt="version"/>
  <img src="https://img.shields.io/badge/Rust-Memory%20Safe-0d1117?style=for-the-badge&logo=rust&labelColor=161b22&color=f97583" alt="rust"/>
  <img src="https://img.shields.io/badge/Ghidra-12.x%20Native-0d1117?style=for-the-badge&labelColor=161b22&color=56d364" alt="ghidra"/>
  <img src="https://img.shields.io/badge/License-MIT-0d1117?style=for-the-badge&labelColor=161b22&color=d2a8ff" alt="license"/>
</p>

<h1 align="center">WISDRA V2</h1>
<p align="center">
  <strong>Advanced Binary Analysis & Live Memory Forensics Platform</strong>
</p>
<p align="center">
  A high-performance Rust engine orchestrating Ghidra's P-Code architecture, Formal Verification (Z3), and Live Process Memory Scanning for comprehensive threat intelligence.
</p>

---

## Overview

**Wisdra V2** transcends standard metadata extraction by offering an all-in-one defensive analysis platform. It wraps Ghidra's Headless Analyzer, integrates a Formal Verification engine (ExposureZ3), and features a built-in Live Memory Forensics module. Wisdra empowers security analysts to perform static binary reversing, mathematical exploit verification, and dynamic in-memory threat hunting—all from a blazingly fast, memory-safe Rust orchestrator.

## Key Capabilities

- **P-Code Taint Analysis:** Recursive backward data-flow traversal identifying `CWE-190` and `CWE-120/134` by tracking untrusted variables to dangerous sinks using Ghidra's P-Code AST.
- **Formal Verification (ExposureZ3):** Bridges Wisdra's vulnerability findings into the Z3 SMT Theorem Prover to mathematically verify if a discovered vulnerability is reachable/exploitable.
- **Live Memory Extraction (Valkyrie Engine):** Hooks directly into the Windows API to scan running processes (PIDs) for memory anomalies like `PAGE_EXECUTE_READWRITE` (RWX) blocks, effectively hunting Process Hollowing and memory-injected payloads.
- **Auto-YARA Generation:** Dynamically builds deployable YARA rules from binary entropy, malicious API imports, and sanitized string extractions.
- **SIGINT-Style Reporting:** Compiles forensic, intelligence-grade Markdown reports detailing the exact execution contexts of discovered threats.

## Installation

### Prerequisites
1. [Rust](https://rustup.rs/) (1.70+)
2. [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) (11.x or 12.x) - Ensure Java 21+ is installed.
3. Microsoft C++ Build Tools (Required for Z3 Bindings & Windows API)

### Step 1: Clone the Repository
```bash
git clone https://github.com/WiseHax/Wisdra.git
cd Wisdra
```

### Step 2: Build the Optimized Engine
Compile the entire workspace (including the core engine and the ExposureZ3 verifier):
```bash
cargo build --release
```
*The compiled binaries will be located in the `target/release/` directory.*

### Step 3: Setup Ghidra Environment
Wisdra needs to know where your Ghidra installation is located. You can either set it as a system environment variable, or pass it directly during runtime.
```powershell
$env:GHIDRA_HOME="C:\path\to\ghidra_12.1.x_PUBLIC"
```

## Usage Guide

Wisdra V2 offers multiple modes of operation for both static analysis and live dynamic hunting.

### 1. Standard Static Analysis (Ghidra Headless)
Analyzes a binary file on disk, extracts heuristics, decompiles code, and generates a threat report.
```powershell
.\target\release\wisdra_core.exe analyze "C:\Suspicious\malware.exe"
```

### 2. Formal Verification Mode (Z3)
Runs the static analysis and automatically feeds any discovered vulnerabilities into the Z3 SMT solver to mathematically verify exploitability.
```powershell
.\target\release\wisdra_core.exe analyze "C:\Suspicious\malware.exe" --verify
```

### 3. Live Process Memory Scanning (In-Memory Hunting)
Bypasses disk analysis entirely and attaches to a live running process to scan its virtual memory map for injected payloads and RWX anomalies.
```powershell
# Scan a live process by its Process ID (PID)
.\target\release\wisdra_core.exe live-scan 11864
```

## Outputs
All analysis reports, extracted YARA rules, and JSON telemetry are automatically saved to the `output/` directory located in the root of the project.

## Disclaimer

Wisdra is a defensive security research tool intended solely for authorized binary analysis, memory forensics, malware research, and proactive cyber defense. The authors assume no liability for misuse. Ensure proper authorization before processing any binary or scanning live memory environments.
