<p align="center">
  <img src="https://img.shields.io/badge/WISDRA-v2.1.0-0d1117?style=for-the-badge&labelColor=161b22&color=58a6ff" alt="version"/>
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
- **Formal Verification (ExposureZ3, experimental):** Optional hand-off to the external ExposureZ3 engine, which uses the Z3 SMT solver to classify opaque predicates. Feeding Wisdra's own findings into it is on the roadmap.
- **Live Memory Extraction (Valkyrie Engine):** Hooks directly into the Windows API to scan running processes (PIDs) for memory anomalies like `PAGE_EXECUTE_READWRITE` (RWX) blocks, effectively hunting Process Hollowing and memory-injected payloads.
- **Auto-YARA Generation:** Dynamically builds deployable YARA rules from binary entropy, malicious API imports, and sanitized string extractions.
- **SIGINT-Style Reporting:** Compiles forensic, intelligence-grade Markdown reports detailing the exact execution contexts of discovered threats.

## Installation

### Prerequisites
1. [Rust](https://rustup.rs/) 1.85+
2. [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) 11.x or 12.x with **JDK 21+**
3. *(Optional)* [ExposureZ3](https://github.com/WiseHax/ExposureZ3) for `--verify`; it is built separately and needs Z3.

### Build
```bash
git clone https://github.com/WiseHax/Wisdra.git
cd Wisdra
cargo build --release
```
The binary is `target/release/wisdra` (`wisdra.exe` on Windows). Keep the `scripts/` folder next to it, or run it from the repo.

### Configure and verify
```powershell
$env:GHIDRA_HOME = "C:\path\to\ghidra_12.x_PUBLIC"   # GHIDRA_INSTALL_DIR also works
.\target\release\wisdra.exe setup
elease\wisdra.exe setup
```
`setup` checks Ghidra, the headless launcher, the Java version, the extraction script and ExposureZ3, and exits non-zero if something required is missing.

## Usage

| Command | What it does |
|---|---|
| `wisdra analyze <file>` | Ghidra headless analysis, then the JSON/Markdown/YARA report and the TUI dashboard |
| `wisdra analyze <file> --no-ui` | Same, with a one-line summary instead of the TUI (automatic when piped) |
| `wisdra analyze <file> --json` | Print the final JSON report to stdout, for pipelines |
| `wisdra analyze <file> --verify` | Also run ExposureZ3 (`--z3-path` / `WISDRA_EXPOSURE_Z3`, next to `wisdra`, or `PATH`) |
| `wisdra triage <dir> -j 2` | Analyze a directory with N concurrent Ghidra JVMs and cluster the results |
| `wisdra live-scan <pid>` | *(Windows)* Flag and dump committed RWX regions of a running process |
| `wisdra report <report.json>` | Regenerate the Markdown and YARA output, and the dashboard, from a saved report |
| `wisdra setup` | Environment check |

Common options: `--timeout <secs>` (default 600), `--deep`, `--ghidra-path`, `--output-dir` (`WISDRA_OUTPUT_DIR`), `-v`/`-vv` (or `WISDRA_LOG=debug`).

## Outputs
Everything goes in `--output-dir` (default `./output`), keyed by the sample's SHA-256:

| File | Contents |
|---|---|
| `<sha256>.json` | Full report, including MD5, SHA-1, SHA-256 and size |
| `<sha256>.md` | Markdown report with MITRE mapping and YARA rule |
| `<sha256>.yar` | Standalone YARA rule |
| `<sha256>.ghidra.log` | Full Ghidra headless log (check this first when a run fails) |
| `triage_summary.json` | Triage results and clusters |
| `dumps/pid_<pid>_region_<addr>.bin` | Memory regions dumped by `live-scan` (capped at 64 MiB each). **Treat these as live malware.** |

Each analysis runs in its own temporary Ghidra project, which is removed afterwards. On timeout, the whole Ghidra process tree is killed.

## Disclaimer

Wisdra is a defensive security research tool intended solely for authorized binary analysis, memory forensics, malware research, and proactive cyber defense. The authors assume no liability for misuse. Ensure proper authorization before processing any binary or scanning live memory environments.
