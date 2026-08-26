//! CLI argument definitions using `clap` derive macros.

use clap::{Parser, Subcommand};

/// Wisdra — Automated Malware Analysis CLI
///
/// Orchestrates Ghidra's headless engine for rapid binary intelligence
/// extraction and renders professional-grade analysis dashboards.
#[derive(Parser)]
#[command(
    name = "wisdra",
    version,
    about = "Next-generation automated malware analysis CLI",
    long_about = "Wisdra commands Ghidra's analyzeHeadless engine to perform \
                  automated static analysis on suspicious binaries, extracting \
                  API imports, high-entropy sections, decompiled code, and \
                  rendering results in a professional terminal dashboard.",
    after_help = "EXAMPLES:\n  \
                  wisdra analyze target.exe\n  \
                  wisdra analyze malware.dll --deep --timeout 600\n  \
                  wisdra report output/analysis.json\n  \
                  wisdra setup --ghidra-path C:\\ghidra\n  \
                  wisdra info"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Suppress the startup banner
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a binary file using Ghidra's headless engine
    #[command(alias = "scan")]
    Analyze {
        /// Path to the target binary (PE, ELF, Mach-O, etc.)
        target: String,

        /// Output JSON file path (default: output/<hash>.json)
        #[arg(short, long)]
        output: Option<String>,

        /// Path to Ghidra installation directory
        #[arg(long, env = "GHIDRA_INSTALL_DIR")]
        ghidra_path: Option<String>,

        /// Analysis timeout in seconds (default: 300)
        #[arg(short, long, default_value = "300")]
        timeout: u64,

        /// Enable deep analysis (function cross-references, string extraction)
        #[arg(long)]
        deep: bool,

        /// Automatically verify exploitability with ExposureZ3 (Formal Verification)
        #[arg(long, short = 'v', default_value_t = false)]
        verify: bool,
    },

    /// Render a dashboard from a previously generated JSON report
    Report {
        /// Path to the analysis JSON file
        json_file: String,
    },

    /// Display system and configuration information
    Info,

    /// Set up the Ghidra headless environment
    Setup {
        /// Path to existing Ghidra installation (skips clone)
        #[arg(long, env = "GHIDRA_INSTALL_DIR")]
        ghidra_path: Option<String>,
    },
}
