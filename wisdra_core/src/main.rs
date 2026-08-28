mod entropy;
mod threat;
mod ghidra_bridge;
mod reporter;
mod ui;
mod mitre;
mod yara;
mod verifier;
mod memory;
// mod emulator; // Temporarily disabled until MSVC is installed

use clap::{Parser, Subcommand};
use std::env;

#[derive(Parser)]
#[command(name = "wisdra")]
#[command(about = "WISDRA V2 :: STANDALONE CORE", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a binary file using Ghidra's headless engine
    Analyze {
        /// Path to the target binary
        target_file: String,

        /// Optional path to Ghidra installation (fallback: GHIDRA_HOME env var)
        #[arg(long, short)]
        ghidra_path: Option<String>,
        
        /// Run in headless mode without the interactive Ratatui dashboard
        #[arg(long, short = 'n', default_value_t = false)]
        no_ui: bool,

        /// Automatically verify exploitability with ExposureZ3 (Formal Verification)
        #[arg(long, short = 'v', default_value_t = false)]
        verify: bool,
    },
    
    /// Attach to a live process to scan for memory anomalies (Process Hollowing/Injection)
    LiveScan {
        /// The Process ID (PID) to attach to and scan
        pid: u32,
    },

    /// Safely detonate an extracted binary payload inside the Unicorn CPU Sandbox
    Emulate {
        /// Path to the extracted .bin payload
        payload_file: String,
    },
}

fn main() {
    println!("[*] Initializing Wisdra V2 Core Engine...\n");

    let cli = Cli::parse();

    match &cli.command {
        Commands::Analyze { target_file, ghidra_path, no_ui, verify } => {
            let resolved_ghidra_path = match ghidra_path {
                Some(path) => path.clone(),
                None => {
                    match env::var("GHIDRA_HOME") {
                        Ok(val) => val,
                        Err(_) => {
                            eprintln!("\n[-] FATAL ERROR: Ghidra path not provided and GHIDRA_HOME environment variable is not set.");
                            eprintln!("    Please set the GHIDRA_HOME variable or pass the path via --ghidra-path");
                            std::process::exit(1);
                        }
                    }
                }
            };

            match ghidra_bridge::run_headless_analysis(target_file, &resolved_ghidra_path) {
                Ok(report) => {
                    // Always generate the markdown report
                    if let Err(e) = reporter::export_markdown(&report) {
                        eprintln!("[-] Warning: Failed to export markdown report: {}", e);
                    }

                    // Phase 12: Automated Formal Verification
                    if *verify {
                        if report.vulnerabilities.is_empty() {
                            println!("\n[*] Verification skipped: No vulnerabilities found to verify.");
                        } else {
                            if let Err(e) = verifier::run_exposure_z3(target_file) {
                                eprintln!("\n[-] Formal Verification Error: {}", e);
                            }
                        }
                    }

                    if !no_ui {
                        // Clear the terminal and render the Ratatui dashboard
                        if let Err(e) = ui::render_dashboard(&report) {
                            eprintln!("UI Error: {}", e);
                        }
                    } else {
                        println!("\n[+] Analysis complete in headless mode.");
                    }
                }
                Err(e) => {
                    eprintln!("\n[-] FATAL ERROR: {}", e);
                }
            }
        },
        Commands::LiveScan { pid } => {
            if let Err(e) = memory::scan_process_memory(*pid) {
                eprintln!("\n[-] MEMORY SCAN ERROR: {}", e);
            }
        },
        Commands::Emulate { payload_file: _ } => {
            println!("[-] Emulation is currently disabled. Please install MSVC Build Tools and CMake.");
            // match std::fs::read(payload_file) {
            //     Ok(bytes) => {
            //         let base_address = 0x1000000;
            //         if let Err(e) = emulator::sandbox_and_emulate(&bytes, base_address) {
            //             eprintln!("\n[-] EMULATION ERROR: {}", e);
            //         }
            //     }
            //     Err(e) => {
            //         eprintln!("\n[-] Failed to read payload file '{}': {}", payload_file, e);
            //     }
            // }
        }
    }
}
