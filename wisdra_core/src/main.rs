mod entropy;
mod threat;
mod ghidra_bridge;
mod reporter;
mod ui;
mod mitre;
mod yara;

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
    },
}

fn main() {
    println!("============================================================");
    println!("[ WISDRA V2 :: STANDALONE CORE ]");
    println!("============================================================\n");

    let cli = Cli::parse();

    match &cli.command {
        Commands::Analyze { target_file, ghidra_path, no_ui } => {
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
        }
    }
}
