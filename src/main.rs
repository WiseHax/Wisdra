//! # Wisdra — Next-Generation Automated Malware Analysis CLI
//!
//! Wisdra orchestrates Ghidra's headless analysis engine to deliver
//! rapid binary intelligence extraction via a professional terminal dashboard.
//!
//! Architecture:
//!   CLI (clap) → Engine (tokio subprocess) → Ghidra Headless + Python payload
//!   → JSON ingest → Terminal Dashboard (ratatui)

mod cli;
mod config;
mod engine;
mod parser;
mod dashboard;
mod banner;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use std::process;

#[tokio::main]
async fn main() {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wisdra=info".parse().unwrap()),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    let cli = Cli::parse();

    // Print the banner unless suppressed
    if !cli.quiet {
        banner::print_banner();
    }

    let result = match cli.command {
        Commands::Analyze {
            target,
            output,
            ghidra_path,
            timeout,
            deep,
        } => {
            engine::run_analysis(
                &target,
                output.as_deref(),
                ghidra_path.as_deref(),
                timeout,
                deep,
                cli.quiet,
            )
            .await
        }
        Commands::Report { json_file } => {
            dashboard::render_from_file(&json_file)
        }
        Commands::Info => {
            print_system_info();
            Ok(())
        }
        Commands::Setup { ghidra_path } => {
            engine::setup_environment(ghidra_path.as_deref()).await
        }
    };

    if let Err(e) = result {
        eprintln!(
            "\n {} {}\n",
            "✖ FATAL:".bright_red().bold(),
            format!("{e}").red()
        );
        process::exit(1);
    }
}

fn print_system_info() {
    let separator = "─".repeat(52);
    println!("\n{}", separator.bright_black());
    println!(
        "  {} {}",
        "WISDRA".bright_cyan().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_black()
    );
    println!("{}", separator.bright_black());
    println!(
        "  {}  {}",
        "Engine".bright_white().bold(),
        "Ghidra Headless Analyzer".bright_yellow()
    );
    println!(
        "  {}  {}",
        "Runtime".bright_white().bold(),
        format!("Rust {}", rustc_version()).bright_yellow()
    );
    println!(
        "  {} {}",
        "Platform".bright_white().bold(),
        format!(" {} / {}", std::env::consts::OS, std::env::consts::ARCH).bright_yellow()
    );
    println!(
        "  {}  {}",
        "Author".bright_white().bold(),
        "Wxse".bright_yellow()
    );
    println!("{}\n", separator.bright_black());
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}
