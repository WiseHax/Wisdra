//! Engine module — orchestrates Ghidra's headless analyzer subprocess.

use crate::config;
use crate::dashboard;
use crate::parser;

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Target not found: {0}")]
    TargetNotFound(String),
    #[error("Ghidra not found. Run `wisdra setup` or set GHIDRA_INSTALL_DIR")]
    GhidraNotFound,
    #[error("Headless analyzer not found: {0}")]
    HeadlessNotFound(String),
    #[error("Extraction script not found: {0}")]
    ScriptNotFound(String),
    #[error("Timeout after {0}s")]
    Timeout(u64),
    #[error("Process failed (code {0}):\n{1}")]
    ProcessFailed(i32, String),
    #[error("Output JSON not generated")]
    NoOutput,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Setup: {0}")]
    Setup(String),
}

type Result<T> = std::result::Result<T, EngineError>;

fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 { return format!("{size:.1} {unit}"); }
        size /= 1024.0;
    }
    format!("{size:.1} TB")
}

fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("  {spinner:.cyan} {msg}").unwrap()
        .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]));
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn create_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(ProgressStyle::with_template(
        "  {spinner:.cyan} Analyzing [{bar:40.cyan/dark_gray}] {pos}/{len}s"
    ).unwrap().progress_chars("━╸─")
     .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]));
    pb
}

pub async fn run_analysis(
    target: &str, output: Option<&str>, ghidra_path: Option<&str>,
    timeout_secs: u64, deep: bool, verify: bool, quiet: bool,
) -> Result<()> {
    let target_path = PathBuf::from(target);
    if !target_path.exists() { return Err(EngineError::TargetNotFound(target.into())); }

    let file_name = target_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown".into());
    let file_size = std::fs::metadata(&target_path)?.len();

    if !quiet {
        println!("\n  {} {} ({})", "▶ TARGET:".bright_cyan().bold(), file_name.bright_white().bold(), human_size(file_size).bright_black());
    }

    let spinner = create_spinner("Computing SHA-256...");
    let sha256 = hash_file(&target_path)?;
    spinner.finish_with_message(format!("{} {}", "SHA-256:".bright_green(), sha256.bright_white()));

    let ghidra_root = config::resolve_ghidra_path(ghidra_path).ok_or(EngineError::GhidraNotFound)?;
    let headless_exe = config::resolve_headless_exe(&ghidra_root);
    if !headless_exe.exists() { return Err(EngineError::HeadlessNotFound(headless_exe.display().to_string())); }

    let script_path = config::resolve_script_path();
    if !script_path.exists() { return Err(EngineError::ScriptNotFound(script_path.display().to_string())); }

    let output_json = match output {
        Some(p) => PathBuf::from(p),
        None => config::output_dir().join(format!("{sha256}.json")),
    };

    let project_dir = config::temp_project_dir();
    let project_name = format!("wisdra_{}", &sha256[..8]);
    let target_abs = std::fs::canonicalize(&target_path)?;
    let script_abs = std::fs::canonicalize(&script_path)?;
    let output_abs = std::path::absolute(&output_json)?;

    let mut cmd = Command::new(&headless_exe);
    cmd.arg(project_dir.to_str().unwrap()).arg(&project_name)
       .arg("-import").arg(target_abs.to_str().unwrap())
       .arg("-scriptPath").arg(script_abs.parent().unwrap().to_str().unwrap())
       .arg("-postScript").arg(script_abs.file_name().unwrap().to_str().unwrap()).arg(output_abs.to_str().unwrap());

    if deep { cmd.env("WISDRA_DEEP_ANALYSIS", "1"); }
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());

    if !quiet { println!("\n  {} Launching Ghidra headless analysis...\n", "⚙".bright_yellow()); }

    let progress = create_progress_bar(timeout_secs);
    let analysis = tokio::spawn(async move { cmd.output().await });
    let pb = progress.clone();
    let ticker = tokio::spawn(async move {
        let mut e = 0u64;
        loop { tokio::time::sleep(Duration::from_secs(1)).await; e+=1; pb.set_position(e); if pb.is_finished() { break; } }
    });

    let result = time::timeout(Duration::from_secs(timeout_secs), analysis).await;
    progress.finish_and_clear();
    ticker.abort();

    match result {
        Ok(Ok(Ok(out))) => {
            if !out.status.success() {
                return Err(EngineError::ProcessFailed(out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).to_string()));
            }
        }
        Ok(Ok(Err(e))) => return Err(EngineError::Io(e)),
        Ok(Err(e)) => return Err(EngineError::Setup(format!("Join: {e}"))),
        Err(_) => return Err(EngineError::Timeout(timeout_secs)),
    }

    if !output_abs.exists() { return Err(EngineError::NoOutput); }
    if !quiet { println!("\n  {} Report: {}\n", "✔".bright_green().bold(), output_abs.display().to_string().bright_white().underline()); }

    let report = parser::parse_report(&output_abs)?;
    
    if verify {
        println!("\n  {} Launching Formal Verification Engine (ExposureZ3)...\n", "⚙".bright_magenta().bold());
        let verifier_exe = Path::new("target").join("release").join("exposure_z3.exe");
        if verifier_exe.exists() {
            let status = std::process::Command::new(&verifier_exe)
                .arg("analyze")
                .arg(&target_abs)
                .status();
            
            if let Ok(st) = status {
                if !st.success() {
                    eprintln!("  {} ExposureZ3 exited with status: {}", "⚠".bright_yellow(), st);
                }
            } else {
                eprintln!("  {} Failed to spawn ExposureZ3", "⚠".bright_yellow());
            }
        } else {
            eprintln!("  {} ExposureZ3 binary not found at: {}", "⚠".bright_red(), verifier_exe.display());
            eprintln!("  Please run `cargo build --release` in the workspace root.");
        }
    }

    dashboard::render(&report)?;
    std::fs::remove_dir_all(&project_dir).ok();
    Ok(())
}

pub async fn setup_environment(ghidra_path: Option<&str>) -> Result<()> {
    println!("\n  {} Wisdra Environment Setup\n", "⚙".bright_cyan().bold());
    let sep = "─".repeat(60);

    if let Some(path) = ghidra_path {
        let p = PathBuf::from(path);
        if p.exists() {
            let headless = config::resolve_headless_exe(&p);
            if headless.exists() {
                println!("  {} Ghidra: {}", "✔".bright_green(), path.bright_white());
                println!("  {} Headless: {}", "✔".bright_green(), headless.display().to_string().bright_white());
                println!("\n  {} Set GHIDRA_INSTALL_DIR={}\n", "💡".bright_yellow(), path.bright_cyan());
                return Ok(());
            }
        }
        return Err(EngineError::Setup(format!("Invalid Ghidra path: {path}")));
    }

    println!("{}", sep.bright_black());
    println!("  {}", "Ghidra Setup Instructions".bright_white().bold());
    println!("{}\n", sep.bright_black());
    println!("  {} Download: {}", "1.".bright_cyan(), "https://github.com/NationalSecurityAgency/ghidra/releases".bright_blue().underline());
    println!("  {} Extract to permanent dir (C:\\ghidra or /opt/ghidra)", "2.".bright_cyan());
    println!("  {} Set env: {}", "3.".bright_cyan(), "GHIDRA_INSTALL_DIR=<path>".bright_yellow());
    println!("  {} Or: {}", "4.".bright_cyan(), "wisdra analyze target.exe --ghidra-path <path>".bright_yellow());
    println!("\n  {} Requires Java 21+\n", "⚠".bright_red());
    println!("{}", sep.bright_black());

    match std::process::Command::new("java").arg("-version").output() {
        Ok(o) => println!("\n  {} Java: {}", "✔".bright_green(), String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("?")),
        Err(_) => println!("\n  {} Java NOT detected", "✖".bright_red()),
    }

    let script = config::resolve_script_path();
    if script.exists() { println!("  {} Script: {}", "✔".bright_green(), script.display()); }
    else { println!("  {} Script missing: {}", "✖".bright_red(), script.display()); }
    println!();
    Ok(())
}
