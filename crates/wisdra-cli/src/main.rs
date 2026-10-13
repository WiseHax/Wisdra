//! Wisdra command-line interface.
//!
//! Engines live in `wisdra-engine`: `--fast` runs the native Rust parser,
//! otherwise Ghidra headless + WisdraExtract.java. Either way the report
//! feeds the Markdown/YARA writers and the TUI dashboard.

mod ui;

use anyhow::Context;
use clap::{ArgAction, Args, Parser, Subcommand};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use wisdra_engine::ghidra::GhidraOptions;
use wisdra_engine::model::WisdraReport;
use wisdra_engine::{Engine, config, ghidra, memory, native, radar, reporter, verifier, yara};

#[derive(Parser)]
#[command(name = "wisdra", version, about = "Automated binary analysis & live memory forensics")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    /// Directory for reports, logs, YARA rules and memory dumps
    #[arg(long, global = true, env = "WISDRA_OUTPUT_DIR", default_value = "output")]
    output_dir: PathBuf,
}

#[derive(Args, Clone)]
struct EngineArgs {
    /// Native Rust triage only: no Ghidra or Java, finishes in milliseconds
    #[arg(long, short = 'f', conflicts_with_all = ["deep", "ghidra_path"])]
    fast: bool,

    /// Ghidra installation directory (fallback: GHIDRA_HOME, then GHIDRA_INSTALL_DIR)
    #[arg(long, short = 'g')]
    ghidra_path: Option<PathBuf>,

    /// Per-sample Ghidra timeout in seconds
    #[arg(long, short = 't', default_value_t = 600)]
    timeout: u64,

    /// Enable deep analysis inside the Ghidra script
    #[arg(long)]
    deep: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a binary (Ghidra deep analysis, or native triage with --fast)
    #[command(alias = "scan")]
    Analyze {
        /// Path to the target binary
        target: PathBuf,
        #[command(flatten)]
        engine: EngineArgs,
        /// Skip the interactive dashboard (implied when stdout is not a terminal)
        #[arg(long, short = 'n')]
        no_ui: bool,
        /// Print the final JSON report to stdout (implies --no-ui)
        #[arg(long)]
        json: bool,
        /// Run the external ExposureZ3 verifier after analysis
        #[arg(long)]
        verify: bool,
        /// Path to the ExposureZ3 binary
        #[arg(long, env = "WISDRA_EXPOSURE_Z3")]
        z3_path: Option<PathBuf>,
    },

    /// Analyze every binary in a directory and cluster the results
    Triage {
        /// Directory of samples (searched recursively; detected by extension or magic bytes)
        target_dir: PathBuf,
        #[command(flatten)]
        engine: EngineArgs,
        /// Concurrent analyses [default: CPU count with --fast, otherwise 2 since each Ghidra JVM needs 1-4 GB]
        #[arg(long, short = 'j')]
        jobs: Option<usize>,
        /// Print the triage summary as JSON to stdout
        #[arg(long)]
        json: bool,
    },

    /// Scan a live process for RWX memory regions (Windows only)
    LiveScan {
        /// Process ID to scan
        pid: u32,
    },

    /// Re-render a saved JSON report (Markdown + optional dashboard)
    Report {
        /// Path to a report produced by `wisdra analyze`
        json_file: PathBuf,
        /// Skip the interactive dashboard
        #[arg(long, short = 'n')]
        no_ui: bool,
    },

    /// Check the environment: Ghidra, Java, extraction script, ExposureZ3
    Setup {
        #[arg(long, short = 'g')]
        ghidra_path: Option<PathBuf>,
        #[arg(long, env = "WISDRA_EXPOSURE_Z3")]
        z3_path: Option<PathBuf>,
    },

    /// Print version, platform and engine information
    Info,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[-] error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("WISDRA_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).with_writer(std::io::stderr).init();
}

fn engine(args: &EngineArgs, output_dir: &Path) -> anyhow::Result<Engine> {
    if args.fast {
        return Ok(Engine::Native { output_dir: output_dir.to_path_buf() });
    }
    Ok(Engine::Ghidra(GhidraOptions {
        ghidra_root: config::resolve_ghidra_root(args.ghidra_path.as_deref())
            .context("Ghidra is required for deep analysis (use --fast for native triage)")?,
        output_dir: output_dir.to_path_buf(),
        timeout: Duration::from_secs(args.timeout),
        deep: args.deep,
    }))
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let out = &cli.output_dir;
    match cli.command {
        Commands::Analyze { target, engine: args, no_ui, json, verify, z3_path } => {
            let report = match engine(&args, out)? {
                Engine::Native { output_dir } => {
                    let started = Instant::now();
                    let a = native::analyze_file(&target, &output_dir)?;
                    eprintln!("[+] JSON report:  {}  ({} ms)", a.report_path.display(), started.elapsed().as_millis());
                    a.report
                }
                Engine::Ghidra(opts) => {
                    eprintln!("[*] Analyzing {} with Ghidra (timeout {}s)...", target.display(), args.timeout);
                    let a = ghidra::run_headless_analysis(&target, &opts)?;
                    eprintln!("[+] JSON report:  {}", a.report_path.display());
                    eprintln!("[+] Ghidra log:   {}", a.log_path.display());
                    a.report
                }
            };
            write_artifacts(&report, out)?;

            if verify {
                if report.vulnerabilities.is_empty() {
                    eprintln!("[*] Verification skipped: no vulnerabilities to verify.");
                } else if let Err(e) = verifier::run_exposure_z3(&target, z3_path.as_deref()) {
                    eprintln!("[-] Formal verification unavailable: {e}");
                }
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                show_dashboard(&report, no_ui)?;
            }
        }
        Commands::Triage { target_dir, engine: args, jobs, json } => {
            let engine = engine(&args, out)?;
            let jobs = jobs.unwrap_or_else(|| match engine {
                Engine::Native { .. } => std::thread::available_parallelism().map_or(4, |n| n.get()),
                Engine::Ghidra(_) => 2,
            });
            let started = Instant::now();
            let summary = radar::run_bulk_triage(&target_dir, &engine, jobs)?;
            let path = config::ensure_output_dir(out)?.join("triage_summary.json");
            std::fs::write(&path, serde_json::to_string_pretty(&summary)?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                radar::print_summary(&summary);
                eprintln!("\n[+] Summary written to {} ({:.1}s)", path.display(), started.elapsed().as_secs_f64());
            }
            if summary.scanned == 0 {
                return Ok(ExitCode::FAILURE);
            }
        }
        Commands::LiveScan { pid } => {
            memory::scan_process_memory(pid, &out.join("dumps"))?;
        }
        Commands::Report { json_file, no_ui } => {
            let report = wisdra_engine::load_report(&json_file)?;
            write_artifacts(&report, out)?;
            show_dashboard(&report, no_ui)?;
        }
        Commands::Setup { ghidra_path, z3_path } => return Ok(setup(ghidra_path.as_deref(), z3_path.as_deref())),
        Commands::Info => print_info(),
    }
    Ok(ExitCode::SUCCESS)
}

/// Write the Markdown report and the standalone YARA rule.
fn write_artifacts(report: &WisdraReport, out: &Path) -> anyhow::Result<()> {
    let dir = config::ensure_output_dir(out)?;
    let md = reporter::export_markdown(report, &dir).context("writing Markdown report")?;
    let yar = dir.join(format!("{}.yar", report.metadata.sha256));
    std::fs::write(&yar, yara::generate_yara_rule(report)).context("writing YARA rule")?;
    eprintln!("[+] Markdown:     {}", md.display());
    eprintln!("[+] YARA rule:    {}", yar.display());
    Ok(())
}

fn show_dashboard(report: &WisdraReport, no_ui: bool) -> anyhow::Result<()> {
    if no_ui || !std::io::stdout().is_terminal() {
        print_summary(report);
        return Ok(());
    }
    ui::render_dashboard(report).map_err(|e| anyhow::anyhow!("dashboard: {e}"))
}

fn print_summary(r: &WisdraReport) {
    let t = &r.threat_indicators;
    println!("[+] {}  [{}]  risk={} ({}/100)", r.metadata.file_name, r.metadata.engine, t.risk_label, t.risk_score);
    println!(
        "    format={}  arch={}  sections={}  imports={}",
        r.metadata.file_format,
        r.metadata.architecture,
        r.sections.len(),
        r.imports.len()
    );
    if let Some(b) = &r.binary {
        let mut facts = vec![format!("signed={}", b.has_signature), format!("overlay={}B", b.overlay_size)];
        if let Some(h) = &b.imphash {
            facts.push(format!("imphash={h}"));
        }
        if let Some(i) = &b.interpreter {
            facts.push(format!("interp={i}"));
        }
        println!("    {}", facts.join("  "));
        if !b.packer_hints.is_empty() {
            println!("    packer hints: {}", b.packer_hints.join(", "));
        }
    }
    if !t.suspicious_imports.is_empty() {
        println!("    suspicious APIs: {}", t.suspicious_imports.join(", "));
    }
    if r.metadata.engine == "ghidra" {
        println!("    vulns={}  kill_chains={}", r.vulnerabilities.len(), r.kill_chains.len());
    }
}

fn print_info() {
    println!("wisdra {} ({}/{})", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH);
    println!("report schema: v{}", wisdra_engine::model::SCHEMA_VERSION);
    println!("engines:       native (PE/ELF/Mach-O), ghidra (headless + WisdraExtract.java)");
    println!("live-scan:     {}", if cfg!(windows) { "available" } else { "Windows only" });
}

fn setup(ghidra_path: Option<&Path>, z3_path: Option<&Path>) -> ExitCode {
    let mut ok = true;
    let mut check = |name: &str, result: Result<String, String>, required: bool| match result {
        Ok(detail) => println!("  [ok]   {name:<14} {detail}"),
        Err(detail) => {
            println!("  [{}] {name:<14} {detail}", if required { "FAIL" } else { "warn" });
            ok &= !required;
        }
    };

    println!(
        "Wisdra {} environment check (needed for Ghidra mode; --fast needs none of this)\n",
        env!("CARGO_PKG_VERSION")
    );
    let root = config::resolve_ghidra_root(ghidra_path);
    check("Ghidra", root.as_ref().map(|p| p.display().to_string()).map_err(|e| e.to_string()), true);
    if let Ok(root) = &root {
        check(
            "Headless",
            config::resolve_headless(root).map(|p| p.display().to_string()).map_err(|e| e.to_string()),
            true,
        );
    }
    let java = std::process::Command::new("java")
        .arg("-version")
        .output()
        .map_err(|_| "java not found on PATH (Ghidra needs JDK 21+)".to_string())
        .and_then(|o| {
            let line = String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("?").to_string();
            match java_major(&line) {
                Some(v) if v < 21 => Err(format!("{line} (Ghidra 11.2+ needs JDK 21+)")),
                _ => Ok(line),
            }
        });
    check("Java", java, true);
    check(
        "Script",
        config::resolve_script_dir()
            .map(|p| p.join(config::EXTRACTION_SCRIPT).display().to_string())
            .map_err(|e| e.to_string()),
        true,
    );
    check(
        "ExposureZ3",
        config::resolve_verifier(z3_path).map(|p| p.display().to_string()).map_err(|e| format!("{e} (optional)")),
        false,
    );

    if ok {
        println!("\nReady.");
        ExitCode::SUCCESS
    } else {
        println!("\nDownload Ghidra: https://github.com/NationalSecurityAgency/ghidra/releases");
        ExitCode::FAILURE
    }
}

/// Parse the major version from `java -version` output, e.g.
/// `openjdk version "17.0.17"` -> 17, `java version "1.8.0_202"` -> 8.
fn java_major(line: &str) -> Option<u32> {
    let version = line.split('"').nth(1)?;
    let mut parts = version.split(['.', '_', '-']);
    match parts.next()?.parse().ok()? {
        1 => parts.next()?.parse().ok(),
        major => Some(major),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_java_versions() {
        assert_eq!(java_major(r#"openjdk version "17.0.17" 2025-10-21 LTS"#), Some(17));
        assert_eq!(java_major(r#"openjdk version "21" 2023-09-19"#), Some(21));
        assert_eq!(java_major(r#"java version "1.8.0_202""#), Some(8));
        assert_eq!(java_major("garbage"), None);
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn fast_conflicts_with_ghidra_flags() {
        assert!(Cli::try_parse_from(["wisdra", "analyze", "x", "--fast", "--deep"]).is_err());
        assert!(Cli::try_parse_from(["wisdra", "analyze", "x", "--fast"]).is_ok());
    }
}
