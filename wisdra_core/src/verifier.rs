use std::path::Path;
use std::process::Command;

pub fn run_exposure_z3(target_path: &str) -> Result<(), String> {
    println!("\n============================================================");
    println!("[ WISDRA V2 :: FORMAL VERIFICATION ENGINE (EXPOSUREZ3) ]");
    println!("============================================================\n");
    
    let target_abs = match std::fs::canonicalize(target_path) {
        Ok(path) => path,
        Err(e) => return Err(format!("Target not found for verification: {}", e)),
    };
    
    // Look for exposure_z3 in the release directory
    let workspace_dir = Path::new("..").canonicalize().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let verifier_exe = workspace_dir.join("target").join("release").join("exposure_z3.exe");
    
    if !verifier_exe.exists() {
        return Err(format!("ExposureZ3 binary not found at: {}\nPlease run `cargo build --release` in the workspace root.", verifier_exe.display()));
    }
    
    println!("[*] Launching Z3 Theorem Prover on extracted constraints...");
    
    let mut child = Command::new(verifier_exe)
        .arg("analyze")
        .arg(target_abs)
        .spawn()
        .map_err(|e| format!("Failed to spawn ExposureZ3: {}", e))?;
        
    let status = child.wait().map_err(|e| format!("Failed to wait for ExposureZ3: {}", e))?;
    
    if !status.success() {
        return Err(format!("ExposureZ3 exited with status: {}", status));
    }
    
    Ok(())
}
