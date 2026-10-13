//! Optional hand-off to the external ExposureZ3 formal verification engine.

use crate::config;
use crate::error::Result;
use std::path::Path;
use std::process::Command;

/// Run `exposure_z3 analyze <target>`, inheriting stdio. A non-zero exit is
/// reported as a warning rather than failing the whole analysis.
pub fn run_exposure_z3(target: &Path, explicit: Option<&Path>) -> Result<()> {
    let exe = config::resolve_verifier(explicit)?;
    tracing::info!(verifier = %exe.display(), "launching ExposureZ3");
    let status = Command::new(&exe).arg("analyze").arg(target).status()?;
    if !status.success() {
        tracing::warn!("ExposureZ3 exited with {status}");
    }
    Ok(())
}
