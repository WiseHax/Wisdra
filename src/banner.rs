//! Startup banner — terse, utilitarian.

use colored::Colorize;

pub fn print_banner() {
    let w = 78;
    let line = "=".repeat(w);
    println!("{}", line.bright_black());
    println!(
        " WISDRA v{}  |  Automated Binary Analysis Engine  |  UNCLASSIFIED//FOUO",
        env!("CARGO_PKG_VERSION")
    );
    println!("{}", line.bright_black());
}
