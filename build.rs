use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let quiche_path =
        env::var("QUICHE_PATH").unwrap_or_else(|_| "libs/patched_quiche/quiche".into());

    // Ensure the logs directory exists so the workflow can write logs
    let logs_dir = Path::new("libs/logs");
    if !logs_dir.exists() {
        if let Err(e) = fs::create_dir_all(logs_dir) {
            println!(
                "cargo:warning=Failed to create log directory {}: {}",
                logs_dir.display(),
                e
            );
        }
    }

    if !Path::new(&quiche_path).exists() {
        println!(
            "cargo:warning=Quiche sources missing at {}. Not running external scripts from build.rs.",
            quiche_path
        );
        println!(
            "cargo:warning=Use the modular scripts: './scripts/Build/build_quiche_and_check.sh'"
        );
        println!(
            "cargo:warning=Alternatively, set QUICHE_PATH to an existing quiche checkout before building."
        );
        // Intentionally do not run any shell scripts here to keep all script logic centralized in modular scripts
    }
}
