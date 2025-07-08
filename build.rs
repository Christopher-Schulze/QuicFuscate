use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let quiche_path = env::var("QUICHE_PATH")
        .unwrap_or_else(|_| "libs/patched_quiche/quiche".into());

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
            "cargo:warning=Quiche sources missing at {}. Running workflow...",
            quiche_path
        );

        let script: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "scripts",
            "quiche_workflow.sh",
        ]
        .iter()
        .collect();

        let output = Command::new("bash")
            .arg(script)
            .arg("--non-interactive")
            .arg("--step")
            .arg("fetch")
            .arg("--step")
            .arg("patch")
            .arg("--step")
            .arg("verify_patches")
            .output()
            .expect("Failed to execute quiche workflow");

        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            eprintln!("Quiche workflow failed with exit code {}", code);
            eprintln!("-- stdout --\n{}", stdout);
            eprintln!("-- stderr --\n{}", stderr);
            eprintln!("See logs in {}", logs_dir.display());
            panic!("Quiche workflow failed");
        } else {
            println!("cargo:warning=Workflow completed successfully");
        }
    }
}
