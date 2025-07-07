use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let quiche_path = env::var("QUICHE_PATH")
        .unwrap_or_else(|_| "libs/patched_quiche/quiche".into());

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

        let status = Command::new("bash")
            .arg(script)
            .arg("--step")
            .arg("fetch")
            .arg("--step")
            .arg("patch")
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("cargo:warning=Workflow completed successfully");
            }
            Ok(s) => {
                println!("cargo:warning=Workflow failed with status {}", s);
            }
            Err(e) => {
                println!("cargo:warning=Could not execute workflow: {}", e);
            }
        }
    }
}
