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
            .arg("--step")
            .arg("verify_patches")
            .status()
            .expect("Failed to execute quiche workflow");

        if !status.success() {
            let code = status.code().unwrap_or(-1);
            panic!("Quiche workflow failed with exit code {}", code);
        } else {
            println!("cargo:warning=Workflow completed successfully");
        }
    }
}
