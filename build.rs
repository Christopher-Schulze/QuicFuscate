use std::env;
use std::path::Path;

fn main() {
    let quiche_path =
        env::var("QUICHE_PATH").unwrap_or_else(|_| "libs/patched_quiche/quiche".into());
    if !Path::new(&quiche_path).exists() {
        println!("cargo:warning=Quiche sources missing at {}. Run ./scripts/quiche_workflow.sh --step fetch", quiche_path);
    }
}
