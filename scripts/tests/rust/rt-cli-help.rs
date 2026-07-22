#![cfg(feature = "rust-tests")]

use std::process::Command;

fn run_help(args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_quicfuscate");
    let output = Command::new(bin).args(args).output().expect("run quicfuscate");
    assert!(
        output.status.success(),
        "help command failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn cli_help_lists_core_subcommands() {
    let help = run_help(&["--help"]);
    assert!(help.contains("client"), "missing client subcommand in help");
    assert!(help.contains("server"), "missing server subcommand in help");
    assert!(help.contains("verify-audit-log"), "missing audit verification subcommand in help");
}

#[test]
fn cli_subcommand_help_is_available() {
    let client_help = run_help(&["client", "--help"]);
    assert!(client_help.contains("--remote"), "client help missing --remote");

    let server_help = run_help(&["server", "--help"]);
    assert!(server_help.contains("--listen"), "server help missing --listen");

    let audit_help = run_help(&["verify-audit-log", "--help"]);
    assert!(audit_help.contains("PATH"), "audit verification help missing path argument");
}
