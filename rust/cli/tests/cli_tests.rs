use quicfuscate_cli::options::{CommandLineOptions, Fingerprint};
use quicfuscate_cli::run_cli;
use clap::Parser;

#[test]
fn default_values() -> Result<(), clap::Error> {
    let opts = CommandLineOptions::try_parse_from(["prog"])?;
    assert_eq!(opts.server, "example.com");
    assert_eq!(opts.port, 443);
    assert_eq!(opts.fingerprint, Fingerprint::Chrome);
    assert!(!opts.no_utls);
    Ok(())
}

#[test]
fn parse_custom_values() -> Result<(), clap::Error> {
    let opts = CommandLineOptions::try_parse_from([
        "prog",
        "--server",
        "host",
        "--port",
        "123",
        "--fingerprint",
        "firefox",
        "--no-utls",
        "--verify-peer",
        "--ca-file",
        "cafile",
        "--verbose",
        "--debug-tls",
    ])?;
    assert_eq!(opts.server, "host");
    assert_eq!(opts.port, 123);
    assert_eq!(opts.fingerprint, Fingerprint::Firefox);
    assert!(opts.no_utls);
    assert!(opts.verify_peer);
    assert_eq!(opts.ca_file.as_deref(), Some("cafile"));
    assert!(opts.verbose);
    assert!(opts.debug_tls);
    Ok(())
}

#[test]
fn host_alias() -> Result<(), clap::Error> {
    let opts = CommandLineOptions::try_parse_from([
        "prog",
        "--host",
        "example.org",
    ])?;
    assert_eq!(opts.server, "example.org");
    Ok(())
}

#[test]
fn demo_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let opts = CommandLineOptions::try_parse_from(["prog"])?;
    let result = run_cli(opts, true)?;
    assert_eq!(result, b"demo data".to_vec());
    Ok(())
}
