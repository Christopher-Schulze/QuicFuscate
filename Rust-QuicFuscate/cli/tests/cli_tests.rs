use quicfuscate_cli::options::{CommandLineOptions, Fingerprint};
use clap::Parser;

#[test]
fn default_values() {
    let opts = CommandLineOptions::try_parse_from(["prog"]).unwrap();
    assert_eq!(opts.server, "example.com");
    assert_eq!(opts.port, 443);
    assert_eq!(opts.fingerprint, Fingerprint::Chrome);
    assert!(!opts.no_utls);
}

#[test]
fn parse_custom_values() {
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
    ])
    .unwrap();
    assert_eq!(opts.server, "host");
    assert_eq!(opts.port, 123);
    assert_eq!(opts.fingerprint, Fingerprint::Firefox);
    assert!(opts.no_utls);
    assert!(opts.verify_peer);
    assert_eq!(opts.ca_file.as_deref(), Some("cafile"));
    assert!(opts.verbose);
    assert!(opts.debug_tls);
}
