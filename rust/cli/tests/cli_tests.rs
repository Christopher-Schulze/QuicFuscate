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

#[test]
fn verify_peer_dummy_ca() -> Result<(), Box<dyn std::error::Error>> {
    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIUSaKuYaaa7DWyHsmE2yAH8KlOHa4wDQYJKoZIhvcNAQEL\nBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUwNzA0MTEyNjE3WhcNMjUw\nNzA1MTEyNjE3WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAK5oTh4xA4rvCDB/Zlh8OFG+Puu4QRq/i/S5V1rS\nAravYHVZAj7uj20VsjzUoL9Zy8R707HQj7N4dr1k7ipKdMUPCD46kO6E9lnuNR9c\nC/IzNIpQwhCDXdaFskl+O2Q+/krK2Ugs9/7K/5Rv8sF4bTjF5oc6qcn3GM0zjJYv\nEM2gkQsTqSqcbbS5w+tNc2Uk9VCjbsnm6Tsfcv3+3HdKloW+IBi8XvhB2icGLXkS\nyNAjr4PCyi8DaBRRgLB/OYtC5V5qiTgTscNvop/1BknvtvPJVPBlgzbuQXaglekB\n9+dWgt2rikQp9idUX5PyhXVKObtMoigpflPjJIde0NO0UCMCAwEAAaNTMFEwHQYD\nVR0OBBYEFD1GRfi6wWeEHBkn38Y5kz/Vy52OMB8GA1UdIwQYMBaAFD1GRfi6wWeE\nHBkn38Y5kz/Vy52OMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAFgF4ECHZJ3PKYNI7L/ZkosQ5GbZWIgrk0BYqS78O6HBxmdJvbdxEOPrsgdnVFqU\nXJdjW7ONNo+fGSIpkCvqEy97/JA0OafrzmKQRuu8BMfT8viLE11CBscBZtL6/zhl\n6wGOFEAdFsBp7e8u7xajzPHORE9OpJOS+grcxXz0Xp9FLcrzF3GatGPBdL4Cklmx\nLJYTtW1wBQzha5bHoBNWn/puhq/xQsLT5SZaEg65l37+8n5yNeGYcsU/JLuAV4jD\nxmmKZJIVt8+KNyVl1OjBO+5LqeT2YromUcznw2YG5eEO8EpqOQsa2/ftEK3WP2ti\nR+Tx5te611wrhDhuTzbyCnM=\n-----END CERTIFICATE-----";

    let dir = tempfile::tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, CERT)?;

    let opts = CommandLineOptions::try_parse_from([
        "prog",
        "--verify-peer",
        "--ca-file",
        ca_path.to_str().unwrap(),
    ])?;

    assert!(run_cli(opts, true).is_err());
    Ok(())
}
