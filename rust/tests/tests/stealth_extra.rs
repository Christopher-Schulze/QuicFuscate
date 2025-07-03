use stealth::{
    doh::{DohClient, DohConfig},
    domain_fronting::{SniConfig, SniHiding},
    fake_tls::FakeTls,
    BrowserProfile,
};
use tokio::runtime::Runtime;

#[test]
fn fake_tls_client_hello_non_empty() {
    let tls = FakeTls::new(BrowserProfile::Chrome);
    let hello = tls.generate_client_hello();
    assert!(!hello.is_empty());
    assert_eq!(hello[0], 0x16);
}

#[test]
fn domain_fronting_replaces_header() {
    let mut df = SniHiding::new(SniConfig {
        front_domain: "front.example.com".into(),
        real_domain: "real.example.com".into(),
    });
    df.enable(true);
    let out = df.apply_domain_fronting("Host: real.example.com");
    assert!(out.contains("front.example.com"));
}

#[test]
fn doh_resolver_caches_result() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut client = DohClient::new(DohConfig::default());
        client.enable(true);
        let first = client.resolve("example.com").await;
        let second = client.resolve("example.com").await;
        assert_eq!(first, second);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
