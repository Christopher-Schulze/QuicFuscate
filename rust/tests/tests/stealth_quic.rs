use stealth::{QuicFuscateStealth, BrowserProfile};
use core::{QuicConfig, QuicConnection};
use tokio::runtime::Runtime;

#[test]
fn stealth_quic_negotiation() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
        let mut client = QuicConnection::new(cfg.clone())?;
        let mut server = QuicConnection::new(cfg)?;
        client.connect("127.0.0.1:443")?;
        server.connect("127.0.0.1:443")?;

        let mut stealth = QuicFuscateStealth::new();
        stealth.domain_fronting = stealth::domain_fronting::SniHiding::new(
            stealth::domain_fronting::SniConfig {
                front_domain: "front.example.com".into(),
                real_domain: "example.com".into(),
            },
        );
        stealth.set_browser_profile(BrowserProfile::Chrome);
        stealth.enable_utls(true);
        stealth.enable_domain_fronting(true);
        stealth.enable_http3_masq(true);

        let hello = stealth.generate_client_hello();
        assert!(!hello.is_empty());
        let fronted = stealth.apply_sni_fronting(&hello);
        assert_ne!(hello, fronted);

        let req = stealth.generate_h3_request("/");
        assert!(req.windows(5).any(|w| w == b":path"));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
