use stealth::QuicFuscateStealth;
use tokio::runtime::Runtime;

#[test]
fn domain_fronting_and_doh() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut s = QuicFuscateStealth::new();
        s.enable_domain_fronting(true);
        s.enable_doh(true);
        let headers = "Host: real.example.com";
        let df = s.apply_domain_fronting(headers);
        assert!(df.contains("front.example.com"));
        let ip = s.resolve_domain("example.com").await;
        assert_eq!(ip.to_string(), "93.184.216.34");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

