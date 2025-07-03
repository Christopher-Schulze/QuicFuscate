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

#[test]
fn stealth_toggles_and_zero_rtt() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut s = QuicFuscateStealth::new();
        s.enable_zero_rtt(true);
        s.set_zero_rtt_max_early_data(32);
        s.set_spinbit_probability(1.0);
        s.enable_spinbit(true);
        assert!(s.zero_rtt.send_early_data(b"hello").await.is_ok());
        assert!(!s.randomize_spinbit(true));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

