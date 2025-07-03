use core::{QuicConfig, QuicConnection};
use fec::{EncoderCore, DecoderCore, FecAlgorithm};
use tokio::runtime::Runtime;

#[test]
fn quic_fec_integration() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
        let _conn = QuicConnection::new(cfg)?;
        let enc = EncoderCore::new(FecAlgorithm::StripeXor);
        let dec = DecoderCore::new(FecAlgorithm::StripeXor);
        let data = b"ping";
        let pkts = enc.encode(data, 1)?;
        let rec = dec.decode(&pkts)?;
        assert_eq!(rec, data);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
