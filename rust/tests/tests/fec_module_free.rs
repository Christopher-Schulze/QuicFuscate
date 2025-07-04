use fec::{FECConfig, FECModule};

#[test]
fn encode_decode_loop_with_free() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = FECModule::new(FECConfig::default());
    for _ in 0..100 {
        let msg = b"hello";
        let packets = module.encode_packet(msg, 1)?;
        let _ = module.decode(&packets)?;
    }
    Ok(())
}
