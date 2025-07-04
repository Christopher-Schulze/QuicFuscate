use fec::{
    fec_module_cleanup, fec_module_decode, fec_module_encode, fec_module_free, fec_module_init,
    FECConfig, FECModule,
};

#[test]
fn encode_decode() {
    let handle = fec_module_init();
    assert!(!handle.is_null());
    let msg = b"hello";
    let mut enc_len = 0usize;
    let enc_ptr = fec_module_encode(handle, msg.as_ptr(), msg.len(), &mut enc_len as *mut usize);
    assert!(!enc_ptr.is_null());
    let enc_slice = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };
    let enc = enc_slice.to_vec();
    fec_module_free(handle, enc_ptr, enc_len);
    let mut dec_len = 0usize;
    let dec_ptr = fec_module_decode(handle, enc.as_ptr(), enc.len(), &mut dec_len as *mut usize);
    let dec_slice = unsafe { std::slice::from_raw_parts(dec_ptr, dec_len) };
    let dec = dec_slice.to_vec();
    fec_module_free(handle, dec_ptr, dec_len);
    fec_module_cleanup(handle);
    assert_eq!(dec, msg);
}

#[test]
fn decode_from_repair_packet() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = FECModule::new(FECConfig::default());
    module.update_network_metrics(fec::NetworkMetrics {
        packet_loss_rate: 0.1,
    });
    let packets = module.encode_packet(b"abc", 1)?;
    assert!(packets.len() >= 2);
    let repair = packets.into_iter().find(|p| p.is_repair).unwrap();
    let result = module.decode(&[repair])?;
    assert_eq!(result, b"abc");
    Ok(())
}

#[test]
fn update_metrics_increases_redundancy() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = FECConfig::default();
    cfg.redundancy_ratio = 0.0;
    let mut module = FECModule::new(cfg);
    let packets_before = module.encode_packet(b"data", 1)?;
    assert!(packets_before.len() >= 1);
    module.update_network_metrics(fec::NetworkMetrics {
        packet_loss_rate: 0.5,
    });
    let packets_after = module.encode_packet(b"data", 1)?;
    assert!(packets_after.len() > 1);
    Ok(())
}

#[test]
fn strategy_switches_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = FECModule::new(FECConfig::default());
    // Initially off
    let pkts = module.encode_packet(b"abc", 1)?;
    assert_eq!(1, pkts.len());
    // Introduce moderate loss
    module.update_network_metrics(fec::NetworkMetrics {
        packet_loss_rate: 0.1,
    });
    let pkts = module.encode_packet(b"abc", 2)?;
    assert!(pkts.len() > 1);
    Ok(())
}
