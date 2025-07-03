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
    assert_eq!(2, packets.len());
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
#[test]
fn adaptive_callback_overrides_ratio() {
    let mut module = FECModule::new(FECConfig::default());
    module.set_adaptive_callback(|m| if m.loss > 0.2 { 0.5 } else { 0.0 });
    module.update_network_metrics(fec::NetworkMetrics { packet_loss_rate: 0.3 });
    assert_eq!(module.config().redundancy_ratio, 0.5);
}

#[test]
fn update_config_resets_pool() {
    let mut module = FECModule::new(FECConfig::default());
    let old_ptr = module.pool_ptr() as usize;
    let mut cfg = FECConfig::default();
    cfg.memory_pool_block_size = 4096;
    module.update_config(cfg);
    let new_ptr = module.pool_ptr() as usize;
    assert_ne!(old_ptr, new_ptr);
    assert_eq!(module.config().memory_pool_block_size, 4096);
}

#[test]
fn stealth_mode_alters_repair() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = FECModule::new(FECConfig::default());
    module.enable_stealth_mode(true);
    module.update_network_metrics(fec::NetworkMetrics { packet_loss_rate: 0.1 });
    let packets1 = module.encode_packet(b"abc", 1)?;
    let repair1 = packets1.iter().find(|p| p.is_repair).unwrap().data.clone();
    module.enable_stealth_mode(false);
    let packets2 = module.encode_packet(b"abc", 1)?;
    let repair2 = packets2.iter().find(|p| p.is_repair).unwrap().data.clone();
    assert_ne!(repair1, repair2);
    Ok(())
}
