use fec::{
    fec_module_cleanup, fec_module_decode, fec_module_encode, fec_module_free, fec_module_init,
    FECConfig, FECModule, FECPacket,
};

#[test]
fn encode_decode() {
    assert_eq!(0, fec_module_init());
    let msg = b"hello";
    let mut enc_len = 0usize;
    let enc_ptr = fec_module_encode(msg.as_ptr(), msg.len(), &mut enc_len as *mut usize);
    assert!(!enc_ptr.is_null());
    let enc_slice = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };
    let enc = enc_slice.to_vec();
    fec_module_free(enc_ptr, enc_len);
    let mut dec_len = 0usize;
    let dec_ptr = fec_module_decode(enc.as_ptr(), enc.len(), &mut dec_len as *mut usize);
    let dec_slice = unsafe { std::slice::from_raw_parts(dec_ptr, dec_len) };
    let dec = dec_slice.to_vec();
    fec_module_free(dec_ptr, dec_len);
    fec_module_cleanup();
    assert_eq!(dec, msg);
}

#[test]
fn decode_returns_empty_without_source_packet() {
    let module = FECModule::new(FECConfig::default());
    let repair = FECPacket {
        sequence_number: 1,
        is_repair: true,
        data: vec![1, 2, 3],
    };
    let result = match module.decode(&[repair]) {
        Ok(data) => data,
        Err(e) => panic!("decode failed: {:?}", e),
    };
    assert!(result.is_empty());
}

#[test]
fn update_metrics_increases_redundancy() {
    let mut cfg = FECConfig::default();
    cfg.redundancy_ratio = 0.0;
    let mut module = FECModule::new(cfg);
    let packets_before = module.encode_packet(b"data", 1).unwrap();
    assert_eq!(packets_before.len(), 1);
    module.update_network_metrics(fec::NetworkMetrics {
        packet_loss_rate: 0.5,
    });
    let packets_after = module.encode_packet(b"data", 1).unwrap();
    assert!(packets_after.len() > 1);
}
