use fec::{
    fec_module_cleanup, fec_module_decode, fec_module_encode, fec_module_init,
    FECConfig, FECModule, FECPacket,
};

#[test]
fn encode_decode() {
    assert_eq!(0, fec_module_init());
    let msg = b"hello";
    let mut enc_len = 0usize;
    let enc_ptr = fec_module_encode(msg.as_ptr(), msg.len(), &mut enc_len as *mut usize);
    assert!(!enc_ptr.is_null());
    let enc = unsafe { Vec::from_raw_parts(enc_ptr, enc_len, enc_len) };
    let mut dec_len = 0usize;
    let dec_ptr = fec_module_decode(enc.as_ptr(), enc.len(), &mut dec_len as *mut usize);
    let dec = unsafe { Vec::from_raw_parts(dec_ptr, dec_len, dec_len) };
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
    let result = module.decode(&[repair]).unwrap();
    assert!(result.is_empty());
}
