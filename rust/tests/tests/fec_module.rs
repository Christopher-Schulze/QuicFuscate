use fec::{
    fec_module_cleanup_stub as fec_module_cleanup,
    fec_module_decode_stub as fec_module_decode,
    fec_module_encode_stub as fec_module_encode,
    fec_module_init_stub as fec_module_init,
};

#[test]
fn encode_decode() {
    assert_eq!(0, fec_module_init());
    let msg = b"hello";
    let enc = fec_module_encode(msg);
    assert!(!enc.is_empty());
    let dec = fec_module_decode(&enc);
    fec_module_cleanup();
    assert_eq!(dec, msg);
}
