use fec::{fec_module_encode, fec_module_decode, fec_module_init, fec_module_cleanup, fec_module_free};

#[test]
fn encode_decode_loop_with_free() {
    let handle = fec_module_init();
    assert!(!handle.is_null());
    for _ in 0..100 {
        let msg = b"hello";
        let mut enc_len = 0usize;
        let enc_ptr = fec_module_encode(handle, msg.as_ptr(), msg.len(), &mut enc_len as *mut usize);
        assert!(!enc_ptr.is_null());
        let mut dec_len = 0usize;
        let dec_ptr = fec_module_decode(handle, enc_ptr, enc_len, &mut dec_len as *mut usize);
        assert!(!dec_ptr.is_null());
        fec_module_free(handle, enc_ptr, enc_len);
        fec_module_free(handle, dec_ptr, dec_len);
    }
    fec_module_cleanup(handle);
}
