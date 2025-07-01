use fec::{fec_module_create, fec_module_destroy, fec_module_encode, fec_module_decode};

#[test]
fn ffi_encode_decode() {
    let handle = fec_module_create();
    assert!(!handle.is_null());
    let msg = b"hello";
    let mut out_len = 0usize;
    let enc_ptr = unsafe { fec_module_encode(handle, msg.as_ptr(), msg.len(), &mut out_len as *mut usize) };
    assert!(!enc_ptr.is_null());
    let enc = unsafe { Vec::from_raw_parts(enc_ptr, out_len, out_len) };
    let mut dec_len = 0usize;
    let dec_ptr = unsafe { fec_module_decode(handle, enc.as_ptr(), enc.len(), &mut dec_len as *mut usize) };
    let dec = unsafe { Vec::from_raw_parts(dec_ptr, dec_len, dec_len) };
    fec_module_destroy(handle);
    assert_eq!(dec, msg);
}
