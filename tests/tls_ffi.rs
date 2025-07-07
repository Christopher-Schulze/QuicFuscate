use quicfuscate::tls_ffi::{quiche_config_set_custom_tls, LAST_HELLO};
use std::os::raw::c_void;

#[test]
fn ffi_records_clienthello_bytes() {
    let data = [0u8, 1, 2, 3];
    unsafe { quiche_config_set_custom_tls(std::ptr::null_mut::<c_void>(), data.as_ptr(), data.len()); }
    let stored = LAST_HELLO.lock().unwrap().clone();
    assert_eq!(stored, data);
}
