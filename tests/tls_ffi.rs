use quicfuscate::tls_ffi::{
    quiche_chlo_builder_add_wrapper, quiche_chlo_builder_free_wrapper,
    quiche_chlo_builder_new_wrapper, quiche_config_set_chlo_builder_wrapper,
    LAST_HELLO,
};
use std::os::raw::c_void;

#[test]
fn ffi_records_clienthello_bytes() {
    let data = [0u8, 1, 2, 3];
    unsafe {
        let b = quiche_chlo_builder_new_wrapper();
        quiche_chlo_builder_add_wrapper(b, data.as_ptr(), data.len());
        quiche_config_set_chlo_builder_wrapper(std::ptr::null_mut::<c_void>(), b);
        quiche_chlo_builder_free_wrapper(b);
    }
    let stored = LAST_HELLO.lock().unwrap().clone();
    assert_eq!(stored, data);
}
