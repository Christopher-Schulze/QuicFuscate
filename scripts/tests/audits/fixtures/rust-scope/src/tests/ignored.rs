pub fn ignored_test_source() {
    unsafe { std::ptr::read_volatile(std::ptr::null()); }
    let _ = std::mem::forget(Box::new(1_u8));
}
