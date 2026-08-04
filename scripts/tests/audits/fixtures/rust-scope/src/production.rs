// unsafe in a comment and mem::forget(value) in a comment.
pub fn production_path() {
    let _literal = "unsafe { mem::forget(value) } Box::leak(value)";
    unsafe {
        std::ptr::read_volatile(std::ptr::null());
    }
    let _raw = r#"unsafe { Box::leak(value) }"#;
    let _char = 'u';
}

pub fn lifetime<'a>(value: &'a [u8]) -> &'a [u8] {
    value
}

pub fn intentional_memory_boundary(value: Box<u8>) {
    let _ = Box::leak(value);
    std::mem::forget(Box::new(0_u8));
}
