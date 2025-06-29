extern "C" {
    fn quic_error_success_code() -> i32;
}

pub fn success_code() -> i32 {
    unsafe { quic_error_success_code() }
}
